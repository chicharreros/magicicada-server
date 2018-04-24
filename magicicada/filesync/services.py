# Copyright 2008-2015 Canonical
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/magicicada-server

"""Gateway objects for accessing Data Access Objects (DAO) from the database.

Each Gateway performs actions based on a security principal and limits the
actions based on the principal. In the case of a ReadWriteVolumeGateway,
security is imposed based on the user's access to the storage objects.
"""

from __future__ import unicode_literals

import mimetypes
import os
import posixpath as pypath
import time
import uuid

from functools import wraps
from weakref import WeakValueDictionary

from django.conf import settings
from django.db import connection, models
from django.utils.timezone import now

from magicicada import metrics
from magicicada.filesync import errors, utils
from magicicada.filesync.dbmanager import (
    fsync_readonly,
    fsync_readonly_slave,
    fsync_commit,
    get_object_or_none,
    retryable_transaction,
)
from magicicada.filesync.models import (
    DEFAULT_QUOTA_BYTES,
    ROOT_PARENT,
    STATUS_LIVE,
    STATUS_DEAD,
    ContentBlob,
    Download,
    MoveFromShare,
    Share,
    ShareVolumeDelta,
    StorageObject,
    StorageUser,
    UploadJob,
    UserVolume,
)
from magicicada.filesync.notifier.notifier import get_notifier


# original dao.py starts here


class DAOBase(object):
    """Base class for all object that provide database access via a gateway."""

    readonly_error = 'This object is readonly.'

    def __init__(self, gateway=None):
        self.__gateway = gateway

    def _get_gateway(self):
        """Return the inner gateway for db access."""
        if self.__gateway is None:
            raise errors.StorageError(self.readonly_error)
        return self.__gateway

    def _set_gateway(self, gateway):
        """Set the gateway for db access."""
        self.__gateway = gateway

    _gateway = property(_get_gateway, _set_gateway)

    def _copy(self, obj):
        """Copy the data from obj into this object."""
        self.__dict__.clear()
        self.__dict__.update(obj.__dict__)

    def _load(self, *args, **kwargs):
        """Overriden by subclasses."""
        raise NotImplementedError("Need to override _load in subclasses.")

    @fsync_readonly
    def load(self, *args, **kwargs):
        """Reload the object."""
        self._load(*args, **kwargs)
        return self


class DAOStorageUser(DAOBase):
    """A Storage User DAO.

    This will be the main DAO for accessing all storage data on behalf of a
    user. All the data access performed from this class will return DAOs.

    """

    def __init__(self, user):
        super(DAOStorageUser, self).__init__()
        self.id = user.id
        self.username = user.username
        self.first_name = user.first_name
        self.last_name = user.last_name
        self.visible_name = user.get_full_name()
        self.is_active = user.is_active
        self.root_node = user.root_node
        self.root_volume = self.root_node.volume
        self.root_volume_id = self.root_volume.id
        self._volumes = WeakValueDictionary()
        self.max_storage_bytes = user.max_storage_bytes
        self.used_storage_bytes = user.used_bytes
        self._user = user

    @property
    def free_bytes(self):
        """Return the free bytes."""
        self._load()
        return max(0, self.max_storage_bytes - self.used_storage_bytes)

    def _load(self):
        """Load this storage user from the database."""
        u = self._gateway.get_user(self.id)
        self._copy(u)
        return self

    def update(self, max_storage_bytes=None):
        """Update the storage user information."""
        u = self._gateway.update(max_storage_bytes=max_storage_bytes)
        self._copy(u)

    @retryable_transaction()
    @fsync_commit
    def recalculate_quota(self):
        """Recalculate the user's quota."""
        return self._gateway.recalculate_quota()

    @retryable_transaction()
    @fsync_commit
    def make_udf(self, path):
        """Create a UDF for this user."""
        return self._gateway.make_udf(path)

    @fsync_readonly
    def get_udf(self, udf_id):
        """Get a UDF owned by this user.

        Note that this is not a udf volume, it is a readonly object.
        """
        return self._gateway.get_udf(udf_id)

    @retryable_transaction()
    @fsync_commit
    def delete_udf(self, udf_id):
        """Delete this UDF."""
        return self._gateway.delete_udf(udf_id)

    @fsync_readonly
    def get_share(self, share_id):
        """Get a share offer."""
        return self._gateway.get_share(share_id, accepted_only=False)

    def get_node_with_key(self, key):
        """Using a nodekey, get the node from the appropriate volume."""
        vol_id, node_id = utils.parse_nodekey(key)
        return self.volume(vol_id).get_node(node_id)

    def get_node(self, id, **kwargs):
        """Get a Node owned by this user."""
        return self.volume().get_node(id, **kwargs)

    @fsync_readonly
    def get_share_volumes(self):
        """Get volume gateways for all accepted shares."""
        gws = []
        for share in self._gateway.get_shared_to(accepted=True):
            gw = self._gateway.get_volume_gateway(share=share)
            vp = VolumeProxy.from_gateway(gw)
            self._volumes[share.id] = vp
            gws.append(vp)
        return gws

    @fsync_readonly
    def get_shared_by(self, node_id=None, accepted=None):
        """Get SharedDirectory volumes for this user."""
        return list(self._gateway.get_shared_by(node_id=node_id,
                                                accepted=accepted))

    @fsync_readonly
    def get_shared_to(self, accepted=None):
        """Get the SharedDirectories to this user."""
        return list(self._gateway.get_shared_to(accepted=accepted))

    @fsync_readonly
    def get_node_shares(self, node_id):
        """Return all shares this node is involved with.

        This will get the also nodes parents and look for shares of them
        """
        gw = self._gateway.get_root_gateway()
        nodeids = gw.get_node_parent_ids(node_id)
        return list(self._gateway.get_shares_of_nodes([node_id] + nodeids))

    @fsync_readonly
    def get_udf_by_path(self, path, from_full_path=False):
        """Get a UDF owned by this user.

        Note that this is not a udf volume, it is a readonly object.
        """
        return self._gateway.get_udf_by_path(path,
                                             from_full_path=from_full_path)

    @fsync_readonly
    def get_udfs(self):
        """Get the user's UDFs."""
        return list(self._gateway.get_udfs())

    @fsync_readonly
    def get_udf_volumes(self):
        """Get volume gatways for all UDFs."""
        gws = []
        for udf in self._gateway.get_udfs():
            gw = self._gateway.get_volume_gateway(udf=udf)
            vp = VolumeProxy.from_gateway(gw)
            self._volumes[udf.id] = vp
            gws.append(vp)
        return gws

    @fsync_readonly
    def get_uploadjobs(self, node_id=None):
        """Get the user's UploadJobs for this user.

        @param node_id: optionally only gets jobs for a specific file
        """
        gw = self._gateway.get_root_gateway()
        return list(gw.get_user_uploadjobs(node_id=node_id))

    @fsync_readonly
    def get_downloads(self):
        """Get all downloads for this user."""
        return self._gateway.get_downloads()

    def volume(self, id=None):
        """Return an uninitialized Volume."""
        key = id or 'root'
        try:
            vol = self._volumes[key]
        except KeyError:
            vol = VolumeProxy(id, self)
            self._volumes[key] = vol
        return vol

    @property
    def root(self):
        """A shortcut for getting user's default root volume."""
        return self.volume().root

    @fsync_readonly
    def get_public_files(self):
        """Get the nodes list of public files for this user."""
        return list(self._gateway.get_public_files())

    @fsync_readonly
    def get_public_folders(self):
        """Get the nodes list of public folders for this user."""
        return list(self._gateway.get_public_folders())

    @fsync_readonly_slave
    def get_photo_directories(self):
        """Get all the directories the user has containing photos."""
        return list(self._gateway.get_photo_directories())

    def _path_helper(self, vol_full_path):
        """Using the path, return the remaining path and the udf."""
        if (vol_full_path == settings.ROOT_USERVOLUME_PATH or
                vol_full_path.startswith(settings.ROOT_USERVOLUME_PATH + "/")):
            udf = self._gateway.get_udf(self.root_volume_id)
        else:
            udf = self._gateway.get_udf_by_path(vol_full_path,
                                                from_full_path=True)
        remaining_path = vol_full_path.split(udf.path)[1] or '/'
        vol_id = udf.id if udf.id != self.root_volume_id else None
        return vol_id, udf, remaining_path

    @fsync_readonly
    def get_node_by_path(self, path, **kwargs):
        """Get a node using only a path."""
        vol_id, udf, remaining_path = self._path_helper(path)
        return self.volume(vol_id).gateway.get_node_by_path(
            remaining_path, **kwargs)

    @retryable_transaction()
    @fsync_commit
    def make_tree_by_path(self, path):
        """Create a subdirectory using a path."""
        vol_id, udf, remaining_path = self._path_helper(path)
        return self.volume(vol_id).gateway.make_tree(
            udf.root_id, remaining_path)

    @retryable_transaction()
    @fsync_commit
    def make_file_by_path(self, path, hash=None, magic_hash=None):
        """Create a file using a path."""
        vol_id, udf, remaining_path = self._path_helper(path)
        dir_path, filename = os.path.split(remaining_path)
        if dir_path == "/":
            d = self.volume(udf.id).gateway.get_root()
        else:
            d = self.volume(udf.id).gateway.make_tree(udf.root_id, dir_path)
        return self.volume(vol_id).gateway.make_file(
            d.id, filename, hash=hash, magic_hash=magic_hash)

    @retryable_transaction()
    @fsync_commit
    def make_filepath_with_content(self, path, hash, crc32, size,
                                   deflated_size, storage_key, mimetype=None,
                                   enforce_quota=True, is_public=False,
                                   previous_hash=None, magic_hash=None):
        """Create a file using a path."""
        vol_id, udf, remaining_path = self._path_helper(path)
        dir_path, filename = os.path.split(remaining_path)
        if dir_path == "/":
            d = self.volume(udf.id).gateway.get_root()
        else:
            d = self.volume(udf.id).gateway.make_tree(udf.root_id, dir_path)
        return self.volume(vol_id).gateway.make_file_with_content(
            d.id, filename, hash, crc32, size, deflated_size, storage_key,
            mimetype=mimetype, enforce_quota=enforce_quota,
            is_public=is_public, previous_hash=previous_hash,
            magic_hash=magic_hash)

    @fsync_readonly
    def is_reusable_content(self, hash_value, magic_hash):
        """Return if the user can reuse the content."""
        return self._gateway.is_reusable_content(hash_value, magic_hash)


class VolumeObjectBase(DAOBase):
    """Base class for Data Access Objects that exist on a volume."""

    def __init__(self, volume, gateway):
        super(VolumeObjectBase, self).__init__(gateway)
        self.__volume = volume
        self.__gateway = gateway

    def _get_gateway(self):
        """Override base class so a gateway can be retrieved from the volume
        proxy."""
        if self.__gateway:
            return self.__gateway
        if self.__volume:
            self.__gateway = self.__volume.gateway
            return self.__gateway
        raise errors.StorageError(self.readonly_error)

    def _set_gateway(self, gateway):
        """Set the gateway for db access."""
        self.__gateway = gateway
    _gateway = property(_get_gateway, _set_gateway)

    @property
    def vol_type(self):
        """Return the volume type (root, udf, share)."""
        if self._gateway.udf:
            return 'udf'
        elif self._gateway.share:
            return 'share'
        return 'root'

    @property
    def vol_share(self):
        """Return the share if this is a share volume."""
        return self._gateway.share

    @property
    def vol_udf(self):
        """Return the udf if this is a share udf."""
        return self._gateway.udf

    @property
    def vol_id(self):
        """The virtual volume id of this object.

        It is either a None or a share or udf id.
        """
        if self.__volume:
            return self.__volume.id
        if self.__gateway:
            return self.__gateway.vol_id

    def _load(self, *args, **kwargs):
        """Overriden by subclasses."""
        raise NotImplementedError("Need to override _load in subclasses.")


class StorageNode(VolumeObjectBase):
    """A base class for File and Directory Nodes.

    This object can be initialized with only an ID for lazy loading. In the
    case that it has been initialized with an id of 'root' This will result
    in a DirectoryNode for the root of the volume.
    """

    def __init__(self, id, gateway=None, volume=None):
        super(StorageNode, self).__init__(volume, gateway)
        self.id = id
        self.kind = None
        self.parent_id = None
        self.owner_id = None
        self.path = None
        self.full_path = None
        self.name = None
        self.content_hash = None
        self.volume_id = None
        self.public_uuid = None
        self.can_delete = None
        self.can_write = None
        self.can_read = None
        self.status = None
        self.when_created = None
        self.when_last_modified = None
        self.generation = None
        self.generation_created = None
        self.mimetype = None
        self._udf = None
        self._owner = None
        self._content = None

    def __eq__(self, other):
        """Return true if objects are the same ID."""
        return (other is not None and
                self.id == other.id and self.vol_id == other.vol_id)

    @staticmethod
    def factory(gateway, node, permissions=None, content=None, udf=None,
                owner=None):
        """Create the appropriate DAO from model."""
        assert owner is None or isinstance(owner, DAOStorageUser)
        if node.kind == StorageObject.FILE:
            klass = FileNode
        elif node.kind == StorageObject.DIRECTORY:
            klass = DirectoryNode
        else:
            raise errors.StorageError(
                'Invalid kind %s when creating a StorageNode' % node.kind)
        o = klass(node.id, gateway=gateway)
        o.kind = node.kind
        o.parent_id = node.parent and node.parent.id or None
        o.owner_id = node.volume.owner.id
        o.path = node.path
        o.full_path = node.full_path
        o.name = node.name
        # if this has a gateway, and it was a share, we want the root
        # to appear as a root, and the paths to start at the root
        if gateway and gateway.share:
            if node.id == gateway.root_id:
                o.parent_id = None
                o.path = '/'
                o.name = ''
                o.full_path = '/'
            else:
                # mask the root path
                o.path = node.path[len(gateway.root_path_mask)::]
                o.path = o.path if o.path else '/'
                o.full_path = pypath.join(o.path, o.name)
        o.volume_id = node.volume.id
        o.public_uuid = node.public_uuid
        o.status = node.status
        o.when_created = node.when_created
        o.when_last_modified = node.when_last_modified
        o.generation = node.generation or 0
        o.generation_created = node.generation_created or 0
        o._owner = owner
        o._udf = udf
        o.mimetype = node.mimetype
        if node.kind == StorageObject.FILE:
            # only files have content
            o.content_hash = node.content_hash
            o._content = content
        # just a sanity check
        if owner:
            assert owner.id == o.owner_id
        o.set_permissions(permissions)
        return o

    def set_permissions(self, permissions):
        """Set the permissions for this node."""
        self.can_write = permissions["can_write"] if permissions else False
        self.can_delete = permissions["can_delete"] if permissions else False
        self.can_read = permissions["can_read"] if permissions else False

    @property
    def public_url(self):
        """Return the public URL of the file."""
        if self.public_uuid is not None and self.kind == StorageObject.FILE:
            return utils.get_public_file_url(self)

    @property
    def public_key(self):
        """Return the public key for this node."""
        return utils.get_node_public_key(self)

    @property
    def owner(self):
        """The owner (StorageUser) of the node."""
        return self._owner

    @property
    def udf(self):
        """The UserVolume of the node."""
        return self._udf

    @property
    def is_public(self):
        """True if the file has a public id."""
        return self.public_uuid is not None

    @property
    def nodekey(self):
        """Get the encoded key for this node."""
        if self.id:
            if self.owner and self.vol_id == self.owner.root_volume_id:
                return utils.make_nodekey(None, self.id)
            return utils.make_nodekey(self.vol_id, self.id)

    def _load(self, with_content=False):
        """Load the object from the database base on the id."""
        ob = self._gateway.get_node(self.id, with_content=with_content)
        self._copy(ob)
        return self

    @retryable_transaction()
    @fsync_commit
    def delete(self, cascade=False):
        """Delete this node."""
        ob = self._gateway.delete_node(self.id, cascade=cascade)
        self._copy(ob)
        return self

    @retryable_transaction()
    @fsync_commit
    def restore(self):
        """Restore this node."""
        ob = self._gateway.restore_node(self.id)
        self._copy(ob)
        return self

    @retryable_transaction()
    @fsync_commit
    def move(self, new_parent_id, new_name):
        """Move this node."""
        ob = self._gateway.move_node(self.id, new_parent_id, new_name)
        self._copy(ob)
        return self

    @property
    def content(self):
        """The FileNodeContent for this FileNode."""
        return self._content

    def has_children(self, kind=None):
        """Return True or False if the node directory has Children.

        Optionally kind can be provided and only children matching the kind
        will be checked.
        """
        if self.kind == StorageObject.DIRECTORY:
            f = fsync_readonly(self._gateway.check_has_children)
            return f(self.id, kind=kind)
        return False

    @retryable_transaction()
    @fsync_commit
    def change_public_access(self, is_public, allow_directory=False):
        """Set the node public based on the value passed in."""
        self._load()
        self._copy(self._gateway.change_public_access(
            self.id, is_public, allow_directory))
        return self


class DirectoryNode(StorageNode):
    """DAO for a Directory."""

    @retryable_transaction()
    @fsync_commit
    def make_file(self, name):
        """Create a file in this directory."""
        self._load()
        return self._gateway.make_file(self.id, name)

    @retryable_transaction()
    @fsync_commit
    def make_subdirectory(self, name):
        """Create a subsdirectory in this directory."""
        self._load()
        return self._gateway.make_subdirectory(self.id, name)

    @retryable_transaction()
    @fsync_commit
    def make_tree(self, path):
        """Create directory structure from a path in this directory."""
        self._load()
        return self._gateway.make_tree(self.id, path)

    @retryable_transaction()
    @fsync_commit
    def share(self, user_id, share_name, readonly=False):
        """Share this directory."""
        self._load()
        return self._gateway.make_share(self.id, share_name, user_id=user_id,
                                        readonly=readonly)

    @retryable_transaction()
    @fsync_commit
    def make_shareoffer(self, email, share_name, readonly=False):
        """Share this directory."""
        self._load()
        return self._gateway.make_share(self.id, share_name, email=email,
                                        readonly=readonly)

    @fsync_readonly
    def get_children(self, **kwargs):
        """Get Children of this directory."""
        self._load()
        if self.has_children():
            return list(self._gateway.get_children(self.id, **kwargs))
        return []

    @fsync_readonly
    def get_child_by_name(self, name, with_content=False):
        """Get a Node in this directory based on name."""
        self._load()
        return self._gateway.get_child_by_name(self.id, name, with_content)

    @retryable_transaction()
    @fsync_commit
    def make_file_with_content(self, file_name, hash, crc32, size,
                               deflated_size, storage_key, mimetype=None,
                               enforce_quota=True, is_public=False,
                               previous_hash=None, magic_hash=None):
        """Make a File and content in one transaction."""
        self._load()
        return self._gateway.make_file_with_content(
            self.id, file_name, hash, crc32, size, deflated_size, storage_key,
            mimetype=mimetype, enforce_quota=enforce_quota,
            is_public=is_public, previous_hash=previous_hash,
            magic_hash=magic_hash)


class FileNode(StorageNode):
    """DAO for an FILE StorageObject."""

    @retryable_transaction()
    @fsync_commit
    def make_uploadjob(self, verify_hash, new_hash, crc32, size,
                       multipart_key=None):
        """Create an UploadJob for this file."""
        self._load()
        return self._gateway.make_uploadjob(
            self.id, verify_hash, new_hash, crc32, size,
            multipart_key=multipart_key)

    @fsync_readonly
    def get_multipart_uploadjob(self, upload_id, hash_hint=None,
                                crc32_hint=None):
        """Get the multipart UploadJob with upload_id for this file."""
        self._load()
        return self._gateway.get_user_multipart_uploadjob(
            self.id, upload_id, hash_hint=hash_hint, crc32_hint=crc32_hint)

    @fsync_readonly
    def get_content(self):
        """Return the FileNodeContent for this file."""
        self._load()
        return self._gateway.get_content(self.content_hash)

    @retryable_transaction()
    @fsync_commit
    def make_content(self, original_hash, hash_hint, crc32_hint,
                     inflated_size_hint, deflated_size_hint, storage_key,
                     magic_hash=None):
        """Make content or reuse it for this file."""
        self._load()
        ob = self._gateway.make_content(self.id, original_hash, hash_hint,
                                        crc32_hint, inflated_size_hint,
                                        deflated_size_hint, storage_key,
                                        magic_hash)
        self._copy(ob)
        return self


class FileNodeContent(object):
    """A ContentBlob for a File."""

    def __init__(self, contentblob):
        self.hash = bytes(contentblob.hash)
        self.crc32 = contentblob.crc32
        self.size = contentblob.size
        self.status = contentblob.status
        if contentblob.magic_hash:
            self.magic_hash = bytes(contentblob.magic_hash)
        else:
            self.magic_hash = None
        if contentblob.size == 0:
            self.deflated_size = 0
            self.storage_key = None
        else:
            self.deflated_size = contentblob.deflated_size or 0
            self.storage_key = contentblob.storage_key
        self.when_created = contentblob.when_created


class DAOUploadJob(VolumeObjectBase):
    """DAO for an Upload Job"""

    def __init__(self, upload, file=None, gateway=None, volume=None):
        """Create DAO from storm model"""
        super(DAOUploadJob, self).__init__(volume, gateway)
        self.id = upload.id
        self.node = upload.node
        self.storage_object_id = upload.node.id
        self.chunk_count = upload.chunk_count
        self.hash_hint = upload.hash_hint
        self.crc32_hint = upload.crc32_hint
        self.when_started = upload.when_started
        self.when_last_active = upload.when_last_active
        self.status = upload.status
        self.multipart_key = upload.multipart_key
        self.uploaded_bytes = upload.uploaded_bytes
        self._file = file

    @property
    def file(self):
        """The FileNode this upload is for."""
        return self._file

    @property
    def content_exists(self):
        """True if there is content for this upload job."""
        return not (self._file is None or self._file.content is None)

    @retryable_transaction()
    @fsync_commit
    def delete(self):
        """Delete this uploadjob."""
        self._gateway.delete_uploadjob(self.id)

    def _load(self):
        "Load the object from the database base on the id"
        ob = self._gateway.get_uploadjob(self.id)
        # the returned object doesn't have the node
        node = self._file
        self.__dict__.update(ob.__dict__)
        self._file = node
        return self

    @retryable_transaction()
    @fsync_commit
    def add_part(self, size):
        """Add part info to this uploadjob."""
        self._gateway.add_uploadjob_part(self.id, size)
        # also update the when_last_active value.
        self._gateway.set_uploadjob_when_last_active(self.id, now())
        self._load()

    @retryable_transaction()
    @fsync_commit
    def touch(self):
        """Update the when_last_active attribute."""
        self._gateway.set_uploadjob_when_last_active(self.id, now())
        self._load()


class SharedDirectory(DAOBase):
    """Represents a Share."""

    def __init__(self, share, by_user=None, to_user=None):
        super(SharedDirectory, self).__init__()
        self.id = share.id
        self.name = share.name
        self.root_id = share.subtree.id
        self.accepted = share.accepted
        self.access = share.access
        self.read_only = share.access == Share.VIEW
        self.when_shared = share.when_shared
        self.when_last_changed = share.when_last_changed
        self.status = share.status
        self.offered_to_email = share.email
        self.shared_by_id = share.shared_by.id
        self.shared_to_id = share.shared_to and share.shared_to.id or None
        self._shared_by = by_user
        self._shared_to = to_user

    def _load(self, **kwargs):
        """Reload the SharedDirectory from the db."""
        s = self._gateway.get_share(self.id, **kwargs)
        self._copy(s)
        return self

    @property
    def shared_by(self):
        """The StorageUser sharing this."""
        return self._shared_by

    @property
    def shared_to(self):
        """The StorageUser this is shared to."""
        return self._shared_to

    @retryable_transaction()
    @fsync_commit
    def delete(self):
        """Delete this share."""
        ob = self._gateway.delete_share(self.id)
        self._copy(ob)
        return self

    @retryable_transaction()
    @fsync_commit
    def accept(self):
        """Accept this share."""
        ob = self._gateway.accept_share(self.id)
        self._copy(ob)
        return self

    @retryable_transaction()
    @fsync_commit
    def decline(self):
        """Decline this share."""
        ob = self._gateway.decline_share(self.id)
        self._copy(ob)
        return self

    @retryable_transaction()
    @fsync_commit
    def set_access(self, readonly):
        """Change readonly access this share."""
        ob = self._gateway.set_share_access(self.id, readonly)
        self._copy(ob)
        return self

    @fsync_readonly
    def get_generation(self):
        """Return the generation for the volume of this share."""
        return self._gateway.get_share_generation(self)


class DAOUserVolume(object):
    """User Defined Folder."""

    def __init__(self, vol, owner):
        super(DAOUserVolume, self).__init__()
        self.id = vol.id
        self.root_id = vol.root_node.id
        self.owner_id = vol.owner.id
        self.status = vol.status
        self.path = vol.path
        self.when_created = vol.when_created
        self.generation = vol.generation or 0
        self.owner = owner

    @property
    def is_root(self):
        """Return true if this is a root volume."""
        return self.id == self.owner.root_volume_id


class VolumeProxy(object):
    """Provide lazy access to gateways via their volume (root, udf or share).

    In the case that id is None, this is always the user's root volume.
    The key 'root' is also used to represent the root directory of a volume.
    """

    def __init__(self, id, user):
        self.id = id
        self.user = user
        self._gateway = None
        self._root = None

    @classmethod
    def from_gateway(cls, gw):
        """Get a Volume Proxy from a gateway."""
        if gw.share:
            id = gw.share.id
        elif gw.udf:
            id = gw.udf.id
        else:
            id = None
        p = cls(id, gw.user)
        p._gateway = gw
        return p

    # the following node references created without created a db query.
    # It will later be dereferenced when used. For example:
    #     volumeproxy.node(id) will not execute a query.
    #     volumeproxy.node(id).delete() will execute a query.
    # This is done to isolate transactions without haveing a purely functional
    # design.
    @property
    def root(self):
        """Return an uninitialized DirectoryNode for the root volume.

        Since root nodes do not change, it is cached.
        """
        if self._root is None:
            self._root = DirectoryNode('root', volume=self)
        return self._root

    def node(self, id):
        """Return an uninitialized StorageNode.

        This is used in the case of moves and deletes only.
        """
        return StorageNode(id, volume=self)

    def dir(self, id):
        """Return an uninitialized DirectoryNode"""
        return DirectoryNode(id, volume=self)

    def file(self, id):
        """Return an uninitialized FileNode"""
        return FileNode(id, volume=self)

    @property
    def gateway(self):
        """Get the gateway for this volume."""
        # if id is None, we must be looking for the root volume
        if self._gateway is None:
            if self.id is None:
                self._gateway = self.user._gateway.get_root_gateway()
            else:
                self._gateway = self.user._gateway.get_share_gateway(self.id)
                if self._gateway is None:
                    self._gateway = self.user._gateway.get_udf_gateway(self.id)
                if self._gateway is None:
                    raise errors.DoesNotExist("Invalid Volume")
        return self._gateway

    @fsync_readonly
    def get_uploadjob(self, uploadjob_id):
        """Get the upload job from this volume."""
        return self.gateway.get_uploadjob(uploadjob_id)

    @fsync_readonly
    def get_volume(self):
        """Get the UserVolume for this volume."""
        return self.gateway.get_user_volume()

    @fsync_readonly
    def get_root(self):
        """Get the root directory for this volume."""
        return self.gateway.get_root()

    @fsync_readonly
    def get_node(self, id, **kwargs):
        """Get a Node off this volume."""
        return self.gateway.get_node(id, **kwargs)

    @fsync_readonly
    def get_node_by_path(self, path, **kwargs):
        """Get a Node off this volume using the path."""
        return self.gateway.get_node_by_path(path, **kwargs)

    @fsync_readonly
    def get_nodes(self, ids, with_content=False):
        """Get Nodes off this volume."""
        return self.gateway.get_nodes(ids, with_content=with_content)

    @fsync_readonly_slave
    def get_all_nodes(self, **kwargs):
        """Get a all nodes on this volume.

        This should be limited by mimetype and kind using named arguments.
        """
        return self.gateway.get_all_nodes(**kwargs)

    @fsync_readonly
    def get_deleted_files(self, start=0, limit=100):
        """Get a dead nodes on this."""
        return self.gateway.get_deleted_files(start=start, limit=limit)

    @fsync_readonly
    def get_content(self, content_hash):
        """Get a FileNodeContent from this volume."""
        return self.gateway.get_content(content_hash)

    @fsync_readonly
    def get_delta(self, generation, limit=None):
        """Get this volumes generational delta.

        The return value is a tuple of (generation, free_bytes, [nodes])
        """
        volume = self.gateway.get_user_volume()
        if volume.generation <= generation:
            return (volume.generation, self.user.free_bytes, [])
        delta_nodes = list(self.gateway.get_generation_delta(generation,
                                                             limit))
        return (volume.generation, self.user.free_bytes, delta_nodes)

    @fsync_readonly
    def get_from_scratch(self, start_from_path=None, limit=None,
                         max_generation=None):
        """Get all of this volumes live nodes.

        The return value is a tuple of (generation, free_bytes, [nodes])
        """
        volume = self.gateway.get_user_volume()
        nodes = self.gateway.get_all_nodes(start_from_path=start_from_path,
                                           limit=limit,
                                           max_generation=max_generation)
        return (volume.generation, self.user.free_bytes, nodes)

    @retryable_transaction()
    @fsync_commit
    def undelete_all(self, prefix, limit=100):
        """Undelete all the deleted files on this volume."""
        return self.gateway.undelete_volume(prefix, limit=limit)

    @fsync_readonly_slave
    def get_directories_with_mimetypes(self, mimetypes):
        """Get a list of {DirectoryNode}s that have files with mimetypes."""
        return self.gateway.get_directories_with_mimetypes(mimetypes)


class DAODownload(object):
    """Pending download."""

    def __init__(self, download):
        super(DAODownload, self).__init__()
        self.id = download.id
        self.owner_id = download.volume.owner.id
        self.volume_id = download.volume.id
        self.file_path = download.file_path
        self.download_url = download.download_url
        self.download_key = download.download_key
        self.status = download.status
        self.status_change_date = download.status_change_date
        self.node_id = download.node.id if download.node else None
        self.error_message = download.error_message


# original getaway.py starts here


class TimingMetrics(object):
    """Class to hold everything related to the timing metrics of DB calls."""

    def __init__(self):
        namespace = settings.ENVIRONMENT_NAME + ".magicicada.DAL"
        self.reporter = metrics.get_meter(namespace)

    def __call__(self, orig_func):
        """Decorator to issue metrics with the timing of the executed method.

        Warning: only apply this decorator to a method that will receive
        as first argument ('self') an object that has a DAO's user.
        """
        @wraps(orig_func)
        def wrapper(inner_self, *args, **kwargs):
            """Wrapper method."""
            # grab info for the metric
            func_name = orig_func.func_name

            tini = time.time()
            try:
                result = orig_func(inner_self, *args, **kwargs)
            finally:
                delta_t = time.time() - tini
                called = str(func_name)
                self.reporter.timing(called, delta_t)
            return result
        return wrapper


timing_metric = TimingMetrics()


class GatewayBase(object):
    """The base for gateway classes"""

    user_dne_error = "The provided User id does not exist."
    node_dne_error = "The provided Node id does not exist."
    contentblob_dne_error = "The provided Content Blob hash does not exist."
    share_dne_error = "The provided Share id does not exist."
    udf_dne_error = "The provided UDF id does not exist."
    shareoffer_dne_error = "The provided Share Offer id does not exist."
    publicfile_dne_error = "The Public File id does not exist."
    uploadjob_dne_error = "The Upload Job id does not exist."
    download_dne_error = "The Download does not exist."
    inactive_user_error = "Inactive user can not access volumes."
    cannot_write_error = "User can not write in the node."
    cannot_delete_error = "User can not delete in the node."
    hash_mismatch_error = "The given hash does not match the node's."
    not_a_directory_error = "The provided Node is not a Directory."
    readonly_error = "The provided Node id is readonly."

    def __init__(self, session_id=None, notifier=None):
        """Initializes a gateway"""
        if notifier is None:
            self._notifier = get_notifier()
        else:
            self._notifier = notifier
        self.session_id = session_id

    def queue_share_created(self, share):
        """When a share is changed."""
        self._notifier.queue_share_created(share,
                                           source_session=self.session_id)

    def queue_share_deleted(self, share):
        """When a share is changed."""
        self._notifier.queue_share_deleted(share,
                                           source_session=self.session_id)

    def queue_share_accepted(self, share):
        """When a share is changed."""
        self._notifier.queue_share_accepted(share,
                                            source_session=self.session_id)

    def queue_share_declined(self, share):
        """When a share is declined."""
        self._notifier.queue_share_declined(share,
                                            source_session=self.session_id)

    def queue_udf_create(self, udf):
        """A UDF has been created."""
        self._notifier.queue_udf_create(udf.owner_id, udf.id, udf.root_id,
                                        udf.path, self.session_id)

    def queue_udf_delete(self, udf):
        """When a udf is deleted."""
        self._notifier.queue_udf_delete(udf.owner_id, udf.id,
                                        self.session_id)

    def queue_new_generation(self, user_id, client_volume_id, generation):
        """Queue a new generation change for a volume."""
        self._notifier.queue_volume_new_generation(
            user_id, client_volume_id, generation or 0,
            source_session=self.session_id)

    def get_user(self, user_id=None, username=None, session_id=None,
                 ignore_lock=False):
        """All gateways are going to need to get a user."""
        self.session_id = session_id
        if user_id is not None:
            user = get_object_or_none(StorageUser, id=user_id)
        elif username is not None:
            user = get_object_or_none(StorageUser, username=username)
        else:
            raise errors.StorageError("Invalid call to get_user,"
                                      " user_id or username must be provided.")

        if user:
            if user.locked and not ignore_lock:
                raise errors.LockedUserError()
            user_dao = DAOStorageUser(user)
            user_dao._gateway = StorageUserGateway(user_dao,
                                                   session_id=session_id)
            return user_dao


class SystemGateway(GatewayBase):
    """Used when there is no authenticated user or used by external systems."""

    def create_or_update_user(self, username, max_storage_bytes, **kwargs):
        """Create or update a StorageUser and related data."""
        user, created = StorageUser.objects.get_or_create(username=username)
        user.is_active = True
        user.max_storage_bytes = max_storage_bytes

        # special handling for password in plaintext
        password = kwargs.pop('password', None)
        if password is not None:
            user.set_password(password)

        # special handling for visible_name, overrides first/last name
        visible_name = kwargs.pop('visible_name', None)
        if visible_name:
            first_name, sep, last_name = visible_name.rpartition(' ')
            kwargs.update(dict(first_name=first_name, last_name=last_name))
        for k, v in kwargs.items():
            setattr(user, k, v)

        user.save()

        # create the user's root volume if necessary
        UserVolume.objects.get_or_create_root(user)
        user_dao = DAOStorageUser(user)
        user_dao._gateway = StorageUserGateway(user_dao, self.session_id)
        return user_dao

    def _get_shareoffer(self, shareoffer_id):
        """Get a shareoffer and who shared it."""
        result = Share.objects.filter(
            id=shareoffer_id, status=STATUS_LIVE).select_related('shared_by')
        share = None
        user = None
        if result.exists():
            share = result.get()
            user = share.shared_by
            if share.accepted or share.shared_to is not None:
                raise errors.ShareAlreadyAccepted(
                    "This share offer has been accepted.")
        return (share, user)

    def get_shareoffer(self, shareoffer_id):
        """Get a Share Offer sent to an email."""
        share, user = self._get_shareoffer(shareoffer_id)
        if share is None:
            raise errors.DoesNotExist(self.shareoffer_dne_error)
        return SharedDirectory(share, by_user=user)

    def claim_shareoffer(self, user_id, username, visible_name,
                         shareoffer_id):
        """Claim a share offer sent to an email."""
        # A anonymous share offer is a share sent to an email address but not
        # to a specific user. We also don't let user's claim their own share
        share, byuser = self._get_shareoffer(shareoffer_id)
        if share is None or byuser.id == user_id:
            raise errors.DoesNotExist(self.shareoffer_dne_error)

        user = get_object_or_none(StorageUser, id=user_id)
        if user is None:
            gw = SystemGateway()
            user = gw.create_or_update_user(
                username, visible_name=visible_name, max_storage_bytes=0,
                is_active=False)
            # they are not subscribed!
            user._gateway.update()
        else:
            user = DAOStorageUser(user)

        share.claim_share(StorageUser.objects.get(id=user_id))
        share_dao = SharedDirectory(share, by_user=byuser, to_user=user)
        self.queue_share_accepted(share_dao)
        return share_dao

    def _get_public_node(self, public_key):
        """Get a node from a public key."""
        if public_key is None:
            raise errors.DoesNotExist(self.publicfile_dne_error)
        try:
            public_id = utils.decode_base62(public_key, allow_padding=True)
        except utils.Base62Error:
            raise errors.DoesNotExist(self.publicfile_dne_error)

        public_uuid = uuid.UUID(int=public_id)
        node = get_object_or_none(StorageObject, public_uuid=public_uuid)
        if node is None:
            raise errors.DoesNotExist(self.publicfile_dne_error)

        user = self.get_user(node.volume.owner.id, ignore_lock=True)
        gw = ReadWriteVolumeGateway(user)
        node = gw.get_node(node.id, with_content=True)
        if not node.is_public:
            # We raise DoesNotExist instead of NoPermission here,
            # since it reveals information to the user that we don't
            # have to (e.g. they might try to look in various caches
            # for files that have been withdrawn).
            raise errors.DoesNotExist(self.publicfile_dne_error)
        return node

    def get_public_directory(self, public_key, mimetypes=None):
        """Get a public directory."""
        # Use UUIDs instead of the old method
        node = self._get_public_node(public_key)
        if node.kind != StorageObject.DIRECTORY:
            raise errors.DoesNotExist(self.publicfile_dne_error)
        return node

    def get_public_file(self, public_key):
        """Get a public file."""
        node = self._get_public_node(public_key)
        if (node.content is None or node.content.storage_key is None or
                node.kind != StorageObject.FILE):
            # if the file has no content, we should not be able to get it
            raise errors.DoesNotExist(self.publicfile_dne_error)
        return node

    def make_download(self, user_id, volume_id, file_path, download_url,
                      download_key=None):
        """Make a new download object."""
        self.get_user(user_id)
        volume = UserVolume.objects.get(owner__id=user_id, id=volume_id)
        download = Download.objects.create(
            volume=volume, file_path=file_path, download_url=download_url,
            download_key=download_key)
        return DAODownload(download)

    def _get_download(self, user_id, download_id):
        """Internal function to get the download and owner."""
        user = self.get_user(user_id)
        download = get_object_or_none(Download, id=download_id)
        return user, download

    def get_download(self, user_id, udf_id, file_path, download_url,
                     download_key=None):
        """Get a download by its UDF, file path and download key."""
        self.get_user(user_id)
        download = Download.objects.filter(
            models.Q(download_key=unicode(repr(download_key))) |
            models.Q(download_url=download_url),
            volume__owner__id=user_id, volume__id=udf_id, file_path=file_path,
        ).order_by('status_change_date').last()
        if download is None:
            raise errors.DoesNotExist(self.download_dne_error)
        return DAODownload(download)

    def get_download_by_id(self, user_id, download_id):
        """Get a download by its ID."""
        user, download = self._get_download(user_id, download_id)
        if download is None:
            raise errors.DoesNotExist(self.download_dne_error)
        return DAODownload(download)

    def update_download(self, user_id, download_id, status=None,
                        node_id=None, error_message=None):
        """Updoate the download properties."""
        user, download = self._get_download(user_id, download_id)
        if download is None:
            raise errors.DoesNotExist(self.download_dne_error)
        if status is not None:
            download.status = status
        if node_id is not None:
            download.node_id = node_id
        if error_message is not None:
            download.error_message = error_message
        download.save()
        return DAODownload(download)

    def download_complete(self, user_id, download_id, hash, crc32, size,
                          deflated_size, mimetype, storage_key):
        """Complete the download."""
        user, download = self._get_download(user_id, download_id)
        if download is None:
            raise errors.DoesNotExist(self.download_dne_error)
        # get the proper gateway for creating the file
        ugw = StorageUserGateway(user)
        if download.volume_id == user.root_volume_id:
            vgw = ugw.get_root_gateway()
        else:
            vgw = ugw.get_udf_gateway(download.volume_id)
        path, filename = os.path.split(download.file_path)
        folder = vgw.make_tree(vgw.get_root().id, path)
        fnode = vgw.make_file_with_content(
            folder.id, filename, hash, crc32,
            size, deflated_size, storage_key, mimetype, enforce_quota=False)
        download.node_id = fnode.id
        download.status = Download.STATUS_COMPLETE
        download.save()
        return DAODownload(download)

    def get_failed_downloads(self, start_date, end_date):
        """Get failed downloads."""
        result = Download.objects.filter(
            status=Download.STATUS_ERROR,
            status_change_date__range=[start_date, end_date])
        for dl in result:
            yield DAODownload(dl)

    def get_node(self, node_id):
        """Get a node for the specified node_id."""
        node = get_object_or_none(
            StorageObject, status=STATUS_LIVE, id=node_id)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        return StorageNode.factory(None, node, permissions={})

    def cleanup_uploadjobs(self, uploadjobs):
        """Delete uploadjobs."""
        uploadjob_ids = [job.id for job in uploadjobs]
        UploadJob.objects.filter(id__in=uploadjob_ids).delete()

    def get_abandoned_uploadjobs(self, last_active, limit=1000):
        """Get uploadjobs that are older than last_active."""
        jobs = UploadJob.objects.filter(when_last_active__lte=last_active)
        return [DAOUploadJob(job) for job in jobs[:limit]]


class StorageUserGateway(GatewayBase):
    """Access point for accessing storage users and shares.

    For a specific user's security context.
    """

    def __init__(self, user, session_id=None):
        super(StorageUserGateway, self).__init__(session_id)
        assert isinstance(user, DAOStorageUser)
        # also set the 'owner' for being explicit to whom share the
        # timing metrics should be reported against
        self.owner = self.user = user

    @timing_metric
    def update(self, max_storage_bytes=None):
        """Update a user's max_storage_bytes."""
        user = StorageUser.objects.get(id=self.user.id)
        if max_storage_bytes is not None:
            user.max_storage_bytes = max_storage_bytes
            user.save(update_fields=['max_storage_bytes'])

        # save all back
        user_dao = DAOStorageUser(user)
        user_dao._gateway = StorageUserGateway(user_dao, self.session_id)
        return user_dao

    @timing_metric
    def recalculate_quota(self):
        """Recalculate a user's quota."""
        user = StorageUser.objects.get(id=self.user.id)
        user.recalculate_used_bytes()
        return user

    def get_root_gateway(self):
        """Get the volume gateway for the user's root folder."""
        return self.get_volume_gateway()

    @timing_metric
    def get_udf_gateway(self, udf_id):
        """Get the volume gateway for a user's udf."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        # sanity check
        udf = get_object_or_none(
            UserVolume, owner__id=self.user.id, id=udf_id, status=STATUS_LIVE)
        if udf:
            return self.get_volume_gateway(udf=DAOUserVolume(udf, self.user))

    @timing_metric
    def get_share_gateway(self, share_id):
        """Get the volume gateway for a folder shared to this user."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        share = get_object_or_none(
            Share.objects.select_related('shared_by'),
            shared_to=self.user.id, id=share_id, status=STATUS_LIVE,
            accepted=True)
        if share:
            by_user = self.get_user(share.shared_by.id)
            return self.get_volume_gateway(
                share=SharedDirectory(share, by_user=by_user))

    @timing_metric
    def get_volume_gateway(self, udf=None, share=None):
        """Get a volume, this may be a user's root, udf, or a share."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        return ReadWriteVolumeGateway(
            self.user, share=share, udf=udf,
            session_id=self.session_id, notifier=self._notifier)

    @timing_metric
    def get_share(self, share_id, accepted_only=True, live_only=True):
        """Get a specific share shared by or shared_to this user."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        shares = Share.objects.select_related('shared_to', 'shared_by').filter(
            models.Q(shared_to__id=self.user.id) |
            models.Q(shared_by__id=self.user.id), id=share_id)
        if accepted_only:
            shares = shares.filter(accepted=True)
        if live_only:
            shares = shares.filter(status=STATUS_LIVE)
        try:
            share = shares.get()
        except Share.DoesNotExist:
            raise errors.DoesNotExist(self.share_dne_error)

        byuser = share.shared_by
        touser = share.shared_to
        if touser:
            touser = DAOStorageUser(touser)
        share_dao = SharedDirectory(
            share, to_user=touser, by_user=DAOStorageUser(byuser))
        share_dao._gateway = self
        return share_dao

    @timing_metric
    def get_shared_by(self, accepted=None, node_id=None):
        """Get shared folders shared by this user.

        Passing in a node_id will get the shares for that node only
        """
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        shares = Share.objects.select_related('shared_to').filter(
            shared_by__id=self.user.id, status=STATUS_LIVE)
        if accepted is not None:
            shares = shares.filter(accepted=accepted)
        if node_id:
            shares = shares.filter(subtree__id=node_id)

        for share in shares:
            user = share.shared_to
            if user:
                user = DAOStorageUser(user)
            share_dao = SharedDirectory(share, to_user=user, by_user=self.user)
            share_dao._gateway = self
            yield share_dao

    @timing_metric
    def get_shares_of_nodes(self, node_ids, accepted_only=True,
                            live_only=True):
        """Get accepted shares for nodes in node_ids."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        shares = Share.objects.select_related('shared_to').filter(
            shared_by__id=self.user.id, subtree__id__in=node_ids)
        if accepted_only:
            shares = shares.filter(accepted=True)
        if live_only:
            shares = shares.filter(status=STATUS_LIVE)

        for share in shares:
            user = share.shared_to
            if user:
                user = DAOStorageUser(user)
            share_dao = SharedDirectory(share, to_user=user, by_user=self.user)
            share_dao._gateway = self
            yield share_dao

    @timing_metric
    def get_shared_to(self, accepted=None):
        """Get shares shared to this user.

        accepted can be True, False, or None (to get all).

        """
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        shares = Share.objects.select_related('shared_by').filter(
            shared_to__id=self.user.id, status=STATUS_LIVE)
        if accepted is not None:
            shares = shares.filter(accepted=accepted)

        for share in shares:
            user = DAOStorageUser(share.shared_by)
            user._gateway = self
            share_dao = SharedDirectory(share, by_user=user, to_user=self.user)
            share_dao._gateway = self
            yield share_dao

    @timing_metric
    def accept_share(self, share_id):
        """Accept a share offer"""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        share = get_object_or_none(
            Share, id=share_id, shared_to__id=self.user.id,
            status=STATUS_LIVE, accepted=False)
        if share is None:
            raise errors.DoesNotExist(self.share_dne_error)
        share.accept()
        share_dao = self.get_share(share.id)
        share_dao._gateway = self
        self.queue_share_accepted(share_dao)
        return share_dao

    @timing_metric
    def decline_share(self, share_id):
        """Decline a share offer"""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        share = get_object_or_none(
            Share, id=share_id, shared_to__id=self.user.id,
            status=STATUS_LIVE)
        if share is None:
            raise errors.DoesNotExist(self.share_dne_error)
        share.decline()
        share_dao = SharedDirectory(share)
        self.queue_share_declined(share_dao)
        self.queue_share_deleted(share_dao)
        return share_dao

    @timing_metric
    def delete_share(self, share_id):
        """Delete a share shared by or to this user."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        share = get_object_or_none(
            Share,
            models.Q(shared_by__id=self.user.id) |
            models.Q(shared_to__id=self.user.id),
            id=share_id, status=STATUS_LIVE)
        if share is None:
            raise errors.DoesNotExist(self.share_dne_error)
        share.kill()
        share_dao = SharedDirectory(share)
        self.queue_share_deleted(share_dao)
        return share_dao

    @timing_metric
    def set_share_access(self, share_id, readonly):
        """Change the readonly access of this share."""
        share = get_object_or_none(
            Share, id=share_id, shared_by__id=self.user.id,
            status=STATUS_LIVE)
        if readonly:
            share.make_ro()
        else:
            share.make_rw()
        share_dao = SharedDirectory(share)
        share_dao._gateway = self
        return share_dao

    @timing_metric
    def delete_related_shares(self, node):
        """Delete all related shares under the node.

        @param node: A StorageNode this user owns
        """
        if node.volume.owner.id != self.user.id:
            msg = "User does not own the node, shares can not be deleted."
            raise errors.NoPermission(msg)
        # since we're using only the ids, use the inner function of the vgw
        nodeids = [
            n.id for n in node.get_descendants(kind=StorageObject.DIRECTORY)]
        nodeids.append(node.id)
        shares = []
        sublist = utils.split_in_list(nodeids)
        for l in sublist:
            s = self.get_shares_of_nodes(l, accepted_only=False)
            shares.extend(list(s))
        for share in shares:
            self.delete_share(share.id)

    @timing_metric
    @fsync_commit
    def make_udf(self, path):
        """Create a UDF."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        # need a lock here.
        StorageUser.objects.select_for_update(nowait=True).get(
            id=self.user.id)
        path_like = path + '/'
        # make sure this UDF wont be the existing UDF of be the parent of
        # and existing UDF
        prev_udfs = UserVolume.objects.filter(
            owner__id=self.user.id, status=STATUS_LIVE)
        for prev_udf in prev_udfs:
            if prev_udf.path == path:
                return DAOUserVolume(prev_udf, self.user)
            prvpath = prev_udf.path + "/"
            if prvpath.startswith(path_like) or path_like.startswith(prvpath):
                raise errors.NoPermission("UDFs can not be nested.")
        udf = UserVolume.objects.create(
            owner=StorageUser.objects.get(id=self.user.id), path=path)
        udf_dao = DAOUserVolume(udf, self.user)
        self.queue_udf_create(udf_dao)
        return udf_dao

    @timing_metric
    def get_udf_by_path(self, path, from_full_path=False):
        """Get a UDF by the path parts."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        path = path.rstrip('/')
        if from_full_path:
            udfs = UserVolume.objects.filter(
                owner__id=self.user.id, status=STATUS_LIVE)
            udfs = [u for u in udfs
                    if u.path == path or path.startswith(u.path + '/')]
            udf = udfs[0] if len(udfs) == 1 else None
        else:
            udf = get_object_or_none(
                UserVolume, path=path, owner__id=self.user.id,
                status=STATUS_LIVE)
        if udf is None:
            raise errors.DoesNotExist(self.udf_dne_error)
        udf_dao = DAOUserVolume(udf, self.user)
        return udf_dao

    @timing_metric
    @fsync_commit
    def delete_udf(self, udf_id):
        """Delete a UDF."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        udf = get_object_or_none(
            UserVolume, id=udf_id, owner__id=self.user.id, status=STATUS_LIVE)
        if udf is None:
            raise errors.DoesNotExist(self.udf_dne_error)
        StorageUser.objects.select_for_update(nowait=True).get(
            id=self.owner.id)
        node = StorageObject.objects.get(id=udf.root_node.id)
        self.delete_related_shares(node)
        udf.kill()
        udf_dao = DAOUserVolume(udf, self.user)
        self.queue_udf_delete(udf_dao)
        return udf_dao

    @timing_metric
    def get_udf(self, udf_id):
        """Get a UDF."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        udf = get_object_or_none(
            UserVolume, id=udf_id, owner__id=self.user.id, status=STATUS_LIVE)
        if udf is None:
            raise errors.DoesNotExist(self.udf_dne_error)
        udf_dao = DAOUserVolume(udf, self.user)
        return udf_dao

    @timing_metric
    def get_udfs(self):
        """Return Live UDFs."""
        if not self.user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        udfs = UserVolume.objects.filter(
            owner__id=self.user.id, status=STATUS_LIVE).exclude(
                path=settings.ROOT_USERVOLUME_PATH)
        for udf in udfs:
            udf_dao = DAOUserVolume(udf, self.user)
            yield udf_dao

    @timing_metric
    def get_downloads(self):
        """Get all downloads for a user."""
        return [DAODownload(download) for download in
                Download.objects.filter(volume__owner__id=self.user.id)]

    @timing_metric
    def get_public_files(self):
        """Get all public files for a user."""
        nodes = StorageObject.objects.filter(
            status=STATUS_LIVE, kind=StorageObject.FILE,
            volume__status=STATUS_LIVE, volume__owner__id=self.user.id,
            public_uuid__isnull=False)
        return self._get_dao_nodes(nodes)

    @timing_metric
    def get_public_folders(self):
        """Get all public folders for a user."""
        nodes = StorageObject.objects.filter(
            status=STATUS_LIVE, kind=StorageObject.DIRECTORY,
            volume__status=STATUS_LIVE, volume__owner__id=self.user.id,
            public_uuid__isnull=False)
        return self._get_dao_nodes(nodes)

    def _get_dao_nodes(self, nodes):
        """Return dao.StorageNode for each node in nodes."""
        gws = {}
        perms = {}
        for node in nodes:
            vgw = gws.get(node.volume_id)
            if not vgw:
                if node.volume_id == self.user.root_volume_id:
                    gws[node.volume_id] = self.get_root_gateway()
                else:
                    gws[node.volume_id] = self.get_udf_gateway(node.volume_id)
            yield StorageNode.factory(
                gws[node.volume_id], node, perms, owner=self.user)

    @timing_metric
    def get_share_generation(self, share):
        """Get the generation of the speficied share."""
        volume = UserVolume.objects.get(storageobject__id=share.root_id)
        return volume.generation

    @timing_metric
    def get_photo_directories(self):
        """Get all the directories with photos in them.

        This is written specifically for the photo gallery.
        """

        sql = """
            WITH RECURSIVE t AS (
            SELECT min(CAST(o.parent_id AS varchar(50))) AS parent_id
            FROM filesync_storageobject o, filesync_uservolume u
            WHERE u.owner_id = %s AND o.status = %s AND o.content_blob_id != %s
            AND o.volume_id = u.id
            AND o.mimetype IN (E'image/jpeg', E'image/jpg')
            UNION ALL
            SELECT (
                SELECT min(CAST(o.parent_id AS varchar(50)))
                FROM filesync_storageobject o, filesync_uservolume u
                WHERE CAST(o.parent_id AS varchar(50)) > t.parent_id AND
                u.owner_id = %s AND o.status = %s AND
                o.content_blob_id != %s AND o.volume_id = u.id AND
                o.mimetype IN (E'image/jpeg', E'image/jpg')
            ) FROM t WHERE t.parent_id IS NOT NULL)
            SELECT o.id, o.volume_id, o.generation, o.generation_created,
                   o.kind, o.name, u.owner_id, o.parent_id, o.path,
                   o.public_uuid, o.status, o.when_created,
                   o.when_last_modified
            FROM filesync_storageobject o, t, filesync_uservolume u
            WHERE o.id = t.parent_id::UUID AND
                  o.volume_id=u.id AND u.status = %s ;
            """
        empty_hash = 'sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709'
        params = (self.user.id, STATUS_LIVE, empty_hash, self.user.id,
                  STATUS_LIVE, empty_hash, STATUS_LIVE)
        gws = {}

        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            nodes = cursor.fetchall()
        for n in nodes:
            (node_id, volume_id, generation, generation_created, kind, name,
                owner_id, parent_id, path, public_uuid, status, when_created,
                when_last_modified) = n
            node_id = node_id
            volume_id = volume_id
            public_uuid = public_uuid if public_uuid else None
            vgw = gws.get(volume_id)
            if not vgw:
                if volume_id == self.user.root_volume_id:
                    vgw = self.get_root_gateway()
                else:
                    vgw = self.get_udf_gateway(volume_id)
                gws[volume_id] = vgw
            d = DirectoryNode(node_id, vgw)
            d.generation = generation
            d.generation_created = generation_created,
            d.kind = kind
            d.name = name
            d.owner_id = owner_id
            d.parent_id = parent_id
            d.public_uuid = public_uuid
            d.path = path
            d.status = status
            d.volume_id = volume_id
            d.when_created = when_created
            d.when_last_modified = when_last_modified
            d.full_path = pypath.join(d.path, d.name)
            d.can_delete = True
            d.can_write = True
            d.can_read = True
            d._owner = self.user
            yield d

    def _get_reusable_content(self, hash_value, magic_hash):
        """Get a contentblob for reusable content."""

        # check to see if we have the content blob for that hash
        try:
            contentblob = ContentBlob.objects.get(hash=hash_value)
        except ContentBlob.DoesNotExist:
            contentblob = None

        # if content is not there, is not reusable
        if not contentblob:
            return False, None

        # if we have content have the same magic hash is reusable!
        if (magic_hash is not None and contentblob.magic_hash is not None and
                bytes(contentblob.magic_hash) == bytes(magic_hash)):
            return True, contentblob

        # if not, but the user owns the blob, still can be reusable
        nodes = StorageObject.objects.filter(
            content_blob__hash=hash_value, volume__owner__id=self.user.id)
        if nodes.exists():
            return True, contentblob

        # exists, but it's not reusable
        return True, None

    @timing_metric
    def is_reusable_content(self, hash_value, magic_hash):
        """Check content blob existence and reusability.

        Return a pair of bools: if the blob exists, and if it's reusable.
        """
        reusable, cb = self._get_reusable_content(hash_value, magic_hash)
        if reusable:
            return True, cb.storage_key if cb else None
        return False, None


def with_notifications(f):
    """Decorator for ReadWriteVolumeGateway to send notifications."""
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        """Wrapper method."""
        with fsync_commit():
            # quota notification handling
            UserVolume.objects.select_for_update(nowait=True).get(
                id=self.volume_id)
            StorageUser.objects.select_for_update(nowait=True).get(
                id=self.owner.id)
            # call the wrapped method
            result = f(self, *args, **kwargs)
        return result
    return wrapper


class ReadOnlyVolumeGateway(GatewayBase):
    """Data access point for accessing storage data on a volume.

    This includes objects, contentblobs, upload jobs, etc.

    This always accesses Nodes based on the context of a StorageUser in
    that it enforces security from the context of a storage user. If
    this volume is associated with a share, the permissions of the
    share are applied.

    When using the root node, the user will have access to all of
    their objects, even if it's on a UDF
    """

    def __init__(self, user, udf=None, share=None, session_id=None,
                 notifier=None):
        super(ReadOnlyVolumeGateway, self).__init__(session_id=session_id,
                                                    notifier=notifier)
        assert isinstance(user, DAOStorageUser)
        self.user = user
        self.udf = None
        self.root_id = None
        self.read_only = False
        self.share = None
        self.owner = self.user
        self._volume_id = None
        # root path, used for shares only
        self.root_path_mask = None
        if not user.is_active:
            raise errors.NoPermission(self.inactive_user_error)
        if udf:
            if self.user.id != udf.owner_id or udf.status == STATUS_DEAD:
                raise errors.NoPermission("UDF access denied.")
            self.udf = udf
            self._volume_id = udf.id
            self.root_id = udf.root_id
        elif share:
            if (self.user.id != share.shared_to_id or
                    share.status == STATUS_DEAD or not share.accepted):
                raise errors.NoPermission("Share access denied.")
            self.owner = share.shared_by
            self.owner._gateway = StorageUserGateway(
                self.owner, session_id=self.session_id)
            self.root_id = share.root_id
            self.read_only = share.read_only
            self.share = share

    @property
    def owner_gateway(self):
        """return the StorageUserGateway for the owner of this volume."""
        return self.owner._gateway

    @property
    def vol_id(self):
        """This is the client volume id of this volume."""
        if self.udf:
            return self.udf.id
        if self.share:
            return self.share.id
        return None

    @property
    def volume_id(self):
        """The id of theUserVolume for this node."""
        if self._volume_id is None:
            if self.udf:
                self._volume_id = self.udf.id
            else:
                self._volume_id = self._get_user_volume().id
        return self._volume_id

    def _get_root_node(self):
        """Get the root node for this volume."""
        if self.share:
            # if this is a share, we just want to check if it's valid.
            # since all share access has to get the root node, this will work.
            self._check_share()

        nodes = StorageObject.objects.filter(
            status=STATUS_LIVE, volume__owner__id=self.owner.id,
            volume__status=STATUS_LIVE)
        if self.root_id:
            nodes = nodes.filter(id=self.root_id)
            # if this is a UDF, we can make sure it's a valid UDF by joining it
            if self.udf:
                nodes = nodes.filter(volume__id=self.udf.id)
        else:
            nodes = nodes.filter(
                volume__id=self.owner.root_volume_id, parent=None)

        if nodes.count() == 0:
            raise errors.DoesNotExist("Could not locate root for the volume.")

        node = nodes.get()
        if self.share:
            self.root_path_mask = node.full_path
        self.root_id = node.id
        self._volume_id = node.volume.id
        return node

    def _check_share(self):
        """Make sure the share is still good."""
        if self.share:
            # if this is a share, make sure it's still valid
            share = get_object_or_none(
                Share, id=self.share.id, subtree__id=self.share.root_id,
                shared_to__id=self.user.id, shared_by__id=self.owner.id,
                accepted=True, status=STATUS_LIVE)
            if not share:
                raise errors.DoesNotExist(self.share_dne_error)

    @timing_metric
    def get_root(self):
        """Get the root node and return the doa.StorageObject."""
        node = self._get_root_node()
        return StorageNode.factory(self, node, owner=self.owner,
                                   permissions=self._get_node_perms(node))

    def _get_user_volume(self):
        """Return the UserVolume for this ReadWriteVolumeGateway."""
        if self.share:
            vol = get_object_or_none(
                UserVolume, storageobject__status=STATUS_LIVE,
                storageobject__id=self.share.root_id, status=STATUS_LIVE)
        elif self.udf:
            vol = get_object_or_none(
                UserVolume, id=self.udf.id, status=STATUS_LIVE)
        else:
            vol = get_object_or_none(
                UserVolume, id=self.owner.root_volume_id, status=STATUS_LIVE)
        if vol is None:
            raise errors.DoesNotExist(self.udf_dne_error)
        return vol

    @timing_metric
    def get_user_volume(self):
        """Return the doa.UserVolume for this ReadWriteVolumeGateway."""
        vol = self._get_user_volume()
        return DAOUserVolume(vol, self.owner)

    def _get_root_path(self):
        """Get the path of the root of this volume.

        This only changes for shares as shares may not start at the root.
        """
        if self.share:
            root = self._get_root_node()
            return root.full_path
        else:
            return '/'

    @property
    def is_root_volume(self):
        """True if this volume is the user's root volume."""
        return (self.user.id == self.owner.id and
                self.share is None and
                self.udf is None)

    def _get_node_perms(self, node):
        """Get the permissions for the node."""
        permissions = {}
        permissions['can_read'] = True
        permissions['can_write'] = not self.read_only
        permissions['can_delete'] = not (
            self.read_only or node.parent == ROOT_PARENT or
            node.id == self.root_id)
        return permissions

    def _check_can_write_node(self, node):
        """Raise error if user can't write to this node."""
        perms = self._get_node_perms(node)
        if not perms["can_write"]:
            raise errors.NoPermission(self.cannot_write_error)

    def _is_on_volume(self, qs):
        """Conditions to only get children of nodes on this volume."""
        if self.share:
            root = self._get_root_node()
            qs = qs.filter(
                models.Q(id=root.id) | models.Q(parent__id=root.id) |
                models.Q(path__startswith=root.absolute_path),
                volume__id=self.volume_id)
        elif self.udf:
            qs = qs.filter(volume__id=self.udf.id)
        return qs

    def _get_node_simple(self, id, live_only=True, with_content=False,
                         with_parent=False, with_volume=False):
        """Just get a StorageObject on this volume."""
        nodes = StorageObject.objects.filter(
            id=id, volume__owner__id=self.owner.id)
        if with_content:
            nodes = nodes.select_related('content_blob')
        if with_parent:
            nodes = nodes.select_related('parent')
        if with_volume:
            nodes = nodes.select_related('volume')
        nodes = self._is_on_volume(nodes)
        if live_only:
            nodes = nodes.filter(status=STATUS_LIVE)
        if nodes.count() == 1:
            result = nodes.get()
        else:
            result = None
        return result

    def _get_node_from_result(self, result):
        """Get a dao.StorageNode from the result."""
        if result.count() == 1:
            return self._get_storage_node(result.get())

    def _get_storage_node(self, node):
        """Get a dao.StorageNode from the result."""
        if node:
            content = node.content_blob
            if content:
                content = FileNodeContent(content)
            return StorageNode.factory(
                self, node, owner=self.owner,
                permissions=self._get_node_perms(node), content=content)

    def _node_finder(self, nodes, with_content=False, with_parent=False):
        """Filter by owner and prefect content and parent, all in one query."""
        if with_content:
            nodes = nodes.select_related('content_blob')
        if with_parent:
            nodes = nodes.select_related('parent')
        nodes = nodes.filter(
            volume__owner__id=self.owner.id, status=STATUS_LIVE)
        return self._is_on_volume(nodes)

    def _get_kind(self, nodes, kind):
        """Get conditions for finding files by kind."""
        if kind is None:
            return nodes
        if kind in [StorageObject.DIRECTORY, StorageObject.FILE]:
            return nodes.filter(kind=kind)
        raise errors.StorageError("Invalid Kind specified")

    def _get_children(self, id, kind=None, with_content=False, mimetypes=None):
        """A common function used to get the children of a node."""
        nodes = StorageObject.objects.filter(parent__id=id)
        nodes = self._get_kind(nodes, kind)
        if mimetypes:
            nodes = nodes.filter(mimetype__in=mimetypes)
        return self._node_finder(nodes, with_content)

    @timing_metric
    def get_generation_delta(self, generation, limit=None):
        """Get nodes since a generation."""
        if self.share:
            root = self._get_root_node()
            # if this is a share, get the delta from ShareVolumeDelta
            # ShareVolumeDelta is a Union of StorageObjects and MoveFromShares

            # Must not return the root node
            nodes = ShareVolumeDelta.objects.exclude(id=root.id)
            nodes = nodes.filter(
                # The union includes a share_id but only
                # MovesFromShare have a share_id this will include the rows
                # from both that meet all other criteria
                models.Q(share_id=None) | models.Q(share_id=self.share.id))
            # we only want to get nodes within the path of the shared node
            path_like = root.absolute_path.rstrip('/')
            nodes = nodes.filter(
                # The path_like will be path.like('/path/with/closing/slash/%')
                # which not match the path of children directly in the root
                # so parent_id == root.id must be also be included.
                models.Q(parent__id=root.id) |
                models.Q(path__startswith=path_like),
            )
        else:
            nodes = StorageObject.objects.filter(parent__isnull=False)
            nodes = self._is_on_volume(nodes)

        nodes = nodes.select_related('content_blob').filter(
            # Must have the same owner id
            volume__id=self.volume_id, volume__owner__id=self.owner.id,
            generation__gt=generation).order_by('generation')
        for node in nodes[:limit]:
            content = node.content_blob
            if content:
                content = FileNodeContent(content)
            yield StorageNode.factory(
                self, node, content=content,
                owner=self.owner, permissions=self._get_node_perms(node))

    @timing_metric
    def get_node(self, id, verify_hash=None, with_content=False):
        """Get one of the user's nodes."""
        if id == 'root':
            id = self._get_root_node().id
        nodes = StorageObject.objects.filter(id=id)
        nodes = self._node_finder(nodes, with_content=with_content)
        node = self._get_node_from_result(nodes)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        if verify_hash and node.content_hash != verify_hash:
            raise errors.HashMismatch(self.hash_mismatch_error)
        return node

    @timing_metric
    def get_node_by_path(self, full_path, kind=None, with_content=None):
        """Get a node based on the path.

        path is a path relative to the volume's root. So a shared
        directory will start relative to the path of the directory.
        """
        if full_path == '/':
            return self.get_root()
        if len(full_path) == 0:
            raise errors.StorageError("Invalid path provided %s" % full_path)
        # join it together with the path for the root of this volume,
        # this is necessary mostly for shares
        root_path = self._get_root_path()
        full_path = os.path.join(root_path, full_path.strip('/'))
        path, name = os.path.split(full_path)

        # this is a little different that typical finds. Since paths can be
        # duplicated across udfs and root, we need to make sure that if
        # this is a root volume, it doesnt' collide with udfs.
        nodes = StorageObject.objects.filter(
            path=path, name=name, volume__id=self.volume_id)
        nodes = self._get_kind(nodes, kind)
        result = self._node_finder(nodes, with_content)
        node = self._get_node_from_result(result)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        return node

    @timing_metric
    def get_all_nodes(self, mimetypes=None, kind=None, with_content=False,
                      start_from_path=None, limit=None, max_generation=None):
        """Get all nodes from this volume."""
        nodes = self._get_kind(StorageObject.objects.all(), kind)
        if mimetypes:
            nodes = nodes.filter(mimetype__in=mimetypes)
        # A temporary hack, because we don't want this crossing volumes
        if self.is_root_volume:
            nodes = nodes.filter(volume__id=self.owner.root_volume_id)
        if max_generation:
            nodes = nodes.filter(generation__lte=max_generation)
        if start_from_path:
            # special case for shares, as the "root" isn't "/" and we need to
            # get the root path+name
            if self.share:
                root = self._get_root_node()
                real_path = root.absolute_path
                # only strip the rightmost "/" if isn't the root of the sharer
                # volume.
                if real_path != '/':
                    real_path = root.absolute_path.rstrip("/")
                if start_from_path[0] != '/':
                    real_path = pypath.join(real_path,
                                            start_from_path[0].lstrip("/"))
                start_from_path = (real_path, start_from_path[1])
            # same path AND greater name OR greater path
            same_path = models.Q(
                path=start_from_path[0], name__gt=start_from_path[1])
            nodes = nodes.filter(
                same_path | models.Q(path__gt=start_from_path[0]))
        results = self._node_finder(nodes, with_content).order_by(
            'path', 'name')
        if limit:
            results = results[:limit]
        return list(self._get_storage_node(n) for n in results)

    @timing_metric
    def get_deleted_files(self, start=0, limit=100):
        """Get Dead files on this volume.

        Files will be returned in descending order by date, path, name
        """
        nodes = StorageObject.objects.filter(
            status=STATUS_DEAD, kind=StorageObject.FILE,
            volume__owner__id=self.owner.id)
        nodes = self._is_on_volume(nodes).order_by(
            '-when_last_modified', 'path', 'name')[start:start+limit]
        return [StorageNode.factory(self, n, owner=self.owner,
                                    permissions=self._get_node_perms(n))
                for n in nodes]

    @timing_metric
    def get_children(self, id, kind=None, with_content=False, mimetypes=None):
        """Get all the nodes children."""
        children = self._get_children(
            id, kind=kind, with_content=with_content, mimetypes=mimetypes)
        for child in children.order_by('name'):
            yield self._get_storage_node(child)

    @timing_metric
    def get_child_by_name(self, id, name, with_content=False):
        """Get a Child by Name returning a StorageNode."""
        children = self._get_children(id, with_content=with_content)
        nodes = children.filter(name=name)
        node = self._get_node_from_result(nodes)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        return node

    @timing_metric
    def get_content(self, content_hash):
        """Get the ContentBlob."""
        content = get_object_or_none(
            ContentBlob, hash=content_hash, status=STATUS_LIVE)
        if content is None:
            raise errors.DoesNotExist(self.contentblob_dne_error)
        return FileNodeContent(content)

    def _get_uploadjob(self, id):
        """Get a UploadJob belonging to this owner."""
        job = get_object_or_none(
            UploadJob, id=id, status=STATUS_LIVE,
            node__volume__owner__id=self.owner.id)
        if job is None:
            raise errors.DoesNotExist(self.uploadjob_dne_error)
        return job

    @timing_metric
    def get_uploadjob(self, id):
        """Get an uploadjob."""
        job = self._get_uploadjob(id)
        return DAOUploadJob(job, gateway=self)

    @timing_metric
    def get_user_uploadjobs(self, node_id=None):
        """Get an uploadjob."""
        jobs = UploadJob.objects.filter(
            status=STATUS_LIVE, node__volume__owner__id=self.owner.id)
        if node_id is not None:
            jobs = jobs.filter(node__id=node_id)
        for job in jobs:
            yield DAOUploadJob(job, gateway=self)

    @timing_metric
    def get_user_multipart_uploadjob(self, node_id, upload_id, hash_hint=None,
                                     crc32_hint=None):
        """Get multipart uploadjob."""
        jobs = UploadJob.objects.filter(
            status=STATUS_LIVE, multipart_key=upload_id,
            node__volume__owner__id=self.owner.id, node__id=node_id)
        node = self._get_node_simple(node_id)
        self._check_can_write_node(node)
        if hash_hint is not None:
            jobs = jobs.filter(hash_hint=hash_hint)
        if crc32_hint is not None:
            jobs = jobs.filter(crc32_hint=crc32_hint)
        if jobs.count() == 0:
            raise errors.DoesNotExist(self.uploadjob_dne_error)
        # load the requested content using the hash_hint
        new_content = get_object_or_none(
            ContentBlob, hash=hash_hint, status=STATUS_LIVE)
        if new_content is not None:
            new_content = FileNodeContent(new_content)
        fnode = StorageNode.factory(
            self, node, content=new_content, permissions={})
        return DAOUploadJob(jobs.get(), file=fnode, gateway=self)

    @timing_metric
    def get_directories_with_mimetypes(self, mimetypes):
        """Get directories that have files with mimetype in mimetypes."""
        files = StorageObject.objects.filter(
            volume__owner__id=self.owner.id, status=STATUS_LIVE,
            mimetype__in=mimetypes, content_blob__isnull=False)
        nodes = files.select_related('parent')
        if self.is_root_volume:
            nodes = nodes.filter(volume__id=self.owner.root_volume_id)
        result = self._is_on_volume(nodes).distinct('parent')
        return [StorageNode.factory(self, d.parent, owner=self.owner)
                for d in result]

    @timing_metric
    def check_has_children(self, id, kind):
        """Find out if the node has children with kind == kind."""
        return self._get_children(id, kind=kind).exists()


class ReadWriteVolumeGateway(ReadOnlyVolumeGateway):
    """Provide Write access to the Volume."""

    def handle_node_change(self, node):
        """Send new generation notifs."""
        # send updates to the owner
        if node.volume_id == self.owner.root_volume_id:
            volume_id = None
        else:
            volume_id = node.volume.id
        self.queue_new_generation(self.owner.id, volume_id,
                                  node.volume.generation)

        # send node updates to all shares of this node.
        nodeids = node.get_parent_ids()
        if node.kind == StorageObject.DIRECTORY:
            nodeids.append(node.id)
        # need to use the owner's user gateway.
        for s in self.owner_gateway.get_shares_of_nodes(nodeids):
            self.queue_new_generation(s.shared_to.id, s.id,
                                      node.volume.generation)

    def _make_content(self, hash, crc32, size, deflated_size,
                      storage_key, magic_hash):
        """Make a content blob."""
        content = ContentBlob.objects.create(
            hash=hash, magic_hash=magic_hash, crc32=crc32, size=size,
            deflated_size=deflated_size, status=STATUS_LIVE,
            storage_key=storage_key)
        return content

    def _get_directory_node(self, id, for_write=True):
        """Get a directory node so it can be modified."""
        if self.read_only and for_write:
            raise errors.NoPermission(self.cannot_write_error)

        nodes = StorageObject.objects.filter(
            volume__owner__id=self.owner.id, status=STATUS_LIVE, id=id)
        nodes = self._is_on_volume(nodes)
        if nodes.count() == 0:
            raise errors.DoesNotExist(self.node_dne_error)
        node = nodes.get()
        if node.kind != StorageObject.DIRECTORY:
            raise errors.NotADirectory(self.not_a_directory_error)
        if for_write:
            self._check_can_write_node(node)
        return node

    @with_notifications
    @timing_metric
    def make_file(self, parent_id, name, hash=None, magic_hash=None):
        """Make a file."""
        reusable = None
        blob = None
        make_new = False
        if hash:
            reusable, blob = self.owner_gateway._get_reusable_content(
                hash, magic_hash)
            if not reusable or not blob:
                raise errors.HashMismatch("The content could not be reused.")

        parent = self._get_directory_node(parent_id)
        newfile = parent.get_child_by_name(name)
        if newfile is None:
            make_new = True
            newfile = parent.make_file(name)
            mime = mimetypes.guess_type(name)
            if mime[0] is not None:
                mime = unicode(mime[0])
                newfile.mimetype = mime
                newfile.save()
        elif newfile.kind != StorageObject.FILE:
            raise errors.AlreadyExists(
                "Node already exists but is not a File.")
        result = None
        if blob:
            # if there's content we'll update the content. This will also
            # trigger the notifications
            result = self._update_node_content(
                fnode=newfile, content=blob, new=make_new, enforce_quota=True)
        elif make_new:
            # if we make a new file, we need to queue a node change
            self.handle_node_change(parent)
        if result is None:
            result = StorageNode.factory(
                self, newfile, owner=self.owner,
                permissions=self._get_node_perms(newfile))
        return result

    @with_notifications
    @timing_metric
    def make_subdirectory(self, parent_id, name):
        """Make a subdirectory."""
        parent = self._get_directory_node(parent_id)
        newdir = parent.get_child_by_name(name)
        if newdir is None:
            newdir = parent.make_subdirectory(name)
            self.handle_node_change(parent)
        elif newdir.kind != StorageObject.DIRECTORY:
            raise errors.AlreadyExists("Node already exists"
                                       " but is not a Directory.")
        return StorageNode.factory(
            self, newdir, owner=self.owner,
            permissions=self._get_node_perms(newdir))

    @with_notifications
    @timing_metric
    def make_tree(self, parent_id, path):
        """Create a directory structure from the path passed in."""
        parent = self._get_directory_node(parent_id)
        if path not in ("", "/"):
            newdir = parent.build_tree_from_path(path)
            self.handle_node_change(newdir.parent)
        else:
            newdir = parent
        return StorageNode.factory(
            self, newdir, owner=self.owner,
            permissions=self._get_node_perms(newdir))

    @timing_metric
    def make_share(self, node_id, name, user_id=None, email='',
                   readonly=True):
        """Create a direct share or a share offer."""
        assert user_id is not None or email, "user_id or an email required"
        if self.share:
            raise errors.NoPermission("Shares can not be nested.")
        to_user = to_db_user = None
        if user_id:
            to_user = self.get_user(user_id)
            if to_user is None or not to_user.is_active:
                raise errors.DoesNotExist(self.user_dne_error)
            to_db_user = StorageUser.objects.get(id=to_user.id)

        node = self._get_directory_node(node_id, for_write=False)
        access_level = Share.VIEW if readonly else Share.MODIFY
        share = Share.objects.create(
            shared_by=StorageUser.objects.get(id=self.user.id), subtree=node,
            shared_to=to_db_user, name=name, access=access_level, email=email)
        share_dao = SharedDirectory(
            share, by_user=self.user, to_user=to_user)
        share_dao._gateway = self.user._gateway
        self.queue_share_created(share_dao)
        return share_dao

    @with_notifications
    @timing_metric
    def delete_node(self, node_id, cascade=False):
        """Decorated _delete_node."""
        return self._delete_node(node_id, cascade)

    def _delete_node(self, node_id, cascade):
        """Delete a node."""
        if self.read_only:
            raise errors.NoPermission(self.readonly_error)

        node = self._get_node_simple(
            node_id, with_parent=True, with_content=True, with_volume=True)

        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        if not self._get_node_perms(node)["can_delete"]:
            raise errors.NoPermission(self.cannot_delete_error)
        if node.status == STATUS_DEAD:
            return
        if node.kind == StorageObject.DIRECTORY:
            self._delete_directory_node(node, cascade=cascade)
        else:
            self._delete_file_node(node)
        return StorageNode.factory(
            self, node, owner=self.owner, permissions={})

    def _delete_file_node(self, node):
        """Internal function to delete a file node."""
        node.unlink()
        self.handle_node_change(node.parent)

    def _delete_directory_node(self, node, cascade=False):
        """Internal function to delete a directory node."""
        parent = StorageObject.objects.get(id=node.parent.id)
        self.owner_gateway.delete_related_shares(node)
        if cascade:
            node.unlink_tree()
        else:
            node.unlink()
        self.handle_node_change(parent)

    @with_notifications
    @timing_metric
    def restore_node(self, node_id, cascade=False):
        """Restore a deleted a node."""
        if self.read_only:
            raise errors.NoPermission(self.readonly_error)
        node = self._get_node_simple(node_id, live_only=False)
        if node.status == STATUS_LIVE:
            return
        node.undelete()
        parent = self._get_node_simple(node.parent_id)
        if parent:
            self.handle_node_change(parent)
        return StorageNode.factory(
            self, node, owner=self.owner, permissions={})

    def _make_moves_from_shares(self, node, old_name, old_parent, new_parent):
        """Create moves from shares."""
        # get all accepted shares
        shares = self.owner_gateway.get_shared_by(accepted=True)
        share_info = {}
        for s in shares:
            share_info.setdefault(s.root_id, []).append(s.id)
        # if the user has no shares, just quit
        if not share_info:
            return
        # get the shared paths:
        shared_node_ids = share_info.keys()
        nodes = StorageObject.objects.filter(
            volume__status=STATUS_LIVE, status=STATUS_LIVE,
            id__in=shared_node_ids).values('id', 'path', 'name')
        shared_paths = {}
        for info in nodes:
            shares = share_info[info['id']]
            shared_paths[pypath.join(info['path'], info['name'])] = shares
        # make sure we have live nodes from these shares:
        if not shared_paths:
            return
        # get the paths that can see this node now.
        see_now = []
        see_after = []
        for path, share_ids in shared_paths.iteritems():
            if old_parent.full_path.startswith(path):
                see_now.extend(share_ids)
            if new_parent.full_path.startswith(path):
                see_after.extend(share_ids)
        # first delete any MoveFromShare where the share is going to see it
        # after the move
        MoveFromShare.objects.filter(
            node_id=node.id, share_id__in=see_after).delete()
        if see_now:
            # create a MoveFromShare for all the nodes shares that will
            # no longer see it
            for share_id in set(see_now).difference(set(see_after)):
                MoveFromShare.objects.from_move(
                    node=node, share_id=share_id, old_parent=old_parent,
                    name=old_name)

    @with_notifications
    @timing_metric
    def move_node(self, node_id, parent_id, new_name):
        """Move a node to a new parent, or rename it."""
        if self.read_only:
            raise errors.NoPermission(self.readonly_error)
        node = self._get_node_simple(node_id)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        is_move = node.parent_id != parent_id
        if not is_move and node.name == new_name:
            return StorageNode.factory(
                self, node, owner=self.owner,
                permissions=self._get_node_perms(node))
        new_parent = self._get_directory_node(parent_id)
        if is_move:
            old_parent = self._get_directory_node(node.parent_id)
            if not self._get_node_perms(node)["can_delete"]:
                raise errors.NoPermission(self.cannot_delete_error)
            if (node.kind == StorageObject.DIRECTORY and
                    new_parent.full_path.startswith(node.full_path + '/')):
                raise errors.NoPermission("Can't move a directory to a child.")

        # make room for the move, delete children with the same name
        conflicting_node = new_parent.get_child_by_name(new_name)
        if conflicting_node:
            self._delete_node(conflicting_node.id, cascade=True)

        old_name = node.name
        node.move(StorageObject.objects.get(id=parent_id), new_name)
        if node.kind == StorageObject.FILE:
            mime = mimetypes.guess_type(node.name)[0]
            node.mimetype = unicode(mime) if mime else None
        if is_move:
            self._make_moves_from_shares(node, old_name,
                                         old_parent, new_parent)
        self.handle_node_change(new_parent)
        return StorageNode.factory(
            self, node, owner=self.owner,
            permissions=self._get_node_perms(node))

    def _update_node_content(self, fnode, content, new, enforce_quota):
        """Reusable function for updating file content."""
        # reload node from DB
        fnode = StorageObject.objects.get(id=fnode.id)
        old_content = fnode.content
        if fnode.content_hash == bytes(content.hash):
            return StorageNode.factory(
                self, fnode, content=FileNodeContent(old_content),
                owner=self.owner, permissions=self._get_node_perms(fnode))
        existing_size = old_content.size if old_content else 0
        needed_size = content.size - existing_size
        if enforce_quota and (needed_size > self.owner.free_bytes):
            raise errors.QuotaExceeded(
                "Upload will exceed quota (needed size %s, free bytes %s)." %
                (needed_size, self.owner.free_bytes),
                self.vol_id, self.owner.free_bytes)
        fnode.set_content(content, enforce_quota=enforce_quota)
        content = FileNodeContent(content)
        if new:
            self.handle_node_change(fnode.parent)
        else:
            self.handle_node_change(fnode)
        return StorageNode.factory(
            self, fnode, content=content, owner=self.owner,
            permissions=self._get_node_perms(fnode))

    @timing_metric
    def make_uploadjob(self, node_id, node_hash, new_hash, crc32,
                       inflated_size, enforce_quota=True, multipart_key=None):
        """Create an upload job for a FileNode."""
        if self.read_only:
            raise errors.NoPermission(self.readonly_error)
        node = self._get_node_simple(node_id)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        if node.kind == StorageObject.DIRECTORY:
            raise NotImplementedError(
                "Uploading Directories is not supported.")
        self._check_can_write_node(node)
        # has file changed?
        db_node_hash = node.content_hash
        if db_node_hash != node_hash and db_node_hash != new_hash:
            raise errors.HashMismatch("The file has changed.")

        old_content = get_object_or_none(
            ContentBlob, hash=db_node_hash, status=STATUS_LIVE)
        existing_size = old_content.size if old_content else 0

        # reload the owner to get the latest quota
        if (enforce_quota and
                inflated_size - existing_size > self.owner.free_bytes):
            raise errors.QuotaExceeded("Upload will exceed quota.",
                                       self.vol_id, self.owner.free_bytes)

        kwargs = dict(node=node, hash_hint=new_hash, crc32_hint=crc32)
        # if we have multipart_key defined it's multipart
        if multipart_key:
            kwargs['multipart_key'] = multipart_key

        upload = UploadJob.objects.create(**kwargs)

        new_content = get_object_or_none(
            ContentBlob, hash=new_hash, status=STATUS_LIVE)
        if new_content:
            new_content = FileNodeContent(new_content)
        fnode = StorageNode.factory(
            self, node, content=new_content,
            owner=self.owner, permissions={})
        upload_dao = DAOUploadJob(upload, file=fnode, gateway=self)
        return upload_dao

    @with_notifications
    @timing_metric
    def make_file_with_content(self, parent_id, name, hash, crc32, size,
                               deflated_size, storage_key, mimetype=None,
                               enforce_quota=True, is_public=False,
                               previous_hash=None, magic_hash=None):
        """Create or update a file with the given content.

        If a file node with name == name as a child of parent_id it will get
        updated with the new content.
        """
        if mimetype is None:
            mime = mimetypes.guess_type(name)[0]
            mimetype = unicode(mime) if mime else ''

        parent = self._get_directory_node(parent_id)
        fnode = parent.get_child_by_name(name)
        is_new = False
        if fnode is None:
            is_new = True
            fnode = parent.make_file(name, mimetype=mimetype)
        elif fnode.kind != StorageObject.FILE:
            raise errors.AlreadyExists(
                "Node already exists but is not a File.")
        elif previous_hash and fnode.content_hash != previous_hash:
            raise errors.HashMismatch("File hash has changed.")

        content = get_object_or_none(ContentBlob, hash=hash)
        if content is None:
            content = self._make_content(hash, crc32, size, deflated_size,
                                         storage_key, magic_hash)
        else:
            if content.magic_hash is None:
                # update magic hash now that we have it!
                content.magic_hash = magic_hash
                content.save()
        if is_public:
            fnode.make_public()
        # do we even need to do this?
        if fnode.content_hash == hash:
            return StorageNode.factory(
                self, fnode, content=FileNodeContent(fnode.content),
                owner=self.owner, permissions=self._get_node_perms(fnode))

        return self._update_node_content(
            fnode, content, new=is_new, enforce_quota=enforce_quota)

    @with_notifications
    @timing_metric
    def make_content(self, file_id, original_hash, hash_hint, crc32_hint,
                     inflated_size_hint, deflated_size_hint,
                     storage_key, magic_hash=None):
        """Make content (if necessary) and update the magic hash (if have it).

        If there is no storage_key, we must have an existing content.
        """
        fnode = self._get_node_simple(file_id)
        if fnode is None:
            raise errors.DoesNotExist("The file no longer exists.")
        if fnode.content_hash != original_hash:
            raise errors.HashMismatch("The file's hash has changed.")
        self._check_can_write_node(fnode)
        content = get_object_or_none(ContentBlob, hash=hash_hint)
        if content is None:
            if storage_key is None:
                # we must have content since we have no storage_key
                raise errors.ContentMissing("The content does not exist.")
            content = self._make_content(
                hash_hint, crc32_hint, inflated_size_hint,
                deflated_size_hint, storage_key, magic_hash)
        else:
            if content.magic_hash is None:
                # update magic hash now that we have it!
                content.magic_hash = magic_hash
                content.save()
        return self._update_node_content(
            fnode, content, new=False, enforce_quota=True)

    @timing_metric
    def delete_uploadjob(self, id):
        """Delete an upload job."""
        job = self._get_uploadjob(id)
        job.delete()
        upload_dao = DAOUploadJob(job, gateway=self)
        return upload_dao

    @timing_metric
    def add_uploadjob_part(self, job_id, size):
        """Add a part to an uploadjob with: size"""
        job = self._get_uploadjob(job_id)
        job.add_part(size)
        return DAOUploadJob(job, gateway=self)

    @timing_metric
    def set_uploadjob_when_last_active(self, job_id, timestamp):
        """Set when_last_active to timestamp."""
        job = self._get_uploadjob(job_id)
        job.when_last_active = timestamp
        job.save()
        return DAOUploadJob(job, gateway=self)

    @with_notifications
    @timing_metric
    def change_public_access(self, node_id, is_public, allow_directory=False):
        """Sets whether a node should be publicly available."""
        # we don't let user's make shared files public
        if self.share:
            raise errors.NoPermission("Can't make shared files public.")

        fnode = self._get_node_simple(node_id)
        if fnode is None:
            raise errors.DoesNotExist(self.node_dne_error)
        if fnode.kind != StorageObject.FILE and allow_directory is False:
            raise errors.NoPermission("Only files can be made public.")

        if fnode.is_public != is_public:
            if is_public:
                fnode.make_public()
            else:
                fnode.make_private()
            self.handle_node_change(fnode)
        return StorageNode.factory(
            self, fnode, owner=self.owner,
            permissions=self._get_node_perms(fnode))

    @timing_metric
    def get_node_parent_ids(self, node_id):
        """Get the parents of this node id."""
        node = self._get_node_simple(node_id)
        if node is None:
            raise errors.DoesNotExist(self.node_dne_error)
        return node.get_parent_ids()

    @with_notifications
    @timing_metric
    def undelete_volume(self, name, limit=100):
        """Undelete all user's data."""
        if self.user.id != self.owner.id:
            raise errors.NoPermission("You can only undelete your own files")
        # get the user's root volume
        root = self._get_root_node()
        parent = root.get_child_by_name(name)
        if parent and parent.kind != StorageObject.DIRECTORY:
            name = root.get_unique_childname(name)
            parent = None
        if parent is None:
            parent = root.make_subdirectory(name)
        StorageUser.objects.get(id=self.owner.id).undelete_volume(
            self.volume_id, parent, limit=limit)
        return StorageNode.factory(self, parent, owner=self.owner)


def fix_udfs_with_generation_out_of_sync(user_ids, logger):
    """Find the UDFs that have an object whose generation is higher than the
    UDF's and update the UDF's generation to be the same as the Object's.

    Only UDFs owned by the given users are considered.
    """
    results = StorageObject.objects.select_related('volume').filter(
        generation__gt=models.F('volume__generation'),
        volume__owner__id__in=user_ids)
    for obj in results:
        # The query above will return all of a UDF's objects that have a higher
        # generation than the UDF itself, so we have this if block here to
        # make sure the UDF ends up with the highest generation of them all.
        udf = obj.volume
        if obj.generation > udf.generation:
            logger.info("Updating the generation of %s from %s to %s" % (
                udf.id, udf.generation, obj.generation))
            udf.generation = obj.generation
            udf.save()


@fsync_commit
def fix_all_udfs_with_generation_out_of_sync(logger, sleep=0, batch_size=500):
    user_ids = StorageUser.objects.all().values_list('id', flat=True)
    start = time.time()
    total_users = len(user_ids)
    total_done = 0
    while user_ids:
        batch = user_ids[:batch_size]
        user_ids = user_ids[batch_size:]
        fix_udfs_with_generation_out_of_sync(batch, logger)
        total_time = time.time() - start
        total_done += len(batch)
        fraction_done = total_done / float(total_users)
        eta = (total_time / fraction_done) - total_time
        logger.info(
            "Processed UDFs for %.2f%% of users in %d seconds. ETA: %d seconds"
            % (fraction_done * 100, total_time, eta))
        time.sleep(sleep)


# original services.py starts here


@retryable_transaction()
@fsync_commit
def make_storage_user(
        username, max_storage_bytes=DEFAULT_QUOTA_BYTES, **kwargs):
    """Create or update a StorageUser."""
    session_id = kwargs.pop('session_id', None)
    gw = SystemGateway(session_id=session_id)
    return gw.create_or_update_user(username, max_storage_bytes, **kwargs)


@fsync_readonly
def get_storage_user(user_id=None, username=None, session_id=None,
                     active_only=True, readonly=False):
    """Get a storage user.

    readonly kwarg is just to not raise LockedUserError in case the user is
    locked.
    """
    gw = SystemGateway()
    user = gw.get_user(user_id=user_id, username=username,
                       session_id=session_id, ignore_lock=readonly)
    if active_only and (user is None or not user.is_active):
        raise errors.DoesNotExist("User does not exist.")
    return user


@fsync_readonly
def get_shareoffer(shareoffer_id):
    """Get a Share Offer."""
    gw = SystemGateway()
    return gw.get_shareoffer(shareoffer_id)


@retryable_transaction()
@fsync_commit
def claim_shareoffer(user_id, username, visible_name, share_offer_id):
    """Claim a shared folder offer sent to an email."""
    gw = SystemGateway()
    return gw.claim_shareoffer(user_id, username, visible_name, share_offer_id)


@fsync_readonly
def get_public_file(public_key):
    """Get a public file."""
    gw = SystemGateway()
    return gw.get_public_file(public_key)


@fsync_readonly
def get_public_directory(public_key):
    """Get a public directory."""
    gw = SystemGateway()
    return gw.get_public_directory(public_key)


@fsync_readonly
def get_node(node_id):
    """Get the StorageNode for the specified node_id.

    raise DoesNotExist if the node isn't there.
    """
    gw = SystemGateway()
    return gw.get_node(node_id)


@fsync_readonly
def get_user(user_id):
    """Get the UserInfo dao (read only) for the user_id."""
    gw = SystemGateway()
    return gw.get_user(user_id)


@fsync_readonly
def get_abandoned_uploadjobs(last_active, limit=1000):
    """Return the live resumable uploadjobs.

    @param last_active_before: datetime, a filter of the when_started field.
    @param limit: the limit on the number of results
    """
    gw = SystemGateway()
    return gw.get_abandoned_uploadjobs(last_active, limit)


@fsync_commit
def cleanup_uploadjobs(uploadjob_ids):
    """Delete UploadJobs

    @param uploadjobs_ids: the list of id of jobs to delete
    """
    gw = SystemGateway()
    return gw.cleanup_uploadjobs(uploadjob_ids)
