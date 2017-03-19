# ubuntuone.syncdaemon.volume_manager - manages volumes
#
# Copyright 2009-2012 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
""" The all mighty Volume Manager """

from __future__ import with_statement

import itertools
import functools
import cPickle
import logging
import os
import re
import sys
import stat

from itertools import ifilter

from twisted.internet import defer
from ubuntuone.platform import expand_user
from ubuntuone.storageprotocol import request
from ubuntuone.storageprotocol.volumes import (
    ShareVolume,
    UDFVolume,
    RootVolume,
)

from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.syncdaemon.interfaces import IMarker
from ubuntuone.syncdaemon import file_shelf, config
from ubuntuone.syncdaemon.tritcask import TritcaskShelf
from ubuntuone.syncdaemon.vm_helper import (
    create_shares_link,
    get_share_dir_name,
    get_udf_path,
    get_udf_suggested_path,
)
from ubuntuone.platform import (
    allow_writes,
    get_path_list,
    is_link,
    listdir,
    make_dir,
    normpath,
    open_file,
    path_exists,
    read_link,
    recursive_move,
    remove_file,
    remove_dir,
    remove_tree,
    rename,
    set_dir_readonly,
    set_dir_readwrite,
    walk,
)

# tritcask row types
SHARE_ROW_TYPE = 3
SHARED_ROW_TYPE = 4
UDF_ROW_TYPE = 5

ACCESS_LEVEL_RO = 'View'
ACCESS_LEVEL_RW = 'Modify'


class _Share(object):
    """Represents a share or mount point"""

    def __init__(self, share_id=request.ROOT, node_id=None, path=None,
                 name=None, access_level=ACCESS_LEVEL_RO, accepted=False,
                 other_username=None, other_visible_name=None):
        """ Creates the instance.

        The received path should be 'bytes'
        """
        if path is None:
            self.path = None
        else:
            self.path = normpath(path)
        self.id = str(share_id)
        self.access_level = access_level
        self.accepted = accepted
        self.name = name
        self.other_username = other_username
        self.other_visible_name = other_visible_name
        self.subtree = node_id
        self.free_bytes = None


class _UDF(object):
    """A representation of a User Defined Folder."""

    def __init__(self, udf_id, node_id, suggested_path,
                 path, subscribed=False):
        """Create the UDF, not subscribed by default"""
        # id and node_id should be str or None
        assert isinstance(udf_id, basestring) or udf_id is None
        assert isinstance(node_id, basestring) or node_id is None
        self.id = udf_id
        self.node_id = node_id
        self.suggested_path = suggested_path
        self.path = path
        self.subscribed = subscribed


class Volume(object):
    """A generic volume."""

    # default generation for all volumes without a value in the metadata
    generation = None
    # transient value used in local rescan during resubscribe. Set it always to
    # False no matter what is passed to the constructor
    local_rescanning = False

    def __init__(self, volume_id, node_id, generation=None, subscribed=False):
        """Create the volume."""
        # id and node_id should be str or None
        assert isinstance(volume_id, basestring) or volume_id is None
        assert isinstance(node_id, basestring) or node_id is None
        self.volume_id = volume_id
        self.node_id = node_id
        self.generation = generation
        self.subscribed = subscribed

    @property
    def id(self):
        return self.volume_id

    def can_write(self):
        raise NotImplementedError('Subclass responsability')

    def __eq__(self, other):
        result = (self.id == other.id and
                  self.node_id == other.node_id and
                  self.subscribed == other.subscribed)
        return result

    def __hash__(self):
        return hash((self.volume_id, self.node_id))

    def __repr__(self):
        return "<Volume id %r, node_id %r, generation %r>" % (self.volume_id,
                                                              self.node_id,
                                                              self.generation)


class Share(Volume):
    """A volume representing a Share."""

    subscribed = True  # old shares should be automatically subscribed

    def __init__(self, volume_id=None, node_id=None, path=None, name=None,
                 other_username=None, other_visible_name=None, accepted=False,
                 access_level=ACCESS_LEVEL_RO, free_bytes=None,
                 generation=None, subscribed=False):
        """Create the share."""
        super(Share, self).__init__(volume_id, node_id, generation, subscribed)
        self.__dict__['type'] = 'Share'
        if path is None:
            self.path = None
        else:
            self.path = normpath(path)
        self.name = name
        self.other_username = other_username
        self.other_visible_name = other_visible_name
        self.accepted = accepted
        self.access_level = access_level
        self.free_bytes = free_bytes

    @classmethod
    def from_response(cls, share_response, path):
        """ Creates a Share instance from a ShareResponse.

        The received path should be 'bytes'
        """
        share = cls(volume_id=str(share_response.id),
                    node_id=str(share_response.subtree),
                    path=path, name=share_response.name,
                    other_username=share_response.other_username,
                    other_visible_name=share_response.other_visible_name,
                    accepted=share_response.accepted,
                    access_level=share_response.access_level)
        return share

    @classmethod
    def from_notify_holder(cls, share_notify, path):
        """ Creates a Share instance from a NotifyShareHolder.

        The received path should be 'bytes'
        """
        share = cls(volume_id=str(share_notify.share_id),
                    node_id=str(share_notify.subtree),
                    path=path, name=share_notify.share_name,
                    other_username=share_notify.from_username,
                    other_visible_name=share_notify.from_visible_name,
                    access_level=share_notify.access_level)
        return share

    @classmethod
    def from_share_volume(cls, share_volume, path):
        """Creates a Share instance from a volumes.ShareVolume.

        The received path should be 'bytes'

        """
        share = cls(volume_id=str(share_volume.volume_id),
                    node_id=str(share_volume.node_id),
                    path=path, name=share_volume.share_name,
                    other_username=share_volume.other_username,
                    other_visible_name=share_volume.other_visible_name,
                    # if it's form a share volume, it was accepted
                    accepted=True,
                    access_level=share_volume.access_level,
                    generation=share_volume.generation,
                    free_bytes=share_volume.free_bytes)
        return share

    def can_write(self):
        """Return True if this share can be modified."""
        return self.access_level == ACCESS_LEVEL_RW

    @property
    def active(self):
        """Return True if this Share is accepted."""
        return self.accepted and self.subscribed and not self.local_rescanning

    def __eq__(self, other):
        result = (super(Share, self).__eq__(other) and
                  self.path == other.path and
                  self.name == other.name and
                  self.other_username == other.other_username and
                  self.other_visible_name == other.other_visible_name and
                  self.accepted == other.accepted and
                  self.access_level == other.access_level)
        return result

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        msg = "<Share id %r, node_id %r, generation %r, active %r (%r, %r), " \
              "access_level %r, other_username %r, other_visible_name %r, " \
              "name %r, path %r>"
        return msg % (self.volume_id, self.node_id, self.generation,
                      self.active, self.accepted, self.subscribed,
                      self.access_level, self.other_username,
                      self.other_visible_name, self.name, self.path)


class Shared(Share):

    def __init__(self, *args, **kwargs):
        super(Shared, self).__init__(*args, **kwargs)
        self.subscribed = True  # other value makes no sense
        self.__dict__['type'] = 'Shared'

    def __repr__(self):
        return "<Shared id %r, node_id %r>" % (self.volume_id, self.node_id)


class Root(Volume):
    """A volume representing the root."""

    subscribed = True

    def __init__(self, volume_id=request.ROOT, node_id=None, path=None,
                 free_bytes=None, generation=None):
        """Create the Root."""
        super(Root, self).__init__(volume_id, node_id, generation,
                                   subscribed=True)
        self.__dict__['type'] = 'Root'
        self.path = path
        self.free_bytes = free_bytes

    def __eq__(self, other):
        result = (super(Root, self).__eq__(other) and
                  self.path == other.path)
        return result

    def can_write(self):
        return True

    @property
    def active(self):
        return True

    @classmethod
    def from_volume(cls, volume):
        """Create a Root instance from a RootVolume."""
        # TODO: include the generation and the volume_id(?)
        return cls(
            node_id=str(volume.node_id),
            free_bytes=volume.free_bytes, generation=volume.generation)

    def __repr__(self):
        return "<Root node_id %r, generation %r>" % (
            self.node_id, self.generation)


class UDF(Volume):
    """A volume representing a User Defined Folder."""

    def __init__(self, volume_id=None, node_id=None, suggested_path=None,
                 path=None, subscribed=False, generation=None):
        """Create the UDF, not subscribed by default"""
        super(UDF, self).__init__(volume_id, node_id, generation, subscribed)
        self.__dict__['type'] = 'UDF'
        self.node_id = node_id
        self.suggested_path = suggested_path
        self.path = path

    def __repr__(self):
        msg = "<UDF id %r, node_id %r, generation %r, active %r, real path %r>"
        return msg % (self.volume_id, self.node_id, self.generation,
                      self.active, self.path)

    @property
    def ancestors(self):
        """Calculate all the ancestors for this UDF's path.

        Return a list of paths that are 'syncdaemon' valid.

        """
        user_home = expand_user('~')
        path_list = get_path_list(self.path)
        common_prefix = os.path.commonprefix([self.path, user_home])
        common_list = get_path_list(common_prefix)

        result = [user_home]
        for p in path_list[len(common_list):-1]:
            result.append(os.path.join(result[-1], p))

        return result

    def can_write(self):
        """We always can write in a UDF."""
        return True

    @property
    def active(self):
        """Returns True if the UDF is subscribed."""
        return self.subscribed and not self.local_rescanning

    @classmethod
    def from_udf_volume(cls, udf_volume, path):
        """Creates a UDF instance from a volumes.UDFVolume.

        The received path should be 'bytes'

        """
        return cls(volume_id=str(udf_volume.volume_id),
                   node_id=str(udf_volume.node_id),
                   suggested_path=udf_volume.suggested_path, path=path,
                   generation=udf_volume.generation)

    def __eq__(self, other):
        result = (super(UDF, self).__eq__(other) and
                  self.suggested_path == other.suggested_path and
                  self.path == other.path)
        return result


class VolumeDoesNotExist(Exception):
    """Exception for non existing volumes."""

    msg = 'DOES_NOT_EXIST'

    def __init__(self, volume_id):
        """Create the instance."""
        super(VolumeDoesNotExist, self).__init__(self.msg, volume_id)

    def __str__(self):
        """The error message."""
        return self.msg


class VolumeManager(object):
    """Manages shares and mount points."""

    METADATA_VERSION = '7'

    def __init__(self, main):
        """Create the instance and populate the shares/d attributes
        from the metadata (if it exists).
        """
        self.log = logging.getLogger('ubuntuone.SyncDaemon.VM')
        self.m = main
        self._data_dir = os.path.join(self.m.data_dir, 'vm')
        self._shares_dir = os.path.join(self._data_dir, 'shares')
        self._shared_dir = os.path.join(self._data_dir, 'shared')
        self._udfs_dir = os.path.join(self._data_dir, 'udfs')

        md_upgrader = MetadataUpgrader(self._data_dir, self._shares_dir,
                                       self._shared_dir, self._udfs_dir,
                                       self.m.root_dir, self.m.shares_dir,
                                       self.m.shares_dir_link, self.m.db)
        md_upgrader.upgrade_metadata()

        # build the dir layout
        if not path_exists(self.m.root_dir):
            self.log.debug('creating root dir: %r', self.m.root_dir)
            make_dir(self.m.root_dir, recursive=True)
        if not path_exists(self.m.shares_dir):
            self.log.debug('creating shares directory: %r', self.m.shares_dir)
            make_dir(self.m.shares_dir, recursive=True)
        # create the shares symlink
        if create_shares_link(self.m.shares_dir, self.m.shares_dir_link):
            self.log.debug('creating Shares symlink: %r -> %r',
                           self.m.shares_dir_link, self.m.shares_dir)
        # make the shares_dir read only
        set_dir_readonly(self.m.shares_dir)
        # make the root read write
        set_dir_readwrite(self.m.root_dir)

        # create the metadata directories
        if not path_exists(self._shares_dir):
            make_dir(self._shares_dir, recursive=True)
        if not path_exists(self._shared_dir):
            make_dir(self._shared_dir, recursive=True)
        if not path_exists(self._udfs_dir):
            make_dir(self._udfs_dir, recursive=True)

        # load the metadata
        self.shares = VMTritcaskShelf(SHARE_ROW_TYPE, self.m.db)
        self.shared = VMTritcaskShelf(SHARED_ROW_TYPE, self.m.db)
        self.udfs = VMTritcaskShelf(UDF_ROW_TYPE, self.m.db)
        root = self.shares.get(request.ROOT)
        if root is None:
            self.shares[request.ROOT] = root = Root(path=self.m.root_dir)
        elif root.path != self.m.root_dir:
            root.path = self.m.root_dir
            self.shares[request.ROOT] = root
        self.marker_share_map = {}
        self.marker_udf_map = {}
        self.list_shares_retries = 0
        self.list_volumes_retries = 0
        self.retries_limit = 5

    @property
    def root(self):
        """Return the Root share instance."""
        return self.shares.get(request.ROOT)

    def init_root(self):
        """Creates the root mdid."""
        self.log.debug('init_root')
        root = self.shares[request.ROOT]
        self._create_share_dir(root)
        try:
            self.m.fs.get_by_path(root.path)
        except KeyError:
            self.m.fs.create(path=root.path,
                             share_id=root.volume_id, is_dir=True)

    def _got_root(self, node_id, free_bytes=None):
        """Set the root node_id to the root share and mdobj."""
        # only set the root if we don't have it
        root = self.shares[request.ROOT]
        if free_bytes is not None:
            root.free_bytes = free_bytes
        mdobj = self.m.fs.get_by_path(root.path)
        if not (root.node_id and mdobj.node_id):
            self.m.fs.set_node_id(root.path, node_id)
            root.node_id = node_id
            self.shares[request.ROOT] = root
            self.m.event_q.push('SYS_ROOT_RECEIVED',
                                root_id=root.node_id, mdid=mdobj.mdid)
        elif root.node_id != node_id:
            self.m.event_q.push('SYS_ROOT_MISMATCH',
                                root_id=root.node_id, new_root_id=node_id)
        else:
            # the root node_id match and we already have it
            self.m.event_q.push('SYS_ROOT_RECEIVED',
                                root_id=root.node_id, mdid=mdobj.mdid)

    def refresh_shares(self):
        """Request the list of shares to the server."""
        self.m.action_q.list_shares()

    def refresh_volumes(self):
        """Request the list of volumes to the server."""
        self.m.action_q.list_volumes()

    def handle_AQ_LIST_VOLUMES(self, volumes):
        """Handle AQ_LIST_VOLUMES event."""
        self.log.debug('handle_AQ_LIST_VOLUMES: handling volumes list.')
        self.list_volumes_retries = 0
        shares, udfs = self._volumes_rescan_cb(volumes)
        self._cleanup_volumes(shares=shares, udfs=udfs)

    def handle_SV_VOLUME_NEW_GENERATION(self, volume_id, generation):
        """Handle SV_VOLUME_NEW_GENERATION.

        Non active volumes would be ignored.

        """
        self.log.debug('handle_SV_VOLUME_NEW_GENERATION(%r, %r)',
                       volume_id, generation)
        volume_id = str(volume_id)  # be safe and use a str
        try:
            volume = self.get_volume(volume_id)
        except VolumeDoesNotExist:
            self.log.warning('Got a SV_VOLUME_NEW_GENERATION for a missing '
                             'volume: %r with %r', volume_id, generation)
            self.refresh_volumes()
        else:
            if not volume.active:
                self.log.info('Skipping SV_VOLUME_NEW_GENERATION for volume '
                              '%r, since is not active.', volume_id)
                return

            current_gen = volume.generation
            if current_gen is None:
                self.m.action_q.rescan_from_scratch(volume_id)
            elif current_gen < generation:
                # XXX: check if we want to impose a hard limit in the size of
                # the delta and do a rescan from scratch if it's too big
                self.m.action_q.get_delta(volume_id, current_gen)
            elif current_gen >= generation:
                self.log.info('Got SV_VOLUME_NEW_GENERATION(%r, %r) but volume'
                              ' is at generation: %r',
                              volume_id, generation, current_gen)

    def handle_AQ_DELTA_NOT_POSSIBLE(self, volume_id):
        """Handle AQ_DELTA_NOT_POSSIBLE."""
        self.log.debug('handle_AQ_DELTA_NOT_POSSIBLE(%r)', volume_id)
        volume_id = str(volume_id)
        try:
            volume = self.get_volume(volume_id)
        except VolumeDoesNotExist:
            self.log.warning('Got a AQ_DELTA_NOT_POSSIBLE for a missing '
                             'volume: %r', volume_id)
            self.refresh_volumes()
        else:
            self.log.info('Requesting a rescan from scratch for: %s', volume)
            self.m.action_q.rescan_from_scratch(volume_id)

    def server_rescan(self):
        """Do the 'server rescan'"""
        d = self.m.action_q.query_volumes()
        d.addCallback(self._volumes_rescan_cb)

        def cleanup(result):
            shares, udfs = result
            self._cleanup_volumes(shares=shares, udfs=udfs)
        d.addCallbacks(cleanup)

        def done(_):
            self.m.event_q.push('SYS_SERVER_RESCAN_DONE')

        def error(failure):
            self.m.event_q.push('SYS_SERVER_RESCAN_ERROR',
                                error=str(failure.value))
        d.addCallbacks(done, error)
        # refresh the pending shares and shared dirs list
        d.addCallback(lambda _: self.refresh_shares())
        return d

    def _volumes_rescan_cb(self, volumes):
        """Handle the volumes list for server rescan."""
        self.log.debug('_volumes_rescan_cb: volumes: %r', volumes)
        events = []
        shares = []
        udfs = []
        for new_volume in volumes:
            # TODO: all this block might need to be inside a try:except
            # to keep handling volumes even when one fails
            volume_id = str(new_volume.volume_id or '')
            try:
                volume = self.get_volume(volume_id)
            except VolumeDoesNotExist:
                # a new volume!
                self.log.debug('_volumes_rescan_cb: new volume! id %r.',
                               volume_id)
                # _handle_new_volume will do a local and server rescan
                # of the volume and will activate it after that.
                volume = self._handle_new_volume(new_volume)
            finally:
                current_generation = volume.generation

            # store the received volumes ids to return them
            if isinstance(new_volume, RootVolume):
                # handle root volume, to set root node_id
                self._got_root(str(new_volume.node_id),
                               free_bytes=new_volume.free_bytes)
                shares.append(volume_id)
                # don't check the fsm node,
                # the root fsm object is created in init_root
            elif isinstance(new_volume, ShareVolume):
                # check if the fsm node exists, and create it if not
                self._create_fsm_object(volume.path, volume.id, volume.node_id)
                shares.append(volume_id)
                # check if the accepted status changed
                if volume.accepted != new_volume.accepted:
                    # this only happens transitioning from False to True
                    volume.accepted = new_volume.accepted
                    # update the share metadata
                    self.shares[volume.volume_id] = volume
                    # queue the VM_SHARE_CREATED event
                    events.append(('VM_SHARE_CREATED',
                                   dict(share_id=volume.volume_id)))
            elif isinstance(new_volume, UDFVolume):
                # check if the fsm node exists, and create it if not
                self._create_fsm_object(volume.path, volume.id, volume.node_id)
                udfs.append(volume_id)
            else:
                self.log.warning("Unknown type in the volumes list: %r",
                                 volume)

            # first check if it's active
            if not volume.active:
                self.log.info('Skipping inactive volume: %r', volume)
                continue

            new_generation = new_volume.generation
            self.log.debug('_volumes_rescan (%s): current_gen=%s new_gen='
                           '%s free_bytes=%s', volume, current_generation,
                           new_generation, new_volume.free_bytes)
            if current_generation is None or \
               current_generation < new_generation:
                # add the event
                d = dict(volume_id=volume_id, generation=new_generation)
                events.append(('SV_VOLUME_NEW_GENERATION', d))

            # update the free_bytes on the volume
            self.update_free_space(volume_id, new_volume.free_bytes)

        volumes = list(self.get_volumes(all_volumes=True))
        events.append(("VM_VOLUMES_CHANGED", dict(volumes=volumes)))

        # push the collected events
        for event in events:
            self.m.event_q.push(event[0], **event[1])

        return shares, udfs

    def _handle_new_volume(self, volume):
        """Handle a (probably) new volume.

        Also call the specific method to handle this volume
        type (share/udf/root).

        Return the share/udf and create it if it doesn't exist.

        """
        self.log.debug('_handle_new_volume: volume %r.', volume)
        if isinstance(volume, ShareVolume):
            dir_name = get_share_dir_name(volume)
            path = os.path.join(self.m.shares_dir, dir_name)
            share = Share.from_share_volume(volume, path)
            autosubscribe = config.get_user_config().get_share_autosubscribe()
            self.log.debug('_handle_new_volume: share_autosubscribe? %r',
                           autosubscribe)
            share.subscribed = autosubscribe
            self.add_share(share)
            return share
        elif isinstance(volume, UDFVolume):
            path = get_udf_path(volume.suggested_path)
            udf = UDF.from_udf_volume(volume, path)
            autosubscribe = config.get_user_config().get_udf_autosubscribe()
            self.log.debug('_handle_new_volume: udf_autosubscribe? %r',
                           autosubscribe)
            udf.subscribed = autosubscribe
            self.add_udf(udf)
            return udf
        elif isinstance(volume, RootVolume):
            self._got_root(str(volume.node_id), free_bytes=volume.free_bytes)
            return self.root
        else:
            self.log.warning("Unknown type in the volumes list: %r", volume)

    def handle_AQ_SHARES_LIST(self, shares_list):
        """ handle AQ_SHARES_LIST event """
        self.log.debug('handling shares list: ')
        self.list_shares_retries = 0
        shares = []
        shared = []
        for a_share in shares_list.shares:
            share_id = getattr(a_share, 'id',
                               getattr(a_share, 'share_id', None))
            self.log.debug('share %r: id=%s, name=%r', a_share.direction,
                           share_id, a_share.name)
            if a_share.direction == "to_me":
                dir_name = get_share_dir_name(a_share)
                path = os.path.join(self.m.shares_dir, dir_name)
                share = Share.from_response(a_share, path)
                shares.append(share.volume_id)
                self.add_share(share)
            elif a_share.direction == "from_me":
                try:
                    mdobj = self.m.fs.get_by_node_id(
                        str(a_share.subtree_volume_id or request.ROOT),
                        str(a_share.subtree))
                    path = self.m.fs.get_abspath(mdobj.share_id, mdobj.path)
                except KeyError:
                    # we don't have the file/md of this shared node_id yet
                    # for the moment ignore this share
                    self.log.warning(
                        "we got a share with 'from_me' direction, "
                        "but don't have the node_id in the metadata yet")
                    path = None
                share = Shared.from_response(a_share, path)
                shared.append(share.volume_id)
                self.add_shared(share)
        self._cleanup_shared(shared)
        self._cleanup_shares(shares)

    def _cleanup_volumes(self, shares=None, udfs=None):
        """Remove missing shares from the shares and shared shelfs."""
        # housekeeping of the shares, udfs shelf's each time we
        # get the list of shares/volumes
        self.log.debug('deleting dead volumes')
        if shares is not None:
            for share in ifilter(lambda item: item and item not in shares,
                                 self.shares):
                self.log.debug('deleting share: id=%s', share)
                self.share_deleted(share)
        if udfs is not None:
            # cleanup missing udfs
            for udf in ifilter(lambda item: item and item not in udfs,
                               self.udfs):
                self.log.debug('deleting udfs: id=%s', udf)
                self.udf_deleted(udf)

    def _cleanup_shared(self, to_keep):
        """Cleanup shared Shares from the shelf."""
        self.log.debug('deleting dead shared')
        for share in ifilter(lambda item: item and item not in to_keep,
                             self.shared):
            self.log.debug('deleting shared: id=%s', share)
            del self.shared[share]

    def _cleanup_shares(self, to_keep):
        """Cleanup not-yet accepted Shares from the shares shelf."""
        self.log.debug('deleting dead shares')
        shares = (
            lambda i: i and i not in to_keep and not self.shares[i].accepted)
        for share in ifilter(shares, self.shares):
            self.log.debug('deleting shares: id=%s', share)
            self.share_deleted(share)

    def handle_AQ_LIST_VOLUMES_ERROR(self, error):
        """Handle AQ_LIST_VOLUMES_ERROR event."""
        # call list_volumes again, until we reach the retry limit
        if self.list_volumes_retries <= self.retries_limit:
            self.m.action_q.list_volumes()
            self.list_volumes_retries += 1

    def handle_AQ_LIST_SHARES_ERROR(self, error):
        """ handle AQ_LIST_SHARES_ERROR event """
        # just call list_shares again, until we reach the retry limit
        if self.list_shares_retries <= self.retries_limit:
            self.m.action_q.list_shares()
            self.list_shares_retries += 1

    def handle_SV_FREE_SPACE(self, share_id, free_bytes):
        """ handle SV_FREE_SPACE event """
        self.update_free_space(str(share_id), free_bytes)
        # check AQ wait conditions
        self.m.action_q.check_conditions()

    def handle_SV_SHARE_CHANGED(self, info):
        """ handle SV_SHARE_CHANGED event """
        if str(info.share_id) not in self.shares:
            self.log.debug("New share notification, share_id: %s",
                           info.share_id)
            # XXX: request a refresh of the shares list(?)
            dir_name = get_share_dir_name(info)
            path = os.path.join(self.m.shares_dir, dir_name)
            share = Share.from_notify_holder(info, path)
            self.add_share(share)
        else:
            self.log.debug('share changed! %s', info.share_id)
            self.share_changed(info)

    def handle_SV_SHARE_DELETED(self, share_id):
        """ handle SV_SHARE_DELETED event """
        self.log.debug('share deleted! %s', share_id)
        self.share_deleted(str(share_id))

    def handle_AQ_CREATE_SHARE_OK(self, share_id, marker):
        """ handle AQ_CREATE_SHARE_OK event. """
        share = self.marker_share_map.get(marker)
        if share is None:
            self.m.action_q.list_shares()
        else:
            share.volume_id = str(share_id)
            if IMarker.providedBy(share.node_id):
                mdobj = self.m.fs.get_by_mdid(str(share.node_id))
                share.node_id = mdobj.node_id
            self.add_shared(share)
            if marker in self.marker_share_map:
                del self.marker_share_map[marker]

    def handle_AQ_CREATE_SHARE_ERROR(self, marker, error):
        """ handle AQ_CREATE_SHARE_ERROR event. """
        if marker in self.marker_share_map:
            del self.marker_share_map[marker]

    def handle_AQ_DELETE_SHARE_OK(self, share_id):
        """Handle AQ_DELETE_SHARE_OK event."""
        share = self.shared.get(share_id)
        if share is not None:
            del self.shared[share_id]
            self.m.event_q.push('VM_SHARE_DELETED', share=share)
        else:
            # delete ok, of something we don't have.
            self.log.warning("AQ_DELETE_SHARE_OK of a non-existing shared "
                             "dir: %s", share_id)

    def handle_AQ_DELETE_SHARE_ERROR(self, share_id, error):
        """Gandle AQ_DELETE_SHARE_ERROR event."""
        self.log.error("Error while deleting offered share: %s", error)
        self.m.event_q.push('VM_SHARE_DELETE_ERROR',
                            share_id=share_id, error=error)

    def handle_SV_SHARE_ANSWERED(self, share_id, answer):
        """ handle SV_SHARE_ANSWERED event. """
        share = self.shared.get(share_id, None)
        if share is None:
            # oops, we got an answer for a share we don't have,
            # probably created from the web.
            # refresh the share list
            self.refresh_shares()
        else:
            share.accepted = True if answer == 'Yes' else False
            self.shared[share_id] = share

    def handle_AQ_ANSWER_SHARE_OK(self, share_id, answer):
        """Handle successfully accepting a share."""
        if answer == 'Yes':
            share = self.shares[share_id]
            share.accepted = True
            self.shares[share.volume_id] = share
            self._create_fsm_object(share.path, share.volume_id, share.node_id)
            self._create_share_dir(share)
            self.m.action_q.rescan_from_scratch(share.volume_id)

    def add_share(self, a_share):
        """ Add a share to the share list, and creates the fs mdobj. """
        self.log.info('add_share: %r', a_share)
        share = self.shares.get(a_share.volume_id)
        is_new_share = share is None
        if share is not None:
            share.accepted = a_share.accepted
            self.shares[share.volume_id] = share
        else:
            share = a_share
        if is_new_share or not share.accepted:
            # if it's a new share or isn't accepted set the generation to None
            # to force a rescan
            share.generation = None
        # store the share
        self.shares[share.volume_id] = share
        if share.accepted:
            self._create_fsm_object(share.path, share.volume_id, share.node_id)

        if share.active:
            self._create_share_dir(share)
            self.log.debug('add_share: volume active, temporarly unsubscribe '
                           'to rescan (scan_local? %r).', share.can_write())
            share.local_rescanning = True
            self.shares[share.volume_id] = share

            def subscribe(result):
                """Subscribe the share after the local rescan."""
                volume = self.get_volume(share.volume_id)
                volume.local_rescanning = False
                self.store_volume(volume)
                return result

            # local and server rescan
            d = self._scan_share(share, scan_local=share.can_write())
            d.addCallback(subscribe)
        else:
            # don't scan the share (not subscribed or read_only)
            d = defer.succeed(None)

        if is_new_share:
            # push the event only if it's a new share
            self.m.event_q.push('VM_SHARE_CREATED', share_id=share.volume_id)

        return d

    def update_free_space(self, volume_id, free_bytes):
        """Update free space for a given share."""
        if volume_id in self.shares:
            share = self.shares[volume_id]
            share.free_bytes = free_bytes
            self.shares[volume_id] = share
        elif volume_id in self.udfs:
            root = self.shares[request.ROOT]
            root.free_bytes = free_bytes
            self.shares[request.ROOT] = root
        else:
            self.log.warning("Update of free space requested, but there is "
                             "no such volume_id: %s", volume_id)
            self.refresh_volumes()

    # same functionality, but other name to be called by EventQueue
    handle_SYS_QUOTA_EXCEEDED = update_free_space

    def get_free_space(self, volume_id):
        """Return the free_space for volume_id.

        If there is no such volume_id in the udfs or shares metadata,
        return 0.
        """
        if volume_id in self.shares:
            share = self.shares[volume_id]
            return share.free_bytes
        elif volume_id in self.udfs:
            root = self.shares[request.ROOT]
            return root.free_bytes
        else:
            self.log.warning("Requested free space of volume_id: %s, but"
                             " there is no such volume.", volume_id)
            self.refresh_volumes()
            return 0

    def accept_share(self, share_id, answer):
        """ Calls AQ.accept_share with answer ('Yes'/'No')."""
        self.log.debug("Accept share, with id: %s - answer: %s ",
                       share_id, answer)
        share = self.shares[share_id]
        share.accepted = answer
        self.shares[share_id] = share
        answer_str = "Yes" if answer else "No"
        self.m.action_q.answer_share(share_id, answer_str)

    def share_deleted(self, share_id):
        """ process the share deleted event. """
        self.log.debug("Share (id: %s) deleted. ", share_id)
        share = self.shares.get(share_id, None)
        if share is None:
            # we don't have this share, ignore it and don't refresh
            self.log.warning("Got a share deleted notification (%r), "
                             "but don't have the share", share_id)
        else:
            if share.can_write():
                self._remove_watches(share.path)
            self._delete_fsm_object(share.path)
            del self.shares[share_id]
            self.m.event_q.push('VM_VOLUME_DELETED', volume=share)

    def share_changed(self, share_holder):
        """Process the share changed event."""
        # the holder id is a uuid, use the str
        share = self.shares.get(str(share_holder.share_id), None)
        if share is None:
            # we don't have this share, refresh volumes
            self.log.warning("Got a share changed notification (%r), "
                             "but don't have the share", share_holder.share_id)
            self.refresh_volumes()
        else:
            share.access_level = share_holder.access_level
            self.shares[share.volume_id] = share
            self.m.event_q.push('VM_SHARE_CHANGED', share_id=share.volume_id)

    @defer.inlineCallbacks
    def _create_share_dir(self, share):
        """ Creates the share root dir, and set the permissions. """
        # XXX: verterok: This is going to be moved into fsm
        # if the share don't exists, create it
        if not path_exists(share.path):
            with allow_writes(os.path.dirname(share.path)):
                make_dir(share.path)
        # add the watch after the mkdir
        if share.can_write():
            self.log.debug('adding inotify watch to: %s', share.path)
            yield self._add_watch(share.path)
        # if it's a ro share, change the perms
        if not share.can_write():
            set_dir_readonly(share.path)

    def _create_udf_dir(self, udf):
        """Create the udf dir if does not exist."""
        if not path_exists(udf.path):
            # the udf path isn't there, create it!
            make_dir(udf.path, recursive=True)

    def _create_volume_dir(self, volume):
        """Create the volume dir if does not exist, set perms for shares."""
        if isinstance(volume, (Share, Root)):
            self._create_share_dir(volume)
        elif isinstance(volume, UDF):
            self._create_udf_dir(volume)

    def _create_fsm_object(self, path, volume_id, node_id):
        """ Creates the mdobj for this share in fs manager. """
        try:
            self.m.fs.get_by_path(path)
        except KeyError:
            self.m.fs.create(path=path, share_id=volume_id, is_dir=True)
            self.m.fs.set_node_id(path, node_id)

    def _delete_fsm_object(self, path):
        """Deletes the share and it files/folders metadata from fsm."""
        # XXX: partially implemented, this should be moved into fsm?.
        # should delete all the files in the share?
        # delete all the metadata but dont touch the files/folders
        for a_path, _ in self.m.fs.get_paths_starting_with(path):
            self.m.fs.delete_metadata(a_path)

    def _add_watch(self, path):
        """Add a inotify watch to path."""
        return self.m.event_q.add_watch(path)

    def _remove_watch(self, path):
        """Remove the inotify watch from path."""
        try:
            self.m.event_q.rm_watch(path)
        except (ValueError, RuntimeError, TypeError, KeyError), e:
            # pyinotify has an ugly error management, if we can call
            # it that, :(. We handle this here because it's possible
            # and correct that the path is not there anymore
            self.log.warning("Error %s when trying to remove the watch"
                             " on %r", e, path)

    def _remove_watches(self, path):
        """Remove the inotify watches from path and it subdirs."""
        for a_path, is_dir in self.m.fs.get_paths_starting_with(path):
            if is_dir:
                self._remove_watch(a_path)

    def create_share(self, path, username, name, access_level):
        """ create a share for the specified path, username, name """
        self.log.debug('create share(%r, %r, %r, %r)',
                       path, username, name, access_level)
        mdobj = self.m.fs.get_by_path(path)
        mdid = mdobj.mdid
        marker = MDMarker(mdid)
        if mdobj.node_id is None:
            # we don't have the node_id yet, use the marker instead
            node_id = marker
        else:
            node_id = mdobj.node_id
        abspath = self.m.fs.get_abspath(mdobj.share_id, mdobj.path)
        share = Shared(path=abspath, volume_id=marker,
                       name=name, access_level=access_level,
                       other_username=username, other_visible_name=None,
                       node_id=node_id)
        self.marker_share_map[marker] = share
        # XXX: unicode boundary! username, name should be unicode
        self.m.action_q.create_share(node_id, username, name,
                                     access_level, marker, abspath)

    def delete_share(self, share_id):
        """Reuqest the deletion of an offered share."""
        share = self.shared.get(share_id)
        if share is None:
            # if the share isn't there, push the error!
            self.m.event_q.push('VM_SHARE_DELETE_ERROR',
                                share_id=share_id, error="DOES_NOT_EXIST")
        else:
            self.m.action_q.delete_share(share_id)

    def add_shared(self, share):
        """ Add a share with direction == from_me """
        self.log.info('New shared subtree: id: %s - path: %r',
                      share.volume_id, share.path)
        current_share = self.shared.get(share.volume_id)
        if current_share is None:
            self.shared[share.volume_id] = share
        else:
            for k in share.__dict__:
                setattr(current_share, k, getattr(share, k))
            self.shared[share.volume_id] = current_share

    def add_udf(self, udf):
        """Add the udf to the VM metadata if isn't there.

        If it's a new udf, create the directory, hook inotify
        and request the full delta.

        """
        self.log.debug('add_udf: %s', udf)
        if self.udfs.get(udf.volume_id, None) is None:
            self.log.debug('add_udf: udf not in metadata, adding it!')
            # if it's a new UDF set the generation to None to force a rescan
            udf.generation = None
            self.udfs[udf.volume_id] = udf
            self._create_fsm_object(udf.path, udf.volume_id, udf.node_id)
            # local and server rescan, this will add the inotify hooks
            # to the udf root dir and any child directory.
            if udf.subscribed:
                self.log.debug('add_udf: volume subscribed, '
                               'temporarly unsubscribe to do local rescan.')
                udf.local_rescanning = True
                self.udfs[udf.volume_id] = udf
                if not path_exists(udf.path):
                    make_dir(udf.path, recursive=True)

                def subscribe(result):
                    """Subscribe the UDF after the local rescan.

                    As we don't wait for server rescan to finish, the udf is
                    subscribed just after the local rescan it's done.

                    """
                    volume = self.get_volume(udf.volume_id)
                    volume.local_rescanning = False
                    self.store_volume(volume)
                    return result

                d = self._scan_udf(udf)
                d.addCallback(subscribe)
            else:
                # don't scan the udf as we are not subscribed to it
                d = defer.succeed(None)

            d.addCallback(
                lambda _: self.m.event_q.push(
                    'VM_UDF_CREATED', udf=self.get_volume(udf.volume_id)))
            return d

    def udf_deleted(self, udf_id):
        """Delete the UDF from the VM and filesystem manager metadata"""
        self.log.info('udf_deleted: %r', udf_id)
        try:
            udf = self.udfs[udf_id]
        except KeyError:
            self.log.exception("UDF with id: %r does not exists", udf_id)
            raise
        # remove the watches
        self._remove_watches(udf.path)
        self._delete_fsm_object(udf.path)
        # remove the udf from VM metadata
        del self.udfs[udf_id]
        self.m.event_q.push('VM_VOLUME_DELETED', volume=udf)

    def get_volume(self, volume_id):
        """Returns the Share or UDF with the matching id."""
        volume = self.shares.get(volume_id, None)
        if volume is None:
            volume = self.udfs.get(volume_id, None)
        if volume is None:
            raise VolumeDoesNotExist(volume_id)
        return volume

    def get_volumes(self, all_volumes=False):
        """Return a generator for the list of 'active' volumes.

        This list contains subscribed UDFs and accepted Shares.

        """
        volumes = itertools.chain(self.shares.values(), self.udfs.values())
        for volume in volumes:
            if all_volumes or volume.active:
                yield volume

    def store_volume(self, volume):
        """Store 'volume'."""
        if isinstance(volume, (Share, Root)):
            self.shares[volume.volume_id] = volume
        elif isinstance(volume, UDF):
            self.udfs[volume.volume_id] = volume

    def _is_nested_udf(self, path):
        """Check if it's ok to create a UDF in 'path'.

        Check if path is child or ancestor of another UDF or if
        it's inside the root.

        """
        new_path = path + os.path.sep
        volumes = itertools.chain(
            [self.shares[request.ROOT]], self.udfs.values())
        for volume in volumes:
            vol_path = volume.path + os.path.sep
            if new_path.startswith(vol_path) or vol_path.startswith(new_path):
                return True
        return False

    def validate_path_for_folder(self, path):
        """Validate 'folder_path' for folder creation."""
        path = normpath(path)
        user_home = expand_user('~')
        # handle folder_path not within '~'
        if not path.startswith(user_home):
            return (False, "UDFs must be within home")

        # check if path is the realpath, bail out if not
        if is_link(path):
            return (False, "UDFs can not be a symlink")

        # check if path exists but is not a directory
        if path_exists(path) and not os.path.isdir(path):
            return (False, "The path exists but is not a folder")

        # check if the path it's ok (outside root and
        # isn't a ancestor or child of another UDF)
        if self._is_nested_udf(path):
            return (False, "UDFs can not be nested")

        return (True, "")

    def create_udf(self, path):
        """Request the creation of a UDF to AQ."""
        self.log.debug('create udf: %r', path)
        valid, msg = self.validate_path_for_folder(path)
        if not valid:
            self.m.event_q.push('VM_UDF_CREATE_ERROR', path=path, error=msg)
            return

        try:
            suggested_path = get_udf_suggested_path(path)
        except ValueError, e:
            self.m.event_q.push('VM_UDF_CREATE_ERROR', path=path,
                                error="INVALID_PATH: %s" % (e,))
        else:
            try:
                marker = MDMarker(path)
                if marker in self.marker_udf_map:
                    # ignore this request
                    self.log.warning('Duplicated create_udf request for '
                                     'path (ingoring it!): %r', path)
                    return
                udf = UDF(volume_id=None, node_id=None,
                          suggested_path=suggested_path,
                          # always subscribed since it's a local request
                          path=path, subscribed=True)
                self.marker_udf_map[marker] = udf
                # XXX: unicode boundary! parameters should be unicode
                server_path, udf_name = suggested_path.rsplit(u'/', 1)
                self.m.action_q.create_udf(server_path, udf_name, marker)
            except Exception, e:
                self.m.event_q.push('VM_UDF_CREATE_ERROR', path=path,
                                    error="UNKNOWN_ERROR: %s" % (e,))

    def delete_volume(self, volume_id):
        """Request the deletion of a volume to AQ.

        if volume_id isn't in the shares or udfs shelf a KeyError is raised

        """
        self.log.info('delete_volume: %r', volume_id)
        volume = self.get_volume(volume_id)
        self.m.action_q.delete_volume(volume.id, volume.path)

    def subscribe_share(self, share_id):
        """Mark the Share with 'share_id' as subscribed.

        Also fire a local and server rescan.

        """

        def push_success(volume):
            return self.m.event_q.push('VM_SHARE_SUBSCRIBED', share=volume)

        push_error = functools.partial(
            self.m.event_q.push, 'VM_SHARE_SUBSCRIBE_ERROR', share_id=share_id)
        self.log.info('subscribe_share: %r', share_id)
        d = self._subscribe_volume(share_id, push_success, push_error)
        return d

    def subscribe_udf(self, udf_id):
        """Mark the UDF with 'udf_id' as subscribed.

        Also fire a local and server rescan.

        """

        def push_success(volume):
            return self.m.event_q.push('VM_UDF_SUBSCRIBED', udf=volume)

        push_error = functools.partial(self.m.event_q.push,
                                       'VM_UDF_SUBSCRIBE_ERROR', udf_id=udf_id)
        self.log.info('subscribe_udf: %r', udf_id)
        d = self._subscribe_volume(udf_id, push_success, push_error)
        return d

    def _subscribe_volume(self, volume_id, push_success, push_error):
        """Mark the volume with 'volume_id' as subscribed.

        If can_write(), fire a local and server rescan while temporary
        unsubscribing from it.

        """
        self.log.debug('_subscribe_volume: %r', volume_id)
        try:
            volume = self.get_volume(volume_id)
        except VolumeDoesNotExist, e:
            push_error(error="DOES_NOT_EXIST")
            return defer.fail(e)

        self._create_volume_dir(volume)

        def subscribe(result):
            """Subscribe the volume after the local rescan.

            As we don't wait for server rescan to finish, the volume is
            subscribed just after the local rescan it's done.

            """
            volume = self.get_volume(volume_id)
            volume.local_rescanning = False
            self.store_volume(volume)
            return result

        try:
            volume.subscribed = True
            volume.local_rescanning = True
            self.store_volume(volume)
            d = self._scan_volume(volume, scan_local=volume.can_write())
        except KeyError, e:
            push_error(error="METADATA_DOES_NOT_EXIST")
            return defer.fail(e)

        def handle_failure(failure):
            """Push error and propagate the failure."""
            push_error(error=failure.type)
            return failure

        d.addCallback(subscribe)
        d.addCallbacks(lambda _: push_success(self.get_volume(volume_id)),
                       handle_failure)
        return d

    def _scan_udf(self, udf):
        """Local and server rescan of a UDF."""
        self.log.debug('_scan_udf: %r.', udf)
        return self._scan_volume(udf)

    def _scan_share(self, share, scan_local=True):
        """Local and server rescan of a Share."""
        self.log.debug('_scan_share: %r.', share)
        return self._scan_volume(share, scan_local)

    @defer.inlineCallbacks
    def _scan_volume(self, volume, scan_local=True):
        """Local and server rescan of a volume."""
        self.log.debug('_scan_volume: %r (scan_local %r).', volume, scan_local)
        if scan_local:
            mdobj = self.m.fs.get_by_path(volume.path)
            yield self.m.lr.scan_dir(mdobj.mdid, volume.path, udfmode=True)
            self.log.debug('_scan_volume: local_rescan.scan_dir is done.')

        # Request the delta from the last known generation, but don't wait for
        # the command to finish.
        self.m.action_q.rescan_from_scratch(volume.volume_id)

    def unsubscribe_share(self, share_id):
        """Mark the share with share_id as unsubscribed."""

        def push_success(volume):
            return self.m.event_q.push('VM_SHARE_UNSUBSCRIBED', share=volume)

        push_error = functools.partial(
            self.m.event_q.push, 'VM_SHARE_UNSUBSCRIBE_ERROR',
            share_id=share_id)
        self.log.info('unsubscribe_share: %r', share_id)
        self._unsubscribe_volume(share_id, push_success, push_error)

    def unsubscribe_udf(self, udf_id):
        """Mark the UDF with udf_id as unsubscribed."""

        def push_success(volume):
            return self.m.event_q.push('VM_UDF_UNSUBSCRIBED', udf=volume)

        push_error = functools.partial(
            self.m.event_q.push, 'VM_UDF_UNSUBSCRIBE_ERROR', udf_id=udf_id)
        self.log.info('unsubscribe_udf: %r', udf_id)
        self._unsubscribe_volume(udf_id, push_success, push_error)

    def _unsubscribe_volume(self, volume_id, push_success, push_error):
        """Mark the volume with volume_id as unsubscribed."""
        self.log.debug('unsubscribe_volume: %r', volume_id)
        try:
            volume = self.get_volume(volume_id)
        except VolumeDoesNotExist:
            push_error(error="DOES_NOT_EXIST")
        else:
            # remove the inotify watches, but don't delete the metadata
            self._remove_watches(volume.path)
            # mark the volume as unsubscribed
            volume.subscribed = False
            self.store_volume(volume)
            push_success(volume)

    def handle_AQ_CREATE_UDF_OK(self, marker, volume_id, node_id):
        """Handle AQ_CREATE_UDF_OK."""
        udf = self.marker_udf_map.pop(marker)
        udf.volume_id = str(volume_id)
        udf.node_id = str(node_id)
        self.add_udf(udf)

    def handle_AQ_CREATE_UDF_ERROR(self, marker, error):
        """Handle AQ_CREATE_UDF_ERROR."""
        udf = self.marker_udf_map.pop(marker)
        self.m.event_q.push('VM_UDF_CREATE_ERROR',
                            path=udf.path, error=str(error))

    def handle_AQ_DELETE_VOLUME_OK(self, volume_id):
        """Handle AQ_DELETE_VOLUME_OK."""
        self._handle_deleted_volume(volume_id)

    def handle_AQ_DELETE_VOLUME_ERROR(self, volume_id, error):
        """Handle AQ_DELETE_VOLUME_ERROR."""
        try:
            self.get_volume(str(volume_id))
        except VolumeDoesNotExist:
            # wasn't able to delete a volume that we don't have any
            # more, we better refresh everything
            self.log.warning("Received a AQ_DELETE_VOLUME_ERROR of a missing "
                             "volume id")
            self.refresh_volumes()
        else:
            self.m.event_q.push('VM_VOLUME_DELETE_ERROR',
                                volume_id=volume_id, error=str(error))

    def handle_SV_VOLUME_CREATED(self, volume):
        """Handle SV_VOLUME_CREATED event."""
        self._handle_new_volume(volume)

    def handle_SV_VOLUME_DELETED(self, volume_id):
        """Handle SV_VOLUME_DELETED event."""
        self._handle_deleted_volume(volume_id)

    def _handle_deleted_volume(self, volume_id):
        """Handle a deleted volume.

        Call the specific method to
        handle this volume type (share/udf/root).

        """
        volume = self.get_volume(str(volume_id))
        if isinstance(volume, Share):
            self.log.debug('share deleted! %s', volume.id)
            self.share_deleted(volume.id)
        elif isinstance(volume, UDF):
            self.log.debug('udf deleted! %s', volume.id)
            self.udf_deleted(volume.id)
        else:
            # just log, don't care we don't have something we should
            # delete anyway
            self.log.warning("Tried to delete a missing volume id: %s",
                             volume_id)

    def update_generation(self, volume_id, generation):
        """Update the generation of the specified volume."""
        self.log.debug('update_generation: %r, %r', volume_id, generation)
        vol = self.get_volume(volume_id)
        vol.generation = generation
        if isinstance(vol, (Share, Root)):
            self.shares[volume_id] = vol
        elif isinstance(vol, UDF):
            self.udfs[volume_id] = vol


class MetadataUpgrader(object):
    """A class that loads old metadata and migrate it."""

    def __init__(self, data_dir, shares_md_dir, shared_md_dir, udfs_md_dir,
                 root_dir, shares_dir, shares_dir_link, tritcask_db):
        """Creates the instance"""
        self.log = logging.getLogger('ubuntuone.SyncDaemon.VM.MD')
        self._data_dir = data_dir
        self._shares_dir = shares_dir
        self._shares_md_dir = shares_md_dir
        self._shared_md_dir = shared_md_dir
        self._udfs_md_dir = udfs_md_dir
        self._root_dir = root_dir
        self._shares_dir_link = shares_dir_link
        self.db = tritcask_db
        self._version_file = os.path.join(self._data_dir, '.version')
        self.md_version = self._get_md_version()

    def upgrade_metadata(self):
        """Upgrade the metadata (only if it's needed)"""
        # upgrade the metadata
        if self.md_version != VolumeManager.METADATA_VERSION:
            upgrade_method = getattr(
                self, "_upgrade_metadata_%s" % self.md_version)
            upgrade_method(self.md_version)

    def _get_md_version(self):
        """Returns the current md_version"""
        if not path_exists(self._data_dir):
            # first run, the data dir don't exist. No metadata to upgrade
            md_version = VolumeManager.METADATA_VERSION
            make_dir(self._data_dir, recursive=True)
            self.update_metadata_version()
        elif path_exists(self._version_file):
            with open_file(self._version_file) as fh:
                md_version = fh.read().strip()
            if not md_version:
                # we don't have a version of the metadata but a .version file?
                # assume it's None and do an upgrade from version 0
                md_version = self._guess_metadata_version()
        else:
            md_version = self._guess_metadata_version()
        self.log.debug('metadata version: %s', md_version)
        return md_version

    def update_metadata_version(self):
        """Write the version of the metadata."""
        if not path_exists(os.path.dirname(self._version_file)):
            make_dir(os.path.dirname(self._version_file), recursive=True)
        with open_file(self._version_file, 'w') as fd:
            fd.write(VolumeManager.METADATA_VERSION)
            # make sure the data get to disk
            fd.flush()
            os.fsync(fd.fileno())

    def _guess_metadata_version(self):
        """Try to guess the metadata version based on current metadata
        and layout, fallbacks to md_version = None if can't guess it.

        """
        md_version = None
        if path_exists(self._shares_md_dir) \
           and path_exists(self._shared_md_dir):
            # we have shares and shared dirs
            # md_version >= 1
            old_root_dir = os.path.abspath(
                os.path.join(self._root_dir, 'My Files'))
            old_share_dir = os.path.abspath(
                os.path.join(self._root_dir, 'Shared With Me'))
            if (path_exists(old_share_dir) and path_exists(old_root_dir) and
                    not is_link(old_share_dir)):
                # md >= 1 and <= 3
                # we have a My Files dir, 'Shared With Me' isn't a
                # symlink and ~/.local/share/ubuntuone/shares doesn't
                # exists.
                # md_version <= 3, set it to 2 as it will migrate
                # .conflict to .u1conflict, and we don't need to upgrade
                # from version 1 any more as the LegacyShareFileShelf
                # takes care of that.
                md_version = '2'
            else:
                try:
                    target = read_link(self._shares_dir_link)
                except OSError:
                    target = None
                abs_link = os.path.abspath(self._shares_dir_link)
                if (normpath(target) == abs_link and
                        is_link(self._shares_dir_link)):
                    # broken symlink, md_version = 4
                    md_version = '4'
                else:
                    # md_version >= 5
                    shelf = LegacyShareFileShelf(self._shares_md_dir)
                    # check a pickled value to check if it's in version
                    # 5 or 6
                    md_version = '5'
                    versions = {'5': 0, '6': 0}
                    for key in shelf:
                        share = shelf[key]
                        if isinstance(share, _Share):
                            versions['5'] += 1
                        else:
                            versions['6'] += 1
                    if versions['5'] > 0:
                        md_version = '5'
                    elif versions['6'] > 0:
                        md_version = '6'
        else:
            # this is metadata 'None'
            md_version = None
        return md_version

    def _upgrade_metadata_None(self, md_version):
        """Upgrade the shelf layout, for *very* old clients."""
        from ubuntuone.syncdaemon.volume_manager import LegacyShareFileShelf
        self.log.debug('Upgrading the share shelf layout')
        # the shelf already exists, and don't have a .version file
        # first backup the old data
        backup = os.path.join(self._data_dir, '0.bkp')
        if not path_exists(backup):
            make_dir(backup, recursive=True)

        def filter_known_dirs(d):
            """Filter 'shares' and 'shared' dirs.

            In case we are in the case of missing version but existing
            .version file.

            """
            shared_to_me = os.path.basename(self._shared_md_dir)
            shared_from_me = os.path.basename(self._shares_md_dir)
            return d != shared_from_me and d != shared_to_me

        for dirname, dirs, files in walk(self._data_dir):
            if dirname == self._data_dir:
                for dir in filter(filter_known_dirs, dirs):
                    if dir != os.path.basename(backup):
                        recursive_move(os.path.join(dirname, dir),
                                       os.path.join(backup, dir))
        # regenerate the shelf using the new layout using the backup as src
        old_shelf = LegacyShareFileShelf(backup)
        if not path_exists(self._shares_dir):
            make_dir(self._shares_dir, recursive=True)
        new_shelf = LegacyShareFileShelf(self._shares_md_dir)
        for key, share in old_shelf.iteritems():
            new_shelf[key] = share
        # now upgrade to metadata 2
        self._upgrade_metadata_2(md_version)

    def _upgrade_metadata_1(self, md_version):
        """Upgrade to version 2.

        Upgrade all pickled Share to the new package/module layout.

        """
        from ubuntuone.syncdaemon.volume_manager import LegacyShareFileShelf
        self.log.debug('upgrading share shelfs from metadata 1')
        shares = LegacyShareFileShelf(self._shares_md_dir)
        for key, share in shares.iteritems():
            shares[key] = share
        shared = LegacyShareFileShelf(self._shared_md_dir)
        for key, share in shared.iteritems():
            shared[key] = share
        # now upgrade to metadata 3
        self._upgrade_metadata_2(md_version)

    def _upgrade_metadata_2(self, md_version):
        """Upgrade to version 3

        Renames foo.conflict files to foo.u1conflict, foo.conflict.N
        to foo.u1conflict.N, foo.partial to .u1partial.foo, and
        .partial to .u1partial.

        """
        self.log.debug('upgrading from metadata 2 (bogus)')
        for top in self._root_dir, self._shares_dir:
            for dirpath, dirnames, filenames in walk(top):
                with allow_writes(dirpath):
                    for names in filenames, dirnames:
                        self._upgrade_names(dirpath, names)
        self._upgrade_metadata_3(md_version)

    def _upgrade_names(self, dirpath, names):
        """Do the actual renaming for _upgrade_metadata_2."""
        for pos, name in enumerate(names):
            new_name = name
            if re.match(r'.*\.partial$|\.u1partial(?:\..+)?', name):
                if name == '.partial':
                    new_name = '.u1partial'
                else:
                    new_name = re.sub(r'^(.+)\.partial$',
                                      r'.u1partial.\1', name)
                if new_name != name:
                    while os.path.lexists(os.path.join(dirpath, new_name)):
                        # very, very strange
                        self.log.warning('Found a .partial and .u1partial'
                                         ' for the same file: %s!', new_name)
                        new_name += '.1'
            elif re.search(r'\.(?:u1)?conflict(?:\.\d+)?$', name):
                new_name = re.sub(r'^(.+)\.conflict((?:\.\d+)?)$',
                                  r'\1.u1conflict\2', name)
                if new_name != name:
                    while os.path.lexists(os.path.join(dirpath, new_name)):
                        m = re.match(r'(.*\.u1conflict)((?:\.\d+)?)$',
                                     new_name)
                        base, num = m.groups()
                        if not num:
                            num = '.1'
                        else:
                            num = '.' + str(int(num[1:]) + 1)
                        new_name = base + num
            if new_name != name:
                old_path = os.path.join(dirpath, name)
                new_path = os.path.join(dirpath, new_name)
                self.log.debug('renaming %r to %r', old_path, new_path)
                rename(old_path, new_path)
                names[pos] = new_name

    def _upgrade_metadata_3(self, md_version):
        """Upgrade to version 4 (new layout!)

        move "~/<root>/Shared With Me" to XDG_DATA/<root>/shares
        move "~/<root>/My Files" contents to "~/<root>"

        """
        from ubuntuone.syncdaemon.volume_manager import LegacyShareFileShelf
        self.log.debug('upgrading from metadata 3 (new layout)')
        old_share_dir = os.path.join(self._root_dir, 'Shared With Me')
        old_root_dir = os.path.join(self._root_dir, 'My Files')
        # change permissions
        set_dir_readwrite(self._root_dir)

        def move(src, dst):
            """Move a file/dir taking care if it's read-only."""
            prev_mode = stat.S_IMODE(os.stat(src).st_mode)
            set_dir_readwrite(src)
            recursive_move(src, dst)
            os.chmod(dst, prev_mode)

        # update the path's in metadata and move the folder
        if path_exists(old_share_dir) and not is_link(old_share_dir):
            set_dir_readwrite(old_share_dir)
            if not path_exists(os.path.dirname(self._shares_dir)):
                make_dir(os.path.dirname(self._shares_dir), recursive=True)
            self.log.debug('moving shares dir from: %r to %r',
                           old_share_dir, self._shares_dir)
            for path in listdir(old_share_dir):
                src = os.path.join(old_share_dir, path)
                dst = os.path.join(self._shares_dir, path)
                move(src, dst)
            remove_dir(old_share_dir)

        # update the shares metadata
        shares = LegacyShareFileShelf(self._shares_md_dir)
        for key, share in shares.iteritems():
            if share.path is not None:
                if share.path == old_root_dir:
                    share.path = share.path.replace(old_root_dir,
                                                    self._root_dir)
                else:
                    share.path = share.path.replace(old_share_dir,
                                                    self._shares_dir)
                shares[key] = share

        shared = LegacyShareFileShelf(self._shared_md_dir)
        for key, share in shared.iteritems():
            if share.path is not None:
                share.path = share.path.replace(old_root_dir, self._root_dir)
            shared[key] = share
        # move the My Files contents, taking care of dir/files with the same
        # name in the new root
        if path_exists(old_root_dir):
            self.log.debug('moving My Files contents to the root')
            # make My Files rw
            set_dir_readwrite(old_root_dir)
            path_join = os.path.join
            for relpath in listdir(old_root_dir):
                old_path = path_join(old_root_dir, relpath)
                new_path = path_join(self._root_dir, relpath)
                if path_exists(new_path):
                    recursive_move(new_path, new_path + '.u1conflict')
                if relpath == 'Shared With Me':
                    # remove the Shared with Me symlink inside My Files!
                    self.log.debug('removing shares symlink from old root')
                    remove_file(old_path)
                else:
                    self.log.debug('moving %r to %r', old_path, new_path)
                    move(old_path, new_path)
            self.log.debug('removing old root: %r', old_root_dir)
            remove_dir(old_root_dir)

        # fix broken symlink (md_version 4)
        self._upgrade_metadata_4(md_version)

    def _upgrade_metadata_4(self, md_version):
        """Upgrade to version 5 (fix the broken symlink!)."""
        self.log.debug('upgrading from metadata 4 (broken symlink!)')
        if is_link(self._shares_dir_link):
            target = read_link(self._shares_dir_link)
            if normpath(target) == self._shares_dir_link:
                # the symnlink points to itself
                self.log.debug('removing broken shares symlink: %r -> %r',
                               self._shares_dir_link, target)
                remove_file(self._shares_dir_link)
        self._upgrade_metadata_5(md_version)

    def _upgrade_metadata_5(self, md_version):
        """Upgrade to version 6 (plain dict storage)."""
        from ubuntuone.syncdaemon.volume_manager import (
            VMFileShelf, LegacyShareFileShelf, UDF)
        self.log.debug('upgrading from metadata 5')
        bkp_dir = os.path.join(os.path.dirname(self._data_dir), '5.bkp')
        new_md_dir = os.path.join(os.path.dirname(self._data_dir), 'md_6.new')
        new_shares_md_dir = os.path.join(new_md_dir, 'shares')
        new_shared_md_dir = os.path.join(new_md_dir, 'shared')
        new_udfs_md_dir = os.path.join(new_md_dir, 'udfs')
        try:
            # upgrade shares
            old_shares = LegacyShareFileShelf(self._shares_md_dir)
            shares = VMFileShelf(new_shares_md_dir)
            for key, share in old_shares.iteritems():
                shares[key] = self._upgrade_share_to_volume(share)
            # upgrade shared folders
            old_shared = LegacyShareFileShelf(self._shared_md_dir)
            shared = VMFileShelf(new_shared_md_dir)
            for key, share in old_shared.iteritems():
                shared[key] = self._upgrade_share_to_volume(share, shared=True)
            # upgrade the udfs
            old_udfs = LegacyShareFileShelf(self._udfs_md_dir)
            udfs = VMFileShelf(new_udfs_md_dir)
            for key, udf in old_udfs.iteritems():
                udfs[key] = UDF(udf.id, udf.node_id, udf.suggested_path,
                                udf.path, udf.subscribed)
            # move md dir to bkp
            rename(self._data_dir, bkp_dir)
            # move new to md dir
            rename(new_md_dir, self._data_dir)
            self._upgrade_metadata_6(md_version)
        except Exception:
            # something bad happend, remove partially upgraded metadata
            remove_tree(new_md_dir)
            raise

    def _upgrade_share_to_volume(self, share, shared=False):
        """Upgrade from _Share to new Volume hierarchy."""
        from ubuntuone.syncdaemon.volume_manager import (
            VMFileShelf, Root, Share, Shared)

        def upgrade_share_dict(share):
            """Upgrade share __dict__ to be compatible with the
            new Share.__init__.

            """
            if 'subtree' in share.__dict__:
                share.node_id = share.__dict__.pop('subtree')
            if 'id' in share.__dict__:
                share.volume_id = share.__dict__.pop('id')
            if 'free_bytes' in share.__dict__:
                share.free_bytes = share.__dict__.pop('free_bytes')
            else:
                share.free_bytes = None
            return share

        if isinstance(share, dict):
            # oops, we have mixed metadata. fix it!
            clazz = VMFileShelf.classes[share[VMFileShelf.TYPE]]
            share_dict = share.copy()
            del share_dict[VMFileShelf.TYPE]
            return clazz(**share_dict)
        elif share.path == self._root_dir or share.id == '':
            # handle the root special case
            return Root(volume_id=request.ROOT,
                        node_id=share.subtree, path=share.path)
        else:
            share = upgrade_share_dict(share)
            if shared:
                return Shared(**share.__dict__)
            else:
                return Share(**share.__dict__)

    def _upgrade_metadata_6(self, md_version):
        """Upgrade to version 7, tritcask!."""
        from ubuntuone.syncdaemon.volume_manager import (
            VMFileShelf, VMTritcaskShelf,
            SHARE_ROW_TYPE, SHARED_ROW_TYPE, UDF_ROW_TYPE,
        )
        self.log.debug('upgrading from metadata 6')
        old_shares = VMFileShelf(self._shares_md_dir)
        old_shared = VMFileShelf(self._shared_md_dir)
        old_udfs = VMFileShelf(self._udfs_md_dir)
        shares = VMTritcaskShelf(SHARE_ROW_TYPE, self.db)
        shared = VMTritcaskShelf(SHARED_ROW_TYPE, self.db)
        udfs = VMTritcaskShelf(UDF_ROW_TYPE, self.db)
        for share_id, share in old_shares.iteritems():
            shares[share_id] = share
        for share_id, share in old_shared.iteritems():
            shared[share_id] = share
        for udf_id, udf in old_udfs.iteritems():
            udfs[udf_id] = udf
        # update the metadata version
        self.update_metadata_version()
        # now delete the old metadata
        remove_tree(self._shares_md_dir)
        remove_tree(self._shared_md_dir)
        remove_tree(self._udfs_md_dir)


class VMFileShelf(file_shelf.CachedFileShelf):
    """Custom file shelf.

    Allow request.ROOT as key, it's replaced by the string: root_node_id.

    """

    TYPE = 'type'
    classes = dict(
        (sub.__name__, sub)
        for sub in Volume.__subclasses__() + Share.__subclasses__())

    def __init__(self, *args, **kwargs):
        """Create the instance."""
        super(VMFileShelf, self).__init__(*args, **kwargs)
        self.key = 'root_node_id'

    def key_file(self, key):
        """Override default key_file, to handle key == request.ROOT."""
        if key == request.ROOT:
            key = self.key
        return super(VMFileShelf, self).key_file(key)

    def keys(self):
        """Override default keys, to handle key == request.ROOT."""
        for key in super(VMFileShelf, self).keys():
            if key == self.key:
                yield request.ROOT
            else:
                yield key

    def _unpickle(self, fd):
        """Custom _unpickle.

        Unpickle a dict and build the class instance specified in
        value['type'].

        """
        value = cPickle.load(fd)
        class_name = value[self.TYPE]
        clazz = self.classes[class_name]
        obj = clazz.__new__(clazz)
        obj.__dict__.update(value)
        return obj

    def _pickle(self, value, fd, protocol):
        """Pickle value in fd using protocol."""
        cPickle.dump(value.__dict__, fd, protocol=protocol)


class LegacyShareFileShelf(VMFileShelf):
    """A FileShelf capable of replacing pickled classes with a different class.

    upgrade_map attribute is a dict of (module, name):class

    """

    upgrade_map = {
        ('ubuntuone.syncdaemon.volume_manager', 'UDF'): _UDF,
        ('ubuntuone.syncdaemon.volume_manager', 'Share'): _Share,
        ('canonical.ubuntuone.storage.syncdaemon.volume_manager',
         'Share'): _Share,
    }

    def _find_global(self, module, name):
        """Returns the class object for (module, name) or None."""
        # handle our 'migration types'
        if (module, name) in self.upgrade_map:
            return self.upgrade_map[(module, name)]
        else:
            # handle all other types
            __import__(module)
            return getattr(sys.modules[module], name)

    def _unpickle(self, fd):
        """Override _unpickle with one capable of migrating pickled classes."""
        unpickler = cPickle.Unpickler(fd)
        unpickler.find_global = self._find_global
        value = unpickler.load()
        return value

    def _pickle(self, value, fd, protocol):
        """Pickle value in fd using protocol."""
        cPickle.dump(value, fd, protocol=protocol)


class VMTritcaskShelf(TritcaskShelf):
    """Custom Tritcask shelf that allow request.ROOT as key.

    The request.ROOT it's replaced by the string: root_node_id.
    """

    TYPE = 'type'
    classes = dict(
        (sub.__name__, sub)
        for sub in Volume.__subclasses__() + Share.__subclasses__())

    def __init__(self, *args, **kwargs):
        """Create the instance."""
        super(VMTritcaskShelf, self).__init__(*args, **kwargs)
        self._root_key = 'root_node_id'

    def _get_key(self, key):
        """Return the 'real' key to use.

        In the case of request.ROOT return self._root_key.
        """
        if key == request.ROOT:
            return self._root_key
        else:
            return key

    def __getitem__(self, key):
        """dict protocol."""
        return super(VMTritcaskShelf, self).__getitem__(self._get_key(key))

    def __setitem__(self, key, value):
        """dict protocol."""
        super(VMTritcaskShelf, self).__setitem__(self._get_key(key), value)

    def __delitem__(self, key):
        """dict protocol."""
        super(VMTritcaskShelf, self).__delitem__(self._get_key(key))

    def __contains__(self, key):
        """dict protocol."""
        return super(VMTritcaskShelf, self).__contains__(self._get_key(key))

    def keys(self):
        """Override default keys, to handle key == request.ROOT."""
        for key in super(VMTritcaskShelf, self).keys():
            if key == self._root_key:
                yield request.ROOT
            else:
                yield key

    def _deserialize(self, pickled_value):
        """Custom _deserialize.

        Unpickle a dict and build the class instance specified in
        value['type'].
        """
        value = cPickle.loads(pickled_value)
        class_name = value[self.TYPE]
        clazz = self.classes[class_name]
        obj = clazz.__new__(clazz)
        obj.__dict__.update(value)
        return obj

    def _serialize(self, value):
        """Serialize value to string using protocol."""
        return cPickle.dumps(value.__dict__, protocol=2)
