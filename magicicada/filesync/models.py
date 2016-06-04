# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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

"""The Storage database model."""

from __future__ import unicode_literals

import os
import posixpath
import uuid

from types import NoneType

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import DataError, models, transaction
from django.db.models.functions import Concat, Substr
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils.timezone import now

from magicicada.filesync import utils
from magicicada.filesync.errors import (
    DirectoriesHaveNoContent,
    InvalidFilename,
    NoPermission,
    NotADirectory,
    NotEmpty,
    QuotaExceeded,
)
from magicicada.filesync.managers import (
    ROOT_NAME,
    ROOT_PARENT,
    STATUS_LIVE,
    STATUS_DEAD,
    DownloadManager,
    MoveFromShareManager,
    ShareManager,
    StorageObjectManager,
    StorageUserManager,
    UserVolumeManager,
    validate_name,
    validate_volume_path,
)
from magicicada.filesync.signals import (
    content_changed,
    node_moved,
    post_kill,
    post_unlink_tree,
    pre_kill,
    pre_unlink_tree,
    public_access_changed,
)


DEFAULT_QUOTA_GIGAS = 20
DEFAULT_QUOTA_BYTES = DEFAULT_QUOTA_GIGAS * (1024 ** 4)

# lifecycle constants
LIFECYCLE_STATUS_CHOICES = (
    (STATUS_DEAD, STATUS_DEAD),
    (STATUS_LIVE, STATUS_LIVE),
)


class StorageUser(AbstractUser):
    """StorageUsers that the storage system is aware of."""

    email_notification = models.BooleanField(default=False)
    active_from = models.DateTimeField(default=now)
    active_until = models.DateTimeField(blank=True, null=True)

    # locked flag
    locked = models.BooleanField(default=False)

    # the storage quota
    max_storage_bytes = models.BigIntegerField(default=DEFAULT_QUOTA_BYTES)

    # used storage bytes
    used_storage_bytes = models.BigIntegerField(default=0)

    objects = StorageUserManager()

    def __init__(self, *args, **kwargs):
        self.session_id = kwargs.pop('session_id', None)
        super(StorageUser, self).__init__(*args, **kwargs)

    @property
    def volumes(self):
        return self.uservolume_set.filter(status=STATUS_LIVE)

    @property
    def root_node(self):
        return StorageObject.objects.select_related('volume').get(
            name=ROOT_NAME, volume__owner__id=self.id,
            volume__path=settings.ROOT_USERVOLUME_PATH)

    @property
    def free_bytes(self):
        """Return the free bytes."""
        return max(0, self.max_storage_bytes - self.used_bytes)

    @property
    def used_bytes(self):
        """Return the used bytes."""
        return StorageObject.objects.calculate_size_by_owner(self)

    def get_storage_stats(self):
        """Return a storage_stats (max_storage_bytes, used_storage_bytes)."""
        return self.max_storage_bytes, self.used_storage_bytes

    def update_used_bytes(self, difference, enforce_quota=True):
        """Adjusts used bytes based on the difference.

        @param difference: change in size

        A negative difference is passed when files are deleted or reduced
        in size. A possitive difference passed when a file is added or
        increased in size.
        """
        if difference == 0:
            return

        new_value = self.used_storage_bytes + difference
        if (difference > 0 and new_value > self.max_storage_bytes and
                enforce_quota):
            raise QuotaExceeded(
                'User %s exceeds quota by %s bytes (used: %s, max: %s)' %
                (self.id, new_value - self.max_storage_bytes,
                 self.used_storage_bytes, self.max_storage_bytes))

        if new_value < 0:
            # XXX: log warning!
            new_value = 0

        self.used_storage_bytes = new_value
        self.save(update_fields=['used_storage_bytes'])

    def recalculate_used_bytes(self):
        """Recalculate the used bytes for this user."""
        result = StorageObject.objects.calculate_size_by_owner(self)
        self.used_storage_bytes = result
        self.save(update_fields=['used_storage_bytes'])
        return self.used_storage_bytes

    def undelete_volume(self, volume_id, restore_parent, limit=100):
        """Undelete all the files the user ever deleted on this volume.

        In this case, everything will be restored to a directory structure
        under restore_parent.

        """
        if volume_id is None:
            root = StorageObject.objects.get_root(self)
        else:
            root = UserVolume.objects.get(id=volume_id).root_node

        path = ""
        # find deleted order by path to make sure directories are created in
        # the correct order
        deleted = StorageObject.objects.filter(
            volume__id=root.volume.id, status=STATUS_DEAD,
            kind=StorageObject.FILE).order_by('-when_last_modified')

        if deleted.exists():
            parent = restore_parent.build_tree_from_path(path)
            for d in deleted[:limit]:
                leaf = parent.build_tree_from_path(d.path)
                d.undelete(leaf)
            root.when_last_modified = now()
            root.save(update_fields=['when_last_modified'])
            return parent


class ContentBlob(models.Model):
    """Associates a hash with a specific storage key."""

    # The hash for the raw file content represented by this record.
    hash = models.BinaryField(primary_key=True)

    # The crc32 for the raw file content represented by this record.
    crc32 = models.BigIntegerField(default=0)

    # The size of the raw file content represented by this record, in bytes.
    size = models.BigIntegerField(default=0)

    # The content key which references the deflated file contents,
    # or NULL if it has been garbage collected.
    storage_key = models.UUIDField(null=True)

    # The deflated size of the file content as stored or NULL if inapplicable.
    deflated_size = models.BigIntegerField(null=True)

    # The file content as a raw byte string, or else NULL.
    # Used for symlinks and potentially sufficiently small files.
    content = models.BinaryField(null=True)

    # Whether this content entry is live, or else a candidate for
    # garbage collection.
    status = models.CharField(
        max_length=128, choices=LIFECYCLE_STATUS_CHOICES, default=STATUS_LIVE)

    # The magic hash of the content
    magic_hash = models.BinaryField(null=True)

    # timestamp at which the blob was first created
    when_created = models.DateTimeField(default=now)


class BaseStorageObject(models.Model):
    """A file, directory, or symbolic link.

    Files or symbolic links refer to ContentBlob for their contents.

    """

    # object kind constants
    FILE = 'File'
    DIRECTORY = 'Directory'
    SYMLINK = 'Symlink'
    OBJECT_KIND_CHOICES = (
        (FILE, FILE),
        (DIRECTORY, DIRECTORY),
        (SYMLINK, SYMLINK),
    )

    # A unique identifier for the file, corresponding roughly in
    # function to an inode number.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    # The directory node containing the object, or NULL if the object is
    # a volume root (only directories should be volume roots).
    parent = models.ForeignKey('self', related_name='children', null=True)

    # The UserVolume containing this object, NULL for the Root volume.
    volume = models.ForeignKey('UserVolume')

    # The object's name within its containing directory.
    # Ignored for volume roots.
    name = models.TextField(validators=[validate_name])

    # The content of the object, represented with a blob.
    content_blob = models.ForeignKey(ContentBlob, null=True)

    # The kind of the object: directory, file, or symbolic link.
    kind = models.CharField(
        max_length=128, choices=OBJECT_KIND_CHOICES)

    # Timestamp at which the object was first created.
    when_created = models.DateTimeField(default=now)

    # Timestamp at which the object was last modified.
    when_last_modified = models.DateTimeField(default=now)

    # Whether this object is alive or dead.
    status = models.CharField(
        max_length=128, choices=LIFECYCLE_STATUS_CHOICES, default=STATUS_LIVE)

    # The path of the object from its root.
    path = models.TextField()

    # The mimetype of the file.
    mimetype = models.TextField()

    # If the node is public, this will be its public UUID.
    # If it is private, then it will be None.
    public_uuid = models.UUIDField(unique=True, null=True)

    # The current generation of the object.
    generation = models.BigIntegerField(default=0)

    # The first generation of this object.
    generation_created = models.BigIntegerField(default=0)

    class Meta:
        abstract = True
        unique_together = (
            ('volume', 'generation'),
            # ('parent', 'name') when status == 'Live',
        )

    def __repr__(self):
        """Representation with info."""
        return "<%s id: %s volume: %s full_path: %r>" % (
            self.__class__.__name__, self.id, self.volume.id, self.full_path)

    def __unicode__(self):
        """Unicode representation with info."""
        return "%s id: %s volume: %s full_path: %r" % (
            self.__class__.__name__, self.id, self.volume.id, self.full_path)

    def save(self, *args, **kwargs):
        update_fields = kwargs.pop('update_fields', None)

        if update_fields is None or 'when_last_modified' not in update_fields:
            self.when_last_modified = now()
            if update_fields is not None:
                update_fields.append('when_last_modified')

        super(BaseStorageObject, self).save(
            *args, update_fields=update_fields, **kwargs)

    def lock_tree_for_update(self):
        """Lock the storageobject record for update."""
        return StorageObject.objects.select_for_update(nowait=True).filter(
            models.Q(parent__id=self.id) |
            models.Q(path__startswith=self.absolute_path),
            status=STATUS_LIVE, volume__id=self.volume.id)

    @property
    def full_path(self):
        """The full path of this node"""
        return posixpath.join(self.path, self.name)

    @property
    def absolute_path(self):
        """The absolute path of this node, useful to check for prefix match."""
        return posixpath.join('/', self.path, self.name, '')

    @property
    def is_dir(self):
        """True if the node is a directory."""
        return self.kind == StorageObject.DIRECTORY

    @property
    def is_file(self):
        """True if the node is a file."""
        return self.kind == StorageObject.FILE

    @property
    def is_symlink(self):
        """True if the node is a symlink."""
        return self.kind == StorageObject.SYMLINK

    @property
    def is_public(self):
        """True if the file is public."""
        return self.public_uuid is not None

    @property
    def is_root(self):
        """Return true if this is a root object."""
        return self.parent is ROOT_PARENT

    @property
    def live_children(self):
        """The LIVE children of this node."""
        result = self.children.filter(status=STATUS_LIVE)
        sanity_check = result.filter(volume=self.volume)
        assert result.count() == sanity_check.count(), 'Children mismatch'
        return result

    def get_descendants(self, live_only=True, kind=None):
        """Return all the descendants of this node."""
        valid = (StorageObject.FILE, StorageObject.DIRECTORY, None)
        if kind not in valid:
            # isn't one of File, Directory or None
            raise ValueError(
                'Invalid kind value, must be %s (got %r instead)' %
                (', '.join((repr(i) for i in valid)), kind))

        # Notice that in order to get indirect children we need to filter
        # by path. Also, we need to add a trailing slash to the path so
        # that our startswith query doesn't match, say, /a/b/code when
        # we're searching for the descendants of /a/b/c. Finally, because
        # of the trailing slash in our startswith query, it won't find
        # direct descendants (e.g. /a/b/c/d will have /a/b/c as path and
        # that won't match /a/b/c/, which is what we're searching for), so
        # we need the extra clause (parent.id == self.id) to get them *and*
        # we need to filter out self.
        result = StorageObject.objects.exclude(id=self.id).filter(
            models.Q(parent__id=self.id) |
            models.Q(path__startswith=self.absolute_path),
            volume__id=self.volume.id)
        if live_only:
            result = result.filter(status=STATUS_LIVE)
        if kind:
            result = result.filter(kind=kind)
        return result

    @property
    def descendants(self):
        """The LIVE descendants of this node."""
        return self.get_descendants()

    def make_private(self):
        """Make this node private."""
        if not self.is_public:
            return
        self.public_uuid = None
        self.update_generation(save=False)
        self.save(update_fields=['public_uuid', 'generation'])
        public_access_changed.send(
            sender=self.__class__, instance=self, public=False)

    def make_public(self):
        """Make this node public."""
        if self.is_public:
            return
        self.public_uuid = uuid.uuid4()
        self.update_generation(save=False)
        self.save(update_fields=['public_uuid', 'generation'])
        public_access_changed.send(
            sender=self.__class__, instance=self, public=True)

    @property
    def base62_public_id(self):
        """The base-62 version of the public id."""
        return utils.encode_base62(self.public_uuid.int, padded_to=22)

    @property
    def content_hash(self):
        """Get the hash value for this node's content."""
        if self.is_dir:
            raise DirectoriesHaveNoContent("Directory has no content.")
        return bytes(self.content_blob.hash) if self.content_blob else None

    @property
    def magic_hash(self):
        """Get the magic hash for this node's content."""
        if self.is_dir:
            raise DirectoriesHaveNoContent("Directory has no content.")
        result = None
        if self.content_blob and self.content_blob.magic_hash:
            result = bytes(self.content_blob.magic_hash)
        return result

    def get_content(self):
        """Return this object ContentBlob"""
        if self.is_dir:
            raise DirectoriesHaveNoContent("Directory has no content.")
        return self.content_blob

    def set_content(self, new_content, enforce_quota=True):
        """Set the ContentBlob and updates owner's used_storage_bytes."""
        if self.is_dir:
            raise DirectoriesHaveNoContent("Directory has no content.")
        curr_size = getattr(self.content_blob, 'size', 0)
        self.content_blob = new_content
        self.update_generation(save=False)
        new_size = new_content.size - curr_size
        content_changed.send(
            sender=self.__class__, instance=self, content_added=True,
            new_size=new_size, enforce_quota=enforce_quota)
        self.save(update_fields=['content_blob', 'generation'])

    content = property(get_content, set_content)

    def update_generation(self, save=True):
        """Update the generation of this object to match it's volume."""
        self.generation = self.volume.increment_generation()
        if save:
            self.save(update_fields=['generation'])

    def get_child_by_name(self, name):
        """Get the child named name."""
        try:
            child = StorageObject.objects.get(
                parent=self, name=name, status=STATUS_LIVE)
        except DataError as e:
            raise InvalidFilename('Name is not valid: %r (%r)' % (name, e))
        except StorageObject.DoesNotExist:
            child = None
        return child

    def move(self, new_parent, new_name):
        """Move the node to another parent and/or to a different name."""
        if not isinstance(new_parent, (StorageObject, NoneType)):
            # It feels weird to accept None for new_parent, but there's an
            # explicit check for that below (new_parent == ROOT_PARENT)
            # so we can leave None through as well.
            raise TypeError(
                'StorageObject.move: new_parent must be a StorageObject or '
                'None, got: %r' % new_parent)

        if not new_name:
            raise InvalidFilename("Invalid name.")
        if self.parent == new_parent and self.name == new_name:
            # no changes, then do nothing
            return
        if new_parent is ROOT_PARENT:
            raise NoPermission("Can't move a node to a root level.")
        if new_parent.id == self.id:
            raise NoPermission("Can't move a node into itself.")

        if new_parent.is_file:
            raise NotADirectory(
                "New parent (%r) isn't a directory" % new_parent)

        if new_parent.volume != self.volume:
            raise NoPermission("Can't move a node between volumes.")

        validate_name(new_name)

        old_parent = self.parent
        old_name = self.name
        new_parent_path = new_parent.path
        new_parent_name = new_parent.name
        descendants = []
        if self.is_dir:
            if self.parent.id != new_parent.id:
                # it was actually moved to other place, not just renamed
                full_path_with_sep = self.full_path + '/'
                if new_parent.full_path.startswith(full_path_with_sep):
                    raise NoPermission("Can't move a node to a child.")

            # need to update all the paths that are under the current directory
            # this will be the new path to all children
            new_path = posixpath.join(
                new_parent_path, new_parent_name, new_name)
            new_path = new_path.replace('\\', '\\\\')
            # this will be the size of the path parts to replace
            replace_size = len(self.full_path) + 1
            # update the path of all descendants
            descendants = list(self.descendants)
            self.descendants.update(
                path=Concat(models.Value(new_path),
                            Substr('path', replace_size)))

        # update this node
        self.update_generation(save=False)
        if self.parent.id != new_parent.id:
            self.parent = new_parent
            self.path = posixpath.join(new_parent_path, new_parent_name)
        self.name = new_name
        self.save(update_fields=['parent', 'path', 'name', 'generation'])
        right_now = now()
        if old_parent.id != new_parent.id:
            old_parent.when_last_modified = right_now
            old_parent.save(update_fields=['when_last_modified'])

        new_parent.when_last_modified = right_now
        new_parent.save(update_fields=['when_last_modified'])

        node_moved.send(
            sender=self.__class__, instance=self, old_name=old_name,
            old_parent=old_parent, descendants=descendants)

    def get_unique_childname(self, name):
        """Find a unique child name in this directory."""
        if not self.is_dir:
            raise NotADirectory("%s is not a directory." % self.full_path)

        basename, extension = os.path.splitext(name)
        idx = 0
        while self.get_child_by_name(name):
            idx += 1
            name = "%s~%s%s" % (basename, idx, extension)
            if idx > 5:
                name = "%s~%s%s" % (basename, uuid.uuid4(), extension)
                break
        return name

    def build_tree_from_path(self, path):
        """Build subdirectories from a path.

        This will return the last directory created from the path.
        """
        if not self.is_dir:
            raise NotADirectory("%s is not a directory." % self.full_path)

        def getleaf(start, path_parts):
            """Get the leaf directory"""
            if not path_parts:
                return start

            rest = path_parts[1:]
            head = path_parts[0]
            try:
                d = StorageObject.objects.get(
                    parent=start, status=STATUS_LIVE, name=head)
            except StorageObject.DoesNotExist:
                d = start.make_subdirectory(head)
            else:
                if d.is_file:
                    # if a file with the same name exists, find a
                    # unique name for the directory
                    name = start.get_unique_childname(d.name)
                    d = start.make_subdirectory(name)
            return getleaf(d, rest)
        return getleaf(self, [x for x in path.split("/") if x])

    def undelete(self, new_parent=None):
        """Undelete file or directory.

        If a new_parent is passed in, the file's parent node and path
        will be updated as well.
        """
        # no need to do anything with a live node
        if self.status == STATUS_LIVE:
            return
        if new_parent and not new_parent.is_dir:
            raise NotADirectory("Must reparent to a Directory on Undelete.")
        parent = new_parent or self.parent
        self.name = parent.get_unique_childname(self.name)
        if self.is_file:
            content_changed.send(
                sender=self.__class__, instance=self, content_added=False,
                new_size=getattr(self.content_blob, 'size', 0),
                enforce_quota=False)

        self.parent = parent
        self.volume = parent.volume
        self.path = parent.full_path
        self.status = STATUS_LIVE
        self.update_generation(save=False)

        # update the parent
        if self.parent.status == STATUS_DEAD:
            # if the parent directory dead, we need to check to see if there
            # is a live directory with the same path to put it in.
            path, name = os.path.split(self.path)
            try:
                # if we have a suitable parent, update the parent
                self.parent = StorageObject.objects.get(
                    volume__id=self.volume.id, path=path, name=name,
                    status=STATUS_LIVE)
            except StorageObject.DoesNotExist:
                # if we can't find a suitable parent, we need to restore the
                # old one.
                self.parent.undelete()
            else:
                self.parent.when_last_modified = now()
                self.parent.save(update_fields=['when_last_modified'])
        else:
            # if the parent was live, we just need to update the timestamp
            self.parent.when_last_modified = now()
            self.parent.save(update_fields=['when_last_modified'])

        self.save(update_fields=[
            'name', 'parent', 'volume', 'path', 'status', 'generation'])

    def unlink(self):
        """Mark the node as Dead."""
        # we don't modify the 'path' when unlinking the file, to preserve
        # its location when unlinked
        if self.is_dir and self.live_children.exists():
                raise NotEmpty("Can't unlink a non empty directory.")

        if self.parent == ROOT_PARENT:
            raise NoPermission("Can't unlink special files.")

        pre_kill.send(sender=self.__class__, instance=self)
        self.status = STATUS_DEAD
        self.update_generation(save=False)
        self.save(update_fields=['status', 'generation'])

        if self.is_file:
            content_changed.send(
                sender=self.__class__, instance=self, content_added=False,
                new_size=0 - getattr(self.content_blob, 'size', 0),
                enforce_quota=False)
        if self.parent != ROOT_PARENT:
            self.parent.when_last_modified = now()
            self.parent.save(update_fields=['when_last_modified'])
        post_kill.send(sender=self.__class__, instance=self)

    def unlink_tree(self):
        """Unlink and entire directory and it's subdirectories"""
        if not self.is_dir:
            raise NotADirectory("%s is not a directory." % self.id)

        if self.parent is None:
            raise NoPermission("Can't unlink volumes root nodes.")

        if self.status == STATUS_DEAD:
            return

        # First update the generation so that we can use it in the new TXLog
        # entries.
        self.update_generation(save=False)

        right_now = now()
        descendants = []
        if self.live_children.exists():
            size_to_remove = self.tree_size
            content_changed.send(
                sender=self.__class__, instance=self, content_added=False,
                new_size=0 - size_to_remove, enforce_quota=False)
            descendants = list(self.descendants)  # make a copy before killing
            self.descendants.update(
                status=STATUS_DEAD, when_last_modified=right_now)

        pre_unlink_tree.send(
            sender=self.__class__, instance=self, descendants=descendants)

        self.status = STATUS_DEAD
        self.save(update_fields=['status', 'generation'])

        if self.parent != ROOT_PARENT:
            self.parent.save()

        post_unlink_tree.send(
            sender=self.__class__, instance=self, descendants=descendants)

    @property
    def tree_size(self):
        """Get the size of the entire tree"""
        if not self.is_dir:
            raise NotADirectory("%s is not a directory." % self.id)
        if self.status == STATUS_DEAD:
            return 0

        size = StorageObject.objects.calculate_size_by_parent(self)
        return size

    def make_subdirectory(self, name):
        """Create a subdirectory named name."""
        if not name:
            raise InvalidFilename("Invalid directory Name")
        # parent must be directory
        if not self.is_dir:
            raise NotADirectory("%s is not a directory." % self)
        node = StorageObject.objects.create_directory(
            volume=self.volume, name=name, parent=self)
        self.when_last_modified = now()
        self.save(update_fields=['when_last_modified'])
        return node

    def make_file(self, name, content_blob=None, mimetype=''):
        """Create a file named name.

        If the "no-content" capability is present, this operation does not put
        any content in the file, and that's why its content_hash remains in
        the default value (Null)
        """
        if not name:
            raise InvalidFilename("Invalid File Name")
        if not self.is_dir:
            raise NotADirectory("%s is not a directory." % self.id)

        node = StorageObject.objects.create_file(
            volume=self.volume, name=name, parent=self, mimetype=mimetype)
        if content_blob is not None:
            node.set_content(content_blob)
        self.when_last_modified = now()
        self.save()
        return node

    @property
    def parent_paths(self):
        """Return a list of paths for parents of this node.

        For example, if the nodes path is /a/b/c/d, the parent paths
        would be ['/', '/a', '/a/b', '/a/b/c', '/a/b/c/d']
        """
        if self.parent is None:
            return []
        if self.path == '/':
            return ['/']
        pp = self.path.split('/')
        pp[0] = '/'
        return [os.path.join(*pp[0:i]) for i in range(1, len(pp) + 1)]

    def get_parent_ids(self):
        """Get the parent ids of this node id."""
        if self.parent is None:
            return []
        # sql = """
        # WITH RECURSIVE parents(id, parent_id, path, name, status) AS (
        #     SELECT id, parent_id, path, name, status
        #     FROM object WHERE id = '%s'
        #     UNION ALL
        #     SELECT p.id, p.parent_id, p.path, p.name, p.status
        #     FROM parents c, filesync_storageobject p
        #     WHERE c.parent_id = p.id
        # )
        # SELECT id FROM parents WHERE status='Live';
        # """ % str(self.parent.id)
        all_parents_but_me = self.parent_paths[:-1]
        parents = StorageObject.objects.filter(
            status=STATUS_LIVE, path__in=all_parents_but_me,
            kind=StorageObject.DIRECTORY, volume=self.volume)
        parents = dict(parents.values_list('id', 'parent__id'))
        # Filter out siblings, which are included in the query above
        result = []
        next_parent = self.parent.id
        while next_parent is not None:
            result.append(next_parent)
            next_parent = parents.get(next_parent)

        return result


class StorageObject(BaseStorageObject):
    """A node for a directory or file."""

    objects = StorageObjectManager()

    @property
    def public_url(self):
        """Return the public URL of the file."""
        return '%s/%s/' % (
            settings.PUBLIC_URL_PREFIX.rstrip('/'), self.base62_public_id)

    @property
    def nodekey(self):
        """Get the encoded key for this node."""
        if self.is_root:
            result = utils.make_nodekey(None, self.id)
        else:
            result = utils.make_nodekey(self.volume.id, self.id)
        return result


class MoveFromShare(BaseStorageObject):
    """A record of a node which was moved outside of it's volume.

    This is to support generation deltas so nodes will show up
    in a delta for a share even though a node has been moved outside of it.

    See BaseStorageObject for details about this model.

    """

    share_id = models.UUIDField()
    node_id = models.UUIDField()
    old_parent = models.ForeignKey(
        StorageObject, related_name='old_children', null=True)
    objects = MoveFromShareManager()

    class Meta:
        unique_together = (('node_id', 'share_id'),)


class ShareVolumeDelta(BaseStorageObject):
    """A special case used only for getting Deltas for shares using a view."""

    share_id = models.UUIDField()

    class Meta:
        db_table = 'share_delta_view'
        managed = False
        unique_together = (('id', 'share_id'),)


class Share(models.Model):
    """A Share: subtree that a user shares to another."""

    # share access constants
    VIEW = 'View'
    MODIFY = 'Modify'
    SHARE_ACCESS_CHOICES = (
        (VIEW, VIEW),
        (MODIFY, MODIFY),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    # node that is root of the shared subtree
    subtree = models.ForeignKey(StorageObject)

    # user who shares
    shared_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='sharedby_folders')

    # user to whom the subtree is shared
    shared_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, related_name='sharedto_folders', null=True)
    email = models.TextField(blank=True)

    # name of the sharing. The pair (shared_to, name) is unique.
    name = models.TextField(validators=[validate_name])

    # if the share was accepted or not
    accepted = models.BooleanField(default=False)

    # access level of the share
    access = models.CharField(max_length=128, choices=SHARE_ACCESS_CHOICES)

    # timestamp at which the share was first created.
    when_shared = models.DateTimeField(default=now)

    # timestamp at which the share was last modified.
    when_last_changed = models.DateTimeField(default=now)

    # whether this object is alive or dead
    status = models.CharField(
        max_length=128, choices=LIFECYCLE_STATUS_CHOICES, default=STATUS_LIVE)

    objects = ShareManager()

    # class Meta:
    #     unique_together = (
    #         ('shared_to', 'shared_by', 'subtree'),
    #         ('shared_to', 'name'),
    #     )

    def save(self, *args, **kwargs):
        update_fields = kwargs.pop('update_fields', None)
        if update_fields is None or 'when_last_modified' not in update_fields:
            self.when_last_modified = now()
            if update_fields is not None:
                update_fields.append('when_last_modified')
        super(Share, self).save(*args, **kwargs)

    def kill(self):
        """Marks itself as dead."""
        pre_kill.send(sender=self.__class__, instance=self)
        self.status = STATUS_DEAD
        self.save(update_fields=['status'])
        post_kill.send(sender=self.__class__, instance=self)

    def accept(self):
        """Marks itself as accepted."""
        assert self.status == STATUS_LIVE
        assert self.shared_to is not None
        self.accepted = True
        self.save(update_fields=['accepted'])

    def decline(self):
        """Marks itself as not accepted."""
        assert self.status == STATUS_LIVE
        assert self.shared_to is not None
        self.accepted = False
        self.status = STATUS_DEAD
        self.save(update_fields=['accepted', 'status'])

    def claim_share(self, user):
        """Claim a share offer."""
        # Check and make sure this folder isn't shared to them already
        try:
            matching_share = Share.objects.get(
                shared_by=self.shared_by, shared_to=user, status=STATUS_LIVE,
                subtree=self.subtree)
        except self.__class__.DoesNotExist:
            pass
        else:
            # if there was already a share matching the share_offer, return it
            if not matching_share.accepted:
                matching_share.accept()
            return matching_share

        # make sure the share_name isn't taken for this user
        self.name = Share.objects.get_unique_name(user, self.name)
        self.shared_to = user
        self.accepted = True
        self.save(update_fields=['accepted', 'shared_to', 'name'])

    def make_ro(self):
        self.access = self.VIEW
        self.save(update_fields=['access'])

    def make_rw(self):
        self.access = self.MODIFY
        self.save(update_fields=['access'])


class UploadJob(models.Model):
    """Pending blob Uploads."""

    # The storage object this blob upload is linked to
    node = models.ForeignKey(StorageObject)

    # A simple sanity check count for how many chunks have been
    # recorded for this blob upload
    chunk_count = models.IntegerField(default=0)

    # The hash the client claims that the completely uploaded file should have.
    hash_hint = models.BinaryField()

    # The crc32 the client claims that the completely uploaded
    # file should have.
    crc32_hint = models.BigIntegerField()

    # When the upload was started.
    when_started = models.DateTimeField(default=now)

    # When the upload was last active.
    when_last_active = models.DateTimeField(default=now)

    # Whether this is a live upload or a done-with one
    status = models.CharField(
        max_length=128, choices=LIFECYCLE_STATUS_CHOICES, default=STATUS_LIVE)

    # the key name for this multipart upload
    multipart_key = models.UUIDField(null=True)

    # the number of the uploaded bytes so far.
    uploaded_bytes = models.BigIntegerField(default=0)

    def add_part(self, size):
        """Add a part of size: 'size' and increment the chunk count."""
        self.uploaded_bytes += size
        self.chunk_count += 1
        self.when_last_active = now()
        self.save(update_fields=[
            'uploaded_bytes', 'chunk_count', 'when_last_active'])


class UserVolume(models.Model):
    """A user defined folder."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    # The object's owner, for access control and accounting purposes.
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)

    # suggested path (it's not enforced to the client)
    path = models.TextField(validators=[validate_volume_path])

    # timestamp at which the udf was first created.
    when_created = models.DateTimeField(default=now)

    # whether this object is alive or dead
    status = models.CharField(
        max_length=128, choices=LIFECYCLE_STATUS_CHOICES, default=STATUS_LIVE)

    # the generation of this volume
    generation = models.BigIntegerField(default=0)

    objects = UserVolumeManager()

    # class Meta:
    #     unique_together = (('owner', 'path'),)

    @property
    def is_root(self):
        """Return true if this is the root volume."""
        return self.path == settings.ROOT_USERVOLUME_PATH

    @property
    def root_node(self):
        """Return true if this is the root volume."""
        return self.storageobject_set.get(name=ROOT_NAME)

    def kill(self):
        """Mark this UDF as Dead."""
        pre_kill.send(sender=self.__class__, instance=self)
        size_to_remove = self.volume_size()
        content_changed.send(
            sender=self.__class__, instance=self, content_added=False,
            new_size=0 - size_to_remove, enforce_quota=False)
        self.increment_generation(save=False)
        self.status = STATUS_DEAD
        self.save(update_fields=['generation', 'status'])
        post_kill.send(sender=self.__class__, instance=self)

    def volume_size(self):
        """Get the size of the entire volume"""
        if self.status == STATUS_DEAD:
            return 0
        return StorageObject.objects.calculate_size_by_volume(self)

    def increment_generation(self, save=True):
        """Update the generation number."""
        # max is to avoid issues when it is None
        self.refresh_from_db()
        self.generation = result = max(0, self.generation) + 1
        if save:
            self.save(update_fields=['generation'])
        return result


class Download(models.Model):
    """A download to be performed by the download daemon."""

    # download status constants
    STATUS_QUEUED = 'Queued'
    STATUS_DOWNLOADING = 'Downloading'
    STATUS_COMPLETE = 'Complete'
    STATUS_ERROR = 'Error'
    DOWNLOAD_STATUS_CHOICES = (
        (STATUS_QUEUED, STATUS_QUEUED),
        (STATUS_DOWNLOADING, STATUS_DOWNLOADING),
        (STATUS_COMPLETE, STATUS_COMPLETE),
        (STATUS_ERROR, STATUS_ERROR),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    volume = models.ForeignKey(UserVolume)
    # The node of the download after it has completed.
    node = models.ForeignKey(StorageObject, null=True)
    file_path = models.TextField()
    download_url = models.TextField()
    download_key = models.TextField(null=True)
    status = models.CharField(
        max_length=128, choices=DOWNLOAD_STATUS_CHOICES, default=STATUS_QUEUED)
    status_change_date = models.DateTimeField(default=now)
    error_message = models.TextField()

    objects = DownloadManager()

    class Meta:
        unique_together = (('volume', 'file_path', 'download_url'))


class ResumableUpload(models.Model):
    """An Upload created through the REST API."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    # the owner of this upload
    owner = models.ForeignKey(settings.AUTH_USER_MODEL)

    # the volume path of the file when this upload completes
    volume_path = models.TextField()

    # the final size of this file
    size = models.BigIntegerField()

    # When the upload was started.
    when_started = models.DateTimeField(default=now)

    # When the upload was last active.
    when_last_active = models.DateTimeField(default=now)

    # Whether this is a live upload or a done-with one
    status = models.CharField(
        max_length=128, choices=LIFECYCLE_STATUS_CHOICES, default=STATUS_LIVE)

    # the key for this upload
    storage_key = models.UUIDField()

    # the number of parts currently created
    part_count = models.BigIntegerField(default=0)

    # the number of the uploaded bytes so far.
    uploaded_bytes = models.BigIntegerField(default=0)

    # the hash context of this resumable upload
    hash_context = models.BinaryField(null=True)

    # the magic hash context of this resumable upload
    magic_hash_context = models.BinaryField(null=True)

    # the crc context from compressing content
    crc_context = models.IntegerField(null=True)

    def add_part(self, size, hash_context, magic_hash_context, crc_context):
        """Updated when a part is added."""
        self.uploaded_bytes += size
        self.part_count += 1
        self.hash_context = hash_context
        self.magic_hash_context = magic_hash_context
        self.crc_context = crc_context
        self.when_last_active = now()
        self.save()


@receiver(pre_save, sender=Download)
def download_pre_save_handler(
        sender, instance, raw, using, update_fields=None, **kwargs):
    try:
        previous_status = Download.objects.get(id=instance.id).status
    except Download.DoesNotExist:
        previous_status = instance.status

    if instance.status != previous_status:
        instance.status_change_date = now()


@receiver(content_changed, sender=StorageObject)
def storage_object_content_changed(
        sender, instance, content_added, new_size, enforce_quota, **kwargs):
    with transaction.atomic():
        owner = StorageUser.objects.select_for_update(nowait=True).get(
            id=instance.volume.owner.id)
        owner.update_used_bytes(new_size, enforce_quota=enforce_quota)
