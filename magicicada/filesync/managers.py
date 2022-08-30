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

"""The Storage database model managers."""

import posixpath
import re
import uuid

from django.conf import settings
from django.contrib.auth.models import UserManager
from django.db import models
from django.core.exceptions import ValidationError

from magicicada.filesync.errors import (
    InvalidFilename,
    InvalidVolumePath,
    LockedUserError,
    NoPermission,
    StorageError,
)
from magicicada.filesync.utils import encode_hash


ROOT_NAME = ''
ROOT_PATH = '/'
ROOT_PARENT = None
ROOT_VOLUME = None

# lifecycle constants
STATUS_LIVE = 'Live'
STATUS_DEAD = 'Dead'

# info for the name validation
ILLEGAL_FILENAMES = [".", ".."]
ILLEGAL_FILENAME_CHARS_RE = re.compile(r'[\000/]')


def validate_name(value):
    """Validate a StorageObject name."""
    if not value:
        return value
    if not isinstance(value, str):
        raise InvalidFilename("Filename is not unicode: %r" % value)
    if value in ILLEGAL_FILENAMES:
        raise InvalidFilename("%s is a reserved filename" % value)
    if ILLEGAL_FILENAME_CHARS_RE.search(value) is not None:
        raise InvalidFilename("%s contains illegal characters" % value)
    return value


def validate_volume_path(value):
    """Validate a UserVolume path."""
    if not value or not value.startswith("~/") or value.endswith('/'):
        raise InvalidVolumePath(
            'Path must start with ~/ and must not end with / (got %r)' % value)
    return value


class HashFieldHandlerQuerySet(models.QuerySet):

    """A custom queryset for models with BinaryFields storing hashes."""

    hash_fields = None

    @classmethod
    def encode_hashes(cls, kwargs):
        fields = cls.hash_fields or []
        result = kwargs.copy()
        for f in kwargs.keys():
            if f in fields:
                result['_' + f] = encode_hash(result.pop(f))
        return result

    def create(self, **kwargs):
        kwargs = self.encode_hashes(kwargs)
        return super(HashFieldHandlerQuerySet, self).create(**kwargs)

    def filter(self, **kwargs):
        kwargs = self.encode_hashes(kwargs)
        return super(HashFieldHandlerQuerySet, self).filter(**kwargs)

    def get(self, **kwargs):
        kwargs = self.encode_hashes(kwargs)
        return super(HashFieldHandlerQuerySet, self).get(**kwargs)


class ContentBlobQuerySet(HashFieldHandlerQuerySet):

    """A custom manager for ContentBlob model."""

    hash_fields = ['hash', 'magic_hash']


ContentBlobManager = ContentBlobQuerySet.as_manager


class ResumableUploadQuerySet(HashFieldHandlerQuerySet):

    """A custom manager for ResumableUpload model."""

    hash_fields = ['hash_context', 'magic_hash_context']


ResumableUploadManager = ResumableUploadQuerySet.as_manager


class UploadJobQuerySet(HashFieldHandlerQuerySet):

    """A custom manager for UploadJob model."""

    hash_fields = ['hash_hint']


UploadJobManager = UploadJobQuerySet.as_manager


class DownloadManager(models.Manager):

    """A custom manager for Download model."""

    def create(self, download_key=None, **kwargs):
        if download_key:
            download_key = repr(download_key)
        return super(DownloadManager, self).create(
            download_key=download_key, **kwargs)


class StorageUserManager(UserManager):

    """A custom manager for User model."""

    def get_with_session_id(
            self, user_id=None, username=None, session_id=None,
            ignore_lock=False):

        try:
            if user_id is not None:
                user = self.get(id=user_id)
            elif username is not None:
                user = self.get(usernam=username)
        except self.model.DoesNotExist:
            user = None

        if user is None:
            raise StorageError(
                'Invalid call to get_with_session_id, user_id or username '
                'must be provided.')

        if user.locked and not ignore_lock:
            raise LockedUserError()

        user.session_id = session_id
        return user


class UserVolumeManager(models.Manager):

    """A custom manager for UserVolume model."""

    def create(self, owner, path, **kwargs):
        """Create a new UserVolume (with its root node) on the given path."""
        validate_volume_path(path)

        if path == settings.ROOT_USERVOLUME_PATH:
            raise NoPermission(
                'Invalid volume path: %r.' % settings.ROOT_USERVOLUME_PATH)

        # Create the udf and fix the volume_id in the node
        volume = super(UserVolumeManager, self).create(
            owner=owner, path=path, **kwargs)

        node = volume.storageobject_set.create_directory(name=ROOT_NAME)
        assert volume.root_node == node
        return volume

    def get_root(self, owner):
        """Get the root UserVolume."""
        return self.get(
            owner=owner, path=settings.ROOT_USERVOLUME_PATH,
            status=STATUS_LIVE)

    def get_or_create_root(self, owner):
        """Create a root UserVolume and its root node, if they don't exist."""
        volume, created = self.get_or_create(
            owner=owner, path=settings.ROOT_USERVOLUME_PATH,
            status=STATUS_LIVE)
        if created:
            node = volume.storageobject_set.create_directory(name=ROOT_NAME)
            assert volume.root_node == node
        return volume, created


class StorageObjectManager(models.Manager):

    """A custom manager for StorageObject model."""

    def create(
            self, name, parent=None, path=None, volume=None, generation=0,
            generation_created=0, validate_path=True, **kwargs):
        validate_name(name)

        if parent is not None:
            expected_path = posixpath.join(parent.path, parent.name)

            if volume is not None and parent.volume != volume:
                raise ValidationError(
                    'Volume can not be set on when parent given (or they must '
                    'match).')

            volume = parent.volume
            generation = volume.increment_generation()
            generation_created = generation
        else:
            # the only node with parent None, and no name is Root; other
            # special nodes (as the root) have no parent, and no path,
            # but different names
            if name == ROOT_NAME:
                expected_path = ROOT_PATH
            else:
                expected_path = ""
            # both have volume and parent ids as None
            parent = ROOT_PARENT
            volume = volume

        # This validation breaks MoveFromShare, use a conditional param
        if validate_path and path is not None and path != expected_path:
            raise ValidationError(
                'Path can not be set, should be %r (got %r).' %
                (expected_path, path))

        if path is None:
            path = expected_path

        return super(StorageObjectManager, self).create(
            parent=parent, name=name, path=path, volume=volume,
            generation=generation, generation_created=generation_created,
            **kwargs)

    def create_directory(self, **kwargs):
        assert 'kind' not in kwargs
        kwargs['kind'] = self.model.DIRECTORY
        return self.create(**kwargs)

    def create_file(self, **kwargs):
        assert 'kind' not in kwargs
        kwargs['kind'] = self.model.FILE
        return self.create(**kwargs)

    def get_root(self, owner):
        """Get the root node for owner."""
        return self.get(
            volume__owner=owner, volume__path=settings.ROOT_USERVOLUME_PATH,
            name=ROOT_NAME)

    def filter_live_files(self):
        return self.filter(kind=self.model.FILE, status=STATUS_LIVE)

    def calculate_size(self, queryset):
        result = queryset.aggregate(size=models.Sum('content_blob__size'))
        # for empty querysets, the aggregation will return None
        return result['size'] or 0

    def calculate_size_by_owner(self, owner):
        result = self.filter_live_files().filter(
            volume__status=STATUS_LIVE, volume__owner__id=owner.id)
        return self.calculate_size(result)

    def calculate_size_by_parent(self, parent):
        result = self.filter_live_files().filter(
            models.Q(parent__id=parent.id) |
            models.Q(path__startswith=parent.absolute_path),
            volume__id=parent.volume.id,
        )
        return self.calculate_size(result)

    def calculate_size_by_volume(self, volume):
        result = self.filter_live_files().filter(volume__id=volume.id)
        return self.calculate_size(result)


class MoveFromShareManager(StorageObjectManager):

    """A custom manager for MoveFromShare model."""

    def from_move(self, node, share_id, old_parent=None, name=None):
        """Create an instance from a StorageObject node.

        This is really the only way one of these should be created.
        """
        name = name or node.name
        result = super(MoveFromShareManager, self).create(
            share_id=share_id, node_id=node.id, old_parent=old_parent,
            name=name, volume=node.volume, kind=node.kind,
            content_blob=node.content_blob, mimetype=node.mimetype,
            when_created=node.when_created,
            when_last_modified=node.when_last_modified, status=STATUS_DEAD,
            path=node.path, public_uuid=node.public_uuid,
            generation=node.generation,
            generation_created=node.generation_created,
            validate_path=False,
        )
        return result


class ShareManager(models.Manager):

    """A custom manager for Share model."""

    def create(self, name, **kwargs):
        validate_name(name)
        return super(ShareManager, self).create(name=name, **kwargs)

    def get_unique_name(self, user, name):
        """Find a unique child name in this directory."""
        basename = name
        idx = 0
        while self.filter(
                status=STATUS_LIVE, shared_to=user, name=name).exists():
            idx += 1
            name = "%s~%s" % (basename, idx)
            if idx > 50:
                name = "%s~%s" % (basename, uuid.uuid4())
                break
        return name
