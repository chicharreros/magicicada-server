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

"""Factory of objects."""

from __future__ import unicode_literals

import hashlib
import random
import string
import uuid

from itertools import count

from django.contrib.auth import get_user_model
from django.utils.timezone import now

from magicicada.filesync.models import (
    STATUS_DEAD,
    STATUS_LIVE,
    ContentBlob,
    Download,
    MoveFromShare,
    ResumableUpload,
    Share,
    StorageObject,
    UploadJob,
    UserVolume,
)
from magicicada.txlog.models import TransactionLog


BASE_CHARS = string.letters + string.digits
User = get_user_model()


class Factory(object):

    counter = count()

    def get_unique_integer(self):
        """Return an integer unique to this factory."""
        return self.counter.next()

    def get_unique_string(self, extra_length=6, prefix='string-'):
        return prefix + ''.join(
            random.choice(BASE_CHARS) for i in range(extra_length))

    def get_fake_hash(self, key=None):
        """Return a hashkey."""
        if key is None:
            key = str(uuid.uuid4())
        return b'sha1:' + hashlib.sha1(key).hexdigest()

    def make_user(
            self, username=None, visible_name=None, max_storage_bytes=2 ** 20,
            with_root=True, **kwargs):
        assert 'user_id' not in kwargs
        if username is None:
            username = self.get_unique_string(prefix='user-')
        if visible_name is None:
            first_name = self.get_unique_string(prefix='first name ')
            last_name = self.get_unique_string(prefix='last name ')
        else:
            first_name, _, last_name = visible_name.rpartition(' ')
        user = User.objects.create_user(
            username=username, first_name=first_name, last_name=last_name,
            max_storage_bytes=max_storage_bytes, **kwargs)
        if with_root:
            UserVolume.objects.get_or_create_root(user)
        return user

    def make_content_blob(
            self, hash=None, crc32=1023, size=1024, deflated_size=10000,
            storage_key=None, magic_hash=b'magic!', content=None,
            status=STATUS_LIVE):
        """Create content for a file node."""
        if content is None:
            content = 'Hola Mundo' + self.get_unique_string()
        if isinstance(content, unicode):
            content = content.encode('utf-8')
        if hash is None:
            hash = self.get_fake_hash(content)
        if storage_key is None:
            storage_key = uuid.uuid4()
        return ContentBlob.objects.create(
            hash=hash, magic_hash=magic_hash, crc32=crc32, size=size,
            deflated_size=deflated_size, status=status, content=content,
            storage_key=storage_key)

    def make_file(
            self, owner=None, parent=None, name=None, mimetype='text/plain',
            public=False, content_blob=None, **kwargs):
        """Create a file node."""
        if owner is None:
            owner = self.make_user()
        if name is None:
            name = self.get_unique_string(prefix='file-')
        if parent is None:
            volume, _ = UserVolume.objects.get_or_create_root(owner)
            parent = volume.root_node
        else:
            volume = parent.volume
        if not content_blob:
            content_blob = self.make_content_blob()
        nodefile = StorageObject.objects.create_file(
            name=name, mimetype=mimetype, parent=parent, volume=volume,
            content_blob=content_blob, **kwargs)
        if public:
            nodefile.make_public()
        return nodefile

    def make_directory(self, owner=None, parent=None, name=None, public=False):
        """Create a folder node."""
        if owner is None:
            owner = self.make_user()
        if name is None:
            name = self.get_unique_string(prefix='directory-')
        if parent is None:
            volume, _ = UserVolume.objects.get_or_create_root(owner)
            parent = volume.root_node

        subdir = parent.make_subdirectory(name)
        if public:
            subdir.make_public()
        return subdir

    def make_root_volume(self, owner=None):
        if owner is None:
            owner = self.make_user()
        volume, _ = UserVolume.objects.get_or_create_root(owner)
        return volume

    def make_user_volume(
            self, owner=None, path=None, status=STATUS_LIVE, **kwargs):
        """Create a UDF node."""
        if owner is None:
            owner = self.make_user()
        if path is None:
            path = '~/' + self.get_unique_string(prefix='udf-')
        udf = UserVolume.objects.create(
            owner=owner, path=path.rstrip('/'), status=status, **kwargs)
        return udf

    def make_share(self, owner=None, subtree=None, name=None, shared_to=None,
                   access=Share.VIEW, accepted=True, **kwargs):
        """Create a share node."""
        if subtree is not None:
            assert owner is None, 'Can not provide both subtree and owner'
            owner = subtree.volume.owner
        else:
            if owner is None:
                owner = self.make_user()
            subtree = self.make_directory(owner=owner)
        assert subtree.volume.owner == owner
        if name is None:
            name = self.get_unique_string(prefix='share-')
        return Share.objects.create(
            subtree=subtree, shared_by=owner, shared_to=shared_to,
            name=name, access=access, accepted=accepted, **kwargs)

    def make_move_from_share(self, owner=None, node=None, share=None):
        if node is None:
            if owner is None:
                owner = self.make_user()
            node = self.make_directory(owner=owner)
            assert node.volume.owner == owner
        if share is None:
            share = self.make_share(owner=node.volume.owner)
        assert share.shared_by == node.volume.owner
        assert share.subtree != node
        return MoveFromShare.objects.from_move(node=node, share_id=share.id)

    def make_resumable_upload(
            self, owner=None, volume_path=None, size=None, storage_key=None):
        if owner is None:
            owner = self.make_user()
        if volume_path is None:
            volume_path = '~/' + self.get_unique_string(
                prefix='resumable-upload-volume-')
        if size is None:
            size = 100
        if storage_key is None:
            storage_key = uuid.uuid4()
        return ResumableUpload.objects.create(
            owner=owner, volume_path=volume_path, size=size,
            storage_key=storage_key)

    def make_upload_job(
            self, node=None, crc32_hint=1024, hash_hint=None,
            when_started=None, when_last_active=None, status=STATUS_DEAD):
        if node is None:
            node = self.make_file(name='file.ext')
        if hash_hint is None:
            hash_hint = self.get_fake_hash(key='hola')
        if when_started is None:
            when_started = now()
        if when_last_active is None:
            when_last_active = now()
        return UploadJob.objects.create(
            node=node, crc32_hint=crc32_hint, hash_hint=hash_hint,
            when_started=when_started, when_last_active=when_last_active,
            status=status)

    def make_download(self, volume, **kwargs):
        return Download.objects.create(volume=volume, **kwargs)

    def make_tree_and_files(self, dirnode, name, content=None, amount=10):
        """Add a subtree and 100 files"""
        if content is None:
            content = self.make_content_blob()
        sub = dirnode.make_subdirectory(name)
        for i in range(amount):
            sub.make_file('%s-%s' % (sub.name, i), content_blob=content)
        return sub

    def make_transaction_log(
            self, node=None, owner=None, volume=None,
            op_type=TransactionLog.OP_DELETE, path='', mimetype='text/plain',
            generation=1, old_path=None, extra_data='', timestamp=None):
        """Create a transaction log."""
        if owner is None:
            owner = self.make_user()
        if node is None:
            node = self.make_file(owner=owner)
        if volume is None:
            volume = node.volume
        kwargs = dict(
            node_id=node.id, owner_id=owner.id, volume_id=volume.id,
            op_type=op_type, path=old_path, mimetype=mimetype,
            generation=generation, old_path=old_path, extra_data=extra_data)
        if timestamp:
            kwargs['timestamp'] = timestamp
        return TransactionLog.objects.create(**kwargs)
