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

"""Base Test class for testing the data access layer"""

from __future__ import unicode_literals

import hashlib
import uuid

from itertools import count

from django.utils.timezone import now

from backends.filesync import utils
from backends.filesync.dbmanager import get_filesync_store, filesync_tm
from backends.filesync.gateway import SystemGateway
from backends.filesync.models import (
    STATUS_DEAD,
    STATUS_LIVE,
    ContentBlob,
    PublicNode,
    Share,
    StorageObject,
    StorageUser,
    UserVolume,
)
from backends.txlog.models import TransactionLog
from backends.testing.testcase import DatabaseResourceTestCase


class StorageDALTestCase(DatabaseResourceTestCase):
    """A base TestCase with an object factory and other helper methods."""

    def setUp(self):
        """Set up."""
        super(StorageDALTestCase, self).setUp()
        self.factory = Factory()
        self.store = get_filesync_store()
        self.save_utils_set_public_uuid = utils.set_public_uuid

    def tearDown(self):
        """Tear down."""
        utils.set_public_uuid = self.save_utils_set_public_uuid
        super(StorageDALTestCase, self).tearDown()

    def patch(self, obj, attr_name, new_val):
        """Patch!"""
        old_val = getattr(obj, attr_name)
        setattr(obj, attr_name, new_val)
        self.addCleanup(setattr, obj, attr_name, old_val)

    def create_user(self, id=1, username="username", visible_name="vname",
                    max_storage_bytes=2 * (2 ** 30)):
        """Deprecated; This is only a compatibility shim for tests that
        haven't been updated to use the object factory directly."""
        return self.factory.make_user(
            user_id=id, username=username,
            visible_name=visible_name, max_storage_bytes=max_storage_bytes)


class ORMTestCase(DatabaseResourceTestCase):
    """Base class for test cases which use storm to connect to Storage DB.

    This class supports older testcases which don't use the DAL.

    """

    def setUp(self):
        super(ORMTestCase, self).setUp()
        self.factory = ORMObjectFactory()

    def create(self, klass, *args, **kwargs):
        """Create and verify all attributes on the object.

        will create the object, set the attributes and then
        commit it to the database. then check to see that the
        attributes match.
        """
        try:
            obj = klass()
            for k, v in kwargs.items():
                setattr(obj, k, v)
            self.store.add(obj)
        except Exception, e:
            filesync_tm.abort()
            raise e
        filesync_tm.commit()
        for k, v in kwargs.items():
            self.assertEqual(getattr(obj, k), v)

        return obj

    @property
    def store(self):
        """Get the store."""
        return self.factory.store

    def make_user(self, id, username):
        """Deprecated! Tests should use self.factory.make_user() directly
        instead."""
        return self.factory.make_user(id, username)


class Factory(object):
    """An anonymous object factory that creates DAO objects."""

    _unique_int_counter = count(100000)

    def get_unique_integer(self):
        """Return an integer unique to this factory.

        For each thread, this will be a series of increasing numbers, but the
        starting point will be unique per thread.
        """
        return Factory._unique_int_counter.next()

    def get_unique_unicode(self):
        return 'unique-string-%d' % self.get_unique_integer()

    def make_user(self, user_id=None, username=None, visible_name=None,
                  max_storage_bytes=2 ** 20):
        if username is None:
            username = self.get_unique_unicode()
        if visible_name is None:
            visible_name = self.get_unique_unicode()
        if user_id is None:
            user_id = self.get_unique_integer()
        user = SystemGateway().create_or_update_user(
            user_id, username, visible_name, max_storage_bytes)
        filesync_tm.commit()
        return user

    def make_file(self, user=None, parent=None, name=None,
                  mimetype='text/plain'):
        if user is None:
            user = self.make_user()
        if name is None:
            name = self.get_unique_unicode()
        if parent is None:
            parent = user.root
        hash = self.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = self.get_unique_integer()
        size = 100
        deflated_size = 10000
        f = parent.make_file_with_content(
            name, hash, crc, size, deflated_size, storage_key, mimetype)
        f.load(with_content=True)
        return f

    def get_fake_hash(self, key=None):
        """Return a hashkey."""
        return b'sha1:' + hashlib.sha1(key or str(uuid.uuid4())).hexdigest()

    def get_test_contentblob(self, content=None):
        """Get a content blob."""
        if content:
            content = content.encode('utf-8')
        cb = ContentBlob()
        cb.hash = self.get_fake_hash(content)
        cb.crc32 = 1023
        cb.size = 1024
        cb.deflated_size = 10000
        cb.storage_key = uuid.uuid4()
        cb.content = content
        cb.status = STATUS_LIVE
        return cb

    def content_blob_args(self):
        """Returns example blob arguments."""
        return dict(
            hash=self.get_fake_hash(), crc32=1023, size=1024,
            storage_key=uuid.uuid4(), deflated_size=10000,
            magic_hash=b'magic!', content=b'hola', status=STATUS_LIVE)

    def uploadjob_args(self, key='hola'):
        """Returns example upload job arguments."""
        return dict(
            crc32_hint=1024,
            hash_hint=b'sha1:' + hashlib.sha1(key).hexdigest(),
            inflated_size_hint=200, deflated_size_hint=100,
            when_started=now(), when_last_active=now(), status=STATUS_DEAD)


class ORMObjectFactory(Factory):
    """A factory used to build model fixtures."""

    def __init__(self):
        super(ORMObjectFactory, self).__init__()
        self.users = {}

    def make_user(self, user_id=None, username=None, visible_name=None,
                  max_storage_bytes=2 ** 20):
        try:
            return self.users[user_id]
        except KeyError:
            pass

        user = super(ORMObjectFactory, self).make_user(
            user_id, username, visible_name, max_storage_bytes)
        suser = self.store.get(StorageUser, user.id)
        self.users[user_id] = suser
        return suser

    def make_content(self, hash=None, crc32=None, size=None,
                     deflated_size=None, storage_key=None, magic_hash=None):
        """Create content for a file node."""
        content = ContentBlob()
        content.hash = hash or self.get_fake_hash()
        content.magic_hash = magic_hash or self.get_fake_hash()
        content.crc32 = crc32 or self.get_unique_integer()
        content.size = size or self.get_unique_integer()
        content.deflated_size = deflated_size or self.get_unique_integer()
        content.status = STATUS_LIVE
        content.storage_key = storage_key or uuid.uuid4()
        self.store.add(content)
        return content

    def make_file(self, user=None, parent=None, name=None,
                  mimetype='text/plain', public=False):
        """Create a file node."""
        if user is None:
            user = self.make_user()
        if name is None:
            name = self.get_unique_unicode()
        if parent is None:
            parent = UserVolume.get_root(self.store, user.id).root_node
        f = StorageObject(
            user.id, name, StorageObject.FILE, provided_mimetype=mimetype,
            parent=parent)
        f.content = self.make_content()
        if public:
            publicfile = self.store.add(PublicNode(f.id, f.owner_id))
            self.store.flush()
            f.publicfile_id = publicfile.id
        self.store.add(f)
        return f

    def make_transaction_log(self, tx_id=None, timestamp=None, owner_id=1,
                             op_type=TransactionLog.OP_DELETE):
        """Create a transaction log."""
        txlog = TransactionLog(
            uuid.uuid4(), owner_id, uuid.uuid4(), op_type, u"",
            u"text/plain", generation=1, old_path=u"",
            extra_data=u"")
        if timestamp:
            txlog.timestamp = timestamp
        if tx_id:
            txlog.id = tx_id
        self.store.add(txlog)
        self.store.flush()
        return txlog

    def make_directory(self, user=None, parent=None, name=None, public=False):
        """Create a folder node."""
        if user is None:
            user = self.make_user()
        if name is None:
            name = self.get_unique_unicode()
        if parent is None:
            parent = UserVolume.get_root(self.store, user.id).root_node
        subdir = parent.make_subdirectory(name)
        if public:
            publicfile = self.store.add(PublicNode(subdir.id, subdir.owner_id))
            self.store.flush()
            subdir.publicfile_id = publicfile.id
        return subdir

    def make_udf(self, user=None, path=None, status=STATUS_LIVE):
        """Create a UDF node."""
        if user is None:
            user = self.make_user()
        if path is None:
            path = '~/' + self.get_unique_unicode()
        udf = UserVolume.create(self.store, user.id, path)
        udf.status = status
        return udf

    def make_share(self, node=None, name=None, recipient=None,
                   access_level=Share.VIEW, accepted=True):
        """Create a share node."""
        if recipient is None:
            recipient = self.make_user()
        if node is None:
            node = self.make_directory()
        if name is None:
            name = self.get_unique_unicode()
        share = Share(node.owner_id, node.id, recipient.id, name, access_level)
        share.accepted = accepted
        self.store.add(share)
        return share

    @property
    def store(self):
        """Get the store, dont cache, threading issues may arise"""
        return get_filesync_store()
