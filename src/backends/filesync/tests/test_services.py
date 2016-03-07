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

"""Test the Data services."""

from __future__ import unicode_literals

import uuid

from django.utils.timezone import now

from backends.filesync import errors
from backends.filesync.models import StorageUser
from backends.filesync.services import (
    DAOStorageUser,
    get_abandoned_uploadjobs,
    get_node,
    get_user_info,
    get_public_file,
    get_public_directory,
    get_storage_user,
    make_storage_user,
)
from backends.filesync.tests.testcase import StorageDALTestCase

MAX_STORAGE_BYTES = 10 * 23


class DataServicesTestCase(StorageDALTestCase):
    """Test the DataServices.

    Since all the logic is in lower level tests, these tests are kept
    to a minimum
    """

    def assert_storage_user(
            self, storage_user, user_id, visible_name, max_storage_bytes):
        self.assertIsInstance(storage_user, DAOStorageUser)
        self.assertEqual(storage_user.id, user_id)
        self.assertEqual(storage_user.visible_name, visible_name)
        quota = storage_user.get_quota()
        self.assertEqual(quota.max_storage_bytes, max_storage_bytes)

    def test_make_storage_user(self):
        """Test the make_storage_user function."""
        storage_user = make_storage_user(
            1, "Cool UserName", "Visible Name", MAX_STORAGE_BYTES)
        self.assert_storage_user(
            storage_user, 1, "Visible Name", MAX_STORAGE_BYTES)

    def test_get_storage_user(self):
        """Test the get_storage_user function."""
        user = make_storage_user(
            1, "Cool UserName", "Visible Name", MAX_STORAGE_BYTES)
        user = get_storage_user(1)
        self.assertTrue(isinstance(user, DAOStorageUser))
        user.update(subscription=False)
        self.assertRaises(errors.DoesNotExist, get_storage_user, 1)
        user = get_storage_user(1, active_only=False)
        user.update(subscription=True)
        # now check a locked user.
        suser = self.store.get(StorageUser, user.id)
        suser.locked = True
        self.store.commit()
        self.assertRaises(errors.LockedUserError, get_storage_user, user.id)
        # and ignore the lock too
        user = get_storage_user(user.id, readonly=True)
        self.assertTrue(isinstance(user, DAOStorageUser))

    def test_get_node(self):
        """Test the get_node function."""
        user1 = self.factory.make_user(
            1, "User 1", "User 1", MAX_STORAGE_BYTES)
        node = user1.volume().root.make_file("test file")
        new_node = get_node(node.id)
        self.assertEqual(node.id, new_node.id)
        self.assertEqual(node.parent_id, new_node.parent_id)
        self.assertEqual(node.name, new_node.name)
        self.assertEqual(node.path, new_node.path)

    def test_get_user_info(self):
        """Test the get_user_info function."""
        user = self.factory.make_user(
            1, "User 1", "User 1", MAX_STORAGE_BYTES)
        user_info = get_user_info(user.id)
        quota = user.get_quota()
        self.assertEqual(quota.max_storage_bytes, user_info.max_storage_bytes)
        self.assertEqual(
            quota.used_storage_bytes, user_info.used_storage_bytes)
        self.assertEqual(quota.free_bytes, user_info.free_bytes)
        self.assertRaises(errors.DoesNotExist, get_user_info, 41)

    def test_get_abandoned_uploadjobs(self):
        """Test the get_abandoned_uploadjobs function."""
        self.assertRaises(TypeError, get_abandoned_uploadjobs)
        jobs = get_abandoned_uploadjobs(now(), 100)
        self.assertTrue(isinstance(jobs, list))

    def test_get_public_file(self):
        """Test the get_public_file function."""
        user = self.factory.make_user(
            1, "Cool UserName", "Visible Name", 10)
        a_file = user.volume().root.make_file_with_content(
            "file.txt", self.factory.get_fake_hash(), 123, 1, 1, uuid.uuid4())
        a_file.change_public_access(True)
        public_key = a_file.public_key
        f1 = get_public_file(public_key)
        self.assertEqual(f1, a_file)
        a_file.change_public_access(False)
        self.assertRaises(errors.DoesNotExist, get_public_file, public_key)

    def test_get_public_directory(self):
        """Test the get_public_directory function."""
        user = self.factory.make_user(
            1, "Cool UserName", "Visible Name", 10)
        a_dir = user.volume().root.make_subdirectory('test_dir')
        a_dir.make_file_with_content(
            "file.txt", self.factory.get_fake_hash(), 123, 1, 1, uuid.uuid4())
        a_dir.change_public_access(True, allow_directory=True)
        public_key = a_dir.public_key
        pub_dir = get_public_directory(public_key)
        self.assertEqual(pub_dir, a_dir)
        a_dir.change_public_access(False, allow_directory=True)
        self.assertRaises(errors.DoesNotExist,
                          get_public_directory, public_key)

    def test_get_public_file_public_uuid(self):
        """Test the get_public_file function."""
        user = self.factory.make_user(
            1, "Cool UserName", "Visible Name", 10)
        a_file = user.volume().root.make_file_with_content(
            "file.txt", self.factory.get_fake_hash(), 123, 1, 1, uuid.uuid4())
        a_file.change_public_access(True)
        public_key = a_file.public_key
        # get the file using the public uuid
        f1 = get_public_file(public_key)
        self.assertEqual(f1, a_file)
        a_file.change_public_access(False)
        self.assertRaises(errors.DoesNotExist, get_public_file, public_key)
