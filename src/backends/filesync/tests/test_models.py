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

"""Test for the storage model."""

from __future__ import unicode_literals

import psycopg2
import threading
import unittest
import uuid
import datetime

from mock import patch
from storm.expr import Or, Max

from django.conf import settings
from backends.filesync import errors
from backends.filesync.dbmanager import filesync_tm
from backends.filesync.models import (
    STATUS_LIVE,
    STATUS_DEAD,
    ContentBlob,
    Download,
    MoveFromShare,
    PublicNode,
    ResumableUpload,
    Share,
    ShareVolumeDelta,
    StorageObject,
    StorageUser,
    StorageUserInfo,
    UploadJob,
    UserVolume,
    delete_user_data,
    delete_user_main_data,
    get_path_startswith,
    validate_name,
    undelete_volume,
)
from backends.filesync.tests.testcase import ORMTestCase
from backends.txlog.models import TransactionLog


class TestStorageUser(ORMTestCase):
    """Tests for StorageUser."""

    def test_create(self):
        """Tests creation of a StorageUser."""
        u = self.factory.make_user()
        self.assertFalse(u.locked)

    def test_lock_for_update(self):
        """Make sure lock_for_update locks the user"""
        user = self.make_user(2, 'f')
        self.store.commit()
        user.lock_for_update()
        self.failed = False

        def try_update():
            """try to update the locked record"""
            try:
                u = self.store.get(StorageUser, user.id)
                u.lock_for_update()
            except psycopg2.OperationalError:
                self.failed = True

        thread = threading.Thread(target=try_update)
        thread.start()
        thread.join()
        self.assertTrue(self.failed)

    def test_delete_user_main_data(self):
        """Test delete_user_main_data."""
        user1 = self.make_user(1, 'shorttimer')
        user2 = self.make_user(2, 'sherry')
        user3 = self.make_user(3, 'sammy')
        self.store.add(PublicNode(uuid.uuid4(), user1.id))
        self.store.add(PublicNode(uuid.uuid4(), user2.id))
        self.store.add(PublicNode(uuid.uuid4(), user3.id))
        self.store.add(Share(
            user1.id, uuid.uuid4(), user2.id, 'Fake1', Share.VIEW))
        self.store.add(Share(
            user2.id, uuid.uuid4(), user1.id, 'Fake2', Share.VIEW))
        self.store.add(Share(
            user3.id, uuid.uuid4(), user2.id, 'Fake3', Share.VIEW))
        self.store.commit()
        self.assertEqual(3, self.store.find(StorageUser).count())
        self.assertEqual(3, self.store.find(PublicNode).count())
        self.assertEqual(3, self.store.find(Share).count())
        delete_user_main_data(self.store, user1.id)
        self.store.commit()
        self.assertEqual(2, self.store.find(StorageUser).count())
        self.assertEqual(2, self.store.find(PublicNode).count())
        self.assertEqual(1, self.store.find(Share).count())

    def test_delete_user_data(self):
        """Test delete_user_data."""
        ui = self.store.add(StorageUserInfo(1, 2 ** 16))
        self.store.add(Download(ui.id, uuid.uuid4(), 'x', 'x'))
        udf = UserVolume.create(self.store, ui.id, '~/p/n')
        self.store.add(MoveFromShare.from_move(
            udf.root_node, uuid.uuid4()))
        cb = ContentBlob.make_empty(self.store)
        cb.hash = b'trashhash'
        ob = udf.root_node.make_file('file.txt')
        ob._content_hash = cb.hash
        self.store.add(UploadJob(ob.id))
        self.assertEqual(1, self.store.find(StorageUserInfo).count())
        self.assertEqual(2, self.store.find(StorageObject).count())
        self.assertEqual(1, self.store.find(UserVolume).count())
        self.assertEqual(1, self.store.find(UploadJob).count())
        self.assertEqual(1, self.store.find(Download).count())
        delete_user_data(self.store, ui.id)
        self.store.commit()
        self.assertEqual(0, self.store.find(StorageUserInfo).count())
        self.assertEqual(0, self.store.find(StorageObject).count())
        self.assertEqual(0, self.store.find(UserVolume).count())
        self.assertEqual(0, self.store.find(UploadJob).count())
        self.assertEqual(0, self.store.find(Download).count())


class TestSharing(ORMTestCase):
    """Tests for StorageUser."""

    def setUp(self):
        super(TestSharing, self).setUp()
        self.sharer = self.make_user(1, 'sammy')
        self.user = self.make_user(2, 'sherry')

    def test_get_unique_name(self):
        """Test get_unique_name."""
        name = Share.get_unique_name(self.store, self.user.id, 'name')
        self.assertEqual(name, 'name')
        share = Share(
            self.sharer.id, uuid.uuid4(), self.user.id, 'name', Share.VIEW)
        self.store.add(share)
        name = Share.get_unique_name(self.store, self.user.id, 'name')
        self.assertEqual(name, 'name~1')
        self.store.add(Share(
            self.sharer.id, uuid.uuid4(), self.user.id, 'name~1', Share.VIEW))
        self.store.add(Share(
            self.sharer.id, uuid.uuid4(), self.user.id, 'name~2', Share.VIEW))
        self.store.add(Share(
            self.sharer.id, uuid.uuid4(), self.user.id, 'name~3', Share.VIEW))
        name = Share.get_unique_name(self.store, self.user.id, 'name')
        self.assertEqual(name, 'name~4')

    def test_claim_share(self):
        """Test claiming a share offer that was sent to an email address."""
        root = StorageObject.get_root(self.store, self.sharer.id)
        share = Share(self.sharer.id, root.id, None, 'For friend',
                      Share.VIEW, email='fake@example.com')
        self.store.add(share)
        filesync_tm.commit()
        # Sammy has shared 1 folder
        self.assertEqual(self.sharer.sharedby_folders.count(), 1)
        # Sherry shouldn't see any shares yet, she hasn't accepted it
        self.assertEqual(self.user.sharedto_folders.count(), 0)
        # now claim the share for Sherry just like the Web UI would.
        share.claim_share(self.store, self.user.id)
        filesync_tm.commit()
        # Sherry should now see the share
        self.assertEqual(self.user.sharedto_folders.count(), 1)
        child = root.make_subdirectory("subd'1")
        share = Share(self.sharer.id, child.id, None, 'For friend',
                      Share.VIEW, email='fake@example.com')
        self.store.add(share)
        share.claim_share(self.store, self.user.id)
        self.assertEqual(share.name, 'For friend~1')

    def test_user_shared(self):
        """Test the sharedto_folders/by of StorageUser"""
        root = StorageObject.get_root(self.store, self.sharer.id)
        # Sammy Shouldn't show sharing stuff
        self.assertEqual(self.sharer.sharedby_folders.count(), 0)
        # Sherry shouldn't see shares
        self.assertEqual(self.user.sharedto_folders.count(), 0)
        # Sharer shares something so sherry should see shares soon
        root = StorageObject.get_root(self.store, self.sharer.id)
        share = Share(self.sharer.id, root.id, self.user.id,
                      'Share Name', Share.VIEW)
        self.store.add(share)
        filesync_tm.commit()
        # Sammy Should show sharing stuff
        self.assertEqual(self.sharer.sharedby_folders.count(), 1)
        # Seeing shares sherry smiles
        self.assertEqual(self.user.sharedto_folders.count(), 1)


class TestContentBlob(ORMTestCase):
    """Tests for ContentBlob."""

    def test_create(self):
        """Tests the creation of a ContentBlob."""
        cb = self.create(ContentBlob, **self.factory.content_blob_args())
        self.assertNotEqual(cb.when_created, None)

    def test_make_empty(self):
        """Tests an empty ContentBlob."""
        self.store.find(ContentBlob).remove()
        cb = ContentBlob.make_empty(self.store)
        filesync_tm.commit()
        self.assertNotEqual(cb.when_created, None)


class TestStorageObjectBase(ORMTestCase):
    """Base class for tests for StorageObject."""

    def createStorageObject(self, fname='file.ext'):
        """Helper function to create an StorageObject."""
        self.create(ContentBlob, **self.factory.content_blob_args())
        u = self.factory.make_user()
        root = StorageObject.get_root(self.store, u.id)
        obj = root.make_file(fname)
        return u, root, obj

    def createUDF(self):
        """Helper function to create an UDF's root."""
        user = self.factory.make_user()
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        root = self.store.get(StorageObject, udf.root_id)
        return user, root


class TestStorageObject(TestStorageObjectBase):
    """Base class for tests for StorageObject."""

    def test_create(self):
        """minimal test"""
        user, root, obj = self.createStorageObject()
        self.failIf(user is None, 'error creating user')
        self.failIf(root is None, 'error creating root')
        self.failIf(obj is None, 'error creating object')

    def test_create_root(self):
        """Create a standard root."""
        user = self.factory.make_user()
        node = StorageObject.get_root(self.store, user.id)

        # check node properties
        self.assertEqual(node.owner_id, user.id)
        self.assertEqual(node.path, '/')
        self.assertEqual(node.name, '')
        self.assertEqual(node.parent, None)
        self.assertEqual(node.kind, StorageObject.DIRECTORY)
        self.assertEqual(node.status, STATUS_LIVE)
        self.assertEqual(node.generation, 0)
        self.assertEqual(node.generation_created, 0)

    def test_make_with_no_name(self):
        """Test make_file and make_directory with no name."""
        user = self.factory.make_user()
        root_node = StorageObject.get_root(self.store, user.id)
        self.assertRaises(errors.StorageError, root_node.make_file, '')
        self.assertRaises(errors.StorageError, root_node.make_file, None)
        self.assertRaises(
            errors.StorageError, root_node.make_subdirectory, '')
        self.assertRaises(
            errors.StorageError, root_node.make_subdirectory, '')

    def test_create_a_node_in_a_root(self):
        """Create a regular node inside a standard root."""
        user = self.factory.make_user()
        root_node = StorageObject.get_root(self.store, user.id)
        # change the generaiton of the volume
        root_node.volume.generation = 12
        obj = root_node.make_file('file.ext')

        # check node properties
        self.assertEqual(obj.owner_id, user.id)
        self.assertEqual(obj.path, '/')
        self.assertEqual(obj.name, 'file.ext')
        self.assertEqual(obj.parent.id, root_node.id)
        self.assertEqual(obj.kind, StorageObject.FILE)
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.volume_id, root_node.volume_id)
        self.assertEqual(obj.generation, 13)
        self.assertEqual(obj.generation_created, 13)

    def test_create_a_node_in_an_udf(self):
        """Create a regular node inside an UDF."""
        user, udf_node = self.createUDF()
        obj = udf_node.make_file('file.ext')

        # check node properties
        self.assertEqual(obj.owner_id, user.id)
        self.assertEqual(obj.path, '/')
        self.assertEqual(obj.name, 'file.ext')
        self.assertEqual(obj.parent.id, udf_node.id)
        self.assertEqual(obj.kind, StorageObject.FILE)
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.volume_id, udf_node.volume_id)

    def test_public_flag(self):
        """Test the is_public flag on storage objects."""
        user, root, obj = self.createStorageObject()
        self.assert_(not obj.is_public,
                     'Object should not be public by default')
        # Any non-null value for publicfile_id makes the file public.
        obj.publicfile_id = 42
        self.assert_(obj.is_public,
                     'Should be possible to make object public')

    def test_update_generation(self):
        """Test update_generation."""
        user, root, obj = self.createStorageObject()
        root.volume.generation = 12
        self.assertEqual(obj.generation, 1)
        obj.update_generation()
        self.assertEqual(obj.generation, 13)

    def test_lock_for_update(self):
        """Make sure lock_for_update locks the object"""
        user = self.make_user(1, 'f')
        root = StorageObject.get_root(self.store, user.id)
        filesync_tm.commit()
        root.lock_for_update()
        self.failed = False

        def try_update():
            """try to update the locked record"""
            try:
                dir = self.store.get(StorageObject, root.id)
                dir.lock_for_update()
            except psycopg2.OperationalError:
                self.failed = True

        thread = threading.Thread(target=try_update)
        thread.start()
        thread.join()
        self.assertTrue(self.failed)

    def test_path_startswith(self):
        """Make sure the path_startwith function is correct"""
        n = StorageObject(1, 'NodeName', StorageObject.DIRECTORY)
        self.assertEqual(get_path_startswith(n), '/NodeName/')
        n.path = '/a/b/c/d'
        self.assertEqual(get_path_startswith(n), '/a/b/c/d/NodeName/')
        n.name = ''
        self.assertEqual(get_path_startswith(n), '/a/b/c/d/')
        n.path = ''
        self.assertEqual(get_path_startswith(n), '/')

    def test_lock_tree_for_update(self):
        """Make sure lock_for_update locks the object"""
        user = self.make_user(1, 'f')
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        root = self.store.get(StorageObject, udf.root_id)
        child = root.make_subdirectory("subd'1")
        childx = root.make_subdirectory("subd'11")
        # making paths are handled correctly
        childx2 = childx.make_subdirectory("subd'11")
        child2 = child.make_subdirectory('subd2')
        # make sure this user's objects aren't locked
        userA = self.make_user(2, 'a')
        userA_root = StorageObject.get_root(self.store, userA.id)
        userA_child = userA_root.make_subdirectory("subd'1")
        userA_childx = userA_child.make_subdirectory("subd'1")
        userA_childx1 = userA_childx.make_subdirectory("subd'1")

        filesync_tm.commit()
        child.lock_tree_for_update()
        self.failed = False

        def try_update(id=root.id):
            """try to update the locked record"""
            try:
                dir = self.store.get(StorageObject, id)
                dir.lock_for_update()
                self.failed = False
            except psycopg2.OperationalError:
                self.failed = True
            finally:
                self.store.rollback()

        def test_it(id, fail):
            """Test the nodeid update"""
            thread = threading.Thread(target=try_update, kwargs={'id': id})
            thread.start()
            thread.join()
            self.assertEqual(self.failed, fail)

        test_it(childx2.id, False)
        test_it(root.id, False)
        # this should fail
        test_it(child2.id, True)

        test_it(userA_root.id, False)
        test_it(userA_child.id, False)
        test_it(userA_childx.id, False)
        # the next one was being locked due to lack of owner_id checking
        test_it(userA_childx1.id, False)

    def test_lock_tree_for_update_root(self):
        """Make sure lock_for_update locks the object"""
        user = self.make_user(1, 'f')
        root = StorageObject.get_root(self.store, user.id)
        child1 = root.make_subdirectory("subd'1")
        child2 = child1.make_subdirectory("subd'1")
        # create files with the same paths but on a udf (different volume_id)
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        udf_root = self.store.get(StorageObject, udf.root_id)
        udf_child1 = udf_root.make_subdirectory("subd'1")
        udf_child2 = udf_child1.make_subdirectory("subd'1")
        filesync_tm.commit()
        self.failed = False
        root.lock_tree_for_update()

        def try_update(id=root.id):
            """try to update the locked record"""
            try:
                dir = self.store.get(StorageObject, id)
                dir.lock_for_update()
                self.failed = False
            except psycopg2.OperationalError:
                self.failed = True
            finally:
                self.store.rollback()

        def test_it(id, fail):
            """Test the nodeid update"""
            thread = threading.Thread(target=try_update, kwargs={'id': id})
            thread.start()
            thread.join()
            self.assertEqual(self.failed, fail)

        test_it(child1.id, True)
        test_it(child2.id, True)
        test_it(udf_child1.id, False)
        test_it(udf_child2.id, False)

    def test_filename_validation(self):
        """Tests that the model validates filenames when creating files or
        directories."""
        user = self.make_user(1, 'f')
        root = StorageObject.get_root(self.store, user.id)
        self.assertRaises(errors.InvalidFilename,
                          root.make_subdirectory, 'Beta/Licorice')
        self.assertRaises(errors.InvalidFilename,
                          root.make_file, 'Beta/Licorice')

    def test_has_children(self):
        """Test to make sure has_children works with different deletions."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        self.assertFalse(root._has_children())
        subdir = root.make_subdirectory('subdir')
        file = root.make_file('file')
        self.assertTrue(root._has_children())
        file.unlink()
        subdir.unlink()
        self.assertFalse(root._has_children())
        subdir = root.make_subdirectory('subdir')
        subdir.make_subdirectory('subdir')
        subdir.make_file('file2')
        subdir.make_file('file3')
        subdir.make_file('file4')
        subdir.make_file('file5')
        self.assertTrue(root._has_children())
        subdir.unlink_tree()
        self.assertFalse(root._has_children())

    def test_storage_stats(self):
        """Test the storage stats for a user"""
        user = self.make_user(1, 'f')
        info = self.store.get(StorageUserInfo, 1)
        root = StorageObject.get_root(self.store, user.id)
        sub = root.make_subdirectory('My Subfolder')
        used = info.used_storage_bytes
        self.assertEqual(used, 0)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        for i in range(100):
            file = sub.make_file('File%s' % i)
            file.content = content
            self.store.add(file)
            if i % 2 == 0:
                file.unlink()
        filesync_tm.commit()
        used = info.used_storage_bytes
        self.assertEqual(used, 51200L)

    def test_storage_stats_in_UDF(self):
        """Test the storage stats for a user using an UDF."""
        user, udf_root = self.createUDF()
        info = self.store.get(StorageUserInfo, user.id)
        sub = udf_root.make_subdirectory('My Subfolder')

        # check when empty
        self.assertEqual(info.used_storage_bytes, 0)

        # create some nodes
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        for i in range(10):
            file = sub.make_file('File%s' % i)
            file.content = content
            self.store.add(file)
            if i % 2 == 0:
                file.unlink()
        filesync_tm.commit()

        # check after the creation
        self.assertEqual(info.used_storage_bytes, 5120)

    def test_get_root_udf(self):
        """Tests get_root when having an UDF."""
        user, root, obj = self.createStorageObject()
        UserVolume.create(self.store, user.id, '~/Path/Dir')
        root2 = StorageObject.get_root(self.store, user.id)
        self.assertEqual(root2, root, 'root should be returned')

    def test_make_directory(self):
        """Tests make_subdirectory."""
        user, root, obj = self.createStorageObject()
        newnode = root.make_subdirectory('subdir')
        self.assertEqual(newnode.parent.id, root.id)
        self.assertEqual(newnode.volume_id, root.volume_id)

    def test_make_directory_udf(self):
        """Tests make_subdirectory in the udf."""
        user, udf_root = self.createUDF()
        newnode = udf_root.make_subdirectory('subdir')
        self.assertEqual(newnode.parent.id, udf_root.id)
        self.assertEqual(newnode.volume_id, udf_root.volume_id)

    def test_path(self):
        """Tests that the path is well constructed."""
        user, root, obj = self.createStorageObject()
        node1 = root.make_subdirectory('subdir')
        filesync_tm.commit()
        self.assertEqual(node1.path, '/')

        node2 = node1.make_subdirectory('otherdir')
        self.assertEqual(node2.path, '/subdir')

    def test_path_udf(self):
        """Tests that the path is well constructed for an udf."""
        user, udf_root = self.createUDF()
        node1 = udf_root.make_subdirectory('subdir')
        filesync_tm.commit()
        self.assertEqual(node1.path, '/')

        node2 = node1.make_subdirectory('otherdir')
        self.assertEqual(node2.path, '/subdir')

    def test_udf_trailing_slashes(self):
        """Tests that the path for an udf doesn't have trailing slashes."""
        user = self.factory.make_user()
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF/')
        filesync_tm.commit()
        self.assertEqual(udf.path, '~/Documents/Stuff/DirToUDF')

    def test_move_no_name(self):
        """Test to make sure move with no name errors."""
        user, root, obj = self.createStorageObject()
        self.assertRaises(errors.InvalidFilename, obj.move, root.id, '')
        self.assertRaises(errors.InvalidFilename, obj.move, root.id, None)

    def test_path_move_file(self):
        """Tests that the path changes when moving the file."""
        user, root, obj = self.createStorageObject()
        subdir1 = root.make_subdirectory('subdir1')
        subdir11 = subdir1.make_subdirectory('subdir11')
        subdir2 = root.make_subdirectory('subdir2')
        filesync_tm.commit()

        self.assertEqual(obj.path, '/')

        obj.move(subdir1.id, obj.name)
        self.assertEqual(obj.path, '/subdir1')

        obj.move(subdir11.id, obj.name)
        self.assertEqual(obj.path, '/subdir1/subdir11')

        obj.move(subdir2.id, obj.name)
        self.assertEqual(obj.path, '/subdir2')

        obj.move(root.id, obj.name)
        self.assertEqual(obj.path, '/')

    def test_path_move_file_udf(self):
        """Tests that the path changes when moving the file in an UDF."""
        user, udf_root = self.createUDF()
        obj = udf_root.make_file('file.ext')

        subdir1 = udf_root.make_subdirectory('subdir1')
        subdir11 = subdir1.make_subdirectory('subdir11')
        subdir2 = udf_root.make_subdirectory('subdir2')
        filesync_tm.commit()

        self.assertEqual(obj.path, '/')

        obj.move(subdir1.id, obj.name)
        self.assertEqual(obj.path, '/subdir1')

        obj.move(subdir11.id, obj.name)
        self.assertEqual(obj.path, '/subdir1/subdir11')

        obj.move(subdir2.id, obj.name)
        self.assertEqual(obj.path, '/subdir2')

        obj.move(udf_root.id, obj.name)
        self.assertEqual(obj.path, '/')

    def test_path_move_file_between_volumes(self):
        """Test that no move is allowed between volumes."""
        user, root, obj = self.createStorageObject()
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        udf_root = self.store.get(StorageObject, udf.root_id)
        obj = root.make_file('file2.ext')
        self.assertRaises(
            errors.StorageError, obj.move, udf_root.id, obj.name)

    def test_path_move_dir(self):
        """Tests that the path changes when moving the dir."""
        user, root, obj = self.createStorageObject()
        subdir1 = root.make_subdirectory("sub'dir1")
        subdir11 = subdir1.make_subdirectory("sub'dir11")
        subdir2 = root.make_subdirectory("sub'dir2")
        filesync_tm.commit()

        self.assertEqual(subdir11.path, "/sub'dir1")
        subdir11.move(subdir2.id, subdir11.name)
        self.assertEqual(subdir11.path, "/sub'dir2")

    def test_path_move_dir_grandparent(self):
        """Tests a move to grandparent."""
        user, root, obj = self.createStorageObject()
        subdir1 = root.make_subdirectory('dir')
        subdir2 = subdir1.make_subdirectory('dir')
        subdir3 = subdir2.make_subdirectory('dir')
        filesync_tm.commit()

        subdir3.move(subdir1.id, 'newname')
        self.assertEqual(subdir3.path, '/dir')
        self.assertEqual(subdir3.name, 'newname')
        self.assertEqual(subdir3.full_path, '/dir/newname')

    def test_path_move_deeptree(self):
        """Tests a very deep inside move."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('sub')
        all_dirs = [subdir]
        for i in range(1000):  # bigger than the limit for recursive calls
            subdir = subdir.make_subdirectory('x')
            all_dirs.append(subdir)
        filesync_tm.commit()

        grand_parent = all_dirs[-3]  # -1 is the tree's leaf, -2 is parent
        subdir.move(grand_parent.id, 'y')

    def test_path_move_dir_udf(self):
        """Tests that the path changes when moving the dir in an UDF."""
        _, udf_root = self.createUDF()
        subdir1 = udf_root.make_subdirectory("sub'dir1")
        subdir11 = subdir1.make_subdirectory("sub'dir11")
        subdir2 = udf_root.make_subdirectory("sub'dir2")
        filesync_tm.commit()

        self.assertEqual(subdir11.path, "/sub'dir1")
        subdir11.move(subdir2.id, subdir11.name)
        self.assertEqual(subdir11.path, "/sub'dir2")

    def test_move_udf_root(self):
        """Test that the root of an UDF can not be moved or renamed."""
        user, udf_root = self.createUDF()
        self.assertRaises(errors.StorageError, udf_root.unlink)
        subdir1 = udf_root.make_subdirectory('subdir1')
        subdir11 = subdir1.make_subdirectory('subdir11')
        filesync_tm.commit()

        # don't move to subdir 11
        self.assertRaises(
            errors.InvalidFilename, udf_root.move, subdir11.id, udf_root.name)

        # don't rename
        self.assertRaises(
            errors.NoPermission,
            udf_root.move, udf_root.parent_id, 'new name')

    def test_get_descendants(self):
        """Test the get descendants method."""
        # to test this, make volumes for this user with similar paths
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        self.assertTrue(root not in root.descendants)
        self.assertEqual(root.descendants.count(), 0)
        r_sub1 = root.make_subdirectory('sub1')
        r_sub2 = r_sub1.make_subdirectory('sub2')
        # an udf and three dirs in it
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        udf_root = self.store.get(StorageObject, udf.root_id)
        u_sub1 = udf_root.make_subdirectory('sub1')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub3 = u_sub2.make_subdirectory('sub3')
        u_sub4 = u_sub2.make_subdirectory('sub4')
        u_sub4.status = STATUS_DEAD
        self.assertEqual(root.descendants.count(), 2)
        self.assertEqual(udf_root.descendants.count(), 3)
        self.assertTrue(u_sub4 not in udf_root.descendants)
        for n in [r_sub1, r_sub2]:
            self.assertTrue(n in root.descendants)
        for n in [u_sub1, u_sub2, u_sub3]:
            self.assertTrue(n in udf_root.descendants)

    def test_get_descendants_by_kind(self):
        """Test the get descendants filtering by kind."""
        # to test this, make volumes for this user with similar paths
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        self.assertTrue(root not in root.descendants)
        self.assertEqual(root.descendants.count(), 0)
        r_sub1 = root.make_subdirectory('sub1')
        r_sub1.make_file('sub1_file.ext')
        r_sub2 = r_sub1.make_subdirectory('sub2')
        r_sub2.make_file('sub2_file.ext')
        # an udf and three dirs in it
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        udf_root = self.store.get(StorageObject, udf.root_id)
        u_sub1 = udf_root.make_subdirectory('sub1')
        # create a few files
        u_sub1.make_file('sub1_file.ext')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub2.make_file('sub2_file.ext')
        u_sub3 = u_sub2.make_subdirectory('sub3')
        u_sub3.make_file('sub3_file.ext')
        u_sub4 = u_sub2.make_subdirectory('sub4')
        u_sub4.status = STATUS_DEAD
        self.assertEqual(
            root.get_descendants(kind=StorageObject.FILE).count(), 2)
        self.assertEqual(
            root.get_descendants(kind=StorageObject.DIRECTORY).count(), 2)
        self.assertEqual(root.get_descendants(kind=None).count(), 4)
        self.assertEqual(
            udf_root.get_descendants(kind=StorageObject.FILE).count(), 3)
        self.assertEqual(
            udf_root.get_descendants(kind=StorageObject.DIRECTORY).count(), 3)
        self.assertEqual(udf_root.get_descendants(kind=None).count(), 6)

    def test_tree_size(self):
        """Test to make sure tree size works"""
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        info.max_storage_bytes = 50 * (2 ** 30)
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        self.assertEqual(0, info.used_storage_bytes)
        self.assertEqual(0, subdir.tree_size)
        file_size = self.factory.content_blob_args()['size']
        content = self.create(ContentBlob, **self.factory.content_blob_args())

        def add_tree_and_files(dir, name):
            """Add a subtree and 100 files"""
            sub = dir.make_subdirectory(name)
            for i in range(100):
                file = sub.make_file('%s-%s' % (sub.name, i))
                file.content = content
            return sub
        # create 3 subdirectories (300 files)
        subdira = add_tree_and_files(subdir, "subdir'1")
        subdirb = add_tree_and_files(subdira, "subdir'11")
        subdirc = add_tree_and_files(subdirb, "subdir'111")
        # these folders have a similar path pattern, but will be included
        root = StorageObject.get_root(self.store, user.id)
        subdirx = root.make_subdirectory("subdir'1")
        subdirxx = add_tree_and_files(subdirx, "subdir'1")
        subdirxxx = add_tree_and_files(subdirxx, "subdir'11")
        add_tree_and_files(subdirxxx, "subdir'111")

        self.assertEqual(file_size * 600, info.used_storage_bytes)
        self.assertEqual(info.used_storage_bytes, root.tree_size)
        self.assertEqual(file_size * 300, subdira.tree_size)
        self.assertEqual(file_size * 200, subdirb.tree_size)
        self.assertEqual(file_size * 100, subdirc.tree_size)
        self.assertEqual(file_size * 300, subdir.tree_size)
        self.store.commit()
        # hey...lets go ahead an unlink it
        subdir.unlink_tree()
        # we should still have the files not incuded
        self.assertEqual(file_size * 300, subdirx.tree_size)
        self.assertEqual(file_size * 300, info.used_storage_bytes)
        self.assertEqual(0, subdir.tree_size)

    def test_tree_size_with_mixed_udfs(self):
        """Test to make sure tree size works"""
        # a root and two dirs in it
        user, root, obj = self.createStorageObject()
        r_sub1 = root.make_subdirectory('sub1')
        r_sub2 = r_sub1.make_subdirectory('sub2')

        # an udf and three dirs in it
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        udf_root = self.store.get(StorageObject, udf.root_id)
        u_sub1 = udf_root.make_subdirectory('sub1')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub3 = u_sub2.make_subdirectory('sub3')

        # create a content of 100
        args = self.factory.content_blob_args()
        args['size'] = 100
        content = self.create(ContentBlob, ** args)

        # add a file in these dirs, with that small content
        for sub in (r_sub1, r_sub2, u_sub1, u_sub2, u_sub3):
            file = sub.make_file('file in %s' % (sub.name,))
            file.content = content
        filesync_tm.commit()

        # trees sizes should be separated
        self.assertEqual(200, r_sub1.tree_size)
        self.assertEqual(300, u_sub1.tree_size)

    def test_build_tree_from_path_basic(self):
        """Test build_tree_from_path."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('subdir')
        d = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d.full_path, '/subdir/a/b/c/d/e')
        d2 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d.id, d2.id)
        self.assertEqual(d2.full_path, '/subdir/a/b/c/d/e')
        # check the subdirectories:
        nodes = self.store.find(StorageObject)
        paths = [
            n.full_path for n in nodes if n.kind == StorageObject.DIRECTORY]
        # seven directories including root
        self.assertEqual(len(paths), 7)
        self.assertTrue('/' in paths)
        self.assertTrue('/subdir' in paths)
        self.assertTrue('/subdir/a' in paths)
        self.assertTrue('/subdir/a/b' in paths)
        self.assertTrue('/subdir/a/b/c' in paths)
        self.assertTrue('/subdir/a/b/c/d' in paths)
        self.assertTrue('/subdir/a/b/c/d/e' in paths)

    def test_build_tree_from_path_with_file(self):
        """Test build_tree_from_path with multiple dead nodes."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('subdir')
        d = subdir.make_subdirectory('a')
        d.unlink()
        d = subdir.make_subdirectory('a')
        d.unlink()
        d3 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d3.full_path, '/subdir/a/b/c/d/e')
        # multiple calls return the same directory and path
        d4 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d4.full_path, '/subdir/a/b/c/d/e')
        self.assertEqual(d3.id, d4.id)

    def test_build_tree_from_path_with_file2(self):
        """Test build_tree_from_path."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('subdir')
        d = subdir.build_tree_from_path('/a/b/c')
        # create a file with the same name as a perspective directory, this
        # will end up in a different named folder path
        d.make_file('d')
        d2 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d2.full_path, '/subdir/a/b/c/d~1/e')
        self.assertEqual(d.status, STATUS_LIVE)
        # check the subdirectories:
        nodes = self.store.find(StorageObject)
        paths = [
            n.full_path for n in nodes if n.kind == StorageObject.DIRECTORY]
        # seven directories including root
        self.assertEqual(len(paths), 7)
        self.assertTrue('/' in paths)
        self.assertTrue('/subdir' in paths)
        self.assertTrue('/subdir/a' in paths)
        self.assertTrue('/subdir/a/b' in paths)
        self.assertTrue('/subdir/a/b/c' in paths)
        self.assertTrue('/subdir/a/b/c/d~1' in paths)
        self.assertTrue('/subdir/a/b/c/d~1/e' in paths)

    def test_unlink_tree_exception(self):
        """Test unlink tree exceptions"""
        user, root, obj = self.createStorageObject()
        self.assertRaises(errors.NotADirectory, obj.unlink_tree)

    def test_unlink_tree_basic(self):
        """Tests that a shared object and the Share are deleted"""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('subdir')
        subdira = subdir.make_subdirectory('subdira')
        subdirab = subdira.make_subdirectory('subdirab')
        subdirabc = subdirab.make_subdirectory('subdiraaa')
        subdirac = subdira.make_subdirectory('subdiraaa')
        # due to a bug (488412) in the path check, this was added
        subdirxxx = root.make_subdirectory('subdiraa')
        subdirxxx1 = subdirxxx.make_subdirectory('subdirxxx1')
        self.assertEqual(subdirxxx.generation, 7)
        subdir.unlink_tree()
        filesync_tm.commit()
        gen = self.store.find(
            Max(StorageObject.generation),
            StorageObject.owner_id == user.id)[0]
        self.assertEqual(subdir.volume.generation, gen)
        self.assertEqual(subdir.status, STATUS_DEAD)
        self.assertEqual(subdira.status, STATUS_DEAD)
        self.assertEqual(subdirab.status, STATUS_DEAD)
        self.assertEqual(subdirabc.status, STATUS_DEAD)
        self.assertEqual(subdirac.status, STATUS_DEAD)
        # this node didn't change
        self.assertEqual(subdirxxx.status, STATUS_LIVE)
        self.assertEqual(subdirxxx.generation, 7)
        # this bug is fixed
        self.assertEqual(subdirxxx1.status, STATUS_LIVE)

    def test_unlink_tree_calls_transaction_log_recording_method(self):
        directory = self.factory.make_directory()
        self.factory.make_file(parent=directory)

        with patch.object(TransactionLog, 'record_unlink_tree') as mock_unlink:
            directory.unlink_tree()
            mock_unlink.assert_called_once_with(directory)

    def test_unlink_tree_basic_bigname(self):
        """Test a big name inside the tree of what is deleted."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('subdir')
        subdir.make_subdirectory('f' * 255)  # big filename
        subdir.unlink_tree()
        filesync_tm.commit()

    def test_unlink_tree_udfmixed(self):
        """Tests deleting things with same paths in different volumes."""
        # a root and two dirs in it
        user, root, obj = self.createStorageObject()
        r_sub1 = root.make_subdirectory('sub1')
        r_sub2 = r_sub1.make_subdirectory('sub2')

        # an udf and three dirs in it
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        udf_root = self.store.get(StorageObject, udf.root_id)
        u_sub1 = udf_root.make_subdirectory('sub1')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub3 = u_sub2.make_subdirectory('sub3')

        # remove the sub 1 in root
        r_sub1.unlink_tree()
        filesync_tm.commit()

        # check
        self.assertEqual(r_sub1.status, STATUS_DEAD)
        self.assertEqual(r_sub2.status, STATUS_DEAD)
        self.assertEqual(u_sub1.status, STATUS_LIVE)
        self.assertEqual(u_sub2.status, STATUS_LIVE)
        self.assertEqual(u_sub3.status, STATUS_LIVE)

    def test_unlink(self):
        """Test the the unlink object method."""
        user, root, obj = self.createStorageObject()
        filesync_tm.commit()
        parent = obj.parent
        self.assertTrue(parent._has_children())
        obj.unlink()
        filesync_tm.commit()
        self.assertFalse(parent._has_children())
        self.assertEqual(obj.status, STATUS_DEAD)

    def test_unlink_calls_transaction_log_recording_method(self):
        f = self.factory.make_file()

        with patch.object(TransactionLog, 'record_unlink') as mock_unlink:
            f.unlink()
            mock_unlink.assert_called_once_with(f)

    def test_unlink_udf(self):
        """Test unlinking inside an UDF."""
        _, udf_root = self.createUDF()
        obj = udf_root.make_file('file.ext')
        obj.unlink()
        self.assertEqual(obj.status, STATUS_DEAD)

    def test_unlink_udfroot(self):
        """Test that the root of an UDF can not be unlinked."""
        _, udf_root = self.createUDF()
        self.assertRaises(errors.StorageError, udf_root.unlink)

    def test_get_unique_childname(self):
        """Test the get_unique_childname method."""
        user, root, obj = self.createStorageObject()
        f1 = root.make_file('filename.ext')
        f2 = root.make_file('filename2.ext')
        f2.unlink()
        name = root.get_unique_childname(f1.name)
        self.assertEqual(name, 'filename~1.ext')
        # since f2 is Dead, it's name can be used.
        name = root.get_unique_childname(f2.name)
        self.assertEqual(name, f2.name)
        # it won't overwrite user created files.
        for i in range(1, 5):
            root.make_file('filename~%s.ext' % i)
        name = root.get_unique_childname(f1.name)
        self.assertEqual(name, 'filename~5.ext')

    def test_undelete_newparent(self):
        """Tests undelete into a new parent."""
        user, root, obj = self.createStorageObject()
        self.assertTrue(root._has_children())
        filesync_tm.commit()
        self.assert_(obj in root.children)
        obj.unlink()
        filesync_tm.commit()
        self.assertFalse(root._has_children())
        parent = root.make_subdirectory('restore folder')
        obj.undelete(parent)
        filesync_tm.commit()
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.path, parent.full_path)
        self.assertEqual(obj.parent, parent)
        self.assertTrue(obj in parent.children)
        self.assertFalse(obj in root.children)
        self.assertTrue(root._has_children())

    def test_undelete_deadparent(self):
        """Tests undelete with a dead parent."""
        user, root, obj = self.createStorageObject()
        p1 = root.make_subdirectory('dir1')
        p2 = p1.make_subdirectory('dir2')
        file1 = p2.make_file('file.txt')
        filesync_tm.commit()
        self.assertEqual(p1._has_children(), True)
        self.assertEqual(p1.status, STATUS_LIVE)
        self.assertEqual(p2._has_children(), True)
        self.assertEqual(p2.status, STATUS_LIVE)
        p1.unlink_tree()
        file1.undelete()
        self.assertEqual(p1._has_children(), True)
        self.assertEqual(p1.status, STATUS_LIVE)
        self.assertEqual(p2._has_children(), True)
        self.assertEqual(p2.status, STATUS_LIVE)

    def test_undelete_inplace(self):
        """Tests undelete in place."""
        user, root, obj = self.createStorageObject()
        self.assertTrue(obj in root.children)
        obj.unlink()
        self.assertEqual(obj.status, STATUS_DEAD)
        self.assertTrue(obj not in root.children)
        obj.undelete()
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.parent, root)
        self.assertTrue(obj in root.children)

    def test_undelete_w_reparent(self):
        """Test undelete with conflicting name."""
        user, root, obj = self.createStorageObject()
        p1 = root.make_subdirectory('dir1')
        file1 = p1.make_file('file1.txt')
        p1.make_file('file2.txt')
        # delete p1
        p1.unlink_tree()
        # create a new directory with the same name
        # all files in d1 should be restored to this directory
        p1a = root.make_subdirectory('dir1')
        file1.undelete()
        # make sure the path and parent are correct
        self.assertEqual(file1.path, '/dir1')
        self.assertEqual(file1.parent_id, p1a.id)

    def test_undelete_volume(self):
        """Test undelete_volume."""
        user, user_root, obj = self.createStorageObject()
        vol1 = UserVolume.create(self.store, user.id, '~/v1')
        restore_dir = vol1.root_node.make_subdirectory('r1')
        a = vol1.root_node.make_subdirectory('a')
        b = a.make_subdirectory('b')
        c = b.make_subdirectory('c')
        node1 = c.make_file('file1.txt')
        node2 = c.make_file('file2.txt')
        a.unlink_tree()
        filesync_tm.commit()
        self.assertEqual(node1.status, STATUS_DEAD)
        self.assertEqual(node2.status, STATUS_DEAD)
        undelete_volume(self.store, user.id, vol1.id, restore_dir)
        self.assertEqual(node1.path, '/r1/a/b/c')
        self.assertEqual(node1.status, STATUS_LIVE)
        self.assertEqual(node1.parent.full_path, '/r1/a/b/c')
        self.assertEqual(node1.parent.status, STATUS_LIVE)
        self.assertEqual(node2.path, '/r1/a/b/c')
        self.assertEqual(node2.status, STATUS_LIVE)
        self.assertEqual(node2.parent.full_path, '/r1/a/b/c')
        self.assertEqual(node2.parent.status, STATUS_LIVE)
        self.assertEqual(node1.parent_id, node2.parent_id)

    def test_undelete_volume_limit(self):
        """Test undelete_volume with limit."""
        user, user_root, obj = self.createStorageObject()
        vol1 = UserVolume.create(self.store, user.id, '~/v1')
        restore_dir = vol1.root_node.make_subdirectory('r1')
        a = vol1.root_node.make_subdirectory('a')
        b = a.make_subdirectory('b')
        c = b.make_subdirectory('c')
        node = c.make_file('file.txt')
        a.unlink_tree()
        # delete a bunch of files...these will not be restored
        del_files = [a.make_file('file%s.txt' % i) for i in range(100)]
        for f in del_files:
            f.unlink()
            filesync_tm.commit()
        # delete this file...this will get restored
        node.unlink()
        filesync_tm.commit()
        self.assertEqual(node.status, STATUS_DEAD)
        undelete_volume(self.store, user.id, vol1.id, restore_dir, limit=1)
        self.assertEqual(node.path, '/r1/a/b/c')
        self.assertEqual(node.status, STATUS_LIVE)
        for f in del_files:
            self.assertEqual(f.status, STATUS_DEAD)

    def test_path_middle_change(self):
        """Tests that the path changes when moving a parent of the file."""
        user, root, obj = self.createStorageObject()
        subdir1 = root.make_subdirectory('subdir1')
        subdir2 = root.make_subdirectory('subdir2')
        filesync_tm.commit()
        obj.move(subdir1.id, obj.name)
        self.assertEqual(obj.path, '/subdir1')

        subdir1.move(subdir2.id, subdir1.name)
        self.assertEqual(obj.path, '/subdir2/subdir1')

        subdir2.move(subdir2.parent.id, 'newdir2name')
        self.assertEqual(obj.path, '/newdir2name/subdir1')

        subdir1.move(root.id, subdir1.name)
        self.assertEqual(obj.path, '/subdir1')
        # when a parent is moved, dead children don't get path updates
        obj.status = STATUS_DEAD
        subdir1.move(subdir2.id, subdir1.name)
        # object's path is the same
        self.assertEqual(obj.path, '/subdir1')
        # object's parent is updated
        self.assertEqual(obj.parent.path, '/newdir2name')
        # since we're here, make sure the node path is rewritten on restore
        obj.undelete()
        self.assertEqual(obj.path, '/newdir2name/subdir1')

    def test_unlink_is_not_delete(self):
        """Tests that the object is deleted/removed from the store."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory('subdir')
        self.assertIsNotNone(subdir)
        filesync_tm.commit()
        parent = subdir.parent
        name = subdir.name
        # test subdir is 'there'
        self.assertIsNotNone(self.store.get(StorageObject, subdir.id))
        subdir.unlink()
        subdir2 = self.store.get(StorageObject, subdir.id)
        self.assertIsNotNone(subdir2)
        self.assertEqual(name, subdir2.name)
        self.assertEqual(parent, subdir2.parent)
        self.assertEqual(subdir2.status, STATUS_DEAD)

    def test_unlink_is_not_delete_udf(self):
        """Tests that the object is deleted/removed from the udf."""
        user, udf_root = self.createUDF()
        subdir = udf_root.make_subdirectory('subdir')
        filesync_tm.commit()

        # test subdir is 'there', and remove it
        self.assertIsNotNone(
            self.store.get(StorageObject, subdir.id))
        subdir.unlink()

        subdir2 = self.store.get(StorageObject, subdir.id)
        self.assertIsNotNone(subdir2)
        self.assertEqual('subdir', subdir2.name)
        self.assertEqual(udf_root, subdir2.parent)
        self.assertEqual(subdir2.status, STATUS_DEAD)

    def test_update_used_bytes(self):
        """Test the tracking of storage bytes used by a user"""
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        info.max_storage_bytes = 2 ** 18
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        self.assertEqual(0, info.used_storage_bytes)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)

        def add_file(name):
            """Adds a file to the user storage."""
            file = subdir.make_file(name)
            file.content = content
            self.store.add(file)
            return file

        for i in range(100):
            add_file('File%s' % i)

        filesync_tm.commit()
        self.assertEqual(info.used_storage_bytes,
                         self.factory.content_blob_args()['size'] * 100)

    def test_update_used_bytes_udf(self):
        """Test the tracking of storage bytes used by a user in an UDF."""
        user, udf_root = self.createUDF()
        info = self.store.get(StorageUserInfo, user.id)
        info.max_storage_bytes = 2 ** 18
        subdir = udf_root.make_subdirectory('subdir')
        filesync_tm.commit()

        self.assertEqual(0, info.used_storage_bytes)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)

        def add_file(name):
            """Adds a file to the user storage."""
            file = subdir.make_file(name)
            file.content = content
            self.store.add(file)
            return file

        for i in range(10):
            add_file('File%s' % i)

        filesync_tm.commit()
        self.assertEqual(info.used_storage_bytes,
                         self.factory.content_blob_args()['size'] * 10)

    def test_recalculate_used_bytes(self):
        """Test the recalculating used bytes."""
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, user.id)
        info.max_storage_bytes = 2 ** 18
        root = StorageObject.get_root(self.store, user.id)
        vol1 = UserVolume.create(self.store, user.id, '~/v1')
        vol2 = UserVolume.create(self.store, user.id, '~/v2')
        filesync_tm.commit()
        self.assertEqual(0, info.used_storage_bytes)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        expected_used = self.factory.content_blob_args()['size'] * 30

        def add_file(subdir, name):
            """Adds a file to the user storage."""
            file = subdir.make_file(name)
            file.content = content
            self.store.add(file)
            return file
        for i in range(10):
            add_file(root, 'File%s' % i)
            add_file(vol1.root_node, 'File%s' % i)
            add_file(vol2.root_node, 'File%s' % i)
        filesync_tm.commit()
        self.assertEqual(info.used_storage_bytes, expected_used)
        # we now have 3 volumes with data on them.
        info.used_storage_bytes = 100
        self.assertEqual(info.used_storage_bytes, 100)
        info.recalculate_used_bytes()
        self.assertEqual(info.used_storage_bytes, expected_used)
        # manually mark root files as Dead
        for c in root.children:
            c.status = STATUS_DEAD
        # manually change the volume status
        vol2.status = STATUS_DEAD
        self.assertEqual(info.used_storage_bytes, expected_used)
        info.recalculate_used_bytes()
        self.assertEqual(info.used_storage_bytes, expected_used * 1 / 3)

    def test_update_used_bytes_on_delete(self):
        """Test the tracking of storage bytes used by a user, when files
        are deleted.
        """
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        info.max_storage_bytes = 2 ** 18
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        self.assertEqual(0, info.used_storage_bytes)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        for i in range(100):
            file = subdir.make_file('File%s' % i)
            file.content = content
            self.store.add(file)
            if i % 2:
                file.unlink()
        filesync_tm.commit()
        self.assertEqual(info.used_storage_bytes,
                         self.factory.content_blob_args()['size'] * 50)

        file = subdir.make_file('Blah')
        file.content = content
        self.store.add(file)
        info.max_storage_bytes = 0
        file.unlink()  # should succeed even if we are over quota

    def test_update_used_bytes_on_delete_udf(self):
        """Test the tracking of bytes used, when files in UDF are deleted."""
        user, udf_root = self.createUDF()
        info = self.store.get(StorageUserInfo, user.id)
        info.max_storage_bytes = 2 ** 18
        subdir = udf_root.make_subdirectory('subdir')
        self.assertEqual(0, info.used_storage_bytes)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        for i in range(10):
            file = subdir.make_file('File%s' % i)
            file.content = content
            self.store.add(file)
            if i % 2:
                file.unlink()
        filesync_tm.commit()
        self.assertEqual(info.used_storage_bytes,
                         self.factory.content_blob_args()['size'] * 5)

        file = subdir.make_file('Blah')
        file.content = content
        self.store.add(file)
        info.max_storage_bytes = 0
        file.unlink()  # should succeed even if we are over quota

    def test_update_used_bytes_on_move(self):
        """Test the tracking of storage bytes used by a user, when
        files are moved.
        """
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        info.max_storage_bytes = 2 ** 18
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        subdir2 = root.make_subdirectory('subdir2')
        self.assertEqual(0, info.used_storage_bytes)
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        for i in range(100):
            file = subdir.make_file('File%s' % i)
            file.content = content
            self.store.add(file)
            if i % 2:
                file.move(subdir2.id, file.name)
        filesync_tm.commit()
        self.assertEqual(info.used_storage_bytes,
                         self.factory.content_blob_args()['size'] * 100)

    def test_update_last_modified_on_content(self):
        """Tests that when_last_modified is updated when the content changes"""
        user = self.make_user(1, 'a_test_user')
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        self.store.add(content)
        root = StorageObject.get_root(self.store, user.id)
        file = root.make_file('a_File')
        before = datetime.datetime.utcnow()
        file.content = content
        after = datetime.datetime.utcnow()
        self.assertTrue(after > file.when_last_modified > before)

    def test_update_last_modified_on_make(self):
        """Tests that when_last_modified is updated when the contents change"""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        before_file = datetime.datetime.utcnow()
        subdir.make_file('a_File')
        after_file = datetime.datetime.utcnow()
        self.assertTrue(after_file > subdir.when_last_modified > before_file)

        before_dir = datetime.datetime.utcnow()
        subdir.make_subdirectory('subsubdir')
        after_dir = datetime.datetime.utcnow()
        self.assertTrue(after_dir > subdir.when_last_modified > before_dir)

    def test_max_used_bytes(self):
        """Tests that used_storage_bytes accepts the max bigint value. """
        self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        max = 9223372036854775807  # max bigint value
        info.used_storage_bytes = max
        filesync_tm.commit()
        info = self.store.get(StorageUserInfo, 1)
        self.assertEqual(max, info.used_storage_bytes)

    def test_move_directory_into_itself(self):
        """Tests that a directory can't be moved into itself."""
        subdir = self.factory.make_directory()
        self.assertRaises(
            errors.NoPermission, subdir.move, subdir.id, subdir.name)

    def test_move_file_into_itself(self):
        """Tests that a file can't be moved into itself."""
        a_file = self.factory.make_file()
        self.assertRaises(
            errors.NoPermission, a_file.move, a_file.id, a_file.name)

    def test_move_no_op(self):
        """Do nothing when the new parent/name are equal the existing ones.

        If move() is called with the existing parent and name as arguments, it
        does nothing.
        """
        f = self.factory.make_file()
        old_generation = f.generation

        f.move(f.parent_id, f.name)

        self.assertEqual(old_generation, f.generation)

    def test_move_requires_uuid_for_new_parent_id(self):
        """move() will raise a TypeError if parent_id is a str."""
        f = self.factory.make_file()

        self.assertRaises(TypeError, f.move, str(uuid.uuid4()), f.name)

    def test_move_to_file(self):
        """Tests that a node can't be moved to a file."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        a_file = root.make_file('a_file')
        self.assertRaises(
            errors.NotADirectory, subdir.move, a_file.id, subdir.name)
        b_file = root.make_file('b_file')
        self.assertRaises(
            errors.NotADirectory, b_file.move, a_file.id, b_file.name)

    def test_move_to_child(self):
        """Tests that a node can't be moved to a child."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        subdir2 = subdir.make_subdirectory('subdir2')
        self.assertRaises(
            errors.NoPermission, subdir.move, subdir2.id, subdir.name)
        # move to a child file
        a_file = subdir2.make_file('a_file')
        self.assertRaises(
            errors.NotADirectory, subdir.move, a_file.id, a_file.name)

    def test_move_to_child_deeper(self):
        """Tests that a node can't be moved to a child."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        subdir = root.make_subdirectory('subdir')
        subdir1 = subdir.make_subdirectory('subdir1')
        subdir2 = subdir1.make_subdirectory('subdir2')
        self.assertRaises(
            errors.NoPermission, subdir.move, subdir2.id, subdir.name)
        # move to a child file
        a_file = subdir2.make_file('a_file')
        self.assertRaises(
            errors.NotADirectory, subdir.move, a_file.id, a_file.name)

    def test_move_to_inner_dir_specific_case(self):
        """Test a specific case of moving it down."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        dira = root.make_subdirectory('dira')
        dirb = dira.make_subdirectory('dirb')
        dirc = root.make_subdirectory('dirc')

        # this should be just fine
        dirc.move(dirb.id, dirc.name)

    def test_move_to_inner_dir_similar_name_1(self):
        """Test a case of moving it down with similar name."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        dir1 = root.make_subdirectory('foobar')
        dir2 = root.make_subdirectory('foobarX')

        # this should be just fine
        dir1.move(dir2.id, dir1.name)

    def test_move_to_inner_dir_similar_name_2(self):
        """Test a case of moving it down with similar name."""
        user = self.make_user(1, 'a_test_user')
        root = StorageObject.get_root(self.store, user.id)
        dir1 = root.make_subdirectory('foobarX')
        dir2 = root.make_subdirectory('foobar')

        # this should be just fine
        dir1.move(dir2.id, dir1.name)

    def test_has_volume_id_attribute(self):
        """Test that StorageObject has a volume_id attribute."""
        user, root, obj = self.createStorageObject()
        self.assertTrue(hasattr(obj, 'volume_id'))

    def test_volume_id_is_correct(self):
        """volume_id is the same as the node's parent."""
        user, root, obj = self.createStorageObject()
        self.assertEqual(obj.volume_id, obj.parent.volume_id)

    def test_volume_id_is_correct_on_children(self):
        """volume_id is the root's no matter how deep the node is."""
        user, root, obj = self.createStorageObject()
        subdir = root.make_subdirectory(name='A test')
        self.assertEqual(subdir.volume_id, root.volume_id)

        subfile = subdir.make_file(name='A file test.txt')
        self.assertEqual(subfile.volume_id, root.volume_id)

    def test_invalid_volume_id(self):
        """volume_id should be None or a valid UUID."""
        user, root, obj = self.createStorageObject()

        kwargs = dict(user_id=user.id, name='test.txt',
                      volume_id='yaddayadda',
                      kind=StorageObject.FILE, parent=obj)
        self.assertRaises(TypeError, StorageObject, ** kwargs)

    def test_get_node_parent_paths(self):
        """Test get_node_parent_paths."""
        user, root, node = self.createStorageObject()
        self.assertEqual(root.parent_paths, [])
        node.parent_id = uuid.uuid4()
        node.path = '/'
        expected = ['/']
        self.assertEqual(node.parent_paths, expected)
        node.path = '/a/b/c'
        expected = ['/', '/a', '/a/b', '/a/b/c']
        self.assertEqual(node.parent_paths, expected)

    def test_get_node_parentids(self):
        """Test get_node_parentids"""
        user, root, node = self.createStorageObject()
        pids = root.get_parent_ids()
        self.assertEqual(pids, [])
        dir1 = root.make_subdirectory('dir1')
        dir2 = dir1.make_subdirectory('dir2')
        dir3 = dir2.make_subdirectory('dir3')
        dir4 = dir3.make_subdirectory('dir4')
        dir5 = dir4.make_subdirectory('dir5')
        dir6 = dir5.make_subdirectory('dir6')
        pids = dir6.get_parent_ids()
        # 6 parents including root_id
        self.assertEqual(len(pids), 6)
        self.assertTrue(root.id in pids)
        self.assertTrue(dir1.id in pids)
        self.assertTrue(dir2.id in pids)
        self.assertTrue(dir3.id in pids)
        self.assertTrue(dir4.id in pids)
        self.assertTrue(dir5.id in pids)
        # the node itself is not included
        self.assertFalse(dir6.id in pids)

    def test_get_node_parentids_only_live(self):
        """Test that get_node_parentids only return Live nodes."""
        _, root, _ = self.createStorageObject()
        dir1 = root.make_subdirectory('dir1')
        dir2 = dir1.make_subdirectory('dir2')
        dir3 = dir2.make_subdirectory('dir3')
        leaf = dir3.make_subdirectory('leaf')
        pids = leaf.get_parent_ids()
        # 4 parents including root_id
        self.assertEqual(len(pids), 4)
        dir2.unlink_tree()
        # filesync_tm.commit()
        pids = leaf.get_parent_ids()
        # 2 parents (root_id and dir1)
        self.assertEqual(len(pids), 2)


class TestStorageObjectGenerations(TestStorageObjectBase):
    """Test generation handling in StorageObject methods."""

    def setUp(self):
        super(TestStorageObjectGenerations, self).setUp()
        self.usr = self.factory.make_user()
        self.volume = UserVolume.make_root(self.store, self.usr.id)
        self.root = self.volume.root_node

    def test_init_from_parent(self):
        """Make sure __init__ increments generation when from parent.

        This basically tests all the make_file, make_subdirectory methods.
        """
        start_gen = self.volume.generation
        # when an object is created it increments the gen.
        node = StorageObject(
            self.usr.id, 'n', StorageObject.FILE, parent=self.root)
        self.assertEqual(node.generation, start_gen + 1)

    def test_publicfile_id_property(self):
        """Generation is incremented when the publicfile_id is changed"""
        node = self.root.make_file('file.txt')
        start_gen = self.volume.generation
        node.publicfile_id = 12
        self.assertEqual(node.generation, start_gen + 1)

    def test_content_property(self):
        """Generation is incremented when content is updated."""
        cb = self.create(ContentBlob, **self.factory.content_blob_args())
        node = self.root.make_file('file.txt')
        start_gen = self.volume.generation
        node.content = cb
        self.assertEqual(node.generation, start_gen + 1)

    def test_move(self):
        """Move updates the generation of the moved node."""
        d1 = self.root.make_subdirectory('d1')
        node = d1.make_file('f1.txt')
        start_gen = self.volume.generation
        node.move(self.root.id, node.name)
        self.assertEqual(node.generation, start_gen + 1)

    def test_move_dir_special(self):
        """Test move directory to another with a % in it."""
        d1 = self.root.make_subdirectory('a%bc')
        d2 = self.root.make_subdirectory('x%yz')
        d2.move(d1.id, d2.name)
        self.assertEqual(d2.full_path, '/a%bc/x%yz')

    def test_move_rename(self):
        """Move rename updates the generation of the moved node."""
        node = self.root.make_subdirectory('d1')
        start_gen = self.volume.generation
        node.move(self.root.id, 'newname')
        self.assertEqual(node.generation, start_gen + 1)

    def test_move_with_backslash(self):
        """Move works also with backslash in the name."""
        node = self.root.make_subdirectory('break me')
        start_gen = self.volume.generation
        node.move(self.root.id, 'break\\347\\343it really\\355bad')
        filesync_tm.commit()
        self.assertEqual(node.generation, start_gen + 1)

    def test_unlink(self):
        """Unlink updates the generation of the moved node."""
        node = self.root.make_subdirectory('d1')
        start_gen = self.volume.generation
        node.unlink()
        self.assertEqual(node.generation, start_gen + 1)

    def test_unlink_tree(self):
        """Unlink Tree updates the generation of the moved node."""
        node = self.root.make_subdirectory('d1')
        d1 = node.make_subdirectory('d2')
        d2 = d1.make_subdirectory('d3')
        d1_gen = d1.generation
        d2_gen = d2.generation
        start_gen = self.volume.generation
        node.unlink_tree()
        self.assertEqual(node.generation, start_gen + 1)
        self.assertEqual(d1.generation, d1_gen)
        self.assertEqual(d2.generation, d2_gen)

    def test_undelete(self):
        """Undelete updates the generation of the moved node."""
        node = self.root.make_subdirectory('d1')
        node.unlink()
        start_gen = self.volume.generation
        node.undelete()
        self.assertEqual(node.generation, start_gen + 1)


class TestMoveFromShare(ORMTestCase):
    """Test MoveFromShare."""

    def test_create_mfs(self):
        """Basic create test."""
        u = self.factory.make_user()
        node = StorageObject(u.id, 'TheFile.txt', StorageObject.FILE)
        self.store.add(node)
        share_id = uuid.uuid4()
        mnode = MoveFromShare.from_move(node, share_id)
        self.assertEqual(mnode.share_id, share_id)
        self.assertEqual(mnode.id, node.id)
        self.assertEqual(mnode.owner_id, node.owner_id)
        self.assertEqual(mnode.parent_id, node.parent_id)
        self.assertEqual(mnode.volume_id, node.volume_id)
        self.assertEqual(mnode._content_hash, node._content_hash)
        self.assertEqual(mnode.kind, node.kind)
        self.assertEqual(mnode.when_created, node.when_created)
        self.assertEqual(mnode.when_last_modified, node.when_last_modified)
        self.assertEqual(mnode.status, STATUS_DEAD)
        self.assertEqual(mnode.path, node.path)
        self.assertEqual(mnode.publicfile_id, node.publicfile_id)
        self.assertEqual(mnode.generation, node.generation)
        self.assertEqual(mnode.generation_created, node.generation_created)

    def test_ShareVolumeDelta(self):
        """Test the ShareVolumeDelta view."""
        u = self.factory.make_user()
        # create 10 StorageObjects and MoveFromShare.
        share_id = uuid.uuid4()
        for i in range(10):
            node = StorageObject(u.id, 'TheFile%s.txt' % i, StorageObject.FILE)
            node.generation = i
            self.store.add(node)
            MoveFromShare.from_move(node, share_id)
        share_none = None
        result = self.store.find(
            ShareVolumeDelta,
            Or(ShareVolumeDelta.share_id == share_none,
               ShareVolumeDelta.share_id == share_id))
        # it is 21 because of the root node
        self.assertEqual(result.count(), 21)


class TestShare(ORMTestCase):
    """Tests for Share."""

    def create_share(self, *args, ** kwargs):
        """Helper function to create the Share."""
        share = Share(*args, ** kwargs)
        self.store.add(share)
        try:
            filesync_tm.commit()
        except psycopg2.IntegrityError:
            filesync_tm.abort()
            raise
        return share

    def test_Share_invalid_name(self):
        """Attempt to create a Share with an invalid filename."""
        self.assertRaises(
            errors.InvalidFilename,
            Share, 0, uuid.uuid4(), 1, 'bob/../../../', Share.VIEW)

    def test_create_share(self):
        """Creates a Share."""
        # create all the needed objects
        usr1 = self.factory.make_user(0, 'user0')
        usr2 = self.factory.make_user(1, 'user1')
        usr3 = self.factory.make_user(2, 'user2')
        root = StorageObject.get_root(self.store, usr1.id)

        # see if creation goes ok
        share = self.create_share(usr1.id, root.id, usr2.id, 'foo', Share.VIEW)
        self.assertEqual(share.shared_by, usr1.id)
        self.assertEqual(share.subtree, root.id)
        self.assertEqual(share.shared_to, usr2.id)
        self.assertEqual(share.name, 'foo')
        self.assertEqual(share.access, Share.VIEW)

        # with other access level
        share = self.create_share(
            usr1.id, root.id, usr3.id, 'bar', Share.MODIFY)
        self.assertEqual(share.access, Share.MODIFY)

    def test_create_share_udf(self):
        """Creates a Share in an UDF."""
        # create all the needed objects
        usr1 = self.factory.make_user(0, 'user0')
        usr2 = self.factory.make_user(1, 'user1')
        usr3 = self.factory.make_user(2, 'user2')
        udf = UserVolume.create(
            self.store, usr1.id, path='~/Documents/Stuff/DirToUDF')
        root = self.store.get(StorageObject, udf.root_id)

        # see if creation goes ok
        share = self.create_share(usr1.id, root.id, usr2.id, 'foo', Share.VIEW)
        self.assertEqual(share.shared_by, usr1.id)
        self.assertEqual(share.subtree, root.id)
        self.assertEqual(share.shared_to, usr2.id)
        self.assertEqual(share.name, 'foo')
        self.assertEqual(share.access, Share.VIEW)

        # with other access level
        share = self.create_share(
            usr1.id, root.id, usr3.id, 'bar', Share.MODIFY)
        self.assertEqual(share.access, Share.MODIFY)

    def test_create_share_same_name(self):
        """Creates a Share from usr1 to usr2, different nodes, but same name"""
        # create all the needed objects
        usr1 = self.factory.make_user(0, 'user0')
        usr2 = self.factory.make_user(1, 'user1')
        root = StorageObject.get_root(self.store, usr1.id)
        node = root.make_subdirectory('newdir')

        self.create_share(usr1.id, root.id, usr2.id, 'foo', Share.MODIFY)
        self.assertRaises(
            psycopg2.IntegrityError,
            self.create_share, usr1.id, node.id, usr2.id, 'foo', Share.MODIFY)

    def test_create_same_share_after_delete(self):
        """ (re)creates a share after deleting it """
        # create all the needed objects
        usr1 = self.factory.make_user(0, 'user0')
        usr2 = self.factory.make_user(1, 'user1')
        root = StorageObject.get_root(self.store, usr1.id)
        root.make_subdirectory('newdir')

        # create and delete the share
        for x in range(3):
            share = self.create_share(usr1.id, root.id, usr2.id,
                                      'foo', Share.MODIFY)
            share.delete()
        # now make sure we have more than one share named 'foo' marked as dead
        dead_shares = self.store.find(
            Share,
            Share.shared_to == usr2.id,
            Share.name == share.name,
            Share.status == STATUS_DEAD)
        self.failIf(dead_shares.is_empty())
        self.assertEqual(dead_shares.count(), 3)

    def test_multiple_shares_same_subtree(self):
        """ checks db constraints that enforce only one share per subtree """
        # create all the needed objects
        usr1 = self.factory.make_user(0, 'user0')
        usr2 = self.factory.make_user(1, 'user1')
        root = StorageObject.get_root(self.store, usr1.id)
        node = root.make_subdirectory('newdir')

        # attempt to share same subtree as different shares should fail
        share1 = self.create_share(usr1.id, node.id, usr2.id,
                                   'share1', Share.VIEW)
        # we can not create another share using same or different access
        self.assertRaises(psycopg2.IntegrityError,
                          self.create_share, usr1.id, node.id, usr2.id,
                          'share2', Share.VIEW)
        self.assertRaises(psycopg2.IntegrityError,
                          self.create_share, usr1.id, node.id, usr2.id,
                          'share2', Share.MODIFY)
        # check behavior on delete
        share1.delete()
        share2 = self.create_share(usr1.id, node.id, usr2.id,
                                   'share2', Share.VIEW)
        # we can not create another share using same or different access
        self.assertRaises(psycopg2.IntegrityError,
                          self.create_share, usr1.id, node.id, usr2.id,
                          'share1', Share.VIEW)
        self.assertRaises(psycopg2.IntegrityError,
                          self.create_share, usr1.id, node.id, usr2.id,
                          'share1', Share.MODIFY)
        share2.delete()
        # test creating shares for 'self' and others
        share1 = self.create_share(usr1.id, node.id, usr1.id,
                                   'share1', Share.VIEW)
        share2 = self.create_share(usr1.id, node.id, usr2.id,
                                   'share2', Share.VIEW)


class TestUserVolume(ORMTestCase):
    """Tests for UDFs."""

    def create_volume(self, *args, ** kwargs):
        """Helper function to create the UDF."""
        volume = UserVolume(*args, ** kwargs)
        self.store.add(volume)
        try:
            filesync_tm.commit()
        except psycopg2.IntegrityError:
            self.store.rollback()
            raise
        return volume

    def test_create_volume(self):
        """Create an UDF."""
        # create all the needed objects
        usr = self.factory.make_user()
        node = StorageObject.make_root(self.store, usr.id)

        # see if creation goes ok
        volume = self.create_volume(usr.id, node.id, '~/somepath')
        self.assertEqual(volume.owner_id, usr.id)
        self.assertEqual(volume.root_id, node.id)
        self.assertEqual(volume.path, '~/somepath')
        self.assertEqual(volume.status, STATUS_LIVE)

    def test_increment_generation(self):
        """Test increment_generation."""
        usr = self.factory.make_user()
        volume = UserVolume.make_root(self.store, usr.id)
        self.assertEqual(volume.generation, 0)
        volume.increment_generation()
        self.assertEqual(volume.generation, 1)
        gen = UserVolume.get_new_generation(self.store, volume.id)
        self.assertEqual(gen, 2)

    def test_create_volume_baduser(self):
        """Create an UDF with a wrong user."""
        usr = self.factory.make_user()
        node = StorageObject.get_root(self.store, usr.id)
        self.assertRaises(psycopg2.IntegrityError,
                          self.create_volume, 999, node.id, '~/somepath')

    def test_create_volume_badnode(self):
        """Create an UDF with a wrong node."""
        usr = self.factory.make_user()
        self.assertRaises(
            psycopg2.IntegrityError,
            self.create_volume, usr.id, uuid.uuid4(), '~/somepath')

    def test_create_volume_badpath(self):
        """Create an UDF with a wrong node."""
        usr = self.factory.make_user()
        node = StorageObject.get_root(self.store, usr.id)
        self.assertRaises(
            errors.InvalidVolumePath,
            self.create_volume, usr.id, node.id, 'badpath')

    def test_delete_volume(self):
        """Delete an UDF."""
        # create all the needed objects
        usr = self.factory.make_user()
        node = StorageObject.get_root(self.store, usr.id)
        volume = self.create_volume(usr.id, node.id, '~/somepath')
        generation = volume.generation

        # see if deletion goes ok
        volume.delete()
        self.assertEqual(volume.status, STATUS_DEAD)
        self.assertEqual(generation + 1, volume.generation)

    def test_create_volume_using_the_classmethod(self):
        """Create an UserVolume."""
        user = self.factory.make_user()
        self.assertRaises(
            errors.NoPermission, UserVolume.create,
            self.store, user.id, settings.ROOT_USERVOLUME_PATH)
        volume = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        node = self.store.get(StorageObject, volume.root_id)

        # check node properties
        self.assertEqual(node.owner_id, user.id)
        self.assertEqual(node.path, '/')
        self.assertEqual(node.name, '')
        self.assertEqual(node.parent, None)
        self.assertEqual(node.kind, StorageObject.DIRECTORY)
        self.assertEqual(node.status, STATUS_LIVE)
        self.assertEqual(node.volume_id, volume.id)

        # check volume is ok
        self.assertEqual(volume.root_id, node.id)
        self.assertEqual(volume.owner_id, user.id)
        self.assertEqual(volume.path, '~/Documents/Stuff/DirToUDF')
        self.assertEqual(volume.status, STATUS_LIVE)

    def test_make_root(self):
        """Create the root UserVolume."""
        user = self.factory.make_user()
        volume = UserVolume.make_root(self.store, user.id)
        node = self.store.get(StorageObject, volume.root_id)

        # check node properties
        self.assertEqual(node.owner_id, user.id)
        self.assertEqual(node.path, '/')
        self.assertEqual(node.name, '')
        self.assertEqual(node.parent, None)
        self.assertEqual(node.kind, StorageObject.DIRECTORY)
        self.assertEqual(node.status, STATUS_LIVE)
        self.assertEqual(node.volume_id, volume.id)

        # check volume is ok
        self.assertEqual(volume.root_id, node.id)
        self.assertEqual(volume.owner_id, user.id)
        self.assertEqual(volume.path, settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(volume.status, STATUS_LIVE)

    def test_get_root_volume(self):
        """Test the get_root method."""
        user = self.factory.make_user()
        volume1 = UserVolume.make_root(self.store, user.id)
        volume2 = UserVolume.get_root(self.store, user.id)
        self.assertEqual(volume1.id, volume2.id)

    def add_tree_and_files(self, volume):
        """Add a subtree and 100 files to the volume"""
        sub = volume.root_node.make_subdirectory('SubDir')
        file_size = self.factory.content_blob_args()['size']
        content = self.create(ContentBlob, **self.factory.content_blob_args())
        for i in range(100):
            file = sub.make_file('%s-%s' % (sub.name, i))
            file.content = content
        return file_size * 100

    def test_volume_size(self):
        """Test to make sure tree size works"""
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        info.max_storage_bytes = 50 * (2 ** 30)
        volume = UserVolume.make_root(self.store, user.id)
        self.assertEqual(volume.volume_size(), 0)
        size = self.add_tree_and_files(volume)
        self.assertNotEqual(size, 0)
        self.assertEqual(size, volume.volume_size())
        self.assertEqual(info.used_storage_bytes, size)

    def test_delete(self):
        """Test to make sure delete works."""
        user = self.make_user(1, 'a_test_user')
        info = self.store.get(StorageUserInfo, 1)
        info.max_storage_bytes = 50 * (2 ** 30)
        volume = UserVolume.make_root(self.store, user.id)
        self.add_tree_and_files(volume)
        # delete the volume.
        volume.delete()
        self.assertEqual(volume.volume_size(), 0)
        self.assertEqual(info.used_storage_bytes, 0)


class TestUploadJob(ORMTestCase):
    """Tests for UploadJob."""

    def create_uploadjob(self):
        """Create a UploadJob instance."""
        u = self.factory.make_user()
        root = StorageObject.make_root(self.store, u.id)
        obj = root.make_file(name='file.ext')

        def _UploadJob():
            """ wrapper for the UploadJob __init__ method """
            return UploadJob(obj.id)
        job = self.create(_UploadJob, **self.factory.uploadjob_args())
        filesync_tm.commit()
        return job

    def test_uploadjob_create(self):
        """Test upload job creation."""
        job = self.create_uploadjob()
        self.failIf(job.uploadjob_id is None)
        self.failUnless(job.uploadjob_id > 0)

    def test_uploadjob_create_udf(self):
        """Test upload job creation in an UDF."""
        user = self.factory.make_user()
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        root = self.store.get(StorageObject, udf.root_id)
        obj = root.make_file(name='file.ext')

        def _UploadJob():
            """Wrapper for the UploadJob __init__ method."""
            return UploadJob(obj.id)

        job = self.create(_UploadJob, **self.factory.uploadjob_args())
        self.failIf(job.uploadjob_id is None)
        self.failUnless(job.uploadjob_id > 0)

    def test_uploadjob_new_uploadjob(self):
        """Test creation of a new uploadjob."""
        u = self.factory.make_user()
        root = StorageObject.make_root(self.store, u.id)
        obj = root.make_file(name='file.ext')
        job = UploadJob.new_uploadjob(self.store, obj.id)
        self.store.flush()
        self.failIf(job.uploadjob_id is None)
        self.failUnless(job.uploadjob_id > 0)

    def test_uploadjob_new_uploadjob_udf(self):
        """Test creation of a new uploadjob in an UDF."""
        user = self.factory.make_user()
        udf = UserVolume.create(
            self.store, user.id, path='~/Documents/Stuff/DirToUDF')
        root = self.store.get(StorageObject, udf.root_id)
        obj = root.make_file(name='file.ext')
        job = UploadJob.new_uploadjob(self.store, obj.id)
        self.store.flush()
        self.failIf(job.uploadjob_id is None)
        self.failUnless(job.uploadjob_id > 0)

    def test_uploadjob_new_multipart_uploadjob(self):
        """Test creation of a new multipart uploadjob."""
        u = self.factory.make_user()
        root = StorageObject.make_root(self.store, u.id)
        obj = root.make_file(name='file.ext')
        job = UploadJob.new_multipart_uploadjob(
            self.store, obj.id, uuid.uuid4())
        job.hash_hint = b'bar'
        job.crc32_hint = 0
        job.inflated_size_hint = 10
        job.deflated_size_hint = 10
        self.store.flush()
        self.failIf(job.uploadjob_id is None)
        self.failUnless(job.uploadjob_id > 0)

    def test_uploadjob_add_part(self):
        """Test add_part method."""
        u = self.factory.make_user()
        root = StorageObject.make_root(self.store, u.id)
        obj = root.make_file(name='file.ext')
        job = UploadJob.new_multipart_uploadjob(
            self.store, obj.id, uuid.uuid4())
        job.hash_hint = b'bar'
        job.crc32_hint = 0
        job.inflated_size_hint = 10
        job.deflated_size_hint = 10
        self.store.flush()
        job.add_part(
            10, 15, 1, b'hash context', b'magic hash context', b'zlib context')
        self.assertEqual(job.chunk_count, 1)
        self.assertEqual(job.crc32, 1)
        self.assertEqual(job.inflated_size, 15)
        self.assertEqual(job.uploaded_bytes, 10)
        self.assertEqual(job.hash_context, 'hash context')
        self.assertEqual(job.magic_hash_context, 'magic hash context')
        self.assertEqual(job.decompress_context, 'zlib context')
        job.add_part(
            10, 30, 2, b'more hash context', b'more magic hash context',
            b'more zlib context')
        self.assertEqual(job.chunk_count, 2)
        self.assertEqual(job.crc32, 2)
        self.assertEqual(job.inflated_size, 30)
        self.assertEqual(job.uploaded_bytes, 20)
        self.assertEqual(job.hash_context, 'more hash context')
        self.assertEqual(job.magic_hash_context, 'more magic hash context')
        self.assertEqual(job.decompress_context, 'more zlib context')

    def test_uploadjob_find(self):
        """Test add_part method."""
        u = self.factory.make_user()
        root = StorageObject.make_root(self.store, u.id)
        obj = root.make_file(name='file.ext')
        job = UploadJob.new_multipart_uploadjob(
            self.store, obj.id, uuid.uuid4())
        job.hash_hint = b'bar'
        job.crc32_hint = 0
        job.inflated_size_hint = 10
        job.deflated_size_hint = 10
        job.add_part(
            10, 10, 1, b'hash context', b'magic hash context', b'zlib context')
        self.store.flush()
        same_job = self.store.get(UploadJob, job.uploadjob_id)
        self.assertEqual(job.uploaded_bytes, same_job.uploaded_bytes)
        self.assertEqual(job.chunk_count, same_job.chunk_count)
        self.assertEqual(job.crc32, same_job.crc32)
        self.assertEqual(job.inflated_size, same_job.inflated_size)


class TestStorageUserInfo(ORMTestCase):
    """Tests for StorageUserInfo."""

    def test_storage_user_info(self):
        """A simple test just to confirm that the StorageUserInfo
        table is created and working.
        """
        info = StorageUserInfo(1, 2 * (2 ** 30))
        info.used_storage_bytes = 2 ** 30
        self.store.add(info)
        info2 = self.store.get(StorageUserInfo, 1)
        self.assertEqual(info.id, info2.id)
        self.assertEqual(info.max_storage_bytes, info2.max_storage_bytes)
        self.assertEqual(info.used_storage_bytes, info2.used_storage_bytes)

    def test_lock_for_update(self):
        """Make sure lock_for_update locks the userinfo"""
        info = StorageUserInfo(1, 10)
        self.store.add(info)
        filesync_tm.commit()
        info.lock_for_update()
        self.failed = False

        def try_update():
            """try to update the locked record"""
            try:
                i = self.store.get(StorageUserInfo, info.id)
                i.lock_for_update()
            except psycopg2.OperationalError:
                self.failed = True

        thread = threading.Thread(target=try_update)
        thread.start()
        thread.join()
        self.assertTrue(self.failed)

    def test_update_used_bytes_up(self):
        """Basic test no errors, make sure used in increased"""
        info = StorageUserInfo(1, 10)
        info.update_used_bytes(5)
        self.assertEqual(info.used_storage_bytes, 5)
        info.update_used_bytes(10, enforce_quota=False)
        self.assertEqual(info.used_storage_bytes, 15)

    def test_update_used_bytes_down(self):
        """Basic test no errors, make sure used is decreased"""
        info = StorageUserInfo(1, 1000)
        self.assertEqual(info.used_storage_bytes, 0)
        info.update_used_bytes(-5)
        self.assertEqual(info.used_storage_bytes, 0)
        info.used_storage_bytes = 100
        info.update_used_bytes(-10)
        self.assertEqual(info.used_storage_bytes, 90)


class DownloadTests(TestStorageObjectBase):
    """Tests for the Download object."""

    def test_constructor(self):
        """Test the Download class's constructor."""
        user, udf_root = self.createUDF()
        download = Download(
            user.id, udf_root.volume_id, 'file_path', 'http://download/url')
        self.assertTrue(isinstance(download.id, uuid.UUID))
        self.assertEqual(download.owner_id, user.id)
        self.assertEqual(download.volume_id, udf_root.volume_id)
        self.assertEqual(download.file_path, 'file_path')
        self.assertEqual(download.download_url, 'http://download/url')
        self.assertEqual(download.status, Download.STATUS_QUEUED)
        self.assertTrue(
            isinstance(download.status_change_date, datetime.datetime))
        self.assertEqual(download.node_id, None)
        self.assertEqual(download.error_message, None)

    def test_set_status(self):
        """The set_status() method updates the timestamp."""
        user, udf_root = self.createUDF()
        download = Download(
            user.id, udf_root.volume_id, 'file_path', 'http://download/url')
        old_timestamp = download.status_change_date
        download.set_status(Download.STATUS_DOWNLOADING)
        self.assertEqual(download.status, Download.STATUS_DOWNLOADING)
        # The timestamp has been updated.
        self.assertNotEqual(download.status_change_date, old_timestamp)


class ResumableUploadTest(TestStorageObjectBase):
    """Rest ResumableUpload """

    def test_constructor(self):
        user = self.make_user(1, 'username')
        vol_path = '~/MyVolume/and/file/path.txt'
        size = 1000 * (2 ** 30)
        storage_key = uuid.uuid4()
        upload = ResumableUpload(user.id, vol_path, size, storage_key)
        self.store.add(upload)
        self.store.commit()
        u = self.store.get(ResumableUpload, upload.upload_id)
        self.assertEqual(u.owner_id, user.id)
        self.assertEqual(u.volume_path, vol_path)
        self.assertEqual(u.storage_key, storage_key)
        self.assertEqual(u.uploaded_bytes, 0)
        self.assertEqual(u.part_count, 0)

    def test_add_part(self):
        user = self.make_user(1, 'username')
        vol_path = '~/MyVolume/and/file/path.txt'
        size = 1000 * (2 ** 30)
        storage_key = uuid.uuid4()
        upload = ResumableUpload(user.id, vol_path, size, storage_key)
        self.store.add(upload)
        upload.add_part(
            10 * (2 ** 20), b'hash context', b'magic hash context', 55)
        self.assertEqual(upload.part_count, 1)
        self.assertEqual(upload.uploaded_bytes, 10 * (2 ** 20))
        self.assertEqual(upload.hash_context, 'hash context')
        self.assertEqual(upload.magic_hash_context, 'magic hash context')
        self.assertEqual(upload.crc_context, 55)


class AuxiliaryFunctionsTestCase(unittest.TestCase):
    """Tests for some auxiliary functions."""

    def test_validatename_name_empty(self):
        """Validate an empty name."""
        filename = ''
        result = validate_name(None, None, filename)
        self.assertEqual(result, filename)

    def test_validatename_no_name(self):
        """Validate setting the name to None."""
        filename = None
        result = validate_name(None, None, filename)
        self.assertEqual(result, filename)

    def test_validatename_name_ok(self):
        """Validate a fine name."""
        filename = 'valid file name'
        result = validate_name(None, None, filename)
        self.assertEqual(result, filename)

    def test_validatename_bytes(self):
        """Validate a name that are bytes."""
        self.assertRaises(errors.InvalidFilename,
                          validate_name, None, None, b'bytes')

    def test_validatename_illegal_name(self):
        """Validate not allowed names."""
        self.assertRaises(errors.InvalidFilename,
                          validate_name, None, None, '.')
        self.assertRaises(errors.InvalidFilename,
                          validate_name, None, None, '..')

    def test_validatename_illegal_chars(self):
        """Validate names with illegal chars."""
        self.assertRaises(errors.InvalidFilename,
                          validate_name, None, None, 'with a / in it')
        self.assertRaises(errors.InvalidFilename,
                          validate_name, None, None, 'not \x00 null')
