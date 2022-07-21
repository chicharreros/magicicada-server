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

"""Test for the storage model."""

from __future__ import unicode_literals

import threading
import unittest
import uuid

from datetime import datetime

from django.conf import settings
from django.db import (
    IntegrityError,
    OperationalError,
    connection,
    models,
    transaction,
)
from django.test import TransactionTestCase
from django.utils.timezone import now

from magicicada.filesync import errors
from magicicada.filesync.models import (
    ROOT_NAME,
    STATUS_LIVE,
    STATUS_DEAD,
    Download,
    MoveFromShare,
    ResumableUpload,
    Share,
    ShareVolumeDelta,
    StorageObject,
    StorageUser,
    UploadJob,
    UserVolume,
    validate_name,
)
from magicicada.testing.factory import Factory
from magicicada.testing.testcase import BaseTestCase


class SelectForUpdateTestCase(TransactionTestCase):

    factory = Factory()

    def test_user_select_for_update(self):
        """Make sure select_for_update locks the user."""
        user = self.factory.make_user(username='f', with_root=False)
        self.failed = False

        @transaction.atomic
        def try_update():
            """Try to update the locked record."""
            try:
                StorageUser.objects.select_for_update(nowait=True).get(
                    id=user.id)
            except OperationalError:
                self.failed = True
            connection.close()

        thread = threading.Thread(target=try_update)
        with transaction.atomic():
            user = StorageUser.objects.select_for_update(nowait=True).get(
                id=user.id)
            thread.start()
            thread.join()

        self.assertTrue(self.failed)

    def test_storage_object_select_for_update(self):
        """Make sure select_for_update locks the object."""
        user = self.factory.make_user(username='f')
        root_id = user.root_node.id
        self.failed = False

        @transaction.atomic
        def try_update():
            """Try to update the locked record."""
            try:
                StorageObject.objects.select_for_update(nowait=True).get(
                    id=root_id)
            except OperationalError:
                self.failed = True
            connection.close()

        thread = threading.Thread(target=try_update)
        with transaction.atomic():
            StorageObject.objects.select_for_update(nowait=True).get(
                id=root_id)
            thread.start()
            thread.join()

        self.assertTrue(self.failed)

    def test_select_tree_for_update(self):
        """Make sure lock_tree_for_update locks the object."""
        user = self.factory.make_user(username='f')
        udf = self.factory.make_user_volume(
            owner=user, path='~/Documents/Stuff/DirToUDF')
        root = udf.root_node
        child = root.make_subdirectory("subd-1")
        childx = root.make_subdirectory("subd-11")
        # making paths are handled correctly
        childx2 = childx.make_subdirectory("subd-11")
        child2 = child.make_subdirectory('subd2')
        # make sure this user's objects aren't locked
        userA = self.factory.make_user(username='a')
        userA_root = StorageObject.objects.get_root(userA)
        userA_child = userA_root.make_subdirectory("subd-1")
        userA_childx = userA_child.make_subdirectory("subd-1")
        userA_childx1 = userA_childx.make_subdirectory("subd-1")

        self.failed = False

        @transaction.atomic
        def try_update(node_id):
            """Try to update the locked record."""
            try:
                StorageObject.objects.select_for_update(nowait=True).get(
                    id=node_id)
            except OperationalError:
                self.failed = True
            else:
                self.failed = False
            connection.close()

        def test_it(node, fail):
            """Test the nodeid update"""
            thread = threading.Thread(
                target=try_update, kwargs={'node_id': node.id})
            with transaction.atomic():
                # Query sets are lazy, force access to DB
                list(child.lock_tree_for_update())
                thread.start()
                thread.join()
            self.assertEqual(self.failed, fail)

        test_it(childx2, False)
        test_it(root, False)
        # this should fail
        test_it(child2, True)

        test_it(userA_root, False)
        test_it(userA_child, False)
        test_it(userA_childx, False)
        # the next one was being locked due to lack of owner_id checking
        test_it(userA_childx1, False)

    def test_lock_tree_for_update_root(self):
        """Make sure lock_tree_for_update locks the object."""
        user = self.factory.make_user(username='f')
        root = StorageObject.objects.get_root(user)
        child1 = root.make_subdirectory("subd-1")
        child2 = child1.make_subdirectory("subd-1")
        # create files with the same paths but on a udf (different volume_id)
        udf = self.factory.make_user_volume(
            owner=user, path='~/Documents/Stuff/DirToUDF')
        udf_child1 = udf.root_node.make_subdirectory("subd-1")
        udf_child2 = udf_child1.make_subdirectory("subd-1")

        self.failed = False

        @transaction.atomic
        def try_update(node_id):
            """Try to update the locked record."""
            try:
                StorageObject.objects.select_for_update(nowait=True).get(
                    id=node_id)
            except OperationalError:
                self.failed = True
            else:
                self.failed = False
            connection.close()

        def test_it(node, fail):
            """Test the nodeid update"""
            thread = threading.Thread(
                target=try_update, kwargs={'node_id': node.id})
            with transaction.atomic():
                # Query sets are lazy, force access to DB
                list(root.lock_tree_for_update())
                thread.start()
                thread.join()
            self.assertEqual(self.failed, fail)

        test_it(child1, True)
        test_it(child2, True)
        test_it(udf_child1, False)
        test_it(udf_child2, False)


class StorageUserTestCase(BaseTestCase):
    """Tests for StorageUser."""

    def test_trivial(self):
        user = StorageUser.objects.create_user(username='test', password='foo')
        self.assertEqual(user.username, 'test')

    def test_create(self):
        """Tests creation of a StorageUser."""
        u = self.factory.make_user()
        self.assertFalse(u.locked)

    def test_storage_user_creation(self):
        """Confirm that the StorageUser table is created and working."""
        user = self.factory.make_user(
            max_storage_bytes=2 * (2 ** 30), used_storage_bytes=2 ** 30)

        real = StorageUser.objects.get(id=user.id)
        self.assertEqual(user, real)

    def test_update_used_bytes_up(self):
        """Basic test no errors, make sure used bytes in increased."""
        user = self.factory.make_user(max_storage_bytes=10)
        user.update_used_bytes(5)

        real = StorageUser.objects.get(id=user.id)
        self.assertEqual(user, real)
        self.assertEqual(user.max_storage_bytes, 10)
        self.assertEqual(user.used_storage_bytes, 5)

    def test_update_used_bytes_up_enforce_quota(self):
        """Quota can be bypassed when increasing used bytes."""
        user = self.factory.make_user(
            max_storage_bytes=10, used_storage_bytes=5)
        user.update_used_bytes(10, enforce_quota=False)

        real = StorageUser.objects.get(id=user.id)
        self.assertEqual(user, real)
        self.assertEqual(user.max_storage_bytes, 10)
        self.assertEqual(user.used_storage_bytes, 15)

        self.assertRaises(
            errors.QuotaExceeded, user.update_used_bytes, 10,
            enforce_quota=True)

    def test_update_used_bytes_down(self):
        """Basic test no errors, make sure used bytes is decreased."""
        user = self.factory.make_user(max_storage_bytes=1000)
        self.assertEqual(user.used_storage_bytes, 0)

        user.update_used_bytes(-5)
        self.assertEqual(user.used_storage_bytes, 0)

        user.used_storage_bytes = 100
        user.update_used_bytes(-10)
        self.assertEqual(user.used_storage_bytes, 90)


class SharingTestCase(BaseTestCase):
    """Tests for StorageUser."""

    def setUp(self):
        super(SharingTestCase, self).setUp()
        self.sharer = self.factory.make_user(username='sammy')
        self.user = self.factory.make_user(username='sherry')

    def test_get_unique_name(self):
        """Test get_unique_name."""
        name = Share.objects.get_unique_name(self.user, name='name')
        self.assertEqual(name, 'name')

        self.factory.make_share(
            owner=self.sharer, shared_to=self.user, name='name')
        name = Share.objects.get_unique_name(self.user, name='name')
        self.assertEqual(name, 'name~1')

        self.factory.make_share(
            owner=self.sharer, shared_to=self.user, name='name~1')
        self.factory.make_share(
            owner=self.sharer, shared_to=self.user, name='name~2')
        self.factory.make_share(
            owner=self.sharer, shared_to=self.user, name='name~3')

        name = Share.objects.get_unique_name(self.user, name='name')
        self.assertEqual(name, 'name~4')

    def test_claim_share(self):
        """Test claiming a share offer that was sent to an email address."""
        root = StorageObject.objects.get_root(self.sharer)
        share = self.factory.make_share(
            subtree=root, shared_to=None, name='For friend',
            email='fake@example.com')
        assert share.shared_by == root.volume.owner

        # Sammy has shared 1 folder
        self.assertEqual(self.sharer.sharedby_folders.all().count(), 1)
        # Sherry shouldn't see any shares yet, she hasn't accepted it
        self.assertEqual(self.user.sharedto_folders.all().count(), 0)
        # now claim the share for Sherry just like the Web UI would.
        share.claim_share(self.user)

        # Sherry should now see the share
        self.assertEqual(self.user.sharedto_folders.count(), 1)
        child = root.make_subdirectory("subd-1")
        share = self.factory.make_share(
            subtree=child, shared_to=None, name='For friend',
            email='fake@example.com')
        share.claim_share(self.user)
        self.assertEqual(share.name, 'For friend~1')

    def test_user_shared(self):
        """Test the sharedto_folders/by of StorageUser"""
        root = StorageObject.objects.get_root(self.sharer)
        # Sammy Shouldn't show sharing stuff
        self.assertEqual(self.sharer.sharedby_folders.count(), 0)
        # Sherry shouldn't see shares
        self.assertEqual(self.user.sharedto_folders.count(), 0)
        # Sharer shares something so sherry should see shares soon
        root = StorageObject.objects.get_root(self.sharer)

        self.factory.make_share(
            subtree=root, shared_to=self.user, name='Share Name')
        # Sammy Should show sharing stuff
        self.assertEqual(self.sharer.sharedby_folders.count(), 1)
        # Seeing shares sherry smiles
        self.assertEqual(self.user.sharedto_folders.count(), 1)


class ContentBlobTestCase(BaseTestCase):
    """Tests for ContentBlob."""

    def test_create(self):
        """Tests the creation of a ContentBlob."""
        before = now()
        cb = self.factory.make_content_blob()
        after = now()
        self.assertGreaterEqual(cb.when_created, before)
        self.assertLessEqual(cb.when_created, after)


class StorageObjectTestCase(BaseTestCase):
    """Base class for tests for StorageObject."""

    def test_create_root(self):
        """Create a standard root."""
        user = self.factory.make_user()
        node = StorageObject.objects.get_root(user)

        # check node properties
        self.assertEqual(node.volume.owner, user)
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
        root_node = StorageObject.objects.get_root(user)
        self.assertRaises(errors.StorageError, root_node.make_file, '')
        self.assertRaises(errors.StorageError, root_node.make_file, None)
        self.assertRaises(
            errors.StorageError, root_node.make_subdirectory, '')
        self.assertRaises(
            errors.StorageError, root_node.make_subdirectory, '')

    def test_create_a_node_in_a_root(self):
        """Create a regular node inside a standard root."""
        volume = self.factory.make_user_volume(generation=12)
        # change the generaiton of the volume
        obj = volume.root_node.make_file('file.ext')

        # check node properties
        self.assertEqual(obj.path, '/')
        self.assertEqual(obj.name, 'file.ext')
        self.assertEqual(obj.parent, volume.root_node)
        self.assertEqual(obj.kind, StorageObject.FILE)
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.volume, volume)
        self.assertEqual(obj.generation, 13)
        self.assertEqual(obj.generation_created, 13)

    def test_create_a_node_in_an_udf(self):
        """Create a regular node inside an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        obj = udf.root_node.make_file('file.ext')

        # check node properties
        self.assertEqual(obj.volume.owner, udf.owner)
        self.assertEqual(obj.path, '/')
        self.assertEqual(obj.name, 'file.ext')
        self.assertEqual(obj.parent, udf.root_node)
        self.assertEqual(obj.kind, StorageObject.FILE)
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.volume, udf)

    def test_public_flag(self):
        """Test the is_public flag on storage objects."""
        obj = self.factory.make_file()
        self.assertFalse(
            obj.is_public, 'Object should not be public by default')
        obj.make_public()
        self.assertTrue(
            obj.is_public, 'Should be possible to make object public')

    def test_update_generation(self):
        """Test update_generation."""
        obj = self.factory.make_file()
        self.assertEqual(obj.generation, 1)

        obj.volume.generation = 12
        obj.volume.save()

        obj.update_generation()
        self.assertEqual(obj.generation, 13)

    def test_path_startswith(self):
        """Make sure the path_startwith function is correct"""
        node = self.factory.make_directory(name='NodeName')
        self.assertEqual(node.absolute_path, '/NodeName/')
        node.path = '/a/b/c/d'
        self.assertEqual(node.absolute_path, '/a/b/c/d/NodeName/')
        node.name = ''
        self.assertEqual(node.absolute_path, '/a/b/c/d/')
        node.path = ''
        self.assertEqual(node.absolute_path, '/')

    def test_filename_validation(self):
        """Tests that the model validates filenames when creating files or
        directories."""
        user = self.factory.make_user(username='f')
        root = StorageObject.objects.get_root(user)
        self.assertRaises(errors.InvalidFilename,
                          root.make_subdirectory, 'Beta/Licorice')
        self.assertRaises(errors.InvalidFilename,
                          root.make_file, 'Beta/Licorice')

    def test_live_children(self):
        """Test to make sure has_children works with different deletions."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        self.assertFalse(root.live_children.exists())

        subdir = root.make_subdirectory('subdir')
        self.assertItemsEqual(list(root.live_children), [subdir])

        filenode = root.make_file('somefile')
        self.assertItemsEqual(list(root.live_children), [subdir, filenode])

        filenode.unlink()
        self.assertItemsEqual(list(root.live_children), [subdir])

        subdir.unlink()
        self.assertFalse(root.live_children.exists())

        subdir = root.make_subdirectory('subdir2')
        self.assertItemsEqual(list(root.live_children), [subdir])

        other = subdir.make_subdirectory('subdir')
        self.assertItemsEqual(list(subdir.live_children), [other])
        # This is not descendants! Direct children only.
        self.assertItemsEqual(list(root.live_children), [subdir])

        f2 = subdir.make_file('file2')
        f3 = subdir.make_file('file3')
        f4 = subdir.make_file('file4')
        f5 = subdir.make_file('file5')
        self.assertItemsEqual(list(root.live_children), [subdir])
        self.assertItemsEqual(
            list(subdir.live_children), [other, f2, f3, f4, f5])

        subdir.unlink_tree()
        self.assertFalse(root.live_children.exists())

    def test_storage_stats(self):
        """Test the storage stats for a user"""
        user = self.factory.make_user(username='f')
        root = StorageObject.objects.get_root(user)
        sub = root.make_subdirectory('My Subfolder')
        self.assertEqual(root.volume.owner.used_bytes, 0)
        content = self.factory.make_content_blob()
        for i in range(10):
            filenode = sub.make_file('File%s' % i, content_blob=content)
            if i % 2 == 0:
                filenode.unlink()

        self.assertEqual(
            root.volume.owner.used_bytes, content.size * 5)

    def test_storage_stats_in_UDF(self):
        """Test the storage stats for a user using an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        sub = udf.root_node.make_subdirectory('My Subfolder')

        # check when empty
        self.assertEqual(udf.owner.used_bytes, 0)

        # create some nodes
        content = self.factory.make_content_blob()
        for i in range(10):
            filenode = sub.make_file('File%s' % i, content_blob=content)
            if i % 2 == 0:
                filenode.unlink()

        # check after the creation
        self.assertEqual(udf.owner.used_bytes, 5120)

    def test_get_root_udf(self):
        """Tests get_root when having an UDF."""
        user = self.factory.make_user()
        udf = self.factory.make_user_volume(owner=user, path='~/Path/Dir')

        root = StorageObject.objects.get_root(user)
        self.assertEqual(root, user.root_node, 'root should be returned')
        self.assertItemsEqual(list(user.volumes), [user.root_node.volume, udf])

    def test_make_directory(self):
        """Tests make_subdirectory."""
        root = self.factory.make_user_volume().root_node
        newnode = root.make_subdirectory('subdir')
        self.assertEqual(newnode.parent, root)
        self.assertEqual(newnode.volume, root.volume)

    def test_make_directory_udf(self):
        """Tests make_subdirectory in the udf."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        newnode = udf.root_node.make_subdirectory('subdir')
        self.assertEqual(newnode.parent, udf.root_node)
        self.assertEqual(newnode.volume, udf)

    def test_path(self):
        """Tests that the path is well constructed."""
        root = self.factory.make_root_volume().root_node
        node1 = root.make_subdirectory('subdir')

        self.assertEqual(node1.path, '/')
        self.assertEqual(node1.full_path, '/subdir')

        node2 = node1.make_subdirectory('otherdir')
        self.assertEqual(node2.path, '/subdir')
        self.assertEqual(node2.full_path, '/subdir/otherdir')

    def test_path_udf(self):
        """Tests that the path is well constructed for an udf."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        node1 = udf.root_node.make_subdirectory('subdir')

        self.assertEqual(node1.path, '/')

        node2 = node1.make_subdirectory('otherdir')
        self.assertEqual(node2.path, '/subdir')

    def test_udf_trailing_slashes(self):
        """Tests that the path for an udf doesn't have trailing slashes."""
        user = self.factory.make_user()
        udf = self.factory.make_user_volume(
            owner=user, path='~/Documents/Stuff/DirToUDF/')

        self.assertEqual(udf.path, '~/Documents/Stuff/DirToUDF')

    def test_move_no_name(self):
        """Test to make sure move with no name errors."""
        dirnode = self.factory.make_directory()
        obj = self.factory.make_file()
        self.assertRaises(errors.InvalidFilename, obj.move, dirnode, '')
        self.assertRaises(errors.InvalidFilename, obj.move, dirnode, None)

    def test_path_move_file(self):
        """Tests that the path changes when moving the file."""
        root = self.factory.make_root_volume().root_node
        obj = root.make_file('foo.doc')

        subdir1 = root.make_subdirectory('subdir1')
        subdir11 = subdir1.make_subdirectory('subdir11')
        subdir2 = root.make_subdirectory('subdir2')

        self.assertEqual(obj.path, '/')

        obj.move(subdir1, obj.name)
        self.assertEqual(obj.path, '/subdir1')

        obj.move(subdir11, obj.name)
        self.assertEqual(obj.path, '/subdir1/subdir11')

        obj.move(subdir2, obj.name)
        self.assertEqual(obj.path, '/subdir2')

        obj.move(root, obj.name)
        self.assertEqual(obj.path, '/')

    def test_path_move_file_udf(self):
        """Tests that the path changes when moving the file in an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        obj = udf.root_node.make_file('file.ext')

        subdir1 = udf.root_node.make_subdirectory('subdir1')
        subdir11 = subdir1.make_subdirectory('subdir11')
        subdir2 = udf.root_node.make_subdirectory('subdir2')

        self.assertEqual(obj.path, '/')

        obj.move(subdir1, obj.name)
        self.assertEqual(obj.path, '/subdir1')

        obj.move(subdir11, obj.name)
        self.assertEqual(obj.path, '/subdir1/subdir11')

        obj.move(subdir2, obj.name)
        self.assertEqual(obj.path, '/subdir2')

        obj.move(udf.root_node, obj.name)
        self.assertEqual(obj.path, '/')

    def test_path_move_file_between_volumes(self):
        """Test that no move is allowed between volumes."""
        root = self.factory.make_root_volume().root_node
        udf = self.factory.make_user_volume(
            owner=root.volume.owner, path='~/Documents/Stuff/DirToUDF')

        obj = root.make_file('file2.ext')
        self.assertRaises(
            errors.StorageError, obj.move, udf.root_node, obj.name)

    def test_path_move_dir(self):
        """Tests that the path changes when moving the dir."""
        root = self.factory.make_root_volume().root_node
        subdir1 = root.make_subdirectory("sub'dir1")
        subdir11 = subdir1.make_subdirectory("sub'dir11")
        subdir2 = root.make_subdirectory("sub'dir2")

        self.assertEqual(subdir11.path, "/sub'dir1")
        subdir11.move(subdir2, subdir11.name)
        self.assertEqual(subdir11.path, "/sub'dir2")

    def test_path_move_dir_grandparent(self):
        """Tests a move to grandparent."""
        root = self.factory.make_root_volume().root_node
        subdir1 = root.make_subdirectory('dir')
        subdir2 = subdir1.make_subdirectory('dir')
        subdir3 = subdir2.make_subdirectory('dir')

        subdir3.move(subdir1, 'newname')
        self.assertEqual(subdir3.path, '/dir')
        self.assertEqual(subdir3.name, 'newname')
        self.assertEqual(subdir3.full_path, '/dir/newname')

    def test_path_move_deeptree(self):
        """Tests a very deep inside move."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory('sub')
        all_dirs = [subdir]
        for i in range(1000):  # bigger than the limit for recursive calls
            subdir = subdir.make_subdirectory('x')
            all_dirs.append(subdir)

        grand_parent = all_dirs[-3]  # -1 is the tree's leaf, -2 is parent
        subdir.move(grand_parent, 'y')

    def test_path_move_dir_udf(self):
        """Tests that the path changes when moving the dir in an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        subdir1 = udf.root_node.make_subdirectory("sub'dir1")
        subdir11 = subdir1.make_subdirectory("sub'dir11")
        subdir2 = udf.root_node.make_subdirectory("sub'dir2")

        self.assertEqual(subdir11.path, "/sub'dir1")
        subdir11.move(subdir2, subdir11.name)
        self.assertEqual(subdir11.path, "/sub'dir2")

    def test_move_udf_root(self):
        """Test that the root of an UDF can not be moved or renamed."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        self.assertRaises(errors.StorageError, udf.root_node.unlink)
        subdir1 = udf.root_node.make_subdirectory('subdir1')
        subdir11 = subdir1.make_subdirectory('subdir11')

        # don't move to subdir 11
        self.assertRaises(
            errors.InvalidFilename, udf.root_node.move, subdir11,
            udf.root_node.name)

        # don't rename
        self.assertRaises(
            errors.NoPermission, udf.root_node.move, udf.root_node.parent,
            'new name')

    def test_get_descendants(self):
        """Test the get descendants method."""
        # to test this, make volumes for this user with similar paths
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        self.assertNotIn(root, root.descendants)
        self.assertEqual(root.descendants.count(), 0)
        r_sub1 = root.make_subdirectory('sub1')
        r_sub2 = r_sub1.make_subdirectory('sub2')
        # an udf and three dirs in it
        udf = self.factory.make_user_volume(
            owner=user, path='~/Documents/Stuff/DirToUDF')
        u_sub1 = udf.root_node.make_subdirectory('sub1')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub3 = u_sub2.make_subdirectory('sub3')
        u_sub4 = u_sub2.make_subdirectory('sub4')
        u_sub4.unlink()
        self.assertEqual(root.descendants.count(), 2)
        self.assertEqual(udf.root_node.descendants.count(), 3)
        self.assertNotIn(u_sub4, udf.root_node.descendants)
        for n in [r_sub1, r_sub2]:
            self.assertIn(n, root.descendants)
        for n in [u_sub1, u_sub2, u_sub3]:
            self.assertIn(n, udf.root_node.descendants)

    def test_get_descendants_by_kind(self):
        """Test the get descendants filtering by kind."""
        # to test this, make volumes for this user with similar paths
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        self.assertNotIn(root, root.descendants)
        self.assertEqual(root.descendants.count(), 0)
        r_sub1 = root.make_subdirectory('sub1')
        r_sub1.make_file('sub1_file.ext')
        r_sub2 = r_sub1.make_subdirectory('sub2')
        r_sub2.make_file('sub2_file.ext')
        # an udf and three dirs in it
        udf = self.factory.make_user_volume(
            owner=user, path='~/Documents/Stuff/DirToUDF')
        u_sub1 = udf.root_node.make_subdirectory('sub1')
        # create a few files
        u_sub1.make_file('sub1_file.ext')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub2.make_file('sub2_file.ext')
        u_sub3 = u_sub2.make_subdirectory('sub3')
        u_sub3.make_file('sub3_file.ext')
        u_sub4 = u_sub2.make_subdirectory('sub4')
        u_sub4.unlink()

        self.assertEqual(
            root.get_descendants(kind=StorageObject.FILE).count(), 2)
        self.assertEqual(
            root.get_descendants(kind=StorageObject.DIRECTORY).count(), 2)
        self.assertEqual(root.get_descendants(kind=None).count(), 4)
        self.assertEqual(
            udf.root_node.get_descendants(kind=StorageObject.FILE).count(),
            3)
        self.assertEqual(
            udf.root_node.get_descendants(
                kind=StorageObject.DIRECTORY).count(), 3)
        self.assertEqual(udf.root_node.get_descendants(kind=None).count(), 6)

    def test_tree_size(self):
        """Test to make sure tree size works"""
        user = self.factory.make_user(
            username='a_test_user', max_storage_bytes=50 * (2 ** 30))

        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')
        self.assertEqual(0, user.used_bytes)
        self.assertEqual(0, subdir.tree_size)

        cb = self.factory.make_content_blob()
        # create 3 subdirectories (30 files)
        subdira = self.factory.make_tree_and_files(subdir, "subdir-1", cb)
        subdirb = self.factory.make_tree_and_files(subdira, "subdir-11", cb)
        subdirc = self.factory.make_tree_and_files(subdirb, "subdir-111", cb)

        # these folders have a similar path pattern, but will be included
        root = StorageObject.objects.get_root(user)
        subdirx = root.make_subdirectory("subdir-1")
        subdirxx = self.factory.make_tree_and_files(subdirx, "subdir-1", cb)
        subdirxxx = self.factory.make_tree_and_files(subdirxx, "subdir-11", cb)
        self.factory.make_tree_and_files(subdirxxx, "subdir-111", cb)

        self.assertEqual(cb.size * 60, root.volume.owner.used_bytes)
        self.assertEqual(root.volume.owner.used_bytes, root.tree_size)
        self.assertEqual(cb.size * 30, subdira.tree_size)
        self.assertEqual(cb.size * 20, subdirb.tree_size)
        self.assertEqual(cb.size * 10, subdirc.tree_size)
        self.assertEqual(cb.size * 30, subdir.tree_size)

        # hey...lets go ahead an unlink it
        subdir.unlink_tree()
        # we should still have the files not included
        self.assertEqual(cb.size * 30, subdirx.tree_size)
        self.assertEqual(cb.size * 30, user.used_bytes)
        self.assertEqual(0, subdir.tree_size)

    def test_tree_size_with_mixed_udfs(self):
        """Test to make sure tree size works"""
        # a root and two dirs in it
        root = self.factory.make_root_volume().root_node
        r_sub1 = root.make_subdirectory('sub1')
        r_sub2 = r_sub1.make_subdirectory('sub2')

        # an udf and three dirs in it
        udf = self.factory.make_user_volume(
            owner=root.volume.owner, path='~/Documents/Stuff/DirToUDF')
        u_sub1 = udf.root_node.make_subdirectory('sub1')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub3 = u_sub2.make_subdirectory('sub3')

        # create a content of 100
        content = self.factory.make_content_blob(size=100)

        # add a file in these dirs, with that small content
        for sub in (r_sub1, r_sub2, u_sub1, u_sub2, u_sub3):
            sub.make_file('file in %s' % sub.name, content_blob=content)

        # trees sizes should be separated
        self.assertEqual(200, r_sub1.tree_size)
        self.assertEqual(300, u_sub1.tree_size)

    def test_build_tree_from_path_basic(self):
        """Test build_tree_from_path."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory('subdir')
        d = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d.full_path, '/subdir/a/b/c/d/e')
        d2 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d, d2)
        self.assertEqual(d2.full_path, '/subdir/a/b/c/d/e')
        # check the subdirectories:
        nodes = StorageObject.objects.filter(kind=StorageObject.DIRECTORY)
        paths = [n.full_path for n in nodes]
        # seven directories including root
        self.assertEqual(len(paths), 7)
        self.assertIn('/', paths)
        self.assertIn('/subdir', paths)
        self.assertIn('/subdir/a', paths)
        self.assertIn('/subdir/a/b', paths)
        self.assertIn('/subdir/a/b/c', paths)
        self.assertIn('/subdir/a/b/c/d', paths)
        self.assertIn('/subdir/a/b/c/d/e', paths)

    def test_build_tree_from_path_with_file(self):
        """Test build_tree_from_path with multiple dead nodes."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory('subdir')
        d = subdir.make_subdirectory('a')
        d.unlink()
        d = subdir.make_subdirectory('b')
        d.unlink()
        d3 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d3.full_path, '/subdir/a/b/c/d/e')
        # multiple calls return the same directory and path
        d4 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d4.full_path, '/subdir/a/b/c/d/e')
        self.assertEqual(d3, d4)

    def test_build_tree_from_path_with_file2(self):
        """Test build_tree_from_path."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory('subdir')
        d = subdir.build_tree_from_path('/a/b/c')
        # create a file with the same name as a perspective directory, this
        # will end up in a different named folder path
        d.make_file('d')
        d2 = subdir.build_tree_from_path('/a/b/c/d/e')
        self.assertEqual(d2.full_path, '/subdir/a/b/c/d~1/e')
        self.assertEqual(d.status, STATUS_LIVE)
        # check the subdirectories:
        nodes = StorageObject.objects.filter(kind=StorageObject.DIRECTORY)
        paths = [n.full_path for n in nodes]
        # seven directories including root
        self.assertEqual(len(paths), 7)
        self.assertIn('/', paths)
        self.assertIn('/subdir', paths)
        self.assertIn('/subdir/a', paths)
        self.assertIn('/subdir/a/b', paths)
        self.assertIn('/subdir/a/b/c', paths)
        self.assertIn('/subdir/a/b/c/d~1', paths)
        self.assertIn('/subdir/a/b/c/d~1/e', paths)

    def test_unlink_tree_exception(self):
        """Test unlink tree exceptions"""
        obj = self.factory.make_file()
        self.assertRaises(errors.NotADirectory, obj.unlink_tree)

    def test_unlink_tree_basic(self):
        """Tests that a shared object and the Share are deleted"""
        root = self.factory.make_root_volume().root_node
        root.make_file('some file.txt')

        subdir = root.make_subdirectory('subdir')
        subdira = subdir.make_subdirectory('subdira')
        subdirab = subdira.make_subdirectory('subdirab')
        subdirab.make_subdirectory('subdirabc')
        subdira.make_subdirectory('subdiraaa')
        # due to a bug (488412) in the path check, this was added
        subdiraa = root.make_subdirectory('subdiraa')
        subdiraa1 = subdiraa.make_subdirectory('subdiraa1')
        self.assertEqual(subdiraa.generation, 7)

        # check descendants
        assert subdir.descendants.all().count() == 4
        subdir.unlink_tree()

        gen = StorageObject.objects.filter(
            volume__owner=root.volume.owner).aggregate(
                max_gen=models.Max('generation'))['max_gen']
        self.assertEqual(subdir.volume.generation, gen)
        self.assertEqual(subdir.status, STATUS_DEAD)
        for descendant in subdir.get_descendants(live_only=False):
            self.assertEqual(descendant.status, STATUS_DEAD)

        # this node didn't change
        self.assertEqual(subdiraa.status, STATUS_LIVE)
        self.assertEqual(subdiraa.generation, 7)
        # this bug is fixed
        self.assertEqual(subdiraa1.status, STATUS_LIVE)

    def test_unlink_tree_basic_bigname(self):
        """Test a big name inside the tree of what is deleted."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory('subdir')
        subdir.make_subdirectory('f' * 255)  # big filename
        subdir.unlink_tree()

    def test_unlink_tree_udfmixed(self):
        """Tests deleting things with same paths in different volumes."""
        # a root and two dirs in it
        root = self.factory.make_root_volume().root_node
        r_sub1 = root.make_subdirectory('sub1')
        r_sub1.make_subdirectory('sub2')

        # an udf and three dirs in it
        udf = self.factory.make_user_volume(
            owner=root.volume.owner, path='~/Documents/Stuff/DirToUDF')
        u_sub1 = udf.root_node.make_subdirectory('sub1')
        u_sub2 = u_sub1.make_subdirectory('sub2')
        u_sub2.make_subdirectory('sub3')

        # remove the sub 1 in root
        r_sub1.unlink_tree()

        # check
        for descendant in r_sub1.get_descendants(live_only=False):
            self.assertEqual(descendant.status, STATUS_DEAD)
        for descendant in udf.root_node.get_descendants(live_only=False):
            self.assertEqual(descendant.status, STATUS_LIVE)

    def test_unlink(self):
        """Test the the unlink object method."""
        obj = self.factory.make_file()
        parent = obj.parent
        self.assertTrue(parent.live_children.exists())
        obj.unlink()

        self.assertFalse(parent.live_children.exists())
        self.assertEqual(obj.status, STATUS_DEAD)

    def test_unlink_udf(self):
        """Test unlinking inside an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        obj = udf.root_node.make_file('file.ext')
        obj.unlink()
        self.assertEqual(obj.status, STATUS_DEAD)

    def test_unlink_udfroot(self):
        """Test that the root of an UDF can not be unlinked."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        self.assertRaises(errors.StorageError, udf.root_node.unlink)

    def test_get_unique_childname(self):
        """Test the get_unique_childname method."""
        root = self.factory.make_root_volume().root_node
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
        root = self.factory.make_root_volume().root_node
        obj = root.make_file('undelete')
        self.assertTrue(root.live_children.exists())

        self.assertIn(obj, root.children.all())
        obj.unlink()

        self.assertFalse(root.live_children.exists())
        parent = root.make_subdirectory('restore folder')
        obj.undelete(parent)

        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.path, parent.full_path)
        self.assertEqual(obj.parent, parent)
        self.assertIn(obj, parent.children.all())
        self.assertNotIn(obj, root.children.all())
        self.assertTrue(root.live_children.exists())

    def test_undelete_deadparent(self):
        """Tests undelete with a dead parent."""
        root = self.factory.make_root_volume().root_node
        p1 = root.make_subdirectory('dir1')
        p2 = p1.make_subdirectory('dir2')
        file1 = p2.make_file('file.txt')

        for descendant in root.get_descendants(
                live_only=False, kind=StorageObject.DIRECTORY):
            self.assertTrue(descendant.live_children.exists())
            self.assertEqual(descendant.status, STATUS_LIVE)

        p1.unlink_tree()

        for descendant in root.get_descendants(live_only=False):
            self.assertFalse(descendant.live_children.exists())
            self.assertEqual(descendant.status, STATUS_DEAD)

        file1 = StorageObject.objects.get(id=file1.id)
        file1.undelete()

        for descendant in root.get_descendants(
                live_only=False, kind=StorageObject.DIRECTORY):
            self.assertTrue(descendant.live_children.exists())
            self.assertEqual(descendant.status, STATUS_LIVE)

    def test_undelete_inplace(self):
        """Tests undelete in place."""
        root = self.factory.make_root_volume().root_node
        obj = root.make_file('undelete')
        self.assertIn(obj, root.children.all())

        obj.unlink()
        self.assertEqual(obj.status, STATUS_DEAD)
        self.assertIn(obj, root.children.all())
        self.assertNotIn(obj, root.live_children)

        obj.undelete()
        self.assertEqual(obj.status, STATUS_LIVE)
        self.assertEqual(obj.parent, root)
        self.assertIn(obj, root.children.all())

    def test_undelete_w_reparent(self):
        """Test undelete with conflicting name."""
        root = self.factory.make_root_volume().root_node
        p1 = root.make_subdirectory('dir1')
        file1 = p1.make_file('file1.txt')
        p1.make_file('file2.txt')
        # delete p1
        p1.unlink_tree()

        # create a new directory with the same name
        # all files in d1 should be restored to this directory
        p1a = root.make_subdirectory('dir1')
        file1.refresh_from_db()
        file1.undelete()

        # make sure the path and parent are correct
        self.assertEqual(file1.path, '/dir1')
        self.assertEqual(file1.parent, p1a)

    def test_undelete_volume(self):
        """Test undelete_volume."""
        user = self.factory.make_user()
        vol1 = self.factory.make_user_volume(owner=user, path='~/v1')
        restore_dir = vol1.root_node.make_subdirectory('r1')
        a = vol1.root_node.make_subdirectory('a')
        b = a.make_subdirectory('b')
        c = b.make_subdirectory('c')
        c.make_file('file1.txt')
        c.make_file('file2.txt')
        a.unlink_tree()

        for descendant in a.get_descendants(live_only=False):
            self.assertEqual(descendant.status, STATUS_DEAD)

        user.undelete_volume(vol1.id, restore_dir)

        for descendant in c.get_descendants(live_only=False):
            self.assertEqual(descendant.path, '/r1/a/b/c')
            self.assertEqual(descendant.status, STATUS_LIVE)
            self.assertEqual(descendant.parent.full_path, '/r1/a/b/c')
            self.assertEqual(descendant.status, STATUS_DEAD)
            self.assertEqual(descendant.parent.status, STATUS_LIVE)
            self.assertEqual(descendant.parent, c)

    def test_undelete_volume_limit(self):
        """Test undelete_volume with limit."""
        user = self.factory.make_user()
        vol1 = self.factory.make_user_volume(owner=user, path='~/v1')
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
        # delete this file...this will get restored
        node.unlink()

        self.assertEqual(node.status, STATUS_DEAD)

        user.undelete_volume(vol1.id, restore_dir, limit=1)

        node = StorageObject.objects.get(id=node.id)
        self.assertEqual(node.path, '/r1/a/b/c')
        self.assertEqual(node.status, STATUS_LIVE)
        for f in del_files:
            self.assertEqual(f.status, STATUS_DEAD)

    def test_path_middle_change(self):
        """Tests that the path changes when moving a parent of the file."""
        root = self.factory.make_root_volume().root_node
        obj = root.make_file('path change')
        subdir1 = root.make_subdirectory('subdir1')
        subdir2 = root.make_subdirectory('subdir2')

        obj.move(subdir1, obj.name)
        self.assertEqual(obj.path, '/subdir1')

        subdir1.move(subdir2, subdir1.name)
        self.assertEqual(
            StorageObject.objects.get(id=obj.id).path, '/subdir2/subdir1')

        subdir2.move(subdir2.parent, 'newdir2name')
        self.assertEqual(
            StorageObject.objects.get(id=obj.id).path, '/newdir2name/subdir1')

        subdir1.move(root, subdir1.name)
        self.assertEqual(obj.path, '/subdir1')
        # when a parent is moved, dead children don't get path updates
        obj.unlink()
        subdir1.move(subdir2, subdir1.name)
        # object's path is the same
        self.assertEqual(obj.path, '/subdir1')
        # object's parent is updated
        self.assertEqual(obj.parent.path, '/newdir2name')
        # since we're here, make sure the node path is rewritten on restore
        obj.undelete()
        self.assertEqual(obj.path, '/newdir2name/subdir1')

    def test_unlink_is_not_delete(self):
        """Tests that the object is deleted/removed from the db."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory('subdir')
        self.assertIsNotNone(subdir)

        parent = subdir.parent
        name = subdir.name
        # test subdir is 'there'
        node = StorageObject.objects.get(id=subdir.id)
        self.assertEqual(node, subdir)
        subdir.unlink()

        subdir2 = StorageObject.objects.get(id=subdir.id)
        self.assertEqual(name, subdir2.name)
        self.assertEqual(parent, subdir2.parent)
        self.assertEqual(subdir2.status, STATUS_DEAD)

    def test_unlink_is_not_delete_udf(self):
        """Tests that the object is deleted/removed from the udf."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        subdir = udf.root_node.make_subdirectory('subdir')

        # test subdir is 'there', and remove it
        StorageObject.objects.get(id=subdir.id)
        subdir.unlink()

        subdir2 = StorageObject.objects.get(id=subdir.id)
        self.assertEqual('subdir', subdir2.name)
        self.assertEqual(udf.root_node, subdir2.parent)
        self.assertEqual(subdir2.status, STATUS_DEAD)

    def test_update_used_bytes(self):
        """Test the tracking of storage bytes used by a user"""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')
        self.assertEqual(0, root.volume.owner.used_bytes)
        content = self.factory.make_content_blob()

        for i in range(100):
            subdir.make_file('File%s' % i, content_blob=content)

        self.assertEqual(
            root.volume.owner.used_bytes, content.size * 100)

    def test_update_used_bytes_udf(self):
        """Test the tracking of storage bytes used by a user in an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        subdir = udf.root_node.make_subdirectory('subdir')

        self.assertEqual(0, udf.owner.used_bytes)
        content = self.factory.make_content_blob()

        for i in range(10):
            subdir.make_file('File%s' % i, content_blob=content)

        self.assertEqual(
            udf.owner.used_bytes, content.size * 10)

    def test_recalculate_used_bytes(self):
        """Test the recalculating used bytes."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        vol1 = self.factory.make_user_volume(owner=user, path='~/v1')
        vol2 = self.factory.make_user_volume(owner=user, path='~/v2')

        self.assertEqual(0, user.used_bytes)
        content = self.factory.make_content_blob()

        for i in range(10):
            root.make_file('File%s' % i, content_blob=content)
            vol1.root_node.make_file('File%s' % i, content_blob=content)
            vol2.root_node.make_file('File%s' % i, content_blob=content)

        expected_used = content.size * 30
        self.assertEqual(user.used_bytes, expected_used)

        # we now have 3 volumes with data on them.
        user.used_storage_bytes = 100
        user.recalculate_used_bytes()
        self.assertEqual(user.used_storage_bytes, expected_used)

        for c in root.children.all():
            c.unlink()
        self.assertEqual(user.used_bytes, expected_used * 2 / 3)

        # manually change the volume status
        vol2.status = STATUS_DEAD
        self.assertEqual(user.used_bytes, expected_used * 2 / 3)

        vol2.save()
        user.recalculate_used_bytes()
        self.assertEqual(user.used_bytes, expected_used * 1 / 3)

    def test_update_used_bytes_on_delete(self):
        """Test the tracking of storage bytes used by a user, when files
        are deleted.
        """
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')
        self.assertEqual(0, root.volume.owner.used_bytes)
        content = self.factory.make_content_blob()
        for i in range(10):
            filenode = subdir.make_file('File%s' % i, content_blob=content)
            if i % 2:
                filenode.unlink()

        self.assertEqual(
            root.volume.owner.used_bytes, content.size * 5)

        filenode = subdir.make_file('Blah', content_blob=content)
        filenode.volume.owner.max_storage_bytes = 0
        filenode.unlink()  # should succeed even if we are over quota

    def test_update_used_bytes_on_delete_udf(self):
        """Test the tracking of bytes used, when files in UDF are deleted."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        subdir = udf.root_node.make_subdirectory('subdir')
        self.assertEqual(0, udf.owner.used_bytes)
        content = self.factory.make_content_blob()

        for i in range(10):
            filenode = subdir.make_file('File%s' % i, content_blob=content)
            if i % 2:
                filenode.unlink()

        self.assertEqual(udf.owner.used_bytes, content.size * 5)

        filenode = subdir.make_file('Blah', content_blob=content)
        filenode.volume.owner.max_storage_bytes = 0
        filenode.unlink()  # should succeed even if we are over quota

    def test_update_used_bytes_on_move(self):
        """Test the tracking of storage bytes used by a user, when
        files are moved.
        """
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        assert root.volume.owner.used_bytes == 0

        subdir = root.make_subdirectory('subdir')
        subdir2 = root.make_subdirectory('subdir2')
        self.assertEqual(0, root.volume.owner.used_bytes)
        content = self.factory.make_content_blob()
        for i in range(10):
            filenode = subdir.make_file('File%s' % i, content_blob=content)
            if i % 2:
                filenode.move(subdir2, filenode.name)

        self.assertEqual(
            root.volume.owner.used_bytes, content.size * 10)

    def test_update_last_modified_on_content(self):
        """Tests that when_last_modified is updated when the content changes"""
        user = self.factory.make_user(username='a_test_user')
        content = self.factory.make_content_blob()
        root = StorageObject.objects.get_root(user)
        before = now()
        filenode = root.make_file('a_File', content_blob=content)
        after = now()
        self.assertTrue(after > filenode.when_last_modified > before)

    def test_update_last_modified_on_make(self):
        """Tests that when_last_modified is updated when the contents change"""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')

        before_file = now()
        subdir.make_file('a_file')
        after_file = now()

        self.assertLessEqual(before_file, subdir.when_last_modified)
        self.assertLessEqual(subdir.when_last_modified, after_file)

        before_dir = now()
        subdir.make_subdirectory('subsubdir')
        after_dir = now()
        self.assertLessEqual(before_dir, subdir.when_last_modified)
        self.assertLessEqual(subdir.when_last_modified, after_dir)

    def test_max_used_bytes(self):
        """Tests that used_storage_bytes accepts the max bigint value. """
        user = self.factory.make_user(username='a_test_user')
        max_bigint = 9223372036854775807  # max bigint value
        user.used_storage_bytes = max_bigint

        self.assertEqual(max_bigint, user.used_storage_bytes)

    def test_move_directory_into_itself(self):
        """Tests that a directory can't be moved into itself."""
        subdir = self.factory.make_directory()
        self.assertRaises(
            errors.NoPermission, subdir.move, subdir, subdir.name)

    def test_move_file_into_itself(self):
        """Tests that a file can't be moved into itself."""
        a_file = self.factory.make_file()
        self.assertRaises(
            errors.NoPermission, a_file.move, a_file, a_file.name)

    def test_move_no_op(self):
        """Do nothing when the new parent/name are equal the existing ones.

        If move() is called with the existing parent and name as arguments, it
        does nothing.
        """
        f = self.factory.make_file()
        old_generation = f.generation

        f.move(f.parent, f.name)

        self.assertEqual(old_generation, f.generation)

    def test_move_requires_uuid_for_new_parent_id(self):
        """move() will raise a TypeError if parent_id is a str."""
        f = self.factory.make_file()
        self.assertRaises(TypeError, f.move, object(), f.name)

    def test_move_to_file(self):
        """Tests that a node can't be moved to a file."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')
        a_file = root.make_file('a_file')
        self.assertRaises(
            errors.NotADirectory, subdir.move, a_file, subdir.name)
        b_file = root.make_file('b_file')
        self.assertRaises(
            errors.NotADirectory, b_file.move, a_file, b_file.name)

    def test_move_to_child(self):
        """Tests that a node can't be moved to a child."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')
        subdir2 = subdir.make_subdirectory('subdir2')
        self.assertRaises(
            errors.NoPermission, subdir.move, subdir2, subdir.name)
        # move to a child file
        a_file = subdir2.make_file('a_file')
        self.assertRaises(
            errors.NotADirectory, subdir.move, a_file, a_file.name)

    def test_move_to_child_deeper(self):
        """Tests that a node can't be moved to a child."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        subdir = root.make_subdirectory('subdir')
        subdir1 = subdir.make_subdirectory('subdir1')
        subdir2 = subdir1.make_subdirectory('subdir2')
        self.assertRaises(
            errors.NoPermission, subdir.move, subdir2, subdir.name)
        # move to a child file
        a_file = subdir2.make_file('a_file')
        self.assertRaises(
            errors.NotADirectory, subdir.move, a_file, a_file.name)

    def test_move_to_inner_dir_specific_case(self):
        """Test a specific case of moving it down."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        dira = root.make_subdirectory('dira')
        dirb = dira.make_subdirectory('dirb')
        dirc = root.make_subdirectory('dirc')

        # this should be just fine
        dirc.move(dirb, dirc.name)

    def test_move_to_inner_dir_similar_name_1(self):
        """Test a case of moving it down with similar name."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        dir1 = root.make_subdirectory('foobar')
        dir2 = root.make_subdirectory('foobarX')

        # this should be just fine
        dir1.move(dir2, dir1.name)

    def test_move_to_inner_dir_similar_name_2(self):
        """Test a case of moving it down with similar name."""
        user = self.factory.make_user(username='a_test_user')
        root = StorageObject.objects.get_root(user)
        dir1 = root.make_subdirectory('foobarX')
        dir2 = root.make_subdirectory('foobar')

        # this should be just fine
        dir1.move(dir2, dir1.name)

    def test_has_volume_attribute(self):
        """Test that StorageObject has a volume_id attribute."""
        user = self.factory.make_user()
        root_node = StorageObject.objects.get_root(user)
        expected = UserVolume.objects.get(
            owner=user, storageobject__name=ROOT_NAME)
        self.assertEqual(root_node.volume, expected)
        node = self.factory.make_directory(parent=root_node)
        self.assertEqual(
            node.volume, node.parent.volume)

    def test_volume_id_is_correct(self):
        """volume_id is the same as the node's parent."""
        root = self.factory.make_root_volume().root_node
        obj = root.make_file('foo.py')
        assert obj.parent == root
        dirnode = root.make_subdirectory('some dir')
        assert dirnode.parent == root

        self.assertEqual(obj.volume, obj.parent.volume)
        self.assertEqual(dirnode.volume, dirnode.parent.volume)

    def test_volume_id_is_correct_on_children(self):
        """The volume is the root's no matter how deep the node is."""
        root = self.factory.make_root_volume().root_node
        subdir = root.make_subdirectory(name='A test')
        self.assertEqual(subdir.volume, root.volume)

        subfile = subdir.make_file(name='A file test.txt')
        self.assertEqual(subfile.volume, root.volume)

    def test_invalid_volume_id(self):
        """The volume should be a valid instance."""
        user = self.factory.make_user()

        kwargs = dict(owner=user, name='test.txt', volume=object(),
                      kind=StorageObject.FILE)
        self.assertRaises(ValueError, StorageObject.objects.create, **kwargs)

    def test_get_node_parent_paths(self):
        """Test get_node_parent_paths."""
        root = self.factory.make_root_volume().root_node
        self.assertEqual(root.parent_paths, [])

        node = self.factory.make_file()
        assert node.parent != root
        node.path = '/'
        expected = ['/']
        self.assertEqual(node.parent_paths, expected)
        node.path = '/a/b/c'
        expected = ['/', '/a', '/a/b', '/a/b/c']
        self.assertEqual(node.parent_paths, expected)

    def test_get_node_parentids(self):
        """Test get_node_parentids"""
        root = self.factory.make_root_volume().root_node
        pids = root.get_parent_ids()
        self.assertEqual(pids, [])

        dir1 = root.make_subdirectory('dir1')
        dir2 = dir1.make_subdirectory('dir2')
        dir3 = dir2.make_subdirectory('dir3')
        dir4 = dir3.make_subdirectory('dir4')
        dir5 = dir4.make_subdirectory('dir5')
        dir6 = dir5.make_subdirectory('dir6')

        pids = dir6.get_parent_ids()
        # the node itself is not included -- redundant assert, for explictness
        self.assertNotIn(dir6.id, pids)
        # 6 parents including root_id
        self.assertItemsEqual(
            pids, [root.id, dir1.id, dir2.id, dir3.id, dir4.id, dir5.id])

    def test_get_node_parentids_only_live(self):
        """Test that get_node_parentids only return Live nodes."""
        root = self.factory.make_root_volume().root_node
        dir1 = root.make_subdirectory('dir1')
        dir2 = dir1.make_subdirectory('dir2')
        dir3 = dir2.make_subdirectory('dir3')
        leaf = dir3.make_subdirectory('leaf')

        pids = leaf.get_parent_ids()
        # 4 parents including root_id
        self.assertItemsEqual(pids, [root.id, dir1.id, dir2.id, dir3.id])

        dir2.unlink_tree()
        pids = leaf.get_parent_ids()
        self.assertItemsEqual(pids, [dir3.id])

    def test_get_node_parentids_filters_out_files(self):
        """Test that get_node_parentids only return Directory nodes."""
        root = self.factory.make_root_volume().root_node

        dir1 = root.make_subdirectory('dir1')
        root.make_file('a test')

        dir2 = dir1.make_subdirectory('dir2')
        for i in range(3):  # make many siblings
            dir1.make_subdirectory('sibling%s' % i).id
        dir1.make_file('other test')

        leafdir = dir2.make_subdirectory('leaf dir')
        pids = leafdir.get_parent_ids()
        self.assertItemsEqual(pids, [root.id, dir1.id, dir2.id])

        leaffile = leafdir.make_file('leaf file')
        pids = leaffile.get_parent_ids()
        self.assertItemsEqual(pids, [root.id, dir1.id, dir2.id, leafdir.id])

    def test_get_node_parentids_filters_by_volumes(self):
        """Method get_node_parentids only return parents in the same volume."""
        parent1 = self.factory.make_user_volume().root_node
        parent2 = self.factory.make_user_volume().root_node

        expected = []
        for i in range(4):
            expected.append(parent1.id)
            same_name = 'dir-%s' % i
            parent1 = parent1.make_subdirectory(same_name)
            parent2 = parent2.make_subdirectory(same_name)

        pids = parent1.get_parent_ids()
        self.assertItemsEqual(pids, expected)


class StorageObjectGenerationsTestCase(BaseTestCase):
    """Test generation handling in StorageObject methods."""

    def setUp(self):
        super(StorageObjectGenerationsTestCase, self).setUp()
        self.user = self.factory.make_user()
        self.volume, _ = UserVolume.objects.get_or_create_root(self.user)
        self.root = self.volume.root_node

    def test_init_from_parent(self):
        """Make sure __init__ increments generation when from parent.

        This basically tests all the make_file, make_subdirectory methods.
        """
        start_gen = self.volume.generation
        # when an object is created it increments the gen.
        node = StorageObject.objects.create(
            name='n', kind=StorageObject.FILE, parent=self.root)
        self.assertEqual(node.generation, start_gen + 1)

    def test_make_public(self):
        """Generation is incremented when the public access is changed."""
        node = self.root.make_file('file.txt')
        start_gen = self.volume.generation
        node.make_public()
        self.assertEqual(node.generation, start_gen + 1)

    def test_make_private(self):
        """Generation is incremented when the public access is changed."""
        node = self.root.make_file('file.txt')
        start_gen = self.volume.generation
        node.make_public()
        node.make_private()
        self.assertEqual(node.generation, start_gen + 2)

    def test_content_property(self):
        """Generation is incremented when content is updated."""
        node = self.root.make_file('file.txt')
        start_gen = self.volume.generation

        cb = self.factory.make_content_blob()
        node.content = cb

        self.assertEqual(node.generation, start_gen + 1)

    def test_move(self):
        """Move updates the generation of the moved node."""
        d1 = self.root.make_subdirectory('d1')
        node = d1.make_file('f1.txt')
        start_gen = self.volume.generation
        node.move(self.root, node.name)
        self.assertEqual(node.generation, start_gen + 1)

    def test_move_dir_special(self):
        """Test move directory to another with a % in it."""
        d1 = self.root.make_subdirectory('a%bc')
        d2 = self.root.make_subdirectory('x%yz')
        d2.move(d1, d2.name)
        self.assertEqual(d2.full_path, '/a%bc/x%yz')

    def test_move_rename(self):
        """Move rename updates the generation of the moved node."""
        node = self.root.make_subdirectory('d1')
        start_gen = self.volume.generation
        node.move(self.root, 'newname')
        self.assertEqual(node.generation, start_gen + 1)

    def test_move_with_backslash(self):
        """Move works also with backslash in the name."""
        node = self.root.make_subdirectory('break me')
        start_gen = self.volume.generation
        node.move(self.root, 'break\\347\\343it really\\355bad')

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


class MoveFromShareTestCase(BaseTestCase):
    """Test MoveFromShare."""

    def test_create_mfs(self):
        """Basic create test."""
        node = self.factory.make_file(name='TheFile.txt')
        share_id = uuid.uuid4()
        mnode = MoveFromShare.objects.from_move(node, share_id)
        self.assertEqual(mnode.share_id, share_id)
        self.assertEqual(mnode.node_id, node.id)
        self.assertEqual(mnode.parent, None)
        self.assertEqual(mnode.volume, node.volume)
        self.assertEqual(mnode.content_blob, node.content_blob)
        self.assertEqual(mnode.kind, node.kind)
        self.assertEqual(mnode.when_created, node.when_created)
        # XXX
        # self.assertEqual(mnode.when_last_modified, node.when_last_modified)
        self.assertEqual(mnode.status, STATUS_DEAD)
        self.assertEqual(mnode.path, node.path)
        self.assertEqual(mnode.generation, node.generation)
        self.assertEqual(mnode.generation_created, node.generation_created)

    def test_ShareVolumeDelta(self):
        """Test the ShareVolumeDelta view."""
        u = self.factory.make_user()
        # create 10 StorageObjects and MoveFromShare.
        share_id = uuid.uuid4()
        for i in range(10):
            node = self.factory.make_file(
                owner=u, name='TheFile%s.txt' % i, generation=i)
            MoveFromShare.objects.from_move(node, share_id)
        result = ShareVolumeDelta.objects.filter(
            models.Q(share_id__isnull=True) |
            models.Q(share_id=share_id))
        # it is 21 because of the root node
        self.assertEqual(result.count(), 21)


class ShareTestCase(BaseTestCase):
    """Tests for Share."""

    def setUp(self):
        super(ShareTestCase, self).setUp()
        self.user1 = self.factory.make_user(username='user0')
        self.user2 = self.factory.make_user(username='user1')
        self.root = StorageObject.objects.get_root(self.user1)

    def test_share_invalid_name(self):
        """Attempt to create a Share with an invalid filename."""
        self.assertRaises(
            errors.InvalidFilename, Share.objects.create, name='bob/../../../')

    def test_create_share(self):
        """Create a Share."""
        user3 = self.factory.make_user(username='user2')

        # see if creation goes ok
        share = self.factory.make_share(
            subtree=self.root, shared_to=self.user2, name='foo')
        self.assertEqual(share.shared_by, self.user1)
        self.assertEqual(share.subtree, self.root)
        self.assertEqual(share.shared_to, self.user2)
        self.assertEqual(share.name, 'foo')
        self.assertEqual(share.access, Share.VIEW)

        # with other access level
        share = self.factory.make_share(
            subtree=self.root, shared_to=user3, name='bar',
            access=Share.MODIFY)
        self.assertEqual(share.access, Share.MODIFY)

    def test_create_share_udf(self):
        """Create a Share in an UDF."""
        user3 = self.factory.make_user(username='user2')
        root = self.factory.make_user_volume(
            owner=self.user1, path='~/Documents/Stuff/DirToUDF').root_node

        # see if creation goes ok
        share = self.factory.make_share(
            subtree=root, shared_to=self.user2, name='foo')
        self.assertEqual(share.shared_by, self.user1)
        self.assertEqual(share.subtree, root)
        self.assertEqual(share.shared_to, self.user2)
        self.assertEqual(share.name, 'foo')
        self.assertEqual(share.access, Share.VIEW)

        # with other access level
        share = self.factory.make_share(
            subtree=root, shared_to=user3, name='bar', access=Share.MODIFY)
        self.assertEqual(share.access, Share.MODIFY)

    def test_create_share_same_name(self):
        """Create a Share from user1 to user2, different nodes, same name."""
        node = self.root.make_subdirectory('newdir')

        self.factory.make_share(
            subtree=node, shared_to=self.user2, name='foo',
            access=Share.MODIFY)
        self.assertRaises(
            IntegrityError, self.factory.make_share, subtree=node,
            shared_to=self.user2, name='foo', access=Share.MODIFY)

    def test_create_same_share_after_delete(self):
        """ (re)creates a share after deleting it """
        self.root.make_subdirectory('newdir')

        # create and delete the share
        for x in range(3):
            share = self.factory.make_share(
                subtree=self.root, shared_to=self.user2, name='foo',
                access=Share.MODIFY)
            share.kill()
        # now make sure we have more than one share named 'foo' marked as dead
        dead_shares = Share.objects.filter(
            shared_to=self.user2, name=share.name, status=STATUS_DEAD)
        self.assertTrue(dead_shares.exists())
        self.assertEqual(dead_shares.count(), 3)

    def _test_multiple_shares_same_subtree(self, access):
        """Ensure only one share per subtree."""
        node = self.root.make_subdirectory('newdir')

        # attempt to share same subtree as different shares should fail
        self.factory.make_share(
            subtree=node, shared_to=self.user2, name='share1')
        # we can not create another share using same or different access
        self.assertRaises(
            IntegrityError, self.factory.make_share, subtree=node,
            shared_to=self.user2, name='share2', access=access)

    def test_multiple_shares_same_subtree_access_view(self):
        """Ensure only one share per subtree."""
        self._test_multiple_shares_same_subtree(access=Share.VIEW)

    def test_multiple_shares_same_subtree_access_modify(self):
        """Ensure only one share per subtree."""
        self._test_multiple_shares_same_subtree(access=Share.MODIFY)

    def _test_delete_share(self, access):
        """Share on delete works correctly."""
        node = self.root.make_subdirectory('newdir')
        share1 = self.factory.make_share(
            subtree=node, shared_to=self.user2, name='share1')
        # check behavior on delete
        share1.kill()
        self.factory.make_share(
            subtree=node, shared_to=self.user2, name='share2')
        # we can not create another share using same or different access
        self.assertRaises(
            IntegrityError, self.factory.make_share, subtree=node,
            shared_to=self.user2, name='share1', access=access)

    def test_delete_share_access_view(self):
        self._test_delete_share(access=Share.VIEW)

    def test_delete_share_access_modify(self):
        self._test_delete_share(access=Share.MODIFY)

    def test_share_to_self(self):
        """Share to owner."""
        node = self.root.make_subdirectory('newdir')
        # test creating shares for 'self' and others
        self.factory.make_share(
            subtree=node, shared_to=self.user1, name='share1')
        self.factory.make_share(
            subtree=node, shared_to=self.user2, name='share2')


class UserVolumeTestCase(BaseTestCase):
    """Tests for UDFs."""

    def test_create_volume(self):
        """Create an UDF."""
        # create all the needed objects
        user = self.factory.make_user()

        # see if creation goes ok
        volume = self.factory.make_user_volume(user, '~/somepath')
        self.assertEqual(volume.owner, user)
        self.assertEqual(volume.path, '~/somepath')
        self.assertEqual(volume.status, STATUS_LIVE)
        self.assertEqual(volume.root_node.name, ROOT_NAME)
        self.assertEqual(
            StorageObject.objects.get(volume=volume, parent__isnull=True),
            volume.root_node)
        self.assertTrue(volume.root_node.kind, StorageObject.DIRECTORY)

    def test_increment_generation(self):
        """Test increment_generation."""
        user = self.factory.make_user()
        volume, _ = UserVolume.objects.get_or_create_root(user)
        self.assertEqual(volume.generation, 0)
        volume.increment_generation()
        self.assertEqual(volume.generation, 1)

    def test_create_volume_badpath(self):
        """Create an UDF with a wrong node."""
        user = self.factory.make_user()
        self.assertRaises(
            errors.InvalidVolumePath, UserVolume.objects.create,
            owner=user, path='badpath')

    def test_delete_volume(self):
        """Delete an UDF."""
        # create all the needed objects
        user = self.factory.make_user()
        volume = self.factory.make_user_volume(owner=user, path='~/somepath')
        generation = volume.generation

        # see if deletion goes ok
        volume.kill()
        self.assertEqual(volume.status, STATUS_DEAD)
        self.assertEqual(generation + 1, volume.generation)

    def test_create_volume_using_the_classmethod(self):
        """Create an UserVolume."""
        user = self.factory.make_user()
        self.assertRaises(
            errors.NoPermission, self.factory.make_user_volume,
            owner=user, path=settings.ROOT_USERVOLUME_PATH)
        volume = self.factory.make_user_volume(
            owner=user, path='~/Documents/Stuff/DirToUDF')
        node = volume.root_node

        # check node properties
        self.assertEqual(node.volume.owner, user)
        self.assertEqual(node.path, '/')
        self.assertEqual(node.name, '')
        self.assertEqual(node.parent, None)
        self.assertEqual(node.kind, StorageObject.DIRECTORY)
        self.assertEqual(node.status, STATUS_LIVE)
        self.assertEqual(node.volume, volume)

        # check volume is ok
        self.assertEqual(volume.root_node, node)
        self.assertEqual(volume.owner, user)
        self.assertEqual(volume.path, '~/Documents/Stuff/DirToUDF')
        self.assertEqual(volume.status, STATUS_LIVE)

    def test_get_or_create_root(self):
        """Create the root UserVolume."""
        user = self.factory.make_user(with_root=False)
        volume, created = UserVolume.objects.get_or_create_root(owner=user)
        self.assertTrue(created)
        node = volume.root_node

        # check node properties
        self.assertEqual(node.volume.owner, user)
        self.assertEqual(node.path, '/')
        self.assertEqual(node.name, '')
        self.assertEqual(node.parent, None)
        self.assertEqual(node.kind, StorageObject.DIRECTORY)
        self.assertEqual(node.status, STATUS_LIVE)
        self.assertEqual(node.volume, volume)

        # check volume is ok
        self.assertEqual(volume.root_node, node)
        self.assertEqual(volume.owner, user)
        self.assertEqual(volume.path, settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(volume.status, STATUS_LIVE)
        self.assertEqual(UserVolume.objects.get_root(user), volume)
        self.assertEqual(UserVolume.objects.get_root(user).root_node, node)
        self.assertEqual(StorageObject.objects.get_root(user), node)
        self.assertEqual(
            StorageObject.objects.get(volume=volume, parent__isnull=True),
            node)

        volume2, created = UserVolume.objects.get_or_create_root(owner=user)
        self.assertFalse(created)
        self.assertEqual(volume, volume2)

    def test_get_root_volume(self):
        """Test the get_root method."""
        user = self.factory.make_user()
        volume1, _ = UserVolume.objects.get_or_create_root(owner=user)
        volume2 = UserVolume.objects.get_root(user)
        self.assertEqual(volume1, volume2)

    def add_tree_and_files(self, volume):
        """Add a subtree and 100 files to the volume"""
        content = self.factory.make_content_blob()
        self.factory.make_tree_and_files(
            volume.root_node, name='SubDir', content=content, amount=10)
        return content.size * 10

    def test_volume_size(self):
        """Test to make sure tree size works"""
        user = self.factory.make_user(
            username='a_test_user', max_storage_bytes=50 * (2 ** 30))
        volume, _ = UserVolume.objects.get_or_create_root(owner=user)
        self.assertEqual(volume.volume_size(), 0)

        size = self.add_tree_and_files(volume)
        self.assertGreater(size, 0)
        self.assertEqual(size, volume.volume_size())
        # reload StorageUser
        user = StorageUser.objects.get(id=user.id)
        self.assertEqual(user.used_storage_bytes, size)

    def test_delete(self):
        """Test to make sure delete works."""
        user = self.factory.make_user(
            username='a_test_user', max_storage_bytes=50 * (2 ** 30))
        volume, _ = UserVolume.objects.get_or_create_root(owner=user)
        self.add_tree_and_files(volume)
        # delete the volume.
        volume.kill()
        self.assertEqual(volume.volume_size(), 0)
        self.assertEqual(volume.owner.used_bytes, 0)


class UploadJobTestCase(BaseTestCase):
    """Tests for UploadJob."""

    def test_uploadjob_create(self):
        """Test upload job creation."""
        job = self.factory.make_upload_job()
        self.assertIsNotNone(job.id)

    def test_uploadjob_create_udf(self):
        """Test upload job creation in an UDF."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        root = udf.root_node
        obj = root.make_file(name='file.ext')

        job = self.factory.make_upload_job(node=obj)
        self.assertEqual(job.node, obj)

    def test_uploadjob_add_part(self):
        """Test add_part method."""
        u = self.factory.make_user()
        obj = self.factory.make_file(owner=u, name='file.ext')
        job = UploadJob.objects.create(
            node=obj, multipart_key=uuid.uuid4(), hash_hint=b'bar',
            crc32_hint=0)
        job.add_part(10)
        self.assertEqual(job.chunk_count, 1)
        self.assertEqual(job.uploaded_bytes, 10)
        job.add_part(10)
        self.assertEqual(job.chunk_count, 2)
        self.assertEqual(job.uploaded_bytes, 20)

    def test_uploadjob_find(self):
        """Test add_part method."""
        u = self.factory.make_user()
        obj = self.factory.make_file(owner=u, name='file.ext')
        job = UploadJob.objects.create(
            node=obj, multipart_key=uuid.uuid4(), hash_hint=b'bar',
            crc32_hint=0)
        job.add_part(10)
        same_job = UploadJob.objects.get(id=job.id)
        self.assertEqual(job.uploaded_bytes, same_job.uploaded_bytes)
        self.assertEqual(job.chunk_count, same_job.chunk_count)


class DownloadTestCase(BaseTestCase):
    """Tests for the Download object."""

    def test_constructor(self):
        """Test the Download class's constructor."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        download = Download.objects.create(
            volume=udf, file_path='file_path',
            download_url='http://download/url')
        self.assertIsInstance(download.id, uuid.UUID)
        self.assertEqual(download.volume, udf)
        self.assertEqual(download.file_path, 'file_path')
        self.assertEqual(download.download_url, 'http://download/url')
        self.assertEqual(download.status, Download.STATUS_QUEUED)
        self.assertIsInstance(download.status_change_date, datetime)
        self.assertEqual(download.node_id, None)
        self.assertEqual(download.error_message, '')

    def test_set_status(self):
        """The set_status() method updates the timestamp."""
        udf = self.factory.make_user_volume(path='~/Documents/Stuff/DirToUDF')
        download = Download.objects.create(
            volume=udf, file_path='file_path',
            download_url='http://download/url')
        old_timestamp = download.status_change_date

        download.status = Download.STATUS_DOWNLOADING
        download.save()

        self.assertEqual(download.status, Download.STATUS_DOWNLOADING)
        # The timestamp has been updated.
        self.assertNotEqual(download.status_change_date, old_timestamp)


class ResumableUploadTest(BaseTestCase):
    """Rest ResumableUpload """

    def test_constructor(self):
        user = self.factory.make_user(username='username')
        vol_path = '~/MyVolume/and/file/path.txt'
        storage_key = uuid.uuid4()
        size = 1000 * (2 ** 30)
        upload = self.factory.make_resumable_upload(
            owner=user, volume_path=vol_path, size=size,
            storage_key=storage_key)

        u = ResumableUpload.objects.get(id=upload.id)
        self.assertEqual(u.owner, user)
        self.assertEqual(u.volume_path, vol_path)
        self.assertEqual(u.storage_key, storage_key)
        self.assertEqual(u.uploaded_bytes, 0)
        self.assertEqual(u.part_count, 0)

    def test_add_part(self):
        user = self.factory.make_user(username='username')
        vol_path = '~/MyVolume/and/file/path.txt'
        size = 1000 * (2 ** 30)
        storage_key = uuid.uuid4()
        upload = self.factory.make_resumable_upload(
            owner=user, volume_path=vol_path, size=size,
            storage_key=storage_key)
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
        result = validate_name(filename)
        self.assertEqual(result, filename)

    def test_validatename_no_name(self):
        """Validate setting the name to None."""
        filename = None
        result = validate_name(filename)
        self.assertEqual(result, filename)

    def test_validatename_name_ok(self):
        """Validate a fine name."""
        filename = 'valid file name'
        result = validate_name(filename)
        self.assertEqual(result, filename)

    def test_validatename_bytes(self):
        """Validate a name that are bytes."""
        self.assertRaises(errors.InvalidFilename,
                          validate_name, b'bytes')

    def test_validatename_illegal_name(self):
        """Validate not allowed names."""
        self.assertRaises(errors.InvalidFilename,
                          validate_name, '.')
        self.assertRaises(errors.InvalidFilename,
                          validate_name, '..')

    def test_validatename_illegal_chars(self):
        """Validate names with illegal chars."""
        self.assertRaises(errors.InvalidFilename,
                          validate_name, 'with a / in it')
        self.assertRaises(errors.InvalidFilename,
                          validate_name, 'not \x00 null')
