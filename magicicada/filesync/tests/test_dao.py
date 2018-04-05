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

"""Test the Data Access Objects."""

from __future__ import unicode_literals

import uuid

from operator import attrgetter

from django.conf import settings
from mocker import Mocker, expect

from magicicada.filesync import errors, services, utils
from magicicada.filesync.models import (
    STATUS_LIVE,
    STATUS_DEAD,
    ContentBlob,
    StorageObject,
)
from magicicada.testing.testcase import BaseTestCase


class StorageDALTestCase(BaseTestCase):

    session_id = 'some-session-id'

    def create_user(self, **kwargs):
        assert 'id' not in kwargs
        kwargs.setdefault(
            'username', self.factory.get_unique_string(prefix='user-'))
        return services.make_storage_user(session_id=self.session_id, **kwargs)

    def create_files(self, parent, amount=10):
        result = [
            parent.make_file_with_content(
                'file-%s' % i, hash=b'', crc32=10, size=100, deflated_size=50,
                storage_key=uuid.uuid4())
            for i in range(amount)]
        return result


class DAOInitTestCase(StorageDALTestCase):
    """Test to make sure DAOs are properly initialized from the models.

    These tests have no database access.
    """

    def _compare_props(self, instance, dao_object, properties):
        """Compare the common properties between a model and dao."""
        for prop in properties:
            instance_value = getattr(instance, prop)
            dao_value = getattr(dao_object, prop)
            self.assertEqual(
                instance_value, dao_value,
                'Property %r does not match (instance has %r, dao has %r)' %
                (prop, instance_value, dao_value))

    def test_StorageUser(self):
        """Test StorageUser init"""
        user = self.factory.make_user(username='theusername')
        u_dao = services.DAOStorageUser(user)
        self._compare_props(
            user, u_dao,
            ['id', 'username', 'root_node', 'first_name', 'last_name'])
        self.assertEqual(u_dao.is_active, True)

    def test_StorageNode(self):
        """Test StorageNode init."""
        # the owner of the node
        u = self.factory.make_user(username='theusername')
        owner = services.DAOStorageUser(u)
        # the FileNodeContent of the node
        cb = self.factory.make_content_blob()
        content = services.FileNodeContent(cb)
        # the node
        node = self.factory.make_file(
            owner=u, parent=u.root_node, name='Name', mimetype='image/tiff',
            public=True, content_blob=cb)
        perms = dict(can_read=True, can_write=True, can_delete=True)

        # In this case, StorageNode is different that all other DAOs,
        # it generates either a FileNode or DirectoryNode object, and normally
        # requires a gateway as the first parameter. In addition, it can be
        # created along with a mimetype, content, and owner DAO
        node_dao = services.StorageNode.factory(
            None, node, owner=owner, permissions=perms, content=content)
        self._compare_props(
            node, node_dao,
            ['id', 'kind', 'parent_id', 'status', 'when_created',
             'when_last_modified', 'generation', 'generation_created',
             'mimetype', 'public_uuid'])
        self.assertIsInstance(node_dao, services.FileNode)
        # mimetype object will not be directly accessible
        self.assertEqual(node_dao.nodekey, utils.make_nodekey(None, node.id))
        self.assertEqual(node_dao.content, content)
        self.assertEqual(node_dao.owner, owner)
        self.assertEqual(node_dao.can_read, True)
        self.assertEqual(node_dao.can_write, True)
        self.assertEqual(node_dao.can_delete, True)
        node_dao.public_uuid = None
        self.assertEqual(node_dao.public_key, None)
        node.generation = None
        node.generation_created = None
        node_dao = services.StorageNode.factory(
            None, node, owner=owner, permissions=perms, content=content)
        self.assertEqual(node_dao.generation, 0)
        self.assertEqual(node_dao.generation_created, 0)
        # basic check for a directory
        node.kind = StorageObject.DIRECTORY
        dir_dao = services.StorageNode.factory(
            None, node, owner=owner, content=content, permissions={})
        self.assertIsInstance(dir_dao, services.DirectoryNode)
        # content for Directories is ignored
        self.assertEqual(dir_dao.content, None)
        self.assertEqual(dir_dao.can_read, False)
        self.assertEqual(dir_dao.can_write, False)
        self.assertEqual(dir_dao.can_delete, False)

    def test_FileNodeContent(self):
        """Test ContentBlob init."""
        cb = self.factory.make_content_blob()
        cb_dao = services.FileNodeContent(cb)
        self._compare_props(cb, cb_dao, ['hash', 'size', 'deflated_size',
                                         'storage_key', 'crc32', 'status',
                                         'magic_hash', 'when_created'])
        cb.size = 0
        cb_dao = services.FileNodeContent(cb)
        self.assertEqual(cb_dao.deflated_size, 0)
        self.assertEqual(cb_dao.storage_key, None)
        cb.size = 10
        cb.deflated_size = None
        cb_dao = services.FileNodeContent(cb)
        self.assertEqual(cb_dao.deflated_size, 0)

    def test_SharedFolder(self):
        """Test SharedFolder init."""
        # to test the shared_to and shared_by properties
        u1 = self.factory.make_user(username='the-username')
        u2 = self.factory.make_user(username='other-username')
        user1 = services.DAOStorageUser(u1)
        user2 = services.DAOStorageUser(u2)

        share = self.factory.make_share(owner=u1, shared_to=u2, email='email')
        share_dao = services.SharedDirectory(
            share, by_user=user1, to_user=user2)
        self._compare_props(
            share, share_dao, ['name', 'accepted', 'when_shared', 'status'])
        self.assertEqual(share_dao.root_id, share.subtree.id)
        self.assertEqual(share_dao.read_only, True)
        self.assertEqual(share_dao.offered_to_email, share.email)
        self.assertEqual(share_dao.shared_by, user1)
        self.assertEqual(share_dao.shared_to, user2)

    def test_UserVolume(self):
        """Test UserVolume init."""
        udf = self.factory.make_user_volume(path='~/the path')
        udf_dao = services.DAOUserVolume(udf, None)
        self._compare_props(
            udf, udf_dao, ['id', 'path', 'generation', 'when_created'])
        udf.generation = None
        udf_dao = services.DAOUserVolume(udf, None)
        self.assertEqual(udf_dao.generation, 0)

    def test_UploadJob(self):
        """Test UploadJob init."""
        upload = self.factory.make_upload_job()
        upload_dao = services.DAOUploadJob(upload)
        self._compare_props(
            upload, upload_dao,
            ['node', 'chunk_count', 'hash_hint', 'crc32_hint', 'when_started',
             'when_last_active', 'multipart_key', 'uploaded_bytes'])

    def test_Download(self):
        """Test Download init."""
        volume = self.factory.make_user_volume()
        download = self.factory.make_download(
            volume=volume, file_path='The Path', download_url='The Url',
            download_key='Key')
        dao_download = services.DAODownload(download)
        self.assertEqual(dao_download.owner_id, download.volume.owner.id)
        self.assertEqual(dao_download.volume_id, download.volume.id)
        self.assertEqual(dao_download.file_path, 'The Path')
        self.assertEqual(dao_download.download_url, 'The Url')
        self.assertEqual(dao_download.download_key, "u'Key'")


class VolumeProxyTestCase(StorageDALTestCase):
    """Test the VolumeProxy class."""

    def _make_content_on_volume(self, vol_root):
        """Make content on this volume to get it with the proxy."""
        name = 'filename'
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = 100
        deflated_size = 10000
        vol_root.make_file_with_content(name, hash, crc, size,
                                        deflated_size, storage_key,
                                        mimetype=mime)
        return hash

    def test_VolumeProxy_root(self):
        """Test the VolumeProxy.

        This will also test the laziness of the root property
        """
        user = self.create_user()
        volume = user.volume()
        root = user.volume().root
        # the root on the volume proxy is an uninitialized DirectoryNode
        # the id is set to 'root' until it get's resolve.
        self.assertIsInstance(root, services.DirectoryNode)
        # the root won't get resolved until a db operation is needed
        self.assertEqual(volume.root.id, 'root')
        self.assertEqual(root.id, 'root')
        # we'll force it to load, by doing something
        dir = root.make_subdirectory('A Subdirectory')
        self.assertNotEqual(volume.root.id, 'root')
        self.assertNotEqual(root.id, 'root')
        self.assertEqual(root.id, dir.parent_id)
        self.assertEqual(dir.vol_type, 'root')
        self.assertEqual(dir.vol_share, None)
        self.assertEqual(dir.vol_udf, None)
        self.assertEqual(root.volume_id, dir.volume_id)
        hash = self._make_content_on_volume(root)
        content = user.volume().get_content(hash)
        self.assertEqual(bytes(content.hash), hash)

    def test_VolumeProxy_udf(self):
        """Test the VolumeProxy."""
        user = self.create_user()
        # Test a udf volume:
        udf = user.make_udf('~/path/name')
        udf_volume = user.volume(udf.id)
        root = udf_volume.root
        dir = root.make_subdirectory('A Subdirectory')
        self.assertEqual(dir.parent_id, udf.root_id)
        self.assertEqual(dir.volume_id, udf.id)
        self.assertEqual(dir.vol_id, udf.id)
        self.assertEqual(dir.vol_type, 'udf')
        self.assertEqual(dir.vol_share, None)
        self.assertEqual(dir.vol_udf.id, udf.id)
        self.assertEqual(root.volume_id, udf.id)
        hash = self._make_content_on_volume(root)
        content = user.volume(udf.id).get_content(hash)
        self.assertEqual(bytes(content.hash), hash)

    def test_VolumeProxy_share(self):
        """Test the VolumeProxy."""
        user = self.create_user()
        user2 = self.create_user(username='user2')
        share = user.root.share(user2.id, 'ShareName')
        user2.get_share(share.id).accept()
        root = user2.volume(share.id).root
        dir = root.make_subdirectory('A Subdirectory')
        self.assertEqual(dir.parent_id, share.root_id)
        self.assertEqual(dir.vol_id, share.id)
        self.assertEqual(dir.vol_type, 'share')
        self.assertEqual(dir.vol_udf, None)
        self.assertEqual(dir.vol_share.id, share.id)
        hash = self._make_content_on_volume(root)
        content = user2.volume(share.id).get_content(hash)
        self.assertEqual(bytes(content.hash), hash)

    def test_VolumeProxy_get_root_and_volume(self):
        """Test the get_root method."""
        user = self.create_user()
        volume = user.volume().get_volume()
        root = user.volume().get_root()
        self.assertIsInstance(root, services.DirectoryNode)
        self.assertIsInstance(volume, services.DAOUserVolume)
        self.assertEqual(volume.id, user.root_volume_id)
        self.assertEqual(root.id, volume.root_id)

    def test_VolumeProxy_udf_get_root_and_volume(self):
        """Test the get_root method."""
        user = self.create_user()
        udf = user.make_udf('~/Documents')
        volume = user.volume(udf.id).get_volume()
        root = user.volume(udf.id).get_root()
        self.assertIsInstance(root, services.DirectoryNode)
        self.assertIsInstance(volume, services.DAOUserVolume)
        self.assertEqual(volume.id, udf.id)
        self.assertEqual(root.id, volume.root_id)

    def test_VolumeProxy_share_get_root_and_volume(self):
        """Test the get_root method."""
        user = self.create_user()
        user2 = self.create_user(username='user2')
        share = user.root.share(user2.id, 'ShareName')
        user2.get_share(share.id).accept()
        volume = user2.volume(share.id).get_volume()
        root = user2.volume(share.id).get_root()
        self.assertIsInstance(root, services.DirectoryNode)
        self.assertIsInstance(volume, services.DAOUserVolume)
        self.assertEqual(volume.id, user.root_volume_id)
        self.assertEqual(root.id, volume.root_id)

    def test_get_all_nodes(self):
        """Test get_all_nodes."""
        user = self.create_user(max_storage_bytes=2 * (2 ** 30))
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = 100
        deflated_size = 10000

        def mkfile(i):
            return user.root.make_file_with_content(
                'f%s' % i, hash, crc, size, deflated_size, storage_key,
                mimetype=mime)

        files = [mkfile(i) for i in range(10)]
        nodes = user.volume().get_all_nodes(kind=StorageObject.FILE)
        self.assertEqual(nodes, files)
        nodes = user.volume().get_all_nodes(mimetypes=['xxx'])
        self.assertEqual(nodes, [])
        nodes = user.volume().get_all_nodes(mimetypes=[mime],
                                            with_content=True)
        self.assertEqual(nodes, files)
        self.assertEqual(bytes(nodes[0].content.hash), hash)

    def test_get_deleted_files(self):
        """Test get_deleted_files."""
        user = self.create_user(max_storage_bytes=2 * (2 ** 30))
        files = [user.root.make_file('file%s.txt' % i) for i in range(20)]
        dead_files = user.volume().get_deleted_files()
        self.assertEqual(dead_files, [])
        for f in files:
            f.delete()
        deleted_files = user.volume().get_deleted_files()
        files.sort(key=attrgetter('when_last_modified'), reverse=True)
        self.assertEqual(len(deleted_files), 20)
        self.assertEqual(files, deleted_files)
        # basic tests of start and limit
        deleted_files = user.volume().get_deleted_files(limit=2)
        self.assertEqual(len(deleted_files), 2)
        self.assertEqual(files[:2], deleted_files)
        deleted_files = user.volume().get_deleted_files(start=3, limit=5)
        self.assertEqual(len(deleted_files), 5)
        self.assertEqual(files[3:8], deleted_files)


class DAOTestCase(StorageDALTestCase):
    """Test the DAO with database access."""

    def create_file(
            self, user, name=None, size=100, deflated_size=None,
            mime='image/tif', crc=12345, storage_key=None,
            hash=None, udf=None):
        """Create a file."""
        if name is None:
            name = 'my-file-{}'.format(uuid.uuid4())
        if storage_key is None:
            storage_key = uuid.uuid4()
        if hash is None:
            hash = self.factory.get_fake_hash()
        if deflated_size is None:
            deflated_size = size
        if udf is None:
            base_volume = user.root
        else:
            base_volume = user.volume(udf.id).root
        file = base_volume.make_file_with_content(
            name, hash, crc, size, deflated_size, storage_key)
        return file

    def test_StorageUser(self):
        """Basic test for StorageUser."""
        user = self.create_user()
        user.update(max_storage_bytes=2)
        self.assertEqual(user.max_storage_bytes, 2)
        self.assertEqual(user.free_bytes, 2)
        self.assertEqual(user.is_active, True)
        user = user.recalculate_quota()
        self.assertEqual(user.max_storage_bytes, 2)
        self.assertEqual(user.free_bytes, 2)

    def test_UserVolume(self):
        """Test the various StorageUser data access functions."""
        user = self.create_user()
        self.assertEqual(len(user.get_udfs()), 0)
        udf = user.make_udf('~/path/name')
        self.assertEqual(udf.path, '~/path/name')
        self.assertEqual(udf.owner_id, user.id)
        self.assertEqual(udf.status, STATUS_LIVE)
        self.assertEqual(udf.owner, user)
        self.assertEqual(udf.is_root, False)
        udf2 = user.get_udf_by_path('~/path/name')
        self.assertEqual(udf.id, udf2.id)
        self.assertEqual(len(user.get_udfs()), 1)
        udf = user.delete_udf(udf.id)
        self.assertEqual(len(user.get_udfs()), 0)
        self.assertEqual(udf.status, STATUS_DEAD)
        self.assertRaises(errors.DoesNotExist, user.get_udf, udf.id)

    def test_get_udf_by_path(self):
        """Test the various methods of getting a UDF by path."""
        user = self.create_user()
        udf = user.make_udf('~/a/b/c')
        udf1 = user.get_udf_by_path('~/a/b/c')
        self.assertEqual(udf.id, udf1.id)
        udf1 = user.get_udf_by_path('~/a/b/c/', from_full_path=True)
        self.assertEqual(udf.id, udf1.id)
        udf1 = user.get_udf_by_path('~/a/b/c/d/e/f', from_full_path=True)
        self.assertEqual(udf.id, udf1.id)
        self.assertRaises(errors.DoesNotExist,
                          user.get_udf_by_path, '~/a/b/c/d/e/f')

    def test_user_get_node_by_path_root(self):
        """Test get_node_by_path from root."""
        user = self.create_user()
        udf = user.volume().get_volume()
        d1 = user.get_node_by_path(settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(d1.id, udf.root_id)
        trick_path = udf.path + ' Tricky'
        udf2 = user.make_udf(trick_path)
        d1 = user.get_node_by_path(trick_path)
        self.assertEqual(d1.id, udf2.root_id)

    def test_user_get_node_by_path(self):
        """Test get_node_by_path."""
        user = self.create_user()
        udf = user.make_udf('~/a/b/c')
        user.make_udf('~/a/b/c_continued')
        d = user.volume(udf.id).root.make_tree('/a/b/c/d')
        f = d.make_file('file.txt')
        # make sure we return the root node
        d1 = user.get_node_by_path(udf.path)
        self.assertEqual(d1.id, udf.root_id)
        d1 = user.get_node_by_path(udf.path + '/')
        self.assertEqual(d1.id, udf.root_id)
        d1 = user.get_node_by_path(udf.path + d.full_path)
        self.assertEqual(d.id, d1.id)
        f1 = user.get_node_by_path(udf.path + f.full_path)
        self.assertEqual(f.id, f1.id)
        self.assertRaises(errors.DoesNotExist,
                          user.get_node_by_path, udf.path + '/x/y/x')
        self.assertRaises(errors.DoesNotExist,
                          user.get_node_by_path, udf.path + '/a/b/c/d/file')
        self.assertRaises(errors.DoesNotExist,
                          user.get_node_by_path, udf.path + '/a/b/c/d/e/f/g')

    def test_user_make_tree_by_path(self):
        """Test user.make_tree_by_path."""
        user = self.create_user()
        d = user.make_tree_by_path(settings.ROOT_USERVOLUME_PATH + '/a/b')
        self.assertEqual(d.full_path, '/a/b')
        d1 = user.get_node_by_path(settings.ROOT_USERVOLUME_PATH + '/a/b')
        self.assertEqual(d.id, d1.id)

    def test_user_make_file_by_path1(self):
        """Test user.make_tree_by_path."""
        user = self.create_user()
        f = user.make_file_by_path(settings.ROOT_USERVOLUME_PATH + '/file.txt')
        self.assertEqual(f.full_path, '/file.txt')

    def test_user_make_file_by_path2(self):
        """Test user.make_tree_by_path."""
        user = self.create_user()
        f = user.make_file_by_path(
            settings.ROOT_USERVOLUME_PATH + '/a/b/file.txt')
        self.assertEqual(f.full_path, '/a/b/file.txt')

    def test_SharedDirectories(self):
        """Test SharedDirectory features of the api."""
        user = self.create_user()
        # first do a share offer...
        root = user.volume().root
        share = root.make_shareoffer('email@example.com', 'share')
        self.assertEqual(share.offered_to_email, 'email@example.com')
        self.assertEqual(share.root_id, root.id)
        # make sure get_shared_by picks these up
        self.assertEqual(len(user.get_shared_by(accepted=True)), 0)
        self.assertEqual(len(user.get_shared_by()), 1)
        self.assertEqual(len(user.get_shared_by(node_id=root.id)), 1)

        user2 = self.create_user(username='user2')
        so2 = services.claim_shareoffer(
            user2.id, 'usern2', 'visible2', share.id)
        self.assertEqual(so2.shared_by.id, user.id)
        self.assertEqual(so2.shared_to.id, user2.id)
        self.assertEqual(so2.root_id, root.id)
        # make sure get_shared_by picks these up
        self.assertEqual(len(user.get_shared_by(accepted=False)), 0)
        self.assertEqual(len(user.get_shared_by(accepted=True)), 1)
        self.assertEqual(len(user.get_shared_by()), 1)
        self.assertEqual(len(user.get_shared_by(node_id=root.id)), 1)
        share = user.get_share(so2.id)
        share.delete()
        self.assertEqual(share.status, STATUS_DEAD)
        self.assertRaises(errors.DoesNotExist, user.get_share, so2.id)
        # test a direct share to user3
        user3 = self.create_user(username='user3')
        share = root.share(user3.id, 'Share Name')
        self.assertEqual(share.shared_to_id, user3.id)
        self.assertEqual(share.accepted, False)
        share = user3.get_share(share.id)
        self.assertEqual(len(user3.get_shared_to()), 1)
        self.assertEqual(len(user3.get_shared_to(accepted=True)), 0)
        share.accept()
        self.assertEqual(len(user3.get_shared_to()), 1)
        self.assertEqual(len(user3.get_shared_to(accepted=True)), 1)
        self.assertEqual(len(user3.get_shared_to(accepted=False)), 0)
        self.assertEqual(share.accepted, True)
        shared_volume = user3.volume(share.id)
        dir = shared_volume.root.make_subdirectory('Hi I have a share')
        # the dir is still owned by user
        self.assertEqual(dir.owner_id, user.id)
        # make sure user3 can get the dirctory from the share_volume
        dir = shared_volume.get_node(dir.id)
        # but not from his own volume root
        self.assertRaises(errors.DoesNotExist,
                          user3.volume().get_node, dir.id)
        # user3 got this share, so he can delete it
        share.delete()
        self.assertEqual(share.status, STATUS_DEAD)
        # the volume can no longer work
        self.assertRaises(
            errors.DoesNotExist, shared_volume.get_node, dir.id)
        self.assertRaises(
            errors.DoesNotExist,
            shared_volume.root.make_subdirectory, 'Hi I have a share2')
        # user can still get the new directory from user3
        node = user.get_node(dir.id)
        self.assertEqual(node.id, dir.id)
        # user has no shares any more as they are all Dead
        self.assertEqual(len(user.get_shared_by(accepted=False)), 0)
        self.assertEqual(len(user.get_shared_by(accepted=True)), 0)
        self.assertEqual(len(user.get_shared_by()), 0)
        self.assertEqual(len(user.get_shared_by(node_id=root.id)), 0)
        # make another share to user3 so he can decline it.
        share = root.share(user3.id, 'Share Name2')
        user3.get_share(share.id).decline()
        # once it's declined it's gone forever
        self.assertRaises(errors.DoesNotExist,
                          user.get_share, share.id)
        self.assertRaises(errors.DoesNotExist,
                          user3.get_share, share.id)

    def test_get_node_shares(self):
        """Test get_node_shares."""
        usera = self.create_user()
        userb = self.create_user(username='usera')
        userc = self.create_user(username='userb')
        dir1 = usera.root.make_subdirectory('root1')
        dir1_tree = []
        p = dir1
        for i in range(10):
            p = p.make_subdirectory('dir')
            f = p.make_file('somefile')
            dir1_tree.append(p)
            dir1_tree.append(f)
        self.assertEqual(len(dir1_tree), 20)
        # get the last node and see if it's shared
        shares = usera.get_node_shares(dir1_tree[len(dir1_tree) - 1].id)
        self.assertEqual(shares, [])
        sharea = dir1.share(usera.id, 'sharea')
        usera.get_share(sharea.id).accept()
        shareb = dir1.share(userb.id, 'shareb')
        userb.get_share(shareb.id).accept()
        dir1.share(userc.id, 'sharec')
        # get the last node and see if it's shared
        shares = usera.get_node_shares(dir1_tree[len(dir1_tree) - 1].id)
        self.assertEqual(len(shares), 2)
        # all nodes in the tree will result in 2 shares
        for n in dir1_tree:
            shares = usera.get_node_shares(n.id)
            self.assertEqual(len(shares), 2)

    def test_paths_on_shares(self):
        """Test paths on shares."""
        usera = self.create_user(username='usera')
        userb = self.create_user(username='userb')
        a = usera.root.make_subdirectory('a')
        b = a.make_subdirectory('b')
        c = b.make_subdirectory('c')
        share = c.share(userb.id, 'ShareName')
        userb.get_share(share.id).accept()
        d = c.make_subdirectory('d')
        e = d.make_subdirectory('e')
        userb_c = userb.volume(share.id).get_root()
        # path from shares
        self.assertEqual(userb_c.parent_id, None)
        self.assertEqual(userb_c.path, '/')
        self.assertEqual(userb_c.name, '')
        self.assertEqual(userb_c.full_path, '/')
        userb_e = userb.volume(share.id).get_node(e.id)
        self.assertEqual(userb_e.path, '/d')
        self.assertEqual(userb_e.full_path, '/d/e')
        # make sure paths in deltas are correct
        vol, free, delta = userb.volume(share.id).get_delta(0)
        self.assertEqual(len(delta), 2)
        self.assertEqual(delta[0].full_path, '/d')
        self.assertEqual(delta[1].full_path, '/d/e')
        vol, free, delta = userb.volume(share.id).get_from_scratch()
        self.assertEqual(len(delta), 3)
        self.assertEqual(delta[0].full_path, '/')
        self.assertEqual(delta[1].full_path, '/d')
        self.assertEqual(delta[2].full_path, '/d/e')

    def test_StorageNode__eq__(self):
        """Test the StorageNode __eq___"""
        user = self.create_user()
        dir = user.root.make_file('file.txt')
        dir2 = user.volume().get_node(dir.id)
        self.assertEqual(dir, dir2)
        # it is not the same object
        self.assertFalse(dir is dir2)

    def test_StorageNode_return_self(self):
        """Test return self of StorageNode methods."""
        user = self.create_user()
        root = user.root
        node = root.make_file('somefile')
        n = node.delete()
        self.assertTrue(n is node)
        n = node.restore()
        self.assertTrue(n is node)
        n = node.move(root.id, 'new name')
        self.assertTrue(n is node)

    def test_FileNode_return_self(self):
        """Test return self of FileNode methods."""
        user = self.create_user()
        node = user.root.make_file('somefile')
        n = node.change_public_access(True)
        self.assertTrue(n is node)

    def test_Share_return_self(self):
        """Test return self of Share methods."""
        user = self.create_user()
        user2 = self.create_user(username='user2')
        share = user.root.share(user2.id, 'TheShare')
        share2 = user2.get_share(share.id)
        s = share2.accept()
        self.assertIs(s, share2)
        s = share.set_access(True)
        self.assertIs(s, share)
        s = share.delete()
        self.assertIs(s, share)
        share = user.root.share(user2.id, 'TheShare')
        share2 = user2.get_share(share.id)
        s = share2.decline()
        self.assertIs(s, share2)

    def test_DirectoryNode(self):
        """Test DirectoryNode features in api."""
        user = self.create_user()
        root = user.volume().root
        dir = root.make_subdirectory('A New Subdirectory')
        self.assertIsInstance(dir, services.DirectoryNode)
        self.assertEqual(dir.parent_id, root.id)
        children = root.get_children()
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].id, dir.id)
        self.assertFalse(dir.has_children())
        subdir = dir.make_subdirectory('Another Subdirectory')
        dir.load()
        self.assertTrue(dir.has_children())
        self.assertTrue(dir.has_children(kind=StorageObject.DIRECTORY))
        self.assertFalse(dir.has_children(kind=StorageObject.FILE))
        file = dir.make_file('A File')
        dir.load()
        self.assertTrue(dir.has_children(kind=StorageObject.DIRECTORY))
        self.assertTrue(dir.has_children(kind=StorageObject.FILE))
        self.assertEqual(subdir.parent_id, dir.id)
        self.assertEqual(file.parent_id, dir.id)
        children = dir.get_children()
        self.assertEqual(len(children), 2)
        self.assertRaises(errors.NotEmpty, dir.delete)
        dir.delete(cascade=True)
        root.load()
        self.assertFalse(root.has_children())
        self.assertFalse(root.has_children(kind=StorageObject.FILE))
        self.assertFalse(root.has_children(kind=StorageObject.DIRECTORY))
        #
        # do it the lazy way:
        #
        dir = user.volume().root.make_subdirectory('LazyDir')
        dir.make_file('somefile')
        root.load()
        self.assertEqual(root.has_children(), True)
        self.assertRaises(errors.NotEmpty, user.volume().node(dir.id).delete)
        user.volume().node(dir.id).delete(cascade=True)
        root.load()
        self.assertEqual(root.has_children(), False)

    def test_DirectoryNode_make_tree(self):
        """Test make_tree in directory node."""
        user = self.create_user()
        d = user.volume().root.make_tree('/a/b/c/d/')
        self.assertEqual(d.full_path, '/a/b/c/d')
        c = user.volume().get_node_by_path('/a/b/c')
        self.assertEqual(d.parent_id, c.id)

    def test_FileNode(self):
        """Test FileNode features in api."""
        user = self.create_user()
        root = user.root
        file = root.make_file('A new file')
        self.assertIsInstance(file, services.FileNode)
        self.assertEqual(file.parent_id, root.id)
        children = root.get_children()
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].id, file.id)
        self.assertFalse(file.is_public)
        self.assertEqual(file.public_url, None)
        file.change_public_access(True)
        self.assertTrue(file.is_public)
        file.change_public_access(False)
        self.assertFalse(file.is_public)
        self.assertEqual(file.public_url, None)
        file.delete()
        self.assertEqual(file.status, STATUS_DEAD)
        #
        # do it the lazy way:
        #
        file = user.volume().root.make_file('A new file')
        user.volume().node(file.id).delete()
        self.assertRaises(errors.DoesNotExist,
                          user.volume().get_node, file.id)

    def test_make_filepath_with_content(self):
        """Make file with content using paths."""
        user = self.create_user(max_storage_bytes=200)
        path = settings.ROOT_USERVOLUME_PATH + '/a/b/c/filename.txt'
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = 100
        deflated_size = 10000
        node = user.make_filepath_with_content(
            path, hash, crc, size, deflated_size, storage_key, mimetype=mime)
        file = user.get_node(node.id, with_content=True)
        self.assertEqual(file.name, 'filename.txt')
        self.assertEqual(file.full_path, '/a/b/c/filename.txt')
        self.assertEqual(file.mimetype, mime)
        self.assertEqual(file.status, STATUS_LIVE)
        self.assertEqual(bytes(file.content.hash), hash)
        self.assertEqual(file.content.crc32, crc)
        self.assertEqual(file.content.size, size)
        self.assertEqual(file.content.deflated_size, deflated_size)
        self.assertEqual(file.content.storage_key, storage_key)

    def test_make_file_with_content(self):
        """Make file with contentblob.

        This is similar to the way the updown server creates a file. But it's
        all handled in one function after the upload.

        This also tests StorageUser.get_content
        """
        user = self.create_user(max_storage_bytes=200)
        name = 'filename'
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = 100
        deflated_size = 10000
        self.assertRaises(errors.DoesNotExist, user.volume().get_content, hash)
        f = user.root.make_file_with_content
        # can't create a file with the same name as a directory
        user.root.make_subdirectory('dupe')
        self.assertRaises(errors.AlreadyExists, f, 'dupe', hash, crc,
                          size, deflated_size, storage_key, mimetype=mime)
        # can't exceed your quota fool!
        self.assertRaises(errors.QuotaExceeded, f, name, hash, crc,
                          3000, 3000, storage_key, mimetype=mime)
        # make_file_with_content will create the content blob even if later the
        # upload is rejected because quota exceeded, so delete afterwards
        ContentBlob.objects.all().delete()

        node = f(name, hash, crc, size, deflated_size, storage_key,
                 mimetype=mime)
        file = user.get_node(node.id, with_content=True)
        self.assertEqual(file.name, name)
        self.assertEqual(file.mimetype, mime)
        self.assertEqual(file.status, STATUS_LIVE)
        self.assertEqual(bytes(file.content.hash), hash)
        self.assertEqual(file.content.crc32, crc)
        self.assertEqual(file.content.size, size)
        self.assertEqual(file.content.deflated_size, deflated_size)
        self.assertEqual(file.content.storage_key, storage_key)
        # make sure the user can get the content
        content = user.volume().get_content(hash)
        self.assertEqual(bytes(content.hash), hash)
        self.assertEqual(content.crc32, crc)
        self.assertEqual(content.size, size)
        self.assertEqual(content.deflated_size, deflated_size)
        self.assertEqual(content.storage_key, storage_key)
        self.assertEqual(user.free_bytes, 100)
        # a call later to the same function will create a new content blob and
        # update the file
        new_hash = self.factory.get_fake_hash()
        new_storage_key = uuid.uuid4()
        new_crc = 54321
        new_size = 99
        new_deflated_size = 2000
        node = f(name, new_hash, new_crc, new_size, new_deflated_size,
                 new_storage_key)
        file = user.get_node(node.id, with_content=True)
        self.assertEqual(file.name, name)
        self.assertEqual(file.mimetype, mime)
        self.assertEqual(file.status, STATUS_LIVE)
        self.assertEqual(bytes(file.content.hash), new_hash)
        self.assertEqual(file.content.crc32, new_crc)
        self.assertEqual(file.content.size, new_size)
        self.assertEqual(file.content.deflated_size, new_deflated_size)
        self.assertEqual(file.content.storage_key, new_storage_key)
        # the user's quota decreased
        user.load()
        self.assertEqual(user.used_storage_bytes, 99)
        # uhoh this file grew to big!!
        new_hash = self.factory.get_fake_hash()
        new_size = 10000
        self.assertRaises(errors.QuotaExceeded, f, name, new_hash, new_crc,
                          new_size, new_deflated_size, storage_key)

    def test_make_file_with_content_public(self):
        """Make file with contentblob."""
        user = self.create_user(max_storage_bytes=200)
        name = 'filename'
        a_hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = 100
        deflated_size = 10000
        f = user.root.make_file_with_content(
            name, a_hash, crc, size, deflated_size, storage_key,
            is_public=True)
        self.assertNotEqual(f.public_url, None)

    def test_make_file_with_content_enforces_quota(self):
        """Make file with contentblob enforces quota check (or not)."""
        user = self.create_user(max_storage_bytes=200)
        name = 'filename'
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = deflated_size = 300
        f = user.root.make_file_with_content
        self.assertRaises(errors.QuotaExceeded, f, name, hash, crc,
                          size, deflated_size, storage_key, enforce_quota=True)
        node = f(name, hash, crc, size, deflated_size, storage_key,
                 mimetype=mime, enforce_quota=False)
        self.assertIsNotNone(node)

    def test_make_file_with_content_overwrite_hashmismatch(self):
        """Make file with contentblob enforces quota check (or not)."""
        user = self.create_user(max_storage_bytes=200)
        name = 'filename'
        mime = 'image/tif'
        a_hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = deflated_size = 300
        f = user.root.make_file_with_content
        self.assertRaises(errors.QuotaExceeded, f, name, a_hash, crc,
                          size, deflated_size, storage_key, enforce_quota=True)
        f(name, a_hash, crc, size, deflated_size, storage_key,
          mimetype=mime, enforce_quota=False)
        self.assertRaises(
            errors.HashMismatch,
            f, name, a_hash, crc, size, deflated_size, storage_key,
            previous_hash=self.factory.get_fake_hash('ABC'))

    def test_UploadJob(self):
        """Test the UploadJob."""
        user = self.create_user(max_storage_bytes=200)
        file = user.root.make_file('A new file')
        new_hash = self.factory.get_fake_hash()
        crc = 12345
        size = 100
        #
        # Some steps to simulate what happens during put content.
        #
        # first the expected failures
        self.assertRaises(errors.QuotaExceeded, file.make_uploadjob,
                          file.content_hash, new_hash, crc, 300)
        self.assertRaises(errors.HashMismatch, file.make_uploadjob,
                          'WRONG OLD HASH', new_hash, crc, 300)
        upload_job = file.make_uploadjob(file.content_hash, new_hash, crc,
                                         size)
        job = user.volume().get_uploadjob(upload_job.id)
        self.assertEqual(job.id, upload_job.id)
        jobs = user.get_uploadjobs()
        self.assertEqual(jobs[0].id, upload_job.id)

        # get the file, there should be no Content for the file yet
        new_file = user.get_node(file.id, with_content=True)
        self.assertEqual(new_file.kind, StorageObject.FILE)
        self.assertEqual(new_file.content, None)

        # now play a bit with multipart support
        job = file.make_uploadjob(file.content_hash, new_hash, crc, size,
                                  multipart_key=uuid.uuid4())
        old = job.when_last_active
        job.add_part(10)
        self.assertGreater(job.when_last_active, old)
        self.assertEqual(job.uploaded_bytes, 10)
        self.assertEqual(job.chunk_count, 1)
        old = job.when_last_active
        job.add_part(10)
        self.assertGreater(job.when_last_active, old)
        self.assertEqual(job.uploaded_bytes, 20)
        self.assertEqual(job.chunk_count, 2)
        self.assertEqual(job.file, file)
        job.delete()

        # update the last active time
        job = file.make_uploadjob(file.content_hash, new_hash, crc, size,
                                  multipart_key=uuid.uuid4())
        old = job.when_last_active
        job.touch()
        self.assertGreater(job.when_last_active, old)

    def test_encode_decode(self):
        """Make sure encode/decode can handle UUIDs properly."""
        for i in range(100):
            id1 = uuid.uuid4()
            id2 = uuid.uuid4()
            key = utils.make_nodekey(id1, id2)
            self.assertEqual(utils.parse_nodekey(key), (id1, id2))

    def test_nodekey(self):
        """Test the vairous uses of nodekeys."""
        user = self.create_user()
        root = user.volume().root
        # this is uninitialized so...
        self.assertEqual(root.nodekey, utils.make_nodekey(None, 'root'))
        root._load()
        self.assertEqual(root.nodekey, utils.make_nodekey(None, root.id))
        file = root.make_file('The file')
        self.assertEqual(file.nodekey, utils.make_nodekey(None, file.id))
        file_from_key = user.get_node_with_key(file.nodekey)
        self.assertEqual(file_from_key.id, file.id)
        self.assertEqual(file_from_key.vol_id, file.vol_id)
        user3 = self.create_user(username='user3')
        self.assertRaises(errors.DoesNotExist,
                          user3.get_node_with_key, file.nodekey)
        # do some shares with user3
        share = root.share(user3.id, 'ShareName')
        share = user3.get_share(share.id)
        share.accept()
        node = user3.volume(share.id).get_node(file.id)
        node2 = user3.get_node_with_key(utils.make_nodekey(share.id, file.id))
        self.assertEqual(node.id, node2.id)
        self.assertEqual(node.nodekey, node2.nodekey)
        # how bout a udf
        udf = user.make_udf('~/.fake/path')
        file = user.volume(udf.id).root.make_file('new file')
        node = user.get_node_with_key(utils.make_nodekey(udf.id, file.id))
        self.assertEqual(file.id, node.id)
        self.assertEqual(file.nodekey, node.nodekey)

    def test_volumes(self):
        """Test the root shares and udf volumes and nodekeys.

        This will create files on root, udf and share volumes and collect the
        nodekeys. Then it will verify that the nodes can be retrieved from
        volumes via nodekeys.
        """
        user = self.create_user()
        keys = []
        # add some files to the root and append the keys
        for i in range(5):
            file = user.root.make_file('file%s' % i)
            keys.append((file.nodekey, file))
        # make a few udfs and add some files to it
        for i in range(10):
            user.make_udf('~/path/uname%s' % i)
        for vol in user.get_udf_volumes():
            for i in range(5):
                file = vol.root.make_file('file%s' % i)
                keys.append((file.nodekey, file))
        # make a few shares from different users
        for i in range(10):
            userx = self.create_user(username='user%s' % i)
            share = userx.root.share(user.id, 'Share%s' % i)
            user.get_share(share.id).accept()
        for vol in user.get_share_volumes():
            for i in range(5):
                file = vol.root.make_file('file%s' % i)
                keys.append((file.nodekey, file))
        # Go through all the node keys and make sure they work
        self.assertEqual(len(keys), 105)
        for key, file in keys:
            node = user.get_node_with_key(key)
            self.assertEqual(node.id, file.id)

    def test_move(self):
        """Test StorageNode.move."""
        user = self.create_user()
        dir1 = user.root.make_subdirectory('dir1')
        dir11 = dir1.make_subdirectory('dir1.1')
        dir2 = user.root.make_subdirectory('dir2')
        dir21 = dir2.make_subdirectory('dir2.1')
        self.assertTrue(dir2.has_children())
        dir1.move(dir2.id, 'new name')
        dir2.load()
        dir11.load()
        self.assertTrue(dir2.has_children())
        self.assertEqual(dir1.parent_id, dir2.id)
        self.assertEqual(dir1.name, 'new name')
        self.assertEqual(dir11.path, '/dir2/new name')
        # rename only changes child paths
        dir1.move(dir1.parent_id, 'another name')
        dir11.load()
        self.assertEqual(dir1.name, 'another name')
        self.assertEqual(dir11.path, '/dir2/another name')
        # moving on top of a node, deletes it
        dir1.move(dir1.parent_id, 'dir2.1')
        self.assertRaises(errors.DoesNotExist, user.get_node, dir21.id)

    def test_get_node_by_path(self):
        """Test VolumeProxy.get_node_by_path.

        This test makes sure that common paths don't step on each other, the
        detailed tests for this are in the gateway.
        """

        def make_tree_on_volume(vol):
            """Create the same directory structure on a volume."""
            d1 = vol.make_subdirectory('d1')
            d2 = d1.make_subdirectory('d2')
            d2.make_subdirectory('d3')

        user1 = self.create_user(username='user1')
        user2 = self.create_user(username='user2')
        udf1 = user1.make_udf('~/UDF/path')
        udf1a = user1.make_udf('~/UDF1a/path')
        udf2 = user2.make_udf('~/UDF/path')
        d1 = user1.root.make_subdirectory('shared')
        share = d1.share(user2.id, 'name')
        user2.get_share(share.id).accept()
        make_tree_on_volume(user1.root)
        make_tree_on_volume(user1.volume(udf1.id).root)
        make_tree_on_volume(user1.volume(udf1a.id).root)
        make_tree_on_volume(d1)
        make_tree_on_volume(user2.root)
        make_tree_on_volume(user2.volume(udf2.id).root)
        # now lets get some stuff...
        r = user1.volume().get_node_by_path('/')
        self.assertEqual(r.owner_id, user1.id)
        self.assertEqual(r.id, user1.root.load().id)
        d3 = user1.volume().get_node_by_path('/d1/d2/d3')
        self.assertEqual(d3.vol_id, None)
        d3 = user1.volume(udf1.id).get_node_by_path('/d1/d2/d3')
        self.assertEqual(d3.owner_id, user1.id)
        self.assertEqual(d3.vol_id, udf1.id)
        self.assertEqual(d3.path, '/d1/d2')
        self.assertEqual(d3.name, 'd3')
        d3 = user2.volume(udf2.id).get_node_by_path('/d1/d2/d3')
        self.assertEqual(d3.owner_id, user2.id)
        self.assertEqual(d3.vol_id, udf2.id)
        self.assertEqual(d3.path, '/d1/d2')
        self.assertEqual(d3.name, 'd3')
        d3 = user2.volume(share.id).get_node_by_path('/d1/d2/d3')
        self.assertEqual(d3.owner_id, user1.id)
        self.assertEqual(d3.vol_id, share.id)
        self.assertEqual(d3.path, '/d1/d2')
        self.assertEqual(d3.name, 'd3')

    def test_get_public_files(self):
        """Test StorageUser.get_public_files method."""
        user = self.create_user()
        udf = user.make_udf('~/myfiles/are here')
        # create some files and make them public
        for i in range(5):
            root_file = user.root.make_file('file_%s' % i)
            root_file.change_public_access(True)
            udf_file = user.volume(udf.id).root.make_file('udf file%s' % i)
            udf_file.change_public_access(True)
            # user has no access to noread files
        nodes = user.get_public_files()
        self.assertIsInstance(nodes, list)
        self.assertEqual(10, len(nodes))

    def test_get_public_folders(self):
        """Test StorageUser.get_public_folders method."""
        user = self.create_user()
        # create some folders and make them public
        for i in range(5):
            d = user.root.make_subdirectory('folder_%s' % i)
            d.change_public_access(True, allow_directory=True)
        nodes = user.get_public_folders()
        self.assertIsInstance(nodes, list)
        self.assertEqual(5, len(nodes))

    def test_change_public_access_file(self):
        """Test the basics of changing public access to a file."""
        user = self.create_user()
        f1 = user.root.make_file('a-file.txt')
        # It has no public ID
        self.assertEqual(f1.public_uuid, None)
        self.assertEqual(f1.public_url, None)
        # It now has a public ID
        f1.change_public_access(True)
        self.assertNotEqual(f1.public_uuid, None)
        self.assertNotEqual(f1.public_url, None)
        f1.change_public_access(False)
        self.assertEqual(f1.public_uuid, None)
        self.assertEqual(f1.public_url, None)

    def test_change_public_access_file_uuid(self):
        """Test the basics of changing public access to a file using uuid."""
        user = self.create_user()
        f1 = user.root.make_file('a-file.txt')
        # It has no public ID
        self.assertEqual(f1.public_uuid, None)
        self.assertEqual(f1.public_url, None)
        # It now has a public ID
        f1.change_public_access(True)
        self.assertNotEqual(f1.public_uuid, None)
        self.assertNotEqual(f1.public_url, None)
        f1.change_public_access(False)
        self.assertEqual(f1.public_uuid, None)
        self.assertEqual(f1.public_url, None)

    def test_change_public_access_directory_nopermission(self):
        """Test that by default you can't make a directory public."""
        user = self.create_user()
        dir = user.root.make_subdirectory('xyz')
        self.assertRaises(errors.NoPermission,
                          dir.change_public_access, True)

    def test_change_public_access_directory(self):
        """Test that directories can be made public if explicitly requested."""
        user = self.create_user()
        a_dir = user.root.make_subdirectory('xyz')
        # It has no public ID
        self.assertEqual(a_dir.public_uuid, None)
        # It now has a public ID
        self.assertIsNotNone(
            a_dir.change_public_access(True, True).public_uuid)

    def test_undelete(self):
        """Test various ways of restoring data."""
        user = self.create_user(max_storage_bytes=1000)
        size = 300
        file = self.create_file(user, size=size)
        self.assertEqual(user.free_bytes, 700)
        file.delete()
        self.assertEqual(user.free_bytes, 1000)
        file.restore()
        self.assertEqual(user.free_bytes, 700)
        file.delete()
        # use the restore all which will restore in a special directory
        rstore_dir = user.volume().undelete_all('RestoreHere')
        self.assertEqual(user.free_bytes, 700)
        node = user.volume().get_node(file.id)
        self.assertTrue(node.full_path.startswith(rstore_dir.full_path))
        # udfs and restores
        udf = user.make_udf('~/Something')
        file = self.create_file(user, size=size, udf=udf)
        self.assertEqual(user.free_bytes, 400)
        file.delete()
        self.assertEqual(user.free_bytes, 700)
        # this directory will be in the UDF volume, not root
        rstore_dir = user.volume(udf.id).undelete_all('RestoreHere')
        self.assertEqual(user.free_bytes, 400)
        node = user.volume().get_node(file.id)
        self.assertEqual(node.volume_id, udf.id)
        self.assertTrue(node.full_path.startswith(rstore_dir.full_path))

    def test_undelete_above_quota(self):
        """Fail to restore if there's not enough quota."""
        max_quota = 200
        file_size = 100
        user = self.create_user(max_storage_bytes=max_quota)

        self.create_file(user, size=file_size)
        assert user.free_bytes == 100

        file2 = self.create_file(user, size=file_size)
        assert user.free_bytes == 0
        file2.delete()

        self.create_file(user, size=file_size)
        self.assertEqual(user.free_bytes, 0)

        user.volume().undelete_all('RestoreHere')
        self.assertEqual(user.free_bytes, 0)

    def test_reusable_content(self):
        """Test StorageUser.is_reusable_content."""
        user = self.create_user()
        mocker = Mocker()
        gw = mocker.mock()
        expect(gw.is_reusable_content('hash_value', 'magic_hash'))
        user._gateway = gw
        with mocker:
            user.is_reusable_content('hash_value', 'magic_hash')

    def test_node_make_content(self):
        """Test the make_content call in the node."""
        user = self.create_user()
        filenode = user.root.make_file('A new file')
        ohash, nhash, crc32, size = 'old_hash new_hash crc32 size'.split()
        deflated, skey, magic = 'deflated_size storage_key magic_hash'.split()
        mocker = Mocker()

        # it needs to be reloaded
        load = mocker.mock()
        expect(load())
        filenode._load = load

        # the make content call to the gateway
        gw = mocker.mock()
        new_node = object()
        expect(gw.make_content(filenode.id, ohash, nhash, crc32, size,
                               deflated, skey, magic)).result(new_node)
        filenode._gateway = gw

        # it needs to copy the stuff to self
        copy = mocker.mock()
        expect(copy(new_node))
        filenode._copy = copy

        with mocker:
            r = filenode.make_content(ohash, nhash, crc32, size,
                                      deflated, skey, magic)
        self.assertTrue(r is filenode)

    def test_get_photo_directories(self):
        """Make file with contentblob."""
        user = self.create_user(max_storage_bytes=200000)
        hash = self.factory.get_fake_hash()
        key = uuid.uuid4()
        crc = 12345
        size = 100
        dsize = 10000
        a = user.root.make_subdirectory('a')
        ab = a.make_subdirectory('b')
        ab.change_public_access(True, allow_directory=True)
        b = user.root.make_subdirectory('b')
        a.make_file_with_content('file1.jpg', hash, crc, size, dsize, key)
        a.make_file_with_content('file2.jpg', hash, crc, size, dsize, key)
        a.make_file('file3.jpg')
        a.make_file('file3.txt')
        b.make_file_with_content('file1.txt', hash, crc, size, dsize, key)
        b.make_file_with_content('file2.txt', hash, crc, size, dsize, key)
        # these should not show up
        b.make_file('file3.jpg')
        b.make_file('file3.jpg')
        ab.make_file_with_content('file1.txt', hash, crc, size, dsize, key)
        ab.make_file_with_content('file2.jpg', hash, crc, size, dsize, key)
        ab.make_file('file3.jpg')
        dirs = user.get_photo_directories()
        self.assertEqual(len(dirs), 2)
        self.assertTrue('/a' in [d.full_path for d in dirs])
        self.assertTrue('/a/b' in [d.full_path for d in dirs])
        self.assertTrue('/b' not in [d.full_path for d in dirs])
        # make sure public_key and public_uuid are set correctly
        public_a, = [d for d in dirs if d.full_path == '/a']
        public_ab, = [d for d in dirs if d.full_path == '/a/b']
        self.assertEqual(public_a.public_key, None)
        self.assertEqual(public_ab.public_key, ab.public_key)

    def test_get_directories_with_mimetypes(self):
        """Make file with contentblob."""
        user = self.create_user(max_storage_bytes=200000)
        dirs = user.volume().get_directories_with_mimetypes(['image/jpeg'])
        self.assertEqual(dirs, [])
        hash = self.factory.get_fake_hash()
        key = uuid.uuid4()
        crc = 12345
        size = 100
        dsize = 10000
        a = user.root.make_subdirectory('a')
        ab = a.make_subdirectory('b')
        b = user.root.make_subdirectory('b')
        a.make_file_with_content('file1.jpg', hash, crc, size, dsize, key)
        a.make_file_with_content('file2.jpg', hash, crc, size, dsize, key)
        a.make_file('file3.jpg')
        a.make_file('file3.txt')
        b.make_file_with_content('file1.txt', hash, crc, size, dsize, key)
        b.make_file_with_content('file2.jpg', hash, crc, size, dsize, key)
        b.make_file('file3.jpg')
        b.make_file('file3.txt')
        ab.make_file_with_content('file1.txt', hash, crc, size, dsize, key)
        ab.make_file_with_content('file2.txt', hash, crc, size, dsize, key)
        ab.make_file('file3.jpg')
        dirs = user.volume().get_directories_with_mimetypes(['image/jpeg'])
        dirs = [d.full_path for d in dirs]
        self.assertItemsEqual(dirs, ['/a', '/b'])
        dirs = user.volume().get_directories_with_mimetypes(['text/plain'])
        dirs = [d.full_path for d in dirs]
        self.assertItemsEqual(dirs, ['/a/b', '/b'])
        dirs = user.volume().get_directories_with_mimetypes(
            ['image/jpeg', 'text/plain'])
        dirs = [d.full_path for d in dirs]
        self.assertItemsEqual(dirs, ['/a', '/a/b', '/b'])


class GenerationsDAOTestCase(StorageDALTestCase):
    """Test generation specifics from DAO."""

    def test_get_delta(self):
        """Test basic generations delta.

        Most of this is all tested in the gateway, no details here.
        """
        user = self.create_user(max_storage_bytes=1000)
        nodes = [user.root.make_file('name%s' % i) for i in range(10)]
        generation, free_bytes, delta = user.volume().get_delta(0)
        self.assertEqual(generation, delta[-1].generation)
        # we're not taking up any space with these empty files
        self.assertEqual(free_bytes, 1000)
        # 10 changes
        self.assertEqual(len(delta), 10)
        for n in nodes:
            self.assertTrue(n in delta)

    def test_delta_info(self):
        """A basic test of free_bytes and generation from deltas."""
        user = self.create_user(max_storage_bytes=1000)
        test_file = self.create_files(user.root, amount=1)[0]
        file_size = test_file.content.size
        generation, free_bytes, delta = user.volume().get_delta(1)
        self.assertEqual(len(delta), 1)
        self.assertEqual(free_bytes, 1000 - file_size)
        self.assertEqual(generation, test_file.generation)
        self.assertEqual(delta[0], test_file)

    def test_delta_info_multi(self):
        """Test of free_bytes and generation from deltas with many changes."""
        user = self.create_user(max_storage_bytes=1000)
        files = self.create_files(user.root)
        file_size = files[0].content.size
        new_gen = user.volume().get_volume().generation
        generation, free_bytes, delta = user.volume().get_delta(1, limit=5)
        self.assertEqual(len(delta), 5)
        self.assertEqual(free_bytes, 1000 - file_size * 10)
        self.assertEqual(generation, new_gen)
        self.assertEqual(delta, files[:5])
        start_gen = delta[-1].generation
        generation, free_bytes, delta = user.volume().get_delta(start_gen)
        self.assertEqual(len(delta), 5)
        self.assertEqual(free_bytes, 1000 - file_size * 10)
        self.assertEqual(generation, new_gen)
        self.assertEqual(delta, files[-5:])

    def test_get_from_scratch(self):
        """Test get_from_scratch."""
        user = self.create_user(max_storage_bytes=1000)
        root = user.root.load()
        files = self.create_files(user.root)
        file_size = files[0].content.size
        new_gen = user.volume().get_volume().generation
        files_with_root = [root] + files
        generation, free_bytes, delta = user.volume().get_from_scratch()
        self.assertEqual(len(delta), 11)
        self.assertEqual(free_bytes, 1000 - file_size * 10)
        self.assertEqual(generation, new_gen)
        self.assertEqual(delta[0], root)
        self.assertEqual(delta, files_with_root)
        # delete the first 5 files and check again
        for f in files[:5]:
            f.delete()
        new_gen = user.volume().get_volume().generation
        generation, free_bytes, delta = user.volume().get_from_scratch()
        self.assertEqual(len(delta), 6)
        self.assertEqual(free_bytes, 1000 - file_size * 5)
        self.assertEqual(generation, new_gen)
        self.assertEqual(delta[0], root)
        files_with_root = [root] + files[-5:]
        self.assertEqual(delta, files_with_root)

    def test_SharedDirectory_get_generation(self):
        """Test for SharedDirectory.get_generation method."""
        user = self.create_user()
        user2 = self.create_user(username='user2')
        share = user.root.share(user2.id, 'ShareName')
        share = user2.get_share(share.id)
        share.accept()
        self.assertEqual(0, share.get_generation())
        user.root.make_file('a file in a share')
        self.assertEqual(1, share.get_generation())


class TestSQLStatementCount(StorageDALTestCase):
    """Test the number of SQL statements issued by some critical operations.

    The tests here should just assert that the number of SQL statements issued
    by some performance-sensitive operations are what we expect. This is
    necessary because when using an ORM it's way too easy to make changes that
    seem innocuous but in fact affect the performance in a significant (and
    bad) way. When that happens, one or more tests here may break and
    developers will then be forced to assess the consequences of their
    changes on those operations, and either provide a good reason for them or
    tweak their changes to avoid the extra SQL statement(s).

    """

    mimetype = 'image/jpeg'

    def _create_directory_with_five_files(self):
        """Creates a DirectoryNode with 5 files inside it."""
        user = self.create_user()
        directory = user.root.make_subdirectory('test')
        for i in range(5):
            directory.make_file_with_content(
                file_name='file-%s' % i, hash=b'hash', crc32=0, size=0,
                deflated_size=0, storage_key=uuid.uuid4(),
                mimetype=self.mimetype)
        return directory

    def test_move_directory_with_files(self):
        """Move a directory with files inside it."""
        directory = self._create_directory_with_five_files()
        new_parent = directory.owner.root.make_subdirectory('test2')
        with self.assertNumQueries(48):  # XXX 19
            directory.move(new_parent.id, directory.name)

    def test_delete_directory_with_files(self):
        """Delete a directory with files inside it."""
        directory = self._create_directory_with_five_files()
        with self.assertNumQueries(41):  # XXX 17
            directory.delete(cascade=True)

    def test_delete_file(self):
        """Delete a file."""
        f = self.factory.make_file(mimetype=self.mimetype)
        # SELECT * FROM "filesync_storageobject"
        #     WHERE "filesync_storageobject"."parent_id" IN ('...'::uuid)
        # SELECT * FROM "filesync_share" WHERE "filesync_share"."subtree_id"
        #     IN ('...'::uuid)
        # DELETE FROM "filesync_uploadjob"
        #     WHERE "filesync_uploadjob"."node_id" IN ('...'::uuid)
        # DELETE FROM "filesync_storageobject" WHERE id IN ('...'::uuid)
        # SELECT * FROM "filesync_storageuser" WHERE id = 49
        # INSERT INTO "txlog_transactionlog" VALUES ('...')
        #     RETURNING "txlog_transactionlog"."id"
        with self.assertNumQueries(6):
            f.delete()

    # TODO: Optimize dao.DirectoryNode.make_file_with_content(); there should
    # be lots of low-hanging fruit there that would allow us to reduce the
    # number of queries it issues.
    def test_make_file_with_content(self):
        """Create a file with content."""
        user = self.create_user()
        directory = user.root.make_subdirectory('test')
        hash_ = self.factory.get_fake_hash()
        name = self.factory.get_unique_unicode()
        size = self.factory.get_unique_integer()
        crc32 = self.factory.get_unique_integer()
        storage_key = uuid.uuid4()
        with self.assertNumQueries(37):  # XXX 21
            directory.make_file_with_content(
                name, hash_, crc32, size, size, storage_key,
                mimetype=self.mimetype)
