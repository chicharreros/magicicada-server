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

"""Test the resthelper."""

from __future__ import unicode_literals

import logging
import operator
import os
import unittest
import uuid

from django.conf import settings
from django.utils.timezone import now

from magicicada.filesync import errors
from magicicada.filesync.models import STATUS_LIVE, StorageObject
from magicicada.filesync.resthelper import (
    CannotPublishDirectory,
    FileNodeHasNoChildren,
    InvalidKind,
    ResourceMapper,
    RestHelper,
    date_formatter,
    logger,
)
from magicicada.filesync.services import make_storage_user
from magicicada.metrics.tests import FakeMetrics
from magicicada.testing.testcase import BaseTestCase


class MockUser(object):
    """Fake user for testing."""
    id = 0
    visible_name = "Bob Smith"
    used_storage_bytes = 10
    free_bytes = 2 ** 8
    max_storage_bytes = 2 ** 10


class MockVolume(object):
    """Fake Volume for testing."""
    generation = 1
    id = uuid.uuid4()
    is_root = False
    path = "~/Documents"
    when_created = now()


class MockNode(object):
    """Fake Node for testing."""
    id = uuid.uuid4()
    nodekey = 'nodekey'
    kind = StorageObject.FILE
    path = '/a/b/c/d'
    full_path = '/a/b/c/d/file.txt'
    name = 'file.txt'
    content_hash = 'abcdefg'
    when_created = now()
    when_last_modified = now()
    generation = 1
    generation_created = 1
    mimetype = 'text'
    public_url = "public url"
    is_public = False
    vol_type = 'root'
    status = STATUS_LIVE
    vol_udf = MockVolume()
    vol_udf.is_root = True
    vol_udf.path = settings.ROOT_USERVOLUME_PATH

    class _content(object):
        """Fake content within a Node."""
        size = 12000
    content = _content()

    def has_children(self):
        return False


class ResourceMapperTestCase(unittest.TestCase):
    """Test the resource mapper."""
    def setUp(self):
        super(ResourceMapperTestCase, self).setUp()
        self.mapper = ResourceMapper()

    def test_mapping(self):
        """Test mapping."""
        self.assertEqual(self.mapper.user(), '')
        self.assertEqual(self.mapper.volume('~/1'), '/volumes/~/1')
        self.assertEqual(self.mapper.node('~/1', '/x'), '/~/1/x')

    def test_mapping_override(self):
        """Test mapping."""
        self.mapper.root = ''
        self.mapper.mapping['NODE_INFO'] = '/n/%(node_path)s'
        self.assertEqual(self.mapper.user(), '')
        self.assertEqual(self.mapper.volume(1), '/volumes/1')
        self.assertEqual(self.mapper.node('a', 'b'), '/n/b')

    def test_user_repr(self):
        """Test Rest conversion of a user."""
        user = MockUser()
        udf = MockVolume()
        info = self.mapper.user_repr(user, [udf])
        self.assertEqual(info['user_id'], user.id)
        self.assertEqual(info['visible_name'], user.visible_name)
        self.assertEqual(info['used_bytes'], user.used_storage_bytes)
        self.assertEqual(info['max_bytes'], user.max_storage_bytes)
        self.assertEqual(
            info['root_node_path'],
            self.mapper.node(settings.ROOT_USERVOLUME_PATH))
        self.assertEqual(
            info['user_node_paths'], [self.mapper.node(udf.path)])

    def test_volume_repr(self):
        """Test Rest conversion of a volume."""
        udf = MockVolume()
        info = self.mapper.volume_repr(udf)
        self.assertEqual(info['resource_path'], '/volumes/~/Documents')
        self.assertEqual(info['type'], 'root' if udf.is_root else 'udf')
        self.assertEqual(info['path'], udf.path)
        self.assertEqual(info['generation'], udf.generation)
        self.assertEqual(info['node_path'], self.mapper.node(udf.path))
        self.assertEqual(
            info['when_created'], date_formatter(udf.when_created))

    def test_volume_with_delta_repr0(self):
        """Test Rest conversion of a vol with delta information, no nodes."""
        udf = MockVolume()
        nodes = []
        info = self.mapper.volume_repr(
            volume=udf, from_generation=0, nodes=nodes)
        self.assertEqual(info['resource_path'], '/volumes/~/Documents')
        self.assertEqual(info['type'], 'root' if udf.is_root else 'udf')
        self.assertEqual(info['path'], udf.path)
        self.assertEqual(info['generation'], udf.generation)
        self.assertEqual(info['node_path'], self.mapper.node(udf.path))
        self.assertEqual(
            info['when_created'], date_formatter(udf.when_created))
        self.assertEqual(info['delta']['from_generation'], 0)
        self.assertEqual(info['delta']['nodes'], nodes)

    def test_volume_with_delta_repr1(self):
        """Test Rest conversion of a volume with delta innformation,
        with nodes."""
        udf = MockVolume()
        nodes = [MockNode(), MockNode()]
        info = self.mapper.volume_repr(
            volume=udf, from_generation=0, nodes=nodes)
        self.assertEqual(info['delta']['from_generation'], 0)
        self.assertEqual(
            info['delta']['nodes'],
            [self.mapper.node_repr(node) for node in nodes])

    def test_file_node_repr(self):
        """Test Rest conversion of a file node."""
        f1 = MockNode()
        info = self.mapper.node_repr(f1)
        self.assertEqual(info['key'], f1.nodekey)
        self.assertEqual(info['kind'], f1.kind.lower())
        self.assertEqual(info['path'], f1.full_path)
        self.assertEqual(info['hash'], f1.content_hash)
        self.assertEqual(
            info['when_created'], date_formatter(f1.when_created))
        self.assertEqual(
            info['when_changed'], date_formatter(f1.when_last_modified))
        self.assertEqual(info['generation'], f1.generation)
        self.assertEqual(info['generation_created'], f1.generation_created)
        self.assertEqual(info['public_url'], f1.public_url)
        self.assertEqual(info['is_public'], f1.is_public)
        self.assertEqual(
            info['parent_path'], "/%s/a/b/c/d" % settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(
            info['volume_path'], "/volumes/%s" % settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(
            info['content_path'],
            '/content/%s/a/b/c/d/file.txt' % settings.ROOT_USERVOLUME_PATH)
        # make sure file specific rules apply
        self.assertTrue('has_children' not in info)
        self.assertEqual(info['is_live'], True)

    def test_dir_node_repr(self):
        """Utility method to test Rest conversion of a directory node."""
        f1 = MockNode()
        f1.kind = StorageObject.DIRECTORY
        info = self.mapper.node_repr(f1)
        self.assertEqual(info['key'], f1.nodekey)
        self.assertEqual(info['kind'], f1.kind.lower())
        self.assertEqual(info['path'], f1.full_path)
        self.assertEqual(
            info['when_created'], date_formatter(f1.when_created))
        self.assertEqual(
            info['when_changed'], date_formatter(f1.when_last_modified))
        self.assertEqual(info['generation'], f1.generation)
        self.assertEqual(info['generation_created'], f1.generation_created)
        self.assertEqual(
            info['parent_path'],
            "/%s/a/b/c/d" % settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(
            info['volume_path'], "/volumes/%s" % settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(
            info['content_path'],
            '/content/%s/a/b/c/d/file.txt' % settings.ROOT_USERVOLUME_PATH)
        # make sure directory specific rules apply
        self.assertTrue('hash' not in info)
        self.assertTrue('is_public' not in info)
        self.assertTrue('public_url' not in info)
        self.assertTrue('has_children' in info)
        self.assertEqual(info['is_live'], True)

    def test_root_dir_node_repr(self):
        """Utility method to test Rest conversion of a root directory node."""
        f1 = MockNode()
        f1.kind = StorageObject.DIRECTORY
        f1.name = ""
        f1.path = '/'
        f1.full_path = "/"
        info = self.mapper.node_repr(f1)
        self.assertEqual(info['key'], f1.nodekey)
        self.assertEqual(info['kind'], f1.kind.lower())
        self.assertEqual(info['path'], f1.full_path)
        self.assertEqual(info['when_created'], date_formatter(f1.when_created))
        self.assertEqual(
            info['when_changed'], date_formatter(f1.when_last_modified))
        self.assertEqual(info['generation'], f1.generation)
        self.assertEqual(info['generation_created'], f1.generation_created)
        self.assertEqual(info['parent_path'], None)
        self.assertEqual(
            info['volume_path'], "/volumes/%s" % settings.ROOT_USERVOLUME_PATH)
        self.assertEqual(
            info['content_path'],
            '/content/%s' % settings.ROOT_USERVOLUME_PATH)
        # make sure directory specific rules apply
        self.assertTrue('hash' not in info)
        self.assertTrue('is_public' not in info)
        self.assertTrue('public_url' not in info)
        self.assertTrue('has_children' in info)
        self.assertEqual(info['is_live'], True)


class RestHelperTestCase(BaseTestCase):
    """Test the resthelper."""

    def setUp(self):
        super(RestHelperTestCase, self).setUp()
        self.user = make_storage_user(
            username="bob", visible_name="bobby boo",
            max_storage_bytes=2 * (2 ** 30))
        self.mapper = ResourceMapper()
        self.handler = self.add_memento_handler(logger, level=logging.INFO)
        self.helper = RestHelper(self.mapper)

    def test_GET_user(self):
        """Test for dao to REST conversion of user"""
        info = self.helper.get_user(self.user)
        self.assertEqual(info, self.mapper.user_repr(self.user))
        user_id = repr(self.user.id)
        self.handler.assert_info("get_udfs", user_id)

    def test_GET_user_with_udf(self):
        """Test get_user with udf."""
        udf = self.user.make_udf("~/Documents")
        info = self.helper.get_user(self.user)
        self.assertEqual(info, self.mapper.user_repr(self.user, [udf]))

    def test_GET_volume(self):
        """Test get_volume."""
        volume_path = "~/Documents"
        udf = self.user.make_udf(volume_path)
        info = self.helper.get_volume(user=self.user,
                                      volume_path=volume_path)
        self.assertEqual(info, self.mapper.volume_repr(udf))
        ids = [repr(self.user.id), repr(volume_path)]
        self.handler.assert_info("get_udf_by_path", *ids)

    def test_GET_volume_with_delta0(self):
        """Test get_volume with delta, no nodes"""
        volume_path = "~/Documents"
        udf = self.user.make_udf(volume_path)
        info = self.helper.get_volume(
            user=self.user,
            volume_path=volume_path,
            from_generation=0)
        self.assertEqual(
            info,
            self.mapper.volume_repr(volume=udf, from_generation=0, nodes=[]))
        ids = [repr(self.user.id), repr(volume_path)]
        self.handler.assert_info("get_udf_by_path", *ids)
        ids = [repr(x) for x in [self.user.id, udf.id, 0]]
        self.handler.assert_info("get_delta", *ids)

    def test_GET_volume_with_delta1(self):
        """Test get_volume with delta, with nodes"""
        volume_path = "~/Documents"
        self.user.make_udf(volume_path)
        node0 = self.user.make_file_by_path("~/Documents/file0.txt")
        node1 = self.user.make_file_by_path("~/Documents/file1.txt")
        info = self.helper.get_volume(
            user=self.user,
            volume_path=volume_path,
            from_generation=0)
        udf = self.user.get_udf_by_path('~/Documents')
        self.assertEqual(info, self.mapper.volume_repr(
            volume=udf, from_generation=0, nodes=[node0, node1]))
        node0.delete()
        info = self.helper.get_volume(
            user=self.user,
            volume_path=volume_path,
            from_generation=0)
        self.assertEqual(info['delta']['nodes'][1]['is_live'], False)

    def test_PUT_volume(self):
        """Test put volume."""
        path = "~/Documents"
        info = self.helper.put_volume(user=self.user, path=path)
        udf = self.user.get_udf_by_path(path)
        self.assertEqual(self.mapper.volume_repr(udf), info)
        ids = [repr(self.user.id), repr(path)]
        self.handler.assert_info("make_udf", *ids)

    def test_GET_node_directory(self):
        """Test for get_node a directory node."""
        root = self.user.volume().get_root()
        d1 = root.make_subdirectory("dir1")
        full_path = settings.ROOT_USERVOLUME_PATH + d1.full_path
        info = self.helper.get_node(user=self.user, node_path=full_path)
        self.assertEqual(info, self.mapper.node_repr(d1))

    def test_GET_node_file(self):
        """Test for  get_node conversion of a file node."""
        root = self.user.volume().get_root()
        f1 = root.make_file("file.txt")
        volume_path = settings.ROOT_USERVOLUME_PATH
        full_path = volume_path + f1.full_path
        info = self.helper.get_node(user=self.user, node_path=full_path)
        self.assertEqual(info, self.mapper.node_repr(f1))
        ids = [repr(x) for x in [self.user.id, full_path, True]]
        self.handler.assert_info("get_node_by_path", *ids)

    def test_GET_volumes(self):
        """Test get_volume."""
        udfs = [self.user.make_udf("~/Udf%s" % i) for i in range(10)]
        info = self.helper.get_volumes(self.user)
        root = self.user.volume().get_volume()
        expected_repr = [self.mapper.volume_repr(root)]
        expected_repr.extend([self.mapper.volume_repr(u) for u in udfs])
        info = info.sort(key=operator.itemgetter('path'))
        expected_repr = expected_repr.sort(key=operator.itemgetter('path'))
        self.assertEqual(info, expected_repr)
        self.handler.assert_info("get_volume", repr(self.user.id))
        self.handler.assert_info("get_udfs", repr(self.user.id))

    def test_DELETE_volume(self):
        """Test delete_volume."""
        udf = self.user.make_udf("~/Documents")
        self.helper.delete_volume(self.user, udf.path)
        self.assertRaises(errors.DoesNotExist,
                          self.user.get_udf, udf.id)
        ids = [repr(x) for x in [self.user.id, udf.path]]
        self.handler.assert_info("get_udf_by_path", *ids)
        ids = [repr(x) for x in [self.user.id, udf.id]]
        self.handler.assert_info("delete_udf", *ids)

    def test_GET_node0(self):
        """Test simple node info."""
        root = self.user.volume().get_root()
        f1 = root.make_file("file.txt")
        full_path = settings.ROOT_USERVOLUME_PATH + f1.full_path
        info = self.helper.get_node(self.user, full_path)
        self.assertEqual(info, self.mapper.node_repr(f1))

    def test_GET_node1(self):
        """Test child node info."""
        root = self.user.volume().get_root()
        d1 = root.make_subdirectory("Documents")
        f1 = d1.make_file("file.txt")
        full_path = settings.ROOT_USERVOLUME_PATH + os.path.join(
            d1.full_path, f1.name)
        info = self.helper.get_node(self.user, full_path)
        self.assertEqual(info['key'], f1.nodekey)
        self.assertEqual(info['path'], f1.full_path)

    def test_GET_node2(self):
        """Test simple udf node info."""
        self.user.make_udf("~/Documents")
        udf = self.user.get_node_by_path("~/Documents")
        f1 = udf.make_file("file.txt")
        full_path = "~/Documents" + f1.full_path
        info = self.helper.get_node(self.user, full_path)
        self.assertEqual(info['key'], f1.nodekey)
        self.assertEqual(info['path'], f1.full_path)

    def test_GET_node3(self):
        """Test child udf node info."""
        self.user.make_udf("~/Documents")
        udf = self.user.get_node_by_path("~/Documents")
        d1 = udf.make_subdirectory("slides")
        f1 = d1.make_file("file.txt")
        full_path = "~/Documents" + f1.full_path
        info = self.helper.get_node(self.user, full_path)
        self.assertEqual(info, self.mapper.node_repr(f1))

    def test_DELETE_node(self):
        """Test delete_volume."""
        root = self.user.volume().get_root()
        f1 = root.make_file("file.txt")
        full_path = settings.ROOT_USERVOLUME_PATH + f1.full_path
        self.helper.delete_node(self.user, full_path)
        self.assertRaises(errors.DoesNotExist,
                          self.user.volume().get_node, f1.id)
        ids = [repr(x) for x in [self.user.id, full_path]]
        self.handler.assert_info("get_node_by_path", *ids)
        ids = [repr(x) for x in [self.user.id, f1.id, True]]
        self.handler.assert_info("delete", *ids)

    def test_GET_node_children(self):
        """Test get_node_children."""
        root = self.user.volume().get_root()
        files = [root.make_file("file%s.txt" % i) for i in range(10)]
        full_path = settings.ROOT_USERVOLUME_PATH
        root.load()
        expected = self.mapper.node_repr(root)
        expected['children'] = [self.mapper.node_repr(n) for n in files]
        info = self.helper.get_node(
            self.user, full_path, include_children=True)
        self.assertEqual(info, expected)
        ids = [repr(x) for x in [self.user.id, full_path, True]]
        self.handler.assert_info("get_node", *ids)
        ids = [repr(x) for x in [self.user.id, root.id, True]]
        self.handler.assert_info("get_children", *ids)

    def test_GET_file_node_children(self):
        """Test get_node_children."""
        self.user.volume().root.make_file("file.txt")
        self.assertRaises(
            FileNodeHasNoChildren, self.helper.get_node, self.user,
            settings.ROOT_USERVOLUME_PATH + "/file.txt", include_children=True)

    def test_PUT_node_is_public(self):
        """Test put node to make existing file public."""
        original_metrics = self.helper.metrics
        self.helper.metrics = FakeMetrics()
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        self.assertEqual(node.is_public, False)
        node_rep = self.mapper.node_repr(node)
        node_rep['is_public'] = True
        info = self.helper.put_node(self.user, new_file_path, node_rep)

        ids = [repr(x) for x in [self.user.id, new_file_path]]
        self.handler.assert_info("get_node_by_path", *ids)
        ids = [repr(x) for x in [self.user.id, node.id, True]]
        self.handler.assert_info("change_public_access", *ids)

        node.load()
        self.assertEqual(node.is_public, True)
        self.assertEqual(info, self.mapper.node_repr(node))
        info['is_public'] = False
        info = self.helper.put_node(self.user, new_file_path, info)
        node.load()
        self.assertEqual(node.is_public, False)
        self.assertEqual(info, self.mapper.node_repr(node))
        self.helper.metrics.make_all_assertions(
            self, 'resthelper.put_node.change_public')
        self.helper.metrics = original_metrics

    def test_GET_public_files(self):
        """Test public_files returns the list of public files."""
        self.assertEqual(self.helper.get_public_files(self.user), [])
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        self.assertEqual(node.is_public, False)
        node_rep = self.mapper.node_repr(node)
        node_rep['is_public'] = True
        info = self.helper.put_node(self.user, new_file_path, node_rep)
        self.assertEqual(self.helper.get_public_files(self.user), [info])
        self.handler.assert_info(
            "get_public_files", repr(self.user.id))

    def test_PUT_node_is_public_directory(self):
        """Test put node to make existing file public."""
        dir_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c"
        node = self.user.make_tree_by_path(dir_path)
        self.assertEqual(node.is_public, False)
        node_rep = self.mapper.node_repr(node)
        node_rep['is_public'] = True
        self.assertRaises(CannotPublishDirectory,
                          self.helper.put_node, self.user, dir_path, node_rep)

    def test_PUT_node_path(self):
        """Test put node with a new path."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        self.assertEqual(node.full_path, "/a/b/c/file.txt")
        node_rep = self.mapper.node_repr(node)
        new_path = "/a/newfile.txt"
        node_rep['path'] = new_path
        info = self.helper.put_node(self.user, new_file_path, node_rep)
        node.load()
        self.assertEqual(node.full_path, new_path)
        self.assertEqual(info, self.mapper.node_repr(node))
        ids = [repr(x) for x in [self.user.id, new_file_path]]
        self.handler.assert_info("get_node_by_path", *ids)
        new_dir, new_name = os.path.split(new_path)
        ids = [repr(self.user.id), repr(node.vol_id), repr(new_dir)]
        self.handler.assert_info("get_node_by_path", *ids)
        ids = [repr(self.user.id), repr(node.id), repr(new_name)]
        self.handler.assert_info("move", *ids)

    def test_PUT_node_path_is_public(self):
        """Test put node with a new path and make it public."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        self.assertEqual(node.full_path, "/a/b/c/file.txt")
        node_rep = self.mapper.node_repr(node)
        node_rep['path'] = "/a/newfile.txt"
        node_rep['is_public'] = True
        info = self.helper.put_node(self.user, new_file_path, node_rep)
        node.load()
        self.assertEqual(node.is_public, True)
        self.assertEqual(node.full_path, "/a/newfile.txt")
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_is_public_partial(self):
        """Test put node."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        self.assertEqual(node.is_public, False)
        info = self.helper.put_node(self.user, new_file_path,
                                    {'is_public': True})
        node.load()
        self.assertEqual(node.is_public, True)
        self.assertEqual(info, self.mapper.node_repr(node))
        info = self.helper.put_node(self.user, new_file_path,
                                    {'is_public': False})
        node.load()
        self.assertEqual(node.is_public, False)
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_path_partial(self):
        """Test put node with a new path with partial info."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        info = self.helper.put_node(self.user, new_file_path,
                                    {'path': "/a/newfile.txt"})
        node.load()
        self.assertEqual(node.full_path, "/a/newfile.txt")
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_path_is_pulic_partial(self):
        """Test put node with a new path and make it public."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        info = self.helper.put_node(
            self.user, new_file_path,
            {'path': "/a/newfile.txt", 'is_public': True})
        node.load()
        self.assertEqual(node.full_path, "/a/newfile.txt")
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_do_nothing(self):
        """Test put_node with nothing to do."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        node = self.user.make_file_by_path(new_file_path)
        node_repr = self.mapper.node_repr(node)
        info = self.helper.put_node(self.user, new_file_path,
                                    dict(a=2, b='hi', c='ignored'))
        node.load()
        # here nothing is changed and the info returned
        # matches the existing node_repr
        self.assertEqual(info, node_repr)
        self.assertEqual(node_repr, self.mapper.node_repr(node))

    def test_PUT_node_new_file_magic(self):
        """Test put_node to make a new file with content."""
        cb = self.factory.make_content_blob(
            content="FakeContent", magic_hash='magic')
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        info = self.helper.put_node(
            self.user, new_file_path,
            {'kind': 'file', 'hash': cb.hash, 'magic_hash': 'magic'})
        node = self.user.get_node_by_path(new_file_path)
        self.assertEqual(node.kind, StorageObject.FILE)
        self.assertEqual(node.full_path, '/a/b/c/file.txt')
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_update_file_magic(self):
        """Test put_node to make a new file with content."""
        cb = self.factory.make_content_blob(
            content="FakeContent", magic_hash='magic')
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        info = self.helper.put_node(
            self.user, new_file_path,
            {'kind': 'file', 'hash': cb.hash, 'magic_hash': 'magic'})
        cb = self.factory.make_content_blob(
            content="NewFakeContent", magic_hash='magic2')
        info = self.helper.put_node(
            self.user, new_file_path,
            {'kind': 'file', 'hash': cb.hash, 'magic_hash': 'magic2'})
        node = self.user.get_node_by_path(new_file_path, with_content=True)
        self.assertEqual(node.kind, StorageObject.FILE)
        self.assertEqual(node.full_path, '/a/b/c/file.txt')
        self.assertEqual(info, self.mapper.node_repr(node))
        self.assertEqual(node.content.magic_hash, 'magic2')

    def test_PUT_node_new_file(self):
        """Test put_node to make a new file."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        info = self.helper.put_node(self.user, new_file_path,
                                    {'kind': 'file'})
        node = self.user.get_node_by_path(new_file_path)
        self.assertEqual(node.kind, StorageObject.FILE)
        self.assertEqual(node.full_path, '/a/b/c/file.txt')
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_new_directory(self):
        """Test put_node to make a new directory."""
        new_file_path = settings.ROOT_USERVOLUME_PATH + "/a/b/c/file.txt"
        info = self.helper.put_node(self.user, new_file_path,
                                    {'kind': 'directory'})
        node = self.user.get_node_by_path(new_file_path)
        self.assertEqual(node.kind, StorageObject.DIRECTORY)
        self.assertEqual(node.full_path, '/a/b/c/file.txt')
        self.assertEqual(info, self.mapper.node_repr(node))

    def test_PUT_node_exceptions(self):
        """Test put_node exceptions."""
        self.assertRaises(
            InvalidKind, self.helper.put_node, self.user,
            settings.ROOT_USERVOLUME_PATH + "/x", {"kind": "ABC"})
        # PUT to a non existent node.
        self.assertRaises(errors.DoesNotExist,
                          self.helper.put_node,
                          self.user, "~/Ubuntu/x", {})
        # PUT to a non existent node.
        self.assertRaises(errors.DoesNotExist,
                          self.helper.put_node,
                          self.user, settings.ROOT_USERVOLUME_PATH + "/x", {})
