# Copyright 2008-2015 Canonical
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Tests for the DAL entry point."""

from __future__ import unicode_literals

import uuid

from twisted.internet import defer
from mocker import Mocker, expect, KWARGS

from magicicada.filesync import errors
from magicicada.filesync.models import (
    STATUS_LIVE,
    STATUS_DEAD,
    StorageObject,
)
from magicicada.rpcdb import backend
from magicicada.testing.testcase import BaseTestCase


class DALTestCase(BaseTestCase):
    """Tests for the DAL backend."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(DALTestCase, self).setUp()
        self.backend = backend.DAL()
        self.auth_parameters = dict(username="user", password='testpass')
        self.usr = self.factory.make_user(**self.auth_parameters)

    def test_ping(self):
        """Ping pong."""
        res = self.backend.ping()
        self.assertEqual(res, {'response': 'pong'})

    def test_get_user_id_ok(self):
        """Get user id, all ok."""
        result = self.backend.get_userid_from_token(self.auth_parameters)
        self.assertEqual(result, dict(user_id=self.usr.id))

    def test_get_user_id_bad_auth(self):
        """Bad parameters in the oauth request."""
        bad_parameters = self.auth_parameters.copy()
        bad_parameters['password'] = "bad"
        try:
            self.backend.get_userid_from_token({})
        except backend.FailedAuthentication as exc:
            self.assertEqual(str(exc), "Bad parameters: {}")
        else:
            self.fail("Should have raised an exception.")

    def test_auth_parameters_not_dict(self):
        bad_params = (1, 2, object(), 'foo')
        self.assertRaises(
            AttributeError, self.backend.get_userid_from_token, bad_params)

    def test_auth_parameters_empty_dict(self):
        bad_params = dict()
        with self.assertRaises(backend.FailedAuthentication) as ctx:
            self.backend.get_userid_from_token(bad_params)
        self.assertEqual(str(ctx.exception), 'Bad parameters: {}')

    def test_unlink_node(self):
        """Unlink a node."""
        mocker = Mocker()

        # node, with a generation attribute
        node = mocker.mock()
        expect(node.generation).result(123)
        expect(node.kind).result(StorageObject.FILE)
        expect(node.name).result('foo')
        expect(node.mimetype).result('mime')

        # user, with the chained calls to the delete
        user = mocker.mock()
        expect(user.volume('vol_id').node('node_id').delete()).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            kwargs = dict(user_id='user_id', volume_id='vol_id',
                          node_id='node_id', session_id='session_id')
            result = self.backend.unlink_node(**kwargs)

        d = dict(generation=123, kind=StorageObject.FILE, name='foo',
                 mimetype='mime')
        self.assertEqual(result, d)

    def test_list_volumes_root_and_quota(self):
        """List volumes, check root and quota."""
        mocker = Mocker()

        # root
        root = mocker.mock()
        expect(root.generation).result(123)
        expect(root.root_id).result('root_id')

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume().get_volume()).result(root)
        expect(user.get_shared_to(accepted=True)).result([])
        expect(user.get_udfs()).result([])
        expect(user.free_bytes).result(4567890)

        with mocker:
            result = self.backend.list_volumes('user_id')

        self.assertEqual(sorted(result),
                         ['free_bytes', 'root', 'shares', 'udfs'])
        self.assertEqual(result['root'],
                         dict(generation=123, root_id='root_id'))
        self.assertEqual(result['free_bytes'], 4567890)

    def test_list_volumes_shares(self):
        """List volumes, check shares."""
        mocker = Mocker()

        # root and quota
        root = mocker.mock()
        expect(root.generation).result(123)
        expect(root.root_id).result('root_id')

        # one share
        sharedby1 = mocker.mock()
        expect(sharedby1.username).result('byusername1')
        expect(sharedby1.visible_name).result('byvisible1')
        expect(sharedby1.free_bytes).result(147)
        share1 = mocker.mock()
        expect(share1.id).result('share1_id')
        expect(share1.root_id).result('share1_root_id')
        expect(share1.name).result('name1')
        expect(share1.shared_by).result(sharedby1)
        expect(share1.accepted).result(True)
        expect(share1.access).result(1)
        expect(share1.get_generation()).result(6)

        # other share
        sharedby2 = mocker.mock()
        expect(sharedby2.username).result('byusername2')
        expect(sharedby2.visible_name).result('byvisible2')
        expect(sharedby2.free_bytes).result(852)
        share2 = mocker.mock()
        expect(share2.id).result('share2_id')
        expect(share2.root_id).result('share2_root_id')
        expect(share2.name).result('name2')
        expect(share2.shared_by).result(sharedby2)
        expect(share2.accepted).result(False)
        expect(share2.access).result(0)
        expect(share2.get_generation()).result(8)

        # user
        user = mocker.mock()
        expect(user.free_bytes).result(4567890)
        self.backend._get_user = lambda *a: user
        expect(user.volume().get_volume()).result(root)
        expect(user.get_shared_to(accepted=True)).result([share1, share2])
        expect(user.get_udfs()).result([])

        with mocker:
            result = self.backend.list_volumes('user_id')
        share1, share2 = result['shares']

        self.assertEqual(share1['id'], 'share1_id')
        self.assertEqual(share1['root_id'], 'share1_root_id')
        self.assertEqual(share1['name'], 'name1')
        self.assertEqual(share1['shared_by_username'], 'byusername1')
        self.assertEqual(share1['shared_by_visible_name'], 'byvisible1')
        self.assertEqual(share1['accepted'], True)
        self.assertEqual(share1['access'], 1)
        self.assertEqual(share1['free_bytes'], 147)
        self.assertEqual(share1['generation'], 6)

        self.assertEqual(share2['id'], 'share2_id')
        self.assertEqual(share2['root_id'], 'share2_root_id')
        self.assertEqual(share2['name'], 'name2')
        self.assertEqual(share2['shared_by_username'], 'byusername2')
        self.assertEqual(share2['shared_by_visible_name'], 'byvisible2')
        self.assertEqual(share2['accepted'], False)
        self.assertEqual(share2['access'], 0)
        self.assertEqual(share2['free_bytes'], 852)
        self.assertEqual(share2['generation'], 8)

    def test_list_volumes_udfs(self):
        """List volumes, check shares."""
        mocker = Mocker()

        # root and quota
        root = mocker.mock()
        expect(root.generation).result(123)
        expect(root.root_id).result('root_id')

        # one udf
        udf1 = mocker.mock()
        expect(udf1.id).result('udf1_id')
        expect(udf1.root_id).result('udf1_root_id')
        expect(udf1.path).result('path1')
        expect(udf1.generation).result(6)

        # other udf
        udf2 = mocker.mock()
        expect(udf2.id).result('udf2_id')
        expect(udf2.root_id).result('udf2_root_id')
        expect(udf2.path).result('path2')
        expect(udf2.generation).result(8)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume().get_volume()).result(root)
        expect(user.get_shared_to(accepted=True)).result([])
        expect(user.get_udfs()).result([udf1, udf2])
        expect(user.free_bytes).result(4567890)

        with mocker:
            result = self.backend.list_volumes('user_id')
        udf1, udf2 = result['udfs']

        self.assertEqual(udf1['id'], 'udf1_id')
        self.assertEqual(udf1['root_id'], 'udf1_root_id')
        self.assertEqual(udf1['path'], 'path1')
        self.assertEqual(udf1['generation'], 6)

        self.assertEqual(udf2['id'], 'udf2_id')
        self.assertEqual(udf2['root_id'], 'udf2_root_id')
        self.assertEqual(udf2['path'], 'path2')
        self.assertEqual(udf2['generation'], 8)

    def test_change_public_access(self):
        """Change the public acces of a node."""
        mocker = Mocker()

        # node, with a generation attribute
        node = mocker.mock()
        expect(node.public_url).result('test public url')

        # user, with the chained calls to the action
        user = mocker.mock()
        expect(
            user.volume('vol_id').node('node_id').change_public_access(True)
        ).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            kwargs = dict(user_id='user_id', volume_id='vol_id',
                          node_id='node_id', is_public=True,
                          session_id='session_id')
            result = self.backend.change_public_access(**kwargs)

        self.assertEqual(result, dict(public_url='test public url'))

    def test_list_public_files(self):
        """List public files."""
        mocker = Mocker()

        # node 1
        node1 = mocker.mock()
        expect(node1.id).result('node_id1')
        expect(node1.path).result('path1')
        expect(node1.name).result('name1')
        expect(node1.vol_id).result('volume_id1')
        expect(node1.generation).result('generation1')
        expect(node1.is_public).result(True)
        expect(node1.parent_id).result('parent_id1')
        expect(node1.status).result(STATUS_LIVE)
        expect(node1.content_hash).result('content_hash1')
        expect(node1.kind).result(StorageObject.FILE)
        expect(node1.when_last_modified).result('last_modified1')
        content1 = mocker.mock()
        expect(content1.size).result('size1')
        expect(content1.crc32).result('crc321')
        expect(content1.deflated_size).result('deflated_size1')
        expect(content1.storage_key).result('storage_key1')
        expect(node1.content).result(content1)
        expect(node1.public_url).result('public url 1')

        # node 2
        node2 = mocker.mock()
        expect(node2.id).result('node_id2')
        expect(node2.path).result('path2')
        expect(node2.name).result('name2')
        expect(node2.vol_id).result('volume_id2')
        expect(node2.generation).result('generation2')
        expect(node2.is_public).result(True)
        expect(node2.parent_id).result('parent_id2')
        expect(node2.status).result(STATUS_DEAD)
        expect(node2.content_hash).result('content_hash2')
        expect(node2.kind).result(StorageObject.DIRECTORY)
        expect(node2.when_last_modified).result('last_modified2')
        content2 = mocker.mock()
        expect(content2.size).result('size2')
        expect(content2.crc32).result('crc322')
        expect(content2.deflated_size).result('deflated_size2')
        expect(content2.storage_key).result('storage_key2')
        expect(node2.content).result(content2)
        expect(node2.public_url).result('public url 2')

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.get_public_files()).result([node1, node2])

        with mocker:
            result = self.backend.list_public_files(user_id='user_id',)
        node1, node2 = result['public_files']

        self.assertEqual(node1['id'], 'node_id1')
        self.assertEqual(node1['path'], 'path1')
        self.assertEqual(node1['name'], 'name1')
        self.assertEqual(node1['volume_id'], 'volume_id1')
        self.assertEqual(node1['parent_id'], 'parent_id1')
        self.assertEqual(node1['is_live'], True)
        self.assertEqual(node1['generation'], 'generation1')
        self.assertEqual(node1['is_public'], True)
        self.assertEqual(node1['content_hash'], 'content_hash1')
        self.assertEqual(node1['is_file'], True)
        self.assertEqual(node1['size'], 'size1')
        self.assertEqual(node1['crc32'], 'crc321')
        self.assertEqual(node1['deflated_size'], 'deflated_size1')
        self.assertEqual(node1['storage_key'], 'storage_key1')
        self.assertEqual(node1['last_modified'], 'last_modified1')
        self.assertEqual(node1['public_url'], 'public url 1')

        self.assertEqual(node2['id'], 'node_id2')
        self.assertEqual(node2['path'], 'path2')
        self.assertEqual(node2['name'], 'name2')
        self.assertEqual(node2['volume_id'], 'volume_id2')
        self.assertEqual(node2['parent_id'], 'parent_id2')
        self.assertEqual(node2['is_live'], False)
        self.assertEqual(node2['generation'], 'generation2')
        self.assertEqual(node2['is_public'], True)
        self.assertEqual(node2['content_hash'], 'content_hash2')
        self.assertEqual(node2['is_file'], False)
        self.assertEqual(node2['size'], 'size2')
        self.assertEqual(node2['crc32'], 'crc322')
        self.assertEqual(node2['deflated_size'], 'deflated_size2')
        self.assertEqual(node2['storage_key'], 'storage_key2')
        self.assertEqual(node2['last_modified'], 'last_modified2')
        self.assertEqual(node2['public_url'], 'public url 2')

    def test_move(self):
        """Move."""
        mocker = Mocker()

        # node, with a generation attribute
        node = mocker.mock()
        expect(node.generation).result(123)
        expect(node.mimetype).result('mime')

        # user, with the chained calls to the operation
        user = mocker.mock()
        new_parent_id = uuid.uuid4()
        expect(user.volume('vol_id').node('node_id')
               .move(new_parent_id, 'new_name')).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            kwargs = dict(user_id='user_id', volume_id='vol_id',
                          node_id='node_id', new_parent_id=new_parent_id,
                          new_name='new_name', session_id='session_id')
            result = self.backend.move(**kwargs)

        self.assertEqual(result, dict(generation=123, mimetype='mime'))

    def test_move_with_new_parent_id_as_str(self):
        """Check that DAO.move() will cast new_parent_id into a UUID if it
        gets a str object.

        This is necessary because StorageObject.move() only accepts UUIDs for
        new_parent_id.
        """
        mocker = Mocker()
        node = mocker.mock()
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        parent_id = uuid.uuid4()

        expect(node.generation).result(123)
        expect(node.mimetype).result('mime')
        expect(user.volume('vol_id').node('node_id').move(
            parent_id, 'new_name')).result(node)

        with mocker:
            # Here we pass the new_parent_id as str but above we expect it to
            # be a UUID object.
            self.backend.move(
                'user_id', 'vol_id', 'node_id', str(parent_id), 'new_name',
                'session_id')

    def test_make_dir(self):
        """Make a directory."""
        mocker = Mocker()

        # node, with a generation attribute
        node = mocker.mock()
        expect(node.id).result('node_id')
        expect(node.generation).result(123)
        expect(node.mimetype).result('mime')

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.volume('vol_id').dir('parent_id')
                                    .make_subdirectory('name')).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            kwargs = dict(user_id='user_id', volume_id='vol_id',
                          parent_id='parent_id', name='name',
                          session_id='session_id')
            result = self.backend.make_dir(**kwargs)

        d = dict(generation=123, node_id='node_id', mimetype='mime')
        self.assertEqual(result, d)

    def test_make_file(self):
        """Make a file with no content."""
        mocker = Mocker()

        # node, with a generation attribute
        node = mocker.mock()
        expect(node.id).result('node_id')
        expect(node.generation).result(123)
        expect(node.mimetype).result('mime')

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.volume('vol_id')
               .dir('parent_id').make_file('name')).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            kwargs = dict(user_id='user_id', volume_id='vol_id',
                          parent_id='parent_id', name='name',
                          session_id='session_id')
            result = self.backend.make_file(**kwargs)

        d = dict(generation=123, node_id='node_id', mimetype='mime')
        self.assertEqual(result, d)

    def test_make_file_with_content(self):
        """Make a file with content associated."""
        mocker = Mocker()

        # node, with a generation attribute
        node = mocker.mock()
        expect(node.id).result('node_id')
        expect(node.generation).result(123)

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.volume('vol_id').dir('parent_id')
               .make_file_with_content('name', 'hash', 'crc32', 'size',
                                       'deflated_size', 'storage_key')
               ).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            kwargs = dict(user_id='user_id', volume_id='vol_id', name='name',
                          parent_id='parent_id', crc32='crc32', size='size',
                          node_hash='hash', deflated_size='deflated_size',
                          storage_key='storage_key', session_id='session_id')
            result = self.backend.make_file_with_content(**kwargs)

        self.assertEqual(result, dict(generation=123, node_id='node_id'))

    def test_delete_share(self):
        """Delete a share."""
        mocker = Mocker()

        # share
        share = mocker.mock()
        expect(share.delete())

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.get_share('share_id')).result(share)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.delete_share('user_id', 'share_id')
        self.assertEqual(result, {})

    def test_create_share(self):
        """Create a share."""
        mocker = Mocker()

        # patch the DAL method to get the other user id from the username
        to_user = mocker.mock()
        expect(to_user.id).result('to_user_id')
        fake = mocker.mock()
        expect(fake(username='to_username')).result(to_user)
        self.patch(backend.services, 'get_storage_user', fake)

        # share
        share = mocker.mock()
        expect(share.id).result('share_id')

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.volume().dir('node_id').share(
            'to_user_id', 'name', True)).result(share)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.create_share(
                'user_id', 'node_id', 'to_username', 'name', True)
        self.assertEqual(result, dict(share_id='share_id'))

    def test_accept_share(self):
        """Accept a share."""
        mocker = Mocker()

        # share
        share = mocker.mock()
        expect(share.accept())

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.get_share('share_id')).result(share)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.accept_share('user_id', 'share_id')
        self.assertEqual(result, {})

    def test_decline_share(self):
        """Decline a share."""
        mocker = Mocker()

        # share
        share = mocker.mock()
        expect(share.decline())

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.get_share('share_id')).result(share)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.decline_share('user_id', 'share_id')
        self.assertEqual(result, {})

    def test_list_shares_shared_by(self):
        """List shares, the shared_by part."""
        mocker = Mocker()

        # one share
        sharedto1 = mocker.mock()
        expect(sharedto1.username).result('tousername1')
        expect(sharedto1.visible_name).result('tovisible1')
        share1 = mocker.mock()
        expect(share1.id).result('share1_id')
        expect(share1.root_id).result('share1_root_id')
        expect(share1.name).result('name1')
        expect(share1.shared_to).result(sharedto1)
        expect(share1.accepted).result(True)
        expect(share1.access).result(1)

        # other share, without shared_to
        share2 = mocker.mock()
        expect(share2.id).result('share2_id')
        expect(share2.root_id).result('share2_root_id')
        expect(share2.name).result('name2')
        expect(share2.shared_to).result(None)
        expect(share2.accepted).result(False)
        expect(share2.access).result(0)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.get_shared_by()).result([share1, share2])
        expect(user.get_shared_to(accepted=True)).result([])

        with mocker:
            result = self.backend.list_shares('user_id', accepted=True)
        share1, share2 = result['shared_by']

        self.assertEqual(share1['id'], 'share1_id')
        self.assertEqual(share1['root_id'], 'share1_root_id')
        self.assertEqual(share1['name'], 'name1')
        self.assertEqual(share1['shared_to_username'], 'tousername1')
        self.assertEqual(share1['shared_to_visible_name'], 'tovisible1')
        self.assertEqual(share1['accepted'], True)
        self.assertEqual(share1['access'], 1)

        self.assertEqual(share2['id'], 'share2_id')
        self.assertEqual(share2['root_id'], 'share2_root_id')
        self.assertEqual(share2['name'], 'name2')
        self.assertEqual(share2['shared_to_username'], None)
        self.assertEqual(share2['shared_to_visible_name'], None)
        self.assertEqual(share2['accepted'], False)
        self.assertEqual(share2['access'], 0)

    def test_list_shares_shared_to(self):
        """List shares, the shared_to part."""
        mocker = Mocker()

        # one share
        sharedby1 = mocker.mock()
        expect(sharedby1.username).result('byusername1')
        expect(sharedby1.visible_name).result('byvisible1')
        share1 = mocker.mock()
        expect(share1.id).result('share1_id')
        expect(share1.root_id).result('share1_root_id')
        expect(share1.name).result('name1')
        expect(share1.shared_by).result(sharedby1)
        expect(share1.accepted).result(True)
        expect(share1.access).result(1)

        # other share, without shared_by
        share2 = mocker.mock()
        expect(share2.id).result('share2_id')
        expect(share2.root_id).result('share2_root_id')
        expect(share2.name).result('name2')
        expect(share2.shared_by).result(None)
        expect(share2.accepted).result(False)
        expect(share2.access).result(0)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.get_shared_by()).result([])
        expect(user.get_shared_to(accepted=False)).result([share1, share2])

        with mocker:
            result = self.backend.list_shares('user_id', accepted=False)
        share1, share2 = result['shared_to']

        self.assertEqual(share1['id'], 'share1_id')
        self.assertEqual(share1['root_id'], 'share1_root_id')
        self.assertEqual(share1['name'], 'name1')
        self.assertEqual(share1['shared_by_username'], 'byusername1')
        self.assertEqual(share1['shared_by_visible_name'], 'byvisible1')
        self.assertEqual(share1['accepted'], True)
        self.assertEqual(share1['access'], 1)

        self.assertEqual(share2['id'], 'share2_id')
        self.assertEqual(share2['root_id'], 'share2_root_id')
        self.assertEqual(share2['name'], 'name2')
        self.assertEqual(share2['shared_by_username'], None)
        self.assertEqual(share2['shared_by_visible_name'], None)
        self.assertEqual(share2['accepted'], False)
        self.assertEqual(share2['access'], 0)

    def test_create_udf(self):
        """Create an UDF."""
        mocker = Mocker()

        # udf
        udf = mocker.mock()
        expect(udf.id).result('udf_id')
        expect(udf.root_id).result('udf_root_id')
        expect(udf.path).result('udf_path')

        # user, with the chained calls to the operation
        user = mocker.mock()
        expect(user.make_udf('path')).result(udf)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.create_udf('user_id', 'path', 'session_id')
        should = dict(udf_id='udf_id', udf_root_id='udf_root_id',
                      udf_path='udf_path')
        self.assertEqual(result, should)

    def test_delete_volume_share(self):
        """Delete a volume that was a share."""
        mocker = Mocker()

        # share
        share = mocker.mock()
        expect(share.delete())

        # user, getting a share when asked
        user = mocker.mock()
        expect(user.get_share('volume_id')).result(share)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.delete_volume(
                'user_id', 'volume_id', 'session_id')
        self.assertEqual(result, {})

    def test_delete_volume_udf(self):
        """Delete a volume that was a udf."""
        mocker = Mocker()

        # user, with an exception when asking for the share, and
        # the udf deletion
        user = mocker.mock()
        expect(user.get_share('volume_id')).throw(errors.DoesNotExist('foo'))
        expect(user.delete_udf('volume_id'))
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.delete_volume(
                'user_id', 'volume_id', 'session_id')
        self.assertEqual(result, {})

    def test_delete_volume_none(self):
        """Delete a volume that was not there."""
        mocker = Mocker()

        # user, with an exception when asking for the share, and
        # the udf deletion
        user = mocker.mock()
        volume_id = 'volume_id'
        expect(user.get_share(volume_id)).throw(errors.DoesNotExist('foo'))
        expect(user.delete_udf(volume_id)).throw(errors.DoesNotExist('bar'))
        self.backend._get_user = lambda *a: user

        with mocker:
            with self.assertRaises(errors.DoesNotExist) as ctx:
                self.backend.delete_volume('user_id', volume_id, 'session_id')

        self.assertIn(
            "Volume %r does not exist" % volume_id, unicode(ctx.exception))

    def test_get_user_quota(self):
        """Return the quota info for an user."""
        mocker = Mocker()

        # the user
        user = mocker.mock()
        expect(user.max_storage_bytes).result(100)
        expect(user.used_storage_bytes).result(80)
        expect(user.free_bytes).result(20)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.get_user_quota('user_id')
        should = dict(max_storage_bytes=100, used_storage_bytes=80,
                      free_bytes=20)
        self.assertEqual(result, should)

    def test_get_share(self):
        """Get a share."""
        mocker = Mocker()

        # the share
        share = mocker.mock()
        expect(share.id).result('share_id')
        expect(share.root_id).result('share_root_id')
        expect(share.name).result('name')
        expect(share.shared_by_id).result('shared_by_id')
        expect(share.shared_to_id).result('shared_to_id')
        expect(share.accepted).result(True)
        expect(share.access).result(1)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.get_share('share_id')).result(share)

        with mocker:
            result = self.backend.get_share('user_id', 'share_id')
        should = dict(share_id='share_id', share_root_id='share_root_id',
                      name='name', shared_by_id='shared_by_id', accepted=True,
                      shared_to_id='shared_to_id', access=1)
        self.assertEqual(result, should)

    def test_get_root(self):
        """Get the root id for an user."""
        mocker = Mocker()

        # the root node
        node = mocker.mock()
        expect(node.load()).result(node)
        expect(node.id).result('root_id')
        expect(node.generation).result(123)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.root).result(node)

        with mocker:
            result = self.backend.get_root('user_id')
        self.assertEqual(result, dict(root_id='root_id', generation=123))

    def test_get_node_ok(self):
        """Get a node."""
        mocker = Mocker()

        # node
        node = mocker.mock()
        expect(node.id).result('node_id')
        expect(node.path).result('path')
        expect(node.name).result('name')
        expect(node.vol_id).result('volume_id')
        expect(node.parent_id).result('parent_id')
        expect(node.status).result(STATUS_LIVE)
        expect(node.generation).result('generation')
        expect(node.is_public).result(False)
        expect(node.content_hash).result('content_hash')
        expect(node.kind).result(StorageObject.FILE)
        expect(node.when_last_modified).result('last_modified')
        content = mocker.mock()
        expect(content.size).result('size')
        expect(content.crc32).result('crc32')
        expect(content.deflated_size).result('deflated_size')
        expect(content.storage_key).result('storage_key')
        expect(node.content).count(1).result(content)
        expect(node.public_url).result(None)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id').get_node('node_id', with_content=True)
               ).result(node)

        with mocker:
            result = self.backend.get_node(
                user_id='user_id', node_id='node_id', volume_id='volume_id')

        should = dict(id='node_id', name='name', parent_id='parent_id',
                      is_public=False, is_live=True, is_file=True, size='size',
                      last_modified='last_modified', crc32='crc32',
                      generation='generation', content_hash='content_hash',
                      deflated_size='deflated_size', storage_key='storage_key',
                      volume_id='volume_id', path='path', has_content=True,
                      public_url=None)
        self.assertEqual(result, should)

    def test_get_node_no_content(self):
        """Get a node that has no content."""
        mocker = Mocker()

        # node
        node = mocker.mock()
        expect(node.id).result('node_id')
        expect(node.path).result('path')
        expect(node.name).result('name')
        expect(node.vol_id).result('volume_id')
        expect(node.parent_id).result('parent_id')
        expect(node.status).result(STATUS_LIVE)
        expect(node.generation).result('generation')
        expect(node.is_public).result(False)
        expect(node.content_hash).result('content_hash')
        expect(node.kind).result(StorageObject.FILE)
        expect(node.when_last_modified).result('last_modified')
        expect(node.content).result(None)
        expect(node.public_url).result(None)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id').get_node('node_id', with_content=True)
               ).result(node)

        with mocker:
            result = self.backend.get_node(
                user_id='user_id', node_id='node_id', volume_id='volume_id')

        should = dict(id='node_id', name='name', parent_id='parent_id',
                      is_public=False, is_live=True, is_file=True, size=None,
                      last_modified='last_modified', crc32=None,
                      generation='generation', content_hash='content_hash',
                      deflated_size=None, storage_key=None, public_url=None,
                      volume_id='volume_id', path="path", has_content=False)
        self.assertEqual(result, should)

    def test_get_node_from_user(self):
        """Get a node just giving the user."""
        mocker = Mocker()

        # node
        node = mocker.mock()
        expect(node.id).result('node_id')
        expect(node.path).result('path')
        expect(node.name).result('name')
        expect(node.vol_id).result('volume_id')
        expect(node.parent_id).result('parent_id')
        expect(node.status).result(STATUS_LIVE)
        expect(node.generation).result('generation')
        expect(node.is_public).result(False)
        expect(node.content_hash).result('content_hash')
        expect(node.kind).result(StorageObject.FILE)
        expect(node.when_last_modified).result('last_modified')
        expect(node.content).count(1).result(None)
        expect(node.public_url).result(None)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user

        # patch the DAL to return the node
        fake = mocker.mock()
        expect(fake('node_id')).result(node)
        self.patch(backend.services, 'get_node', fake)

        with mocker:
            result = self.backend.get_node_from_user(
                user_id='user_id', node_id='node_id')

        should = dict(id='node_id', name='name', parent_id='parent_id',
                      is_public=False, is_live=True, is_file=True, size=None,
                      last_modified='last_modified', crc32=None,
                      generation='generation', content_hash='content_hash',
                      deflated_size=None, storage_key=None, public_url=None,
                      volume_id='volume_id', path='path', has_content=False)
        self.assertEqual(result, should)

    def test_get_delta_and_from_scratch(self):
        """Get normal delta and from scratch."""
        mocker = Mocker()

        # node 1
        node1 = mocker.mock()
        expect(node1.id).count(2).result('node_id1')
        expect(node1.path).count(2).result('path1')
        expect(node1.name).count(2).result('name1')
        expect(node1.vol_id).count(2).result('volume_id1')
        expect(node1.generation).count(2).result('generation1')
        expect(node1.is_public).count(2).result(True)
        expect(node1.parent_id).count(2).result('parent_id1')
        expect(node1.status).count(2).result(STATUS_LIVE)
        expect(node1.content_hash).count(2).result('content_hash1')
        expect(node1.kind).count(2).result(StorageObject.FILE)
        expect(node1.when_last_modified).count(2).result('last_modified1')
        content1 = mocker.mock()
        expect(content1.size).count(2).result('size1')
        expect(content1.crc32).count(2).result('crc321')
        expect(content1.deflated_size).count(2).result('deflated_size1')
        expect(content1.storage_key).count(2).result('storage_key1')
        expect(node1.content).count(2).result(content1)
        expect(node1.public_url).count(2).result('public url')

        # node 2
        node2 = mocker.mock()
        expect(node2.id).count(2).result('node_id2')
        expect(node2.path).count(2).result('path2')
        expect(node2.name).count(2).result('name2')
        expect(node2.vol_id).count(2).result('volume_id2')
        expect(node2.generation).count(2).result('generation2')
        expect(node2.is_public).count(2).result(False)
        expect(node2.parent_id).count(2).result('parent_id2')
        expect(node2.status).count(2).result(STATUS_DEAD)
        expect(node2.content_hash).count(2).result('content_hash2')
        expect(node2.kind).count(2).result(StorageObject.DIRECTORY)
        expect(node2.when_last_modified).count(2).result('last_modified2')
        content2 = mocker.mock()
        expect(content2.size).count(2).result('size2')
        expect(content2.crc32).count(2).result('crc322')
        expect(content2.deflated_size).count(2).result('deflated_size2')
        expect(content2.storage_key).count(2).result('storage_key2')
        expect(node2.content).count(2).result(content2)
        expect(node2.public_url).count(2).result(None)

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id').get_delta('from_gen', limit='limit')
               ).result(('vol_generation', 'free_bytes', [node1, node2]))
        expect(user.volume('volume_id').get_from_scratch(KWARGS)
               ).result(('vol_generation', 'free_bytes', [node1, node2]))

        with mocker:
            result1 = self.backend.get_delta(
                user_id='user_id', volume_id='volume_id',
                from_generation='from_gen', limit='limit')
            result2 = self.backend.get_from_scratch(
                user_id='user_id', volume_id='volume_id')
        self.assertEqual(result1, result2)
        self.assertEqual(result1['vol_generation'], 'vol_generation')
        self.assertEqual(result1['free_bytes'], 'free_bytes')
        node1, node2 = result1['nodes']

        self.assertEqual(node1['id'], 'node_id1')
        self.assertEqual(node1['path'], 'path1')
        self.assertEqual(node1['name'], 'name1')
        self.assertEqual(node1['volume_id'], 'volume_id1')
        self.assertEqual(node1['parent_id'], 'parent_id1')
        self.assertEqual(node1['is_live'], True)
        self.assertEqual(node1['generation'], 'generation1')
        self.assertEqual(node1['is_public'], True)
        self.assertEqual(node1['content_hash'], 'content_hash1')
        self.assertEqual(node1['is_file'], True)
        self.assertEqual(node1['size'], 'size1')
        self.assertEqual(node1['crc32'], 'crc321')
        self.assertEqual(node1['deflated_size'], 'deflated_size1')
        self.assertEqual(node1['storage_key'], 'storage_key1')
        self.assertEqual(node1['last_modified'], 'last_modified1')
        self.assertEqual(node1['public_url'], 'public url')

        self.assertEqual(node2['id'], 'node_id2')
        self.assertEqual(node2['path'], 'path2')
        self.assertEqual(node2['name'], 'name2')
        self.assertEqual(node2['volume_id'], 'volume_id2')
        self.assertEqual(node2['parent_id'], 'parent_id2')
        self.assertEqual(node2['is_live'], False)
        self.assertEqual(node2['generation'], 'generation2')
        self.assertEqual(node2['is_public'], False)
        self.assertEqual(node2['content_hash'], 'content_hash2')
        self.assertEqual(node2['is_file'], False)
        self.assertEqual(node2['size'], 'size2')
        self.assertEqual(node2['crc32'], 'crc322')
        self.assertEqual(node2['deflated_size'], 'deflated_size2')
        self.assertEqual(node2['storage_key'], 'storage_key2')
        self.assertEqual(node2['last_modified'], 'last_modified2')
        self.assertEqual(node2['public_url'], None)

    def test_get_user(self):
        """Get accessable nodes and their hashes."""
        mocker = Mocker()

        # user
        user = mocker.mock()
        expect(user.root_volume_id).result('root_volume_id')
        expect(user.username).result('username')
        expect(user.visible_name).result('visible_name')
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.get_user_data(
                user_id='user_id', session_id='session_id')
        should = dict(root_volume_id='root_volume_id', username='username',
                      visible_name='visible_name')
        self.assertEqual(result, should)

    def test_get_volume_id_normal(self):
        """Get the volume_id, normal case."""
        mocker = Mocker()

        # node
        node = mocker.mock()
        expect(node.volume_id).result('volume_id')

        # user
        user = mocker.mock()
        expect(user.root_volume_id).result('root_volume_id')
        expect(user.volume().get_node('node_id')).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.get_volume_id(
                user_id='user_id', node_id='node_id')
        self.assertEqual(result, dict(volume_id='volume_id'))

    def test_get_volume_id_same_root(self):
        """Get the volume_id, special case where the subtree node is root."""
        mocker = Mocker()

        # node
        node = mocker.mock()
        expect(node.volume_id).result('root_volume_id')

        # user
        user = mocker.mock()
        expect(user.root_volume_id).result('root_volume_id')
        expect(user.volume().get_node('node_id')).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            result = self.backend.get_volume_id(
                user_id='user_id', node_id='node_id')
        self.assertEqual(result, dict(volume_id=None))

    def test_make_content(self):
        """Make content."""
        mocker = Mocker()

        # node 'old gen'
        node = mocker.mock()
        expect(node.generation).result('new_generation')
        expect(node.make_content('original_hash', 'hash_hint', 'crc32_hint',
                                 'inflated_size_hint', 'deflated_size_hint',
                                 'storage_key', 'magic_hash'))

        # user
        user = mocker.mock()
        expect(user.volume('volume_id').get_node('node_id')).result(node)
        self.backend._get_user = lambda *a: user

        with mocker:
            d = dict(user_id='user_id', volume_id='volume_id',
                     node_id='node_id', original_hash='original_hash',
                     hash_hint='hash_hint', crc32_hint='crc32_hint',
                     inflated_size_hint='inflated_size_hint',
                     deflated_size_hint='deflated_size_hint',
                     storage_key='storage_key', magic_hash='magic_hash',
                     session_id=None)
            result = self.backend.make_content(**d)
        self.assertEqual(result, dict(generation='new_generation'))

    def test_get_upload_job(self):
        """Get an upload_job."""
        mocker = Mocker()

        # upload job
        uj = mocker.mock()
        expect(uj.id).result('uj_id')
        expect(uj.uploaded_bytes).result('uploaded_bytes')
        expect(uj.multipart_key).result('multipart_key')
        expect(uj.chunk_count).result('chunk_count')
        expect(uj.when_last_active).result('when_last_active')

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id').get_node('node_id')
               .get_multipart_uploadjob('uploadjob_id', 'hash_value', 'crc32')
               ).result(uj)

        with mocker:
            d = dict(user_id='user_id', volume_id='volume_id',
                     node_id='node_id', uploadjob_id='uploadjob_id',
                     hash_value='hash_value', crc32='crc32')
            result = self.backend.get_uploadjob(**d)

        should = dict(uploadjob_id='uj_id', uploaded_bytes='uploaded_bytes',
                      multipart_key='multipart_key', chunk_count='chunk_count',
                      when_last_active='when_last_active')
        self.assertEqual(result, should)

    def test_make_upload_job(self):
        """Make an upload_job."""
        mocker = Mocker()

        # upload job
        uj = mocker.mock()
        expect(uj.id).result('uj_id')
        expect(uj.uploaded_bytes).result('uploaded_bytes')
        expect(uj.multipart_key).result('multipart_key')
        expect(uj.chunk_count).result('chunk_count')
        expect(uj.when_last_active).result('when_last_active')

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id').get_node('node_id')
               .make_uploadjob('previous_hash', 'hash_value', 'crc32',
                               'inflated_size', multipart_key='multipart_key')
               ).result(uj)

        with mocker:
            d = dict(user_id='user_id', volume_id='volume_id',
                     node_id='node_id', previous_hash='previous_hash',
                     hash_value='hash_value', crc32='crc32',
                     inflated_size='inflated_size',
                     multipart_key='multipart_key')
            result = self.backend.make_uploadjob(**d)

        should = dict(uploadjob_id='uj_id', uploaded_bytes='uploaded_bytes',
                      multipart_key='multipart_key', chunk_count='chunk_count',
                      when_last_active='when_last_active')
        self.assertEqual(result, should)

    def test_delete_uploadjob(self):
        """Delete an uploadjob."""
        mocker = Mocker()

        # upload job
        uj = mocker.mock()
        expect(uj.delete())

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id')
               .get_uploadjob('uploadjob_id')).result(uj)

        with mocker:
            d = dict(user_id='user_id', uploadjob_id='uploadjob_id',
                     volume_id='volume_id')
            result = self.backend.delete_uploadjob(**d)

        self.assertEqual(result, {})

    def test_add_part_to_uploadjob(self):
        """Delete an uploadjob."""
        mocker = Mocker()

        # upload job
        uj = mocker.mock()
        expect(uj.add_part('chunk_size'))

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id')
               .get_uploadjob('uploadjob_id')).result(uj)

        with mocker:
            d = dict(user_id='user_id', uploadjob_id='uploadjob_id',
                     chunk_size='chunk_size', volume_id='volume_id')
            result = self.backend.add_part_to_uploadjob(**d)

        self.assertEqual(result, {})

    def test_touch_uploadjob(self):
        """Delete an uploadjob."""
        mocker = Mocker()

        # upload job
        uj = mocker.mock()
        expect(uj.touch())
        expect(uj.when_last_active).result('when_last_active')

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(user.volume('volume_id')
               .get_uploadjob('uploadjob_id')).result(uj)

        with mocker:
            d = dict(user_id='user_id', uploadjob_id='uploadjob_id',
                     volume_id='volume_id')
            result = self.backend.touch_uploadjob(**d)

        self.assertEqual(result, dict(when_last_active='when_last_active'))

    def test_get_reusable_content(self):
        """Get reusable content."""
        mocker = Mocker()

        # user
        user = mocker.mock()
        self.backend._get_user = lambda *a: user
        expect(
            user.is_reusable_content('hash_value', 'magic_hash')).result(
                ('blob_exists', 'storage_key'))

        with mocker:
            result = self.backend.get_reusable_content(
                user_id='user_id', hash_value='hash_value',
                magic_hash='magic_hash')

        should = dict(blob_exists='blob_exists', storage_key='storage_key')
        self.assertEqual(result, should)
