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

"""Tests for the DAL entry point."""

import uuid
from unittest import mock

from twisted.internet import defer

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
        """Bad parameters in the auth request."""
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
            AttributeError, self.backend.get_userid_from_token, bad_params
        )

    def test_auth_parameters_empty_dict(self):
        bad_params = dict()
        with self.assertRaises(backend.FailedAuthentication) as ctx:
            self.backend.get_userid_from_token(bad_params)
        self.assertEqual(str(ctx.exception), 'Bad parameters: {}')

    def test_unlink_node(self):
        """Unlink a node."""
        # node, with a generation attribute
        node = mock.Mock(
            generation=123, kind=StorageObject.FILE, mimetype='mime'
        )
        node.name = 'foo'
        # user, with the chained calls to the delete
        user = mock.Mock(name='user')
        user.volume.return_value.node.return_value.delete.return_value = node
        self.backend._get_user = lambda *a: user

        kwargs = dict(
            user_id='user_id',
            volume_id='vol_id',
            node_id='node_id',
            session_id='session_id',
        )
        result = self.backend.unlink_node(**kwargs)

        d = dict(
            generation=123,
            kind=StorageObject.FILE,
            name='foo',
            mimetype='mime',
        )
        self.assertEqual(result, d)
        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().node('node_id'),
            mock.call.volume().node().delete(),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_list_volumes_root_and_quota(self):
        """List volumes, check root and quota."""
        root = mock.Mock(generation=123, root_id='root_id')
        user = mock.Mock(free_bytes=4567890)
        self.backend._get_user = lambda *a: user
        user.volume().get_volume.return_value = root
        user.get_shared_to.return_value = []
        user.get_udfs.return_value = []

        result = self.backend.list_volumes('user_id')

        self.assertEqual(
            sorted(result), ['free_bytes', 'root', 'shares', 'udfs']
        )
        self.assertEqual(
            result['root'], dict(generation=123, root_id='root_id')
        )
        self.assertEqual(result['free_bytes'], 4567890)
        user.volume.return_value.get_volume.assert_called_once_with()
        user.get_shared_to.assert_called_once_with(accepted=True)
        user.get_udfs.assert_called_once_with()

    def test_list_volumes_shares(self):
        """List volumes, check shares."""
        # root and quota
        root = mock.Mock(generation=123, root_id='root_id')

        # one share
        sharedby1 = mock.Mock(
            username='byusername1', visible_name='byvisible1', free_bytes=147
        )
        share1 = mock.Mock(
            id='share1_id',
            root_id='share1_root_id',
            shared_by=sharedby1,
            accepted=True,
            access=1,
        )
        share1.name = 'name1'
        share1.get_generation.return_value = 6

        # other share
        sharedby2 = mock.Mock(
            username='byusername2', visible_name='byvisible2', free_bytes=852
        )
        share2 = mock.Mock(
            id='share2_id',
            root_id='share2_root_id',
            shared_by=sharedby2,
            accepted=False,
            access=0,
        )
        share2.name = 'name2'
        share2.get_generation.return_value = 8

        # user
        user = mock.Mock(free_bytes=4567890)
        user.volume.return_value.get_volume.return_value = root
        user.get_shared_to.return_value = [share1, share2]
        user.get_udfs.return_value = []
        self.backend._get_user = lambda *a: user

        result = self.backend.list_volumes('user_id')

        share1.get_generation.assert_called_once_with()
        share2.get_generation.assert_called_once_with()
        expected_calls = [
            mock.call.volume(),
            mock.call.volume().get_volume(),
            mock.call.get_shared_to(accepted=True),
            mock.call.get_udfs(),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

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
        # root and quota
        root = mock.Mock(generation=123, root_id='root_id')
        # one udf
        udf1 = mock.Mock(
            id='udf1_id', root_id='udf1_root_id', path='path1', generation=6
        )
        # other udf
        udf2 = mock.Mock(
            id='udf2_id', root_id='udf2_root_id', path='path2', generation=8
        )
        # user
        user = mock.Mock(free_bytes=4567890)
        user.volume.return_value.get_volume.return_value = root
        user.get_shared_to.return_value = []
        user.get_udfs.return_value = [udf1, udf2]
        self.backend._get_user = lambda *a: user

        result = self.backend.list_volumes('user_id')

        expected_calls = [
            mock.call.volume(),
            mock.call.volume().get_volume(),
            mock.call.get_shared_to(accepted=True),
            mock.call.get_udfs(),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

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
        # node, with a generation attribute
        node = mock.Mock(public_url='test public url')

        # user, with the chained calls to the action
        user = mock.Mock()
        node_getter = user.volume.return_value.node.return_value
        node_getter.change_public_access.return_value = node
        self.backend._get_user = lambda *a: user

        kwargs = dict(
            user_id='user_id',
            volume_id='vol_id',
            node_id='node_id',
            is_public=True,
            session_id='session_id',
        )
        result = self.backend.change_public_access(**kwargs)

        self.assertEqual(result, dict(public_url='test public url'))
        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().node('node_id'),
            mock.call.volume().node().change_public_access(True),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_list_public_files(self):
        """List public files."""
        # node 1
        content1 = mock.Mock(
            size='size1',
            crc32='crc321',
            deflated_size='deflated_size1',
            storage_key='storage_key1',
        )
        node1 = mock.Mock(
            id='node_id1',
            path='path1',
            vol_id='volume_id1',
            generation='generation1',
            is_public=True,
            parent_id='parent_id1',
            status=STATUS_LIVE,
            content_hash='content_hash1',
            kind=StorageObject.FILE,
            when_last_modified='last_modified1',
            public_url='public url 1',
            content=content1,
        )
        node1.name = 'name1'

        # node 2
        content2 = mock.Mock(
            size='size2',
            crc32='crc322',
            deflated_size='deflated_size2',
            storage_key='storage_key2',
        )
        node2 = mock.Mock(
            id='node_id2',
            path='path2',
            vol_id='volume_id2',
            generation='generation2',
            is_public=True,
            parent_id='parent_id2',
            status=STATUS_DEAD,
            content_hash='content_hash2',
            kind=StorageObject.DIRECTORY,
            when_last_modified='last_modified2',
            public_url='public url 2',
            content=content2,
        )
        node2.name = 'name2'

        # user
        user = mock.Mock()
        user.get_public_files.return_value = [node1, node2]
        self.backend._get_user = lambda *a: user

        result = self.backend.list_public_files(
            user_id='user_id',
        )
        node1, node2 = result['public_files']

        user.get_public_files.assert_called_once_with()
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
        # node, with a generation attribute
        node = mock.Mock(generation=123, mimetype='mime')

        # user, with the chained calls to the operation
        user = mock.Mock()
        new_parent_id = uuid.uuid4()
        user.volume.return_value.node.return_value.move.return_value = node
        self.backend._get_user = lambda *a: user

        kwargs = dict(
            user_id='user_id',
            volume_id='vol_id',
            node_id='node_id',
            new_parent_id=new_parent_id,
            new_name='new_name',
            session_id='session_id',
        )
        result = self.backend.move(**kwargs)

        self.assertEqual(result, dict(generation=123, mimetype='mime'))
        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().node('node_id'),
            mock.call.volume().node().move(new_parent_id, 'new_name'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_move_with_new_parent_id_as_str(self):
        """Ensure that DAO.move casts new_parent_id into a UUID if it's a str.

        This is necessary because StorageObject.move() only accepts UUIDs for
        new_parent_id.

        """
        node = mock.Mock(generation=123, mimetype='mime')
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        parent_id = uuid.uuid4()
        user.volume.return_value.node.return_value.move.return_value = node

        # Here we pass the new_parent_id as str but above we expect it to
        # be a UUID object.
        self.backend.move(
            'user_id',
            'vol_id',
            'node_id',
            str(parent_id),
            'new_name',
            'session_id',
        )

        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().node('node_id'),
            mock.call.volume().node().move(parent_id, 'new_name'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_make_dir(self):
        """Make a directory."""
        # node, with a generation attribute
        node = mock.Mock(id='node_id', generation=123, mimetype='mime')

        # user, with the chained calls to the operation
        user = mock.Mock()
        dir_getter = user.volume.return_value.dir.return_value
        dir_getter.make_subdirectory.return_value = node
        self.backend._get_user = lambda *a: user

        kwargs = dict(
            user_id='user_id',
            volume_id='vol_id',
            parent_id='parent_id',
            name='name',
            session_id='session_id',
        )
        result = self.backend.make_dir(**kwargs)

        d = dict(generation=123, node_id='node_id', mimetype='mime')
        self.assertEqual(result, d)
        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().dir('parent_id'),
            mock.call.volume().dir().make_subdirectory('name'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_make_file(self):
        """Make a file with no content."""
        # node, with a generation attribute
        node = mock.Mock(id='node_id', generation=123, mimetype='mime')

        # user, with the chained calls to the operation
        user = mock.Mock()
        user.volume.return_value.dir.return_value.make_file.return_value = node
        self.backend._get_user = lambda *a: user

        kwargs = dict(
            user_id='user_id',
            volume_id='vol_id',
            parent_id='parent_id',
            name='name',
            session_id='session_id',
        )
        result = self.backend.make_file(**kwargs)

        d = dict(generation=123, node_id='node_id', mimetype='mime')
        self.assertEqual(result, d)
        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().dir('parent_id'),
            mock.call.volume().dir().make_file('name'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_make_file_with_content(self):
        """Make a file with content associated."""
        # node, with a generation attribute
        node = mock.Mock(id='node_id', generation=123)

        # user, with the chained calls to the operation
        user = mock.Mock()
        dir_getter = user.volume.return_value.dir.return_value
        dir_getter.make_file_with_content.return_value = node
        self.backend._get_user = lambda *a: user

        kwargs = dict(
            user_id='user_id',
            volume_id='vol_id',
            name='name',
            parent_id='parent_id',
            crc32='crc32',
            size='size',
            node_hash='hash',
            deflated_size='deflated_size',
            storage_key='storage_key',
            session_id='session_id',
        )
        result = self.backend.make_file_with_content(**kwargs)

        self.assertEqual(result, dict(generation=123, node_id='node_id'))
        expected_calls = [
            mock.call.volume('vol_id'),
            mock.call.volume().dir('parent_id'),
            mock.call.volume()
            .dir()
            .make_file_with_content(
                'name', 'hash', 'crc32', 'size', 'deflated_size', 'storage_key'
            ),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_delete_share(self):
        """Delete a share."""
        # share
        share = mock.Mock()

        # user, with the chained calls to the operation
        user = mock.Mock()
        user.get_share.return_value = share
        self.backend._get_user = lambda *a: user

        result = self.backend.delete_share('user_id', 'share_id')

        self.assertEqual(result, {})
        share.delete.assert_called_once_with()
        user.get_share.assert_called_once_with('share_id')

    def test_create_share(self):
        """Create a share."""
        # patch the DAL method to get the other user id from the username
        to_user = mock.Mock(id='to_user_id')
        fake = mock.Mock(return_value=to_user)
        self.patch(backend.services, 'get_storage_user', fake)
        # share
        share = mock.Mock(id='share_id')
        # user, with the chained calls to the operation
        user = mock.Mock()
        user.volume.return_value.dir.return_value.share.return_value = share
        self.backend._get_user = lambda *a: user

        result = self.backend.create_share(
            'user_id', 'node_id', 'to_username', 'name', True
        )
        self.assertEqual(result, dict(share_id='share_id'))
        fake.assert_called_once_with(username='to_username')
        expected_calls = [
            mock.call.volume(),
            mock.call.volume().dir('node_id'),
            mock.call.volume().dir().share('to_user_id', 'name', True),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_accept_share(self):
        """Accept a share."""
        # share
        share = mock.Mock()
        # user, with the chained calls to the operation
        user = mock.Mock()
        user.get_share.return_value = share
        self.backend._get_user = lambda *a: user

        result = self.backend.accept_share('user_id', 'share_id')

        self.assertEqual(result, {})
        share.accept.assert_called_once_with()
        user.get_share.assert_called_once_with('share_id')

    def test_decline_share(self):
        """Decline a share."""
        # share
        share = mock.Mock()
        # user, with the chained calls to the operation
        user = mock.Mock()
        user.get_share.return_value = share
        self.backend._get_user = lambda *a: user

        result = self.backend.decline_share('user_id', 'share_id')

        self.assertEqual(result, {})
        share.decline.assert_called_once_with()
        user.get_share.assert_called_once_with('share_id')

    def test_list_shares_shared_by(self):
        """List shares, the shared_by part."""
        # one share
        sharedto1 = mock.Mock(
            username='tousername1', visible_name='tovisible1'
        )
        share1 = mock.Mock(
            id='share1_id',
            root_id='share1_root_id',
            shared_to=sharedto1,
            accepted=True,
            access=1,
        )
        share1.name = 'name1'
        # other share, without shared_to
        share2 = mock.Mock(
            id='share2_id',
            root_id='share2_root_id',
            shared_to=None,
            accepted=False,
            access=0,
        )
        share2.name = 'name2'
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.get_shared_by.return_value = [share1, share2]
        user.get_shared_to.return_value = []

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
        expected_calls = [
            mock.call.get_shared_by(),
            mock.call.get_shared_to(accepted=True),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_list_shares_shared_to(self):
        """List shares, the shared_to part."""
        # one share
        sharedby1 = mock.Mock(
            username='byusername1', visible_name='byvisible1'
        )
        share1 = mock.Mock(
            id='share1_id',
            root_id='share1_root_id',
            name='name1',
            shared_by=sharedby1,
            accepted=True,
            access=1,
        )
        share1.name = 'name1'
        # other share, without shared_by
        share2 = mock.Mock(
            id='share2_id',
            root_id='share2_root_id',
            name='name2',
            shared_by=None,
            accepted=False,
            access=0,
        )
        share2.name = 'name2'

        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.get_shared_by.return_value = []
        user.get_shared_to.return_value = [share1, share2]

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
        expected_calls = [
            mock.call.get_shared_by(),
            mock.call.get_shared_to(accepted=False),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_create_udf(self):
        """Create an UDF."""
        udf = mock.Mock(id='udf_id', root_id='udf_root_id', path='udf_path')
        # user, with the chained calls to the operation
        user = mock.Mock()
        user.make_udf.return_value = udf
        self.backend._get_user = lambda *a: user

        result = self.backend.create_udf('user_id', 'path', 'session_id')
        should = dict(
            udf_id='udf_id', udf_root_id='udf_root_id', udf_path='udf_path'
        )
        self.assertEqual(result, should)
        user.make_udf.assert_called_once_with('path')

    def test_delete_volume_share(self):
        """Delete a volume that was a share."""
        # share
        share = mock.Mock()
        # user, getting a share when asked
        user = mock.Mock()
        user.get_share.return_value = share
        self.backend._get_user = lambda *a: user

        result = self.backend.delete_volume(
            'user_id', 'volume_id', 'session_id'
        )

        self.assertEqual(result, {})
        share.delete.assert_called_once_with()
        user.get_share.assert_called_once_with('volume_id')

    def test_delete_volume_udf(self):
        """Delete a volume that was a udf."""
        # user, with an error when asking for the share, and the udf deletion
        user = mock.Mock()
        user.get_share.side_effect = errors.DoesNotExist('foo')
        self.backend._get_user = lambda *a: user

        result = self.backend.delete_volume(
            'user_id', 'volume_id', 'session_id'
        )

        self.assertEqual(result, {})
        user.get_share.assert_called_once_with('volume_id')
        user.delete_udf.assert_called_once_with('volume_id')

    def test_delete_volume_none(self):
        """Delete a volume that was not there."""
        # user, with an exception when asking for the share, and
        # the udf deletion
        user = mock.Mock()
        volume_id = 'the_volume_id'
        user.get_share.side_effect = errors.DoesNotExist('foo')
        user.delete_udf.side_effect = errors.DoesNotExist('bar')
        self.backend._get_user = lambda *a: user

        with self.assertRaises(errors.DoesNotExist) as ctx:
            self.backend.delete_volume('user_id', volume_id, 'session_id')

        self.assertIn(
            "Volume %r does not exist" % volume_id, str(ctx.exception)
        )
        user.get_share.assert_called_once_with(volume_id)
        user.delete_udf.assert_called_once_with(volume_id)

    def test_get_user_quota(self):
        """Return the quota info for an user."""
        # the user
        user = mock.Mock(
            max_storage_bytes=100, used_storage_bytes=80, free_bytes=20
        )
        self.backend._get_user = lambda *a: user

        result = self.backend.get_user_quota('user_id')

        should = dict(
            max_storage_bytes=100, used_storage_bytes=80, free_bytes=20
        )
        self.assertEqual(result, should)

    def test_get_share(self):
        """Get a share."""
        # the share
        share = mock.Mock(
            id='share_id',
            root_id='share_root_id',
            shared_by_id='shared_by_id',
            shared_to_id='shared_to_id',
            accepted=True,
            access=1,
        )
        share.name = 'name'
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.get_share.return_value = share

        result = self.backend.get_share('user_id', 'share_id')

        should = dict(
            share_id='share_id',
            share_root_id='share_root_id',
            name='name',
            shared_by_id='shared_by_id',
            accepted=True,
            shared_to_id='shared_to_id',
            access=1,
        )
        self.assertEqual(result, should)
        user.get_share.assert_called_once_with('share_id')

    def test_get_root(self):
        """Get the root id for an user."""
        # the root node
        node = mock.Mock(id='root_id', generation=123)
        node.load.return_value = node

        # user
        user = mock.Mock(root=node)
        self.backend._get_user = lambda *a: user

        result = self.backend.get_root('user_id')

        self.assertEqual(result, dict(root_id='root_id', generation=123))
        node.load.assert_called_once_with()

    def test_get_node_ok(self):
        """Get a node."""
        # node
        content = mock.Mock(
            size='size',
            crc32='crc32',
            deflated_size='deflated_size',
            storage_key='storage_key',
        )
        node = mock.Mock(
            id='node_id',
            path='path',
            name='name',
            vol_id='volume_id',
            parent_id='parent_id',
            status=STATUS_LIVE,
            generation='generation',
            is_public=False,
            content_hash='content_hash',
            public_url=None,
            kind=StorageObject.FILE,
            when_last_modified='last_modified',
            content=content,
        )
        node.name = 'name'

        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.volume.return_value.get_node.return_value = node

        result = self.backend.get_node(
            user_id='user_id', node_id='node_id', volume_id='volume_id'
        )

        should = dict(
            id='node_id',
            name='name',
            parent_id='parent_id',
            is_public=False,
            is_live=True,
            is_file=True,
            size='size',
            last_modified='last_modified',
            crc32='crc32',
            generation='generation',
            content_hash='content_hash',
            deflated_size='deflated_size',
            storage_key='storage_key',
            volume_id='volume_id',
            path='path',
            has_content=True,
            public_url=None,
        )
        self.assertEqual(result, should)
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_node('node_id', with_content=True),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_get_node_no_content(self):
        """Get a node that has no content."""
        # node
        node = mock.Mock(
            id='node_id',
            path='path',
            name='name',
            vol_id='volume_id',
            parent_id='parent_id',
            status=STATUS_LIVE,
            generation='generation',
            is_public=False,
            content_hash='content_hash',
            kind=StorageObject.FILE,
            when_last_modified='last_modified',
            content=None,
            public_url=None,
        )
        node.name = 'name'

        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.volume.return_value.get_node.return_value = node

        result = self.backend.get_node(
            user_id='user_id', node_id='node_id', volume_id='volume_id'
        )

        should = dict(
            id='node_id',
            name='name',
            parent_id='parent_id',
            is_public=False,
            is_live=True,
            is_file=True,
            size=None,
            last_modified='last_modified',
            crc32=None,
            generation='generation',
            content_hash='content_hash',
            deflated_size=None,
            storage_key=None,
            public_url=None,
            volume_id='volume_id',
            path="path",
            has_content=False,
        )
        self.assertEqual(result, should)
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_node('node_id', with_content=True),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_get_node_from_user(self):
        """Get a node just giving the user."""
        # node
        node = mock.Mock(
            id='node_id',
            path='path',
            name='name',
            vol_id='volume_id',
            parent_id='parent_id',
            status=STATUS_LIVE,
            generation='generation',
            is_public=False,
            content_hash='content_hash',
            public_url=None,
            kind=StorageObject.FILE,
            when_last_modified='last_modified',
            content=None,
        )
        node.name = 'name'
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user

        # patch the DAL to return the node
        fake = mock.Mock(return_value=node)
        self.patch(backend.services, 'get_node', fake)

        result = self.backend.get_node_from_user(
            user_id='user_id', node_id='node_id'
        )

        should = dict(
            id='node_id',
            name='name',
            parent_id='parent_id',
            is_public=False,
            is_live=True,
            is_file=True,
            size=None,
            last_modified='last_modified',
            crc32=None,
            generation='generation',
            content_hash='content_hash',
            deflated_size=None,
            storage_key=None,
            public_url=None,
            volume_id='volume_id',
            path='path',
            has_content=False,
        )
        self.assertEqual(result, should)
        fake.assert_called_once_with('node_id')

    def test_get_delta_and_from_scratch(self):
        """Get normal delta and from scratch."""
        # node 1
        content1 = mock.Mock(
            size='size1',
            crc32='crc321',
            deflated_size='deflated_size1',
            storage_key='storage_key1',
        )
        node1 = mock.Mock(
            id='node_id1',
            path='path1',
            name='name1',
            vol_id='volume_id1',
            generation='generation1',
            is_public=True,
            parent_id='parent_id1',
            status=STATUS_LIVE,
            content_hash='content_hash1',
            kind=StorageObject.FILE,
            when_last_modified='last_modified1',
            content=content1,
            public_url='public url',
        )
        node1.name = 'name1'

        # node 2
        content2 = mock.Mock(
            size='size2',
            crc32='crc322',
            deflated_size='deflated_size2',
            storage_key='storage_key2',
        )
        node2 = mock.Mock(
            id='node_id2',
            path='path2',
            name='name2',
            vol_id='volume_id2',
            generation='generation2',
            is_public=False,
            parent_id='parent_id2',
            status=STATUS_DEAD,
            content_hash='content_hash2',
            kind=StorageObject.DIRECTORY,
            when_last_modified='last_modified2',
            content=content2,
            public_url=None,
        )
        node2.name = 'name2'

        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.volume.return_value.get_delta.return_value = (
            'vol_generation',
            'free_bytes',
            [node1, node2],
        )
        user.volume.return_value.get_from_scratch.return_value = (
            'vol_generation',
            'free_bytes',
            [node1, node2],
        )

        result1 = self.backend.get_delta(
            user_id='user_id',
            volume_id='volume_id',
            from_generation='from_gen',
            limit='limit',
        )
        result2 = self.backend.get_from_scratch(
            user_id='user_id', volume_id='volume_id'
        )

        self.assertEqual(result1, result2)
        self.assertEqual(result1['vol_generation'], 'vol_generation')
        self.assertEqual(result1['free_bytes'], 'free_bytes')
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_delta('from_gen', limit='limit'),
            mock.call.volume('volume_id'),
            mock.call.volume().get_from_scratch(
                start_from_path=None, limit=None, max_generation=None
            ),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

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
        # user
        user = mock.Mock(
            root_volume_id='root_volume_id',
            username='username',
            visible_name='visible_name',
        )
        self.backend._get_user = lambda *a: user

        result = self.backend.get_user_data(
            user_id='user_id', session_id='session_id'
        )

        should = dict(
            root_volume_id='root_volume_id',
            username='username',
            visible_name='visible_name',
        )
        self.assertEqual(result, should)

    def test_get_volume_id_normal(self):
        """Get the volume_id, normal case."""
        # node
        node = mock.Mock(volume_id='volume_id')
        # user
        user = mock.Mock(root_volume_id='root_volume_id')
        user.volume.return_value.get_node.return_value = node
        self.backend._get_user = lambda *a: user

        result = self.backend.get_volume_id(
            user_id='user_id', node_id='node_id'
        )

        self.assertEqual(result, dict(volume_id='volume_id'))
        expected_calls = [
            mock.call.volume(),
            mock.call.volume().get_node('node_id'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_get_volume_id_same_root(self):
        """Get the volume_id, special case where the subtree node is root."""
        # node
        node = mock.Mock(volume_id='root_volume_id')
        # user
        user = mock.Mock(root_volume_id='root_volume_id')
        user.volume.return_value.get_node.return_value = node
        self.backend._get_user = lambda *a: user

        result = self.backend.get_volume_id(
            user_id='user_id', node_id='node_id'
        )

        self.assertEqual(result, dict(volume_id=None))
        expected_calls = [
            mock.call.volume(),
            mock.call.volume().get_node('node_id'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_make_content(self):
        """Make content."""
        # node 'old gen'
        node = mock.Mock(generation='new_generation')
        # user
        user = mock.Mock()
        user.volume.return_value.get_node.return_value = node
        self.backend._get_user = lambda *a: user

        d = dict(
            user_id='user_id',
            volume_id='volume_id',
            node_id='node_id',
            original_hash='original_hash',
            hash_hint='hash_hint',
            crc32_hint='crc32_hint',
            inflated_size_hint='inflated_size_hint',
            deflated_size_hint='deflated_size_hint',
            storage_key='storage_key',
            magic_hash='magic_hash',
            session_id=None,
        )
        result = self.backend.make_content(**d)

        self.assertEqual(result, dict(generation='new_generation'))
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_node('node_id'),
            mock.call.volume()
            .get_node()
            .make_content(
                'original_hash',
                'hash_hint',
                'crc32_hint',
                'inflated_size_hint',
                'deflated_size_hint',
                'storage_key',
                'magic_hash',
            ),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_get_upload_job(self):
        """Get an upload_job."""
        # upload job
        uj = mock.Mock(
            id='uj_id',
            uploaded_bytes='uploaded_bytes',
            multipart_key='multipart_key',
            chunk_count='chunk_count',
            when_last_active='when_last_active',
        )

        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        node_getter = user.volume.return_value.get_node.return_value
        node_getter.get_multipart_uploadjob.return_value = uj

        d = dict(
            user_id='user_id',
            volume_id='volume_id',
            node_id='node_id',
            uploadjob_id='uploadjob_id',
            hash_value='hash_value',
            crc32='crc32',
        )
        result = self.backend.get_uploadjob(**d)

        should = dict(
            uploadjob_id='uj_id',
            uploaded_bytes='uploaded_bytes',
            multipart_key='multipart_key',
            chunk_count='chunk_count',
            when_last_active='when_last_active',
        )
        self.assertEqual(result, should)
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_node('node_id'),
            mock.call.volume()
            .get_node()
            .get_multipart_uploadjob('uploadjob_id', 'hash_value', 'crc32'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_make_upload_job(self):
        """Make an upload_job."""
        # upload job
        uj = mock.Mock(
            id='uj_id',
            uploaded_bytes='uploaded_bytes',
            multipart_key='multipart_key',
            chunk_count='chunk_count',
            when_last_active='when_last_active',
        )

        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        node_getter = user.volume.return_value.get_node.return_value
        node_getter.make_uploadjob.return_value = uj

        d = dict(
            user_id='user_id',
            volume_id='volume_id',
            node_id='node_id',
            previous_hash='previous_hash',
            hash_value='hash_value',
            crc32='crc32',
            inflated_size='inflated_size',
            multipart_key='multipart_key',
        )
        result = self.backend.make_uploadjob(**d)

        should = dict(
            uploadjob_id='uj_id',
            uploaded_bytes='uploaded_bytes',
            multipart_key='multipart_key',
            chunk_count='chunk_count',
            when_last_active='when_last_active',
        )
        self.assertEqual(result, should)
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_node('node_id'),
            mock.call.volume()
            .get_node()
            .make_uploadjob(
                'previous_hash',
                'hash_value',
                'crc32',
                'inflated_size',
                multipart_key='multipart_key',
            ),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_delete_uploadjob(self):
        """Delete an uploadjob."""
        # upload job
        uj = mock.Mock()
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.volume.return_value.get_uploadjob.return_value = uj

        d = dict(
            user_id='user_id',
            uploadjob_id='uploadjob_id',
            volume_id='volume_id',
        )
        result = self.backend.delete_uploadjob(**d)

        self.assertEqual(result, {})
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_uploadjob('uploadjob_id'),
            mock.call.volume().get_uploadjob().delete(),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_add_part_to_uploadjob(self):
        """Delete an uploadjob."""
        # upload job
        uj = mock.Mock()
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.volume.return_value.get_uploadjob.return_value = uj

        d = dict(
            user_id='user_id',
            uploadjob_id='uploadjob_id',
            chunk_size='chunk_size',
            volume_id='volume_id',
        )
        result = self.backend.add_part_to_uploadjob(**d)

        self.assertEqual(result, {})
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_uploadjob('uploadjob_id'),
            mock.call.volume().get_uploadjob().add_part('chunk_size'),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_touch_uploadjob(self):
        """Delete an uploadjob."""
        # upload job
        uj = mock.Mock(when_last_active='when_last_active')
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.volume.return_value.get_uploadjob.return_value = uj

        d = dict(
            user_id='user_id',
            uploadjob_id='uploadjob_id',
            volume_id='volume_id',
        )
        result = self.backend.touch_uploadjob(**d)

        self.assertEqual(result, dict(when_last_active='when_last_active'))
        expected_calls = [
            mock.call.volume('volume_id'),
            mock.call.volume().get_uploadjob('uploadjob_id'),
            mock.call.volume().get_uploadjob().touch(),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    def test_get_reusable_content(self):
        """Get reusable content."""
        # user
        user = mock.Mock()
        self.backend._get_user = lambda *a: user
        user.is_reusable_content.return_value = ('blob_exists', 'storage_key')

        result = self.backend.get_reusable_content(
            user_id='user_id', hash_value='hash_value', magic_hash='magic_hash'
        )

        should = dict(blob_exists='blob_exists', storage_key='storage_key')
        self.assertEqual(result, should)
        user.is_reusable_content.assert_called_once_with(
            'hash_value', 'magic_hash'
        )
