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

"""Test the action queue's cleanup."""

import os

from magicicadaprotocol import request
from twisted.internet import reactor, defer

from magicicada.server.testing.aq_helpers import (
    NoCloseCustomIO,
    TestBase,
    anEmptyShareList,
    anUUID,
    failure_ignore,
    get_aq_params,
)

defer.setDebugging(True)


class TestCleanup(TestBase):
    """Test the different cleanup-related situations."""

    def tearDown(self):
        """unplug everything and go home"""
        self.eq.push('SYS_USER_DISCONNECT')
        return super(TestCleanup, self).tearDown()

    @defer.inlineCallbacks
    def test_cleanup_pre_make_file(self):
        """Queue a command before connected, and process it when connect."""
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        d = self.wait_for('SYS_QUEUE_DONE')
        file_path = os.path.join(self.main.root_dir, 'foo')
        mdid = self.main.fs.create(file_path, request.ROOT)
        self.aq.make_file('', self.root, 'foo', 'marker:foo', mdid)
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d
        self.assertInListenerEvents(
            'AQ_FILE_NEW_OK',
            {'marker': 'marker:foo', 'new_id': anUUID, 'new_generation': 1,
             'volume_id': request.ROOT})

    @defer.inlineCallbacks
    @failure_ignore('ALREADY_EXISTS')
    def test_make_file_cleanup(self):
        """Cleanup the make file.

        If the connection is closed in the middle of a make_file, we
        retry the make_file. If we get an ALREADY_EXISTS, we can't
        tell if it's the file we asked to be created (ie our request
        got through and we missed the answer) or if it was created by
        other means. ALREADY_EXISTS is the right answer for that
        case. The other case is that the request didn't get through,
        in which case we get AQ_FILE_NEW_OK as usual.
        """
        file_path = os.path.join(self.main.root_dir, 'foo')
        mdid = self.main.fs.create(file_path, request.ROOT)
        self.aq.make_file('', self.root, 'foo', 'marker:foo', mdid)
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        d = self.wait_for('SYS_QUEUE_DONE')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d
        yield self.wait_for_nirvana()

        events = []
        events.append(('AQ_FILE_NEW_ERROR', {'marker': 'marker:foo',
                                             'error': 'ALREADY_EXISTS'}))
        events.append(('AQ_FILE_NEW_OK', {'marker': 'marker:foo',
                                          'new_id': anUUID,
                                          'new_generation': 1,
                                          'volume_id': request.ROOT}))
        self.assertAnyInListenerEvents(events)

    @defer.inlineCallbacks
    @failure_ignore('ALREADY_EXISTS')
    def test_make_dir_cleanup(self):
        """Cleanup the make dir.

        See docstring for test_make_file_cleanup.
        """
        dir_path = os.path.join(self.main.root_dir, 'foo')
        mdid = self.main.fs.create(dir_path, request.ROOT)
        self.aq.make_dir('', self.root, 'foo', 'marker:foo', mdid)
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        d = self.wait_for('SYS_QUEUE_DONE')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d
        yield self.wait_for_nirvana()

        events = []
        events.append(('AQ_DIR_NEW_ERROR',
                       {'marker': 'marker:foo', 'error': 'ALREADY_EXISTS'}))
        events.append(('AQ_DIR_NEW_OK', {'marker': 'marker:foo',
                                         'new_id': anUUID,
                                         'new_generation': 1,
                                         'volume_id': request.ROOT}))
        self.assertAnyInListenerEvents(events)

    @defer.inlineCallbacks
    @failure_ignore('ALREADY_EXISTS', 'DOES_NOT_EXIST')
    def test_move(self):
        """Ditto ditto."""
        d = self.wait_for('SYS_QUEUE_DONE')
        dir_path = os.path.join(self.main.root_dir, 'foo')
        mdid = self.main.fs.create(dir_path, request.ROOT)
        self.aq.make_dir('', self.root, 'foo', 'marker:foo', mdid)

        yield d
        new_id = self.listener.get_id_for_marker('marker:foo')
        self.aq.move('', new_id, self.root, self.root, 'bar', 'f', 't')
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        d1 = self.wait_for('SYS_QUEUE_DONE')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d1
        yield self.wait_for_nirvana()
        events = [
            ('AQ_MOVE_ERROR',
             {'new_name': 'bar', 'share_id': '', 'old_parent_id': self.root,
              'new_parent_id': self.root, 'node_id': new_id,
              'error': 'ALREADY_EXISTS'}),
            ('AQ_MOVE_ERROR',
             {'new_name': 'bar', 'share_id': '', 'old_parent_id': self.root,
              'new_parent_id': self.root, 'node_id': new_id,
              'error': 'DOES_NOT_EXIST'}),
            ('AQ_MOVE_OK',
             {'share_id': '', 'node_id': new_id, 'new_generation': 2}),
        ]
        self.assertAnyInListenerEvents(events)

    @defer.inlineCallbacks
    @failure_ignore('DOES_NOT_EXIST')
    def test_unlink(self):
        """We should be able to unlink, no problem :)."""
        d = self.wait_for('SYS_QUEUE_DONE')
        dir_path = os.path.join(self.main.root_dir, 'foo')
        mdid = self.main.fs.create(dir_path, request.ROOT)
        self.aq.make_dir('', self.root, 'foo', 'marker:foo', mdid)

        yield d
        # Start the unlink, jigger the network."""
        new_id = self.listener.get_id_for_marker('marker:foo')
        self.aq.unlink('', self.root, new_id, '', False)
        d1 = self.wait_for('SYS_QUEUE_DONE')
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d1
        yield self.wait_for_nirvana()

        self.assertAnyInListenerEvents([
            ('AQ_UNLINK_OK',
             {'share_id': '', 'parent_id': self.root, 'node_id': new_id}),
            ('AQ_UNLINK_ERROR',
             {'share_id': '', 'parent_id': self.root, 'node_id': new_id,
              'error': 'DOES_NOT_EXIST'}),
        ])

    @defer.inlineCallbacks
    def test_list_shares(self):
        """And list_shares."""
        self.aq.list_shares()
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        d = self.wait_for('SYS_QUEUE_DONE')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d
        yield self.wait_for_nirvana()

        self.assertInListenerEvents(
            'AQ_SHARES_LIST', {'shares_list': anEmptyShareList})

    @defer.inlineCallbacks
    @failure_ignore('ALREADY_EXISTS')
    def test_create_share(self):
        """Create share..."""
        self.aq.create_share(self.root, u'jane', '', 'View', 'marker:x', '')
        d = self.wait_for('SYS_QUEUE_DONE')
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')

        yield d
        yield self.wait_for_nirvana()

        self.assertAnyInListenerEvents([
            ('AQ_CREATE_SHARE_ERROR',
                {'marker': 'marker:x', 'error': 'ALREADY_EXISTS'}),
            ('AQ_CREATE_SHARE_OK',
                {'marker': 'marker:x', 'share_id': anUUID}),
        ])

    @defer.inlineCallbacks
    def test_download(self):
        """Download."""
        result = yield self._mk_file_w_content('hola.txt')
        buf = NoCloseCustomIO()
        self.patch(self.main.fs, 'get_partial_for_writing', lambda s, n: buf)

        waiter = self.wait_for('SYS_QUEUE_DONE')
        self.aq.download(
            result['share_id'], result['node_id'], result['hash'],
            result['mdid'])
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        self.eq.push('SYS_NET_CONNECTED')
        yield waiter
        yield self.wait_for_nirvana(1)
        self.assertEvent(
            ('AQ_DOWNLOAD_COMMIT',
             {'share_id': result['share_id'], 'node_id': result['node_id'],
              'server_hash': result['hash']}))

    @defer.inlineCallbacks
    def test_upload(self):
        """Upload works! amazing."""
        mdid, node_id = yield self._mkfile('hola')
        params = get_aq_params()
        self.patch(self.main.fs, 'open_file', lambda mdid: params['fd'])

        # Start the upload, jigger the network
        waiter = self.wait_for('SYS_QUEUE_DONE')
        self.aq.upload(
            params['share_id'], node_id, params['previous_hash'],
            params['hash'], params['crc32'], params['size'], mdid)
        self.eq.push('SYS_NET_DISCONNECTED')
        self.eq.push('SYS_CONNECTION_LOST')
        reactor.callLater(0.2, self.eq.push, 'SYS_NET_CONNECTED')
        self.main.vm.update_free_space(request.ROOT, params['size'] * 2)
        yield waiter
        yield self.wait_for_nirvana(1)
        self.assertEvent(
            ('AQ_UPLOAD_FINISHED',
             {'share_id': params['share_id'], 'node_id': anUUID,
              'new_generation': 2, 'hash': params['hash']}))
