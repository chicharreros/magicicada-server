# -*- coding: utf-8 -*-

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

"""Test the action queue."""

import StringIO
import os
import uuid

from magicicadaclient.syncdaemon.states import (
    StateManager, QueueManager, ConnectionManager)
from magicicadaclient.syncdaemon import action_queue
from magicicadaclient.syncdaemon.action_queue import (
    ActionQueue,
    Download,
    Upload,
)
from magicicadaclient.syncdaemon.marker import MDMarker as Marker
from magicicadaprotocol import request
from magicicadaprotocol.client import StorageClient
from twisted.internet import defer, reactor

from magicicada.server.testing.aq_helpers import (
    FakeFailure,
    NoCloseCustomIO,
    TestBase,
    TestWithDatabase,
    aShareInfo,
    aShareUUID,
    anEmptyShareList,
    anUUID,
    failure_expected,
    get_aq_params,
)

LETTERS = 'abcdefghijklmnopqrstuvwxyz'
PROTOCOL = ActionQueue.protocol


class TestBasic(TestWithDatabase):
    """Basic connection tests."""
    client = None

    def tearDown(self):
        """Tear down."""
        self.aq.disconnect()
        return super(TestBasic, self).tearDown()

    @defer.inlineCallbacks
    def test_connect(self):
        """Try to connect."""
        connected = self.wait_for('SYS_CONNECTION_MADE')
        self.eq.push('SYS_INIT_DONE')
        self.eq.push('SYS_LOCAL_RESCAN_DONE')
        self.eq.push('SYS_USER_CONNECT',
                     access_token=self.access_tokens['jack'])
        self.eq.push('SYS_NET_CONNECTED')
        yield connected

    @failure_expected('UNSUPPORTED_VERSION')
    @defer.inlineCallbacks
    def test_connect_bad_version(self):
        """Try to connect with the wrong protocol version"""
        bad_version_happened = self.wait_for('SYS_PROTOCOL_VERSION_ERROR')

        class FakeAQProtocol(PROTOCOL):
            """An ActionQueue's protocol with a bad PROTOCOL_VERSION."""
            PROTOCOL_VERSION = -1

        self.aq.protocol = FakeAQProtocol
        self.eq.push('SYS_INIT_DONE')
        self.eq.push('SYS_LOCAL_RESCAN_DONE')
        self.eq.push('SYS_USER_CONNECT',
                     access_token=self.access_tokens['jack'])
        self.eq.push('SYS_NET_CONNECTED')

        # will continue and finish ok only if couldn't get to the server
        # because of bad version
        yield bad_version_happened


class TestMeta(TestBase):
    """Test things described in IMetaQueue."""

    @defer.inlineCallbacks
    def test_make_file(self):
        """Test we can make files."""
        yield self._mkfile('hola')
        self.assertInListenerEvents(
            'AQ_FILE_NEW_OK',
            {'marker': anUUID, 'new_id': anUUID, 'new_generation': 1,
             'volume_id': ''})

    @defer.inlineCallbacks
    def test_make_file_double(self):
        """Test that when we can make a double mkfile."""
        yield self._mkfile('hola')
        yield self._mkfile('hola', default_id=None)
        self.assertInListenerEvents(
            'AQ_FILE_NEW_OK',
            {'marker': anUUID, 'new_id': anUUID, 'new_generation': 1,
             'volume_id': ''})

    @defer.inlineCallbacks
    def test_make_file_kwargs(self):
        """Test we can make files using keyword arguments."""
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        parent_path = self.main.fs.get_by_node_id(request.ROOT, self.root).path
        mdid = self.main.fs.create(os.path.join(parent_path, u"test"),
                                   request.ROOT)
        self.aq.make_file(share_id=request.ROOT, parent_id=self.root,
                          name='hola', marker='marker:xyzzy', mdid=mdid)
        yield wait_for_queue_done
        self.assertInListenerEvents(
            'AQ_FILE_NEW_OK',
            {'marker': 'marker:xyzzy', 'new_id': anUUID, 'new_generation': 1,
             'volume_id': ''})

    @defer.inlineCallbacks
    def test_make_dir(self):
        """Test we can make directories."""
        yield self._mkdir('hola')
        self.assertInListenerEvents(
            'AQ_DIR_NEW_OK',
            {'marker': anUUID, 'new_id': anUUID, 'new_generation': 1,
             'volume_id': ''})

    @defer.inlineCallbacks
    def test_make_dir_again(self):
        """Test that when we can make directories, we're told nicely."""
        yield self._mkdir('hola')
        yield self._mkdir('hola', default_id=None)
        self.assertInListenerEvents(
            'AQ_DIR_NEW_OK',
            {'marker': anUUID, 'new_id': anUUID, 'new_generation': 1,
             'volume_id': ''})
        self.assertInListenerEvents(
            'AQ_DIR_NEW_OK',
            {'marker': anUUID, 'new_id': anUUID, 'new_generation': 1,
             'volume_id': ''})

    @defer.inlineCallbacks
    def test_move_simple(self):
        """Test that we can move files around."""
        _, dir_id = yield self._mkdir('un_dir')
        _, file_id = yield self._mkfile('hola')
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        self.aq.move(request.ROOT, file_id, self.root, dir_id,
                     'chau', 'f', 't')
        yield wait_for_queue_done
        self.assertInListenerEvents(
            'AQ_MOVE_OK',
            {'share_id': aShareUUID, 'node_id': anUUID, 'new_generation': 3})

    @defer.inlineCallbacks
    def test_node_is_with_queued_move__move(self):
        """Test the node_is_with_queued_move function in a move situation."""
        _, dir_id = yield self._mkdir('un_dir')
        _, file_id = yield self._mkfile('hola')

        # do and check
        waiter = self.wait_for('SYS_QUEUE_DONE')
        self.aq.move(request.ROOT, file_id, self.root,
                     dir_id, 'chau', 'f', 't')
        self.assertTrue(self.aq.node_is_with_queued_move("", file_id))
        self.assertFalse(self.aq.node_is_with_queued_move("", "other_id"))

        # final check, see all is gone
        yield waiter
        self.assertFalse(self.aq.node_is_with_queued_move("", file_id))
        self.assertFalse(self.aq.node_is_with_queued_move("", "other_id"))

    @defer.inlineCallbacks
    def test_node_is_with_queued_move__non_move(self):
        """Test the node_is_with_queued_move function in a non move op."""
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        yield self._mkdir('un_dir')
        _, file_id = yield self._mkfile('hola')

        # make the operation (not a move) and check
        self.aq.unlink(request.ROOT, self.root, file_id, '', False)
        self.assertFalse(self.aq.node_is_with_queued_move("", file_id))
        self.assertFalse(self.aq.node_is_with_queued_move("", "other_id"))
        yield wait_for_queue_done

    @defer.inlineCallbacks
    def test_node_is_with_queued_move__mixed(self):
        """Test the node_is_with_queued_move function in a mixed situation."""
        _, dir_id = yield self._mkdir('un_dir')
        _, file_id = yield self._mkfile('hola')

        # do and check
        waiter = self.wait_for('SYS_QUEUE_DONE')
        self.aq.list_shares()
        self.aq.move(request.ROOT, file_id, self.root,
                     dir_id, 'chau', 'f', 't')
        self.assertTrue(self.aq.node_is_with_queued_move("", file_id))
        self.assertFalse(self.aq.node_is_with_queued_move("", "other_id"))

        # final check, see all is gone
        yield waiter
        self.assertFalse(self.aq.node_is_with_queued_move("", file_id))
        self.assertFalse(self.aq.node_is_with_queued_move("", "other_id"))

    @failure_expected('DOES_NOT_EXIST')
    @defer.inlineCallbacks
    def test_move_fails(self):
        """Test that we can't move files around, we're told so nicely."""
        yield self._mkdir('un_dir')
        yield self._mkfile('hola')
        other_node_id = str(uuid.uuid4())
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        self.aq.move(request.ROOT, other_node_id, self.root, self.root,
                     'hola', 'f', 't')
        yield wait_for_queue_done
        self.assertInListenerEvents(
            'AQ_MOVE_ERROR',
            {'error': 'DOES_NOT_EXIST', 'share_id': request.ROOT,
             'node_id': other_node_id, 'old_parent_id': self.root,
             'new_parent_id': self.root, 'new_name': 'hola'})

    @defer.inlineCallbacks
    def test_unlink_ok(self):
        """Test that we can unlink files."""
        _, file_id = yield self._mkfile('hola')
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        self.aq.unlink(request.ROOT, self.root, file_id, '', False)
        yield wait_for_queue_done
        self.assertInListenerEvents(
            'AQ_UNLINK_OK',
            {'share_id': aShareUUID, 'node_id': anUUID, 'parent_id': self.root,
             'was_dir': False, 'old_path': '', 'new_generation': 2})

    @defer.inlineCallbacks
    @failure_expected('DOES_NOT_EXIST')
    def test_unlink_fails(self):
        """Test that we can't unlink files, we're told so nicely."""
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        self.aq.unlink(request.ROOT, self.root, str(uuid.uuid4()), '', False)
        yield wait_for_queue_done
        self.assertInListenerEvents(
            'AQ_UNLINK_ERROR',
            {'share_id': aShareUUID, 'node_id': anUUID,
             'error': 'DOES_NOT_EXIST', 'parent_id': self.root})

    def test_multi_mk(self):
        """Make some files, and test that they are created in order."""
        dl = []
        parent_path = self.main.fs.get_by_node_id(request.ROOT, self.root).path
        for letter in LETTERS:
            new_path = os.path.join(parent_path, u'hola_' + letter)
            mdid = self.main.fs.create(new_path, request.ROOT)
            marker = 'marker:' + letter
            self.aq.make_file(request.ROOT, self.root,
                              u'hola_' + letter, marker, mdid)
            dl.append(self.wait_for('AQ_FILE_NEW_OK', marker=marker))
        d = defer.DeferredList(dl)

        def check(_):
            """Actually do the check."""
            evs = [kw['marker'][7:] for (ev, kw) in self.listener.q
                   if ev == 'AQ_FILE_NEW_OK']
            # check that the makes arrived in order:
            self.assertEqual(''.join(evs), LETTERS)
        d.addCallback(check)
        return d


class TestNonAscii(TestBase):
    """Test non-ascii handling."""

    @defer.inlineCallbacks
    def test_mkfile_ok(self):
        """Test that AQ correctly handles UTF-8 in mkfile."""
        yield self._mkfile('mo\xc3\xb1o')
        wait_for_rescan = self.wait_for('AQ_RESCAN_FROM_SCRATCH_OK',
                                        volume_id=request.ROOT)
        yield self.aq.rescan_from_scratch(request.ROOT)
        yield wait_for_rescan
        res = self.listener.get_rescan_from_scratch_for(request.ROOT)
        self.assertIn(u"moño", [dt.name for dt in res['delta_content']])

    @defer.inlineCallbacks
    def test_mkdir_ok(self):
        """Test that AQ correctly handles UTF-8 in mkdir."""
        yield self._mkdir('cami\xc3\xb3n')
        wait_for_rescan = self.wait_for('AQ_RESCAN_FROM_SCRATCH_OK',
                                        volume_id=request.ROOT)
        yield self.aq.rescan_from_scratch(request.ROOT)
        yield wait_for_rescan
        res = self.listener.get_rescan_from_scratch_for(request.ROOT)
        self.assertIn(u"camión", [dt.name for dt in res['delta_content']])


class TestDeferredMeta(TestBase):
    """Test that you can create children without really knowing the parent.

    Sounds creepy, huh.
    """
    def test_make_file_in_unknown_dir(self):
        """Test we can make files in directories we don't know."""
        # create a dir
        dir_path = os.path.join(self.main.root_dir, 'testdir')
        mdid = self.main.fs.create(dir_path, request.ROOT)
        dir_marker = Marker(mdid)
        self.aq.make_dir(request.ROOT, self.root, 'testdir', dir_marker, mdid)

        # create a file without really knowing the parent
        file_path = os.path.join(dir_path, 'testfile')
        mdid = self.main.fs.create(file_path, request.ROOT)
        file_marker = Marker(mdid)
        file_deferred = self.wait_for('AQ_FILE_NEW_OK', marker=file_marker)
        self.aq.make_file(request.ROOT, dir_marker,
                          'testfile', file_marker, mdid)

        return file_deferred

    def test_make_lots(self):
        """Test we can make lots of them."""
        # start with root
        dir_path = self.main.root_dir
        parent_id = self.root

        for letter in LETTERS:
            # create a dir, always inside the previous one
            new_dir_path = os.path.join(dir_path, letter)
            mdid = self.main.fs.create(new_dir_path, request.ROOT)
            new_dir_marker = Marker(mdid)
            self.aq.make_dir(request.ROOT, parent_id,
                             letter, new_dir_marker, mdid)
            dir_path = new_dir_path
            parent_id = new_dir_marker

        # returning the last deferred is enough because it isn't fired
        # until all the others are.
        return self.wait_for('AQ_DIR_NEW_OK', marker=new_dir_marker)

    @defer.inlineCallbacks
    @failure_expected('NOT_A_DIRECTORY')
    def test_failure(self):
        """Test we get failures."""
        # create a file
        file_path = os.path.join(self.main.root_dir, 'testfile')
        mdid = self.main.fs.create(file_path, request.ROOT)
        file_marker = Marker(mdid)
        self.aq.make_file(request.ROOT, self.root,
                          'testdir', file_marker, mdid)

        # try to create other file inside it
        inside_file_path = os.path.join(file_path, 'inside_testfile')
        mdid = self.main.fs.create(inside_file_path, request.ROOT)
        inside_file_marker = Marker(mdid)
        inside_file_deferred = self.wait_for('AQ_FILE_NEW_ERROR',
                                             marker=inside_file_marker)
        self.aq.make_file(request.ROOT, file_marker, 'inside_testfile',
                          inside_file_marker, mdid)
        yield inside_file_deferred

        self.assertInListenerEvents(
            'AQ_FILE_NEW_ERROR',
            {'marker': inside_file_marker,
             'failure': FakeFailure('NOT_A_DIRECTORY')})

    @defer.inlineCallbacks
    @failure_expected('NOT_A_DIRECTORY')
    def test_fail_many(self):
        """Test we get many failures."""
        # start with root
        path = self.main.root_dir
        parent_id = self.root

        dl = []
        ml = []
        for letter in LETTERS:
            # create files, always inside the previous one
            new_file_path = os.path.join(path, letter)
            mdid = self.main.fs.create(new_file_path, request.ROOT)
            m = Marker(mdid)
            ml.append(m)
            self.aq.make_file(request.ROOT, parent_id, letter, m, mdid)
            dl.append(self.wait_for('AQ_FILE_NEW_OK', 'AQ_FILE_NEW_ERROR',
                                    marker=m))
            path = new_file_path
            parent_id = m

        yield defer.DeferredList(dl)
        for m in ml[1:]:
            self.assertInListenerEvents(
                'AQ_FILE_NEW_ERROR',
                {'marker': m, 'failure': FakeFailure('NOT_A_DIRECTORY')})


class TestContent(TestBase):
    """Test things described in IContentQueue."""

    @defer.inlineCallbacks
    def test_upload(self):
        """Test we can upload stuff."""
        buf = NoCloseCustomIO()
        self.patch(self.main.fs, 'get_partial_for_writing', lambda s, n: buf)

        result = yield self._mk_file_w_content()
        yield self.aq.download(
            result['share_id'], result['node_id'], result['hash'],
            result['mdid'])
        yield self.wait_for_nirvana()
        self.assertEqual(buf.getvalue(), result['data'])

        self.assertEvent(
            ('AQ_UPLOAD_FINISHED',
             {'share_id': result['share_id'], 'node_id': result['node_id'],
              'hash': result['hash'], 'new_generation': 2}))

    @defer.inlineCallbacks
    def test_upload_several(self):
        """Test we can upload several stuff."""
        for i in range(8):
            filename = 'hola_%d' % i
            result = yield self._mk_file_w_content(filename)
            # download it
            buf = NoCloseCustomIO()
            self.patch(self.main.fs, 'get_partial_for_writing',
                       lambda s, n: buf)
            yield self.aq.download(
                result['share_id'], result['node_id'], result['hash'],
                result['mdid'])
            yield self.wait_for_nirvana()
            self.assertEqual(buf.getvalue(), result['data'])

    @defer.inlineCallbacks
    def test_uploading(self):
        """Test the uploading attribute is set correctly."""
        outer_self = self
        commands = []

        class MyTempFile(object):
            """A temporary file that keep some stats.

            While read is called, checks that the right info is in the command.
            """
            def __init__(self):
                self.name = 'dummy-will-be-ignored'
                self.tempfile = StringIO.StringIO()
                commands.append([x for x in outer_self.aq.queue.waiting
                                 if isinstance(x, Upload)][0])
                self.all_read = 0

            def read(self, size=None):
                """Do the check, proxy the read."""
                data = self.tempfile.read(size)
                self.all_read += len(data)
                return data

            def write(self, *a, **k):
                """Proxy for write."""
                return self.tempfile.write(*a, **k)

            def tell(self, *a, **k):
                """Proxy for tell."""
                return self.tempfile.tell(*a, **k)

            def seek(self, *a, **k):
                """Seek."""
                self.tempfile.seek(*a, **k)

            def flush(self, *a, **k):
                """Flush."""
                self.tempfile.flush(*a, **k)

            def close(self, *a, **k):
                """Close."""
                self.tempfile.close(*a, **k)

        self.patch(action_queue, 'NamedTemporaryFile', MyTempFile)
        result = yield self._mk_file_w_content()
        cmd = commands[0]
        self.assertEqual(cmd.deflated_size, cmd.n_bytes_written)
        self.assertEqual(cmd.deflated_size, cmd.tempfile.all_read)
        self.assertEqual(cmd.hash, result['hash'])

    @defer.inlineCallbacks
    def test_downloading(self):
        """Test the downloading attribute is set correctly"""
        result = yield self._mk_file_w_content()
        deflated_size = result['deflated_size']
        outer_self = self
        commands = []

        class MyFile(object):
            """A filelike to check that the right info is in aq.downloading."""
            def __init__(self):
                self.cmd = [x for x in outer_self.aq.queue.waiting
                            if isinstance(x, Download)][0]
                commands.append(self.cmd)
                self.written = 0

            def write(self, _):
                """Do the check."""
                outer_self.assertEqual(self.cmd.deflated_size, deflated_size)

            def truncate(self, *a, **kw):
                """Stub."""
            flush = close = seek = truncate

        self.patch(self.main.fs, 'get_partial_for_writing',
                   lambda s, n: MyFile())
        wait_for_download = self.wait_for('AQ_DOWNLOAD_COMMIT')
        self.aq.download(
            result['share_id'], result['node_id'], result['hash'],
            result['mdid'])
        yield wait_for_download
        self.assertEqual(commands[0].n_bytes_read, deflated_size)

    @defer.inlineCallbacks
    @failure_expected("it's diet coke now")
    def test_testcase(self):
        """Test for a bug in the testcase setup/teardown order."""
        tmpfile = os.path.join(self.tmpdir, 'tmpfile')

        class FakeFile:
            """A fake file that does nothing except throw an error on read."""

            def __init__(self):
                open(tmpfile, 'w').close()
                self.name = tmpfile

            def read(self, *a, **kw):
                """Don't read; throw an error."""
                raise TabError("it's diet coke now")

            seek = tell = write = close = flush = lambda *a: 42

        self.patch(action_queue, 'NamedTemporaryFile', FakeFile)
        params = get_aq_params()
        self.patch(self.main.fs, 'open_file', lambda mdid: params['fd'])

        mdid, node_id = yield self._mkfile('hola')
        waiter = self.wait_for('AQ_UPLOAD_ERROR')
        yield self.aq.upload(
            params['share_id'], node_id, params['previous_hash'],
            params['hash'], params['crc32'], params['size'], mdid)
        yield waiter

    def test_ordered(self):
        """Three commands that if run out of order will throw an exception."""
        parent_path = self.main.fs.get_by_node_id(request.ROOT, self.root).path
        mdid = self.main.fs.create(os.path.join(parent_path, u"test"),
                                   request.ROOT)
        marker = Marker(mdid)
        self.aq.make_file(request.ROOT, self.root, 'hola', marker, mdid)
        self.aq.unlink(request.ROOT, self.root, marker, '', False)
        self.aq.make_file(request.ROOT, self.root, 'hola', Marker(), mdid)
        return self.wait_for_nirvana()

    @defer.inlineCallbacks
    def test_partial_download(self):
        """Download ok even if interrupted.

        Try downloading stuff from the server, halting the connection
        in the middle: download should continue from where it left off.
        """
        self.addCleanup(self.main.event_q.push, 'SYS_USER_DISCONNECT')
        outer_self = self

        class Foo(object):
            """A proxy for NoCloseCustomIO.

            Disconnects the network after the second write.
            """
            def __init__(self):
                self.buf = NoCloseCustomIO()
                self.writes = 0

            def write(self, data):
                """Write data to the buffer."""
                rv = self.buf.write(data)
                self.writes += 1
                if self.writes == 2:
                    outer_self.main.event_q.push('SYS_NET_DISCONNECTED')
                    outer_self.main.event_q.push('SYS_NET_CONNECTED')
                return rv

            def __getattr__(self, attr):
                return getattr(self.buf, attr)
        buf = Foo()
        result = yield self._mk_file_w_content(data_len=1024 * 128)
        self.patch(
            self.main.fs, 'get_partial_for_writing', lambda s, n: buf)
        yield self.aq.download(
            result['share_id'], result['node_id'], result['hash'],
            result['mdid'])
        yield self.main.wait_for_nirvana(.1)
        self.assertEqual(buf.getvalue(), result['data'])


class TestShares(TestBase):
    """Test things related to shares."""

    @defer.inlineCallbacks
    def test_list_shares(self):
        """Test we can list shares."""
        self.aq.list_shares()
        yield self.wait_for('SYS_QUEUE_DONE')
        self.assertInListenerEvents(
            'AQ_SHARES_LIST', {'shares_list': anEmptyShareList})

    @defer.inlineCallbacks
    @failure_expected('aiee')
    def test_list_shares_failure(self):
        """Test we survive a failure to list shares."""
        self.aq.client.list_shares = lambda: defer.fail(Exception('aiee'))
        d = self.wait_for('SYS_QUEUE_DONE')
        self.aq.list_shares()

        yield d
        self.assertInListenerEvents('AQ_LIST_SHARES_ERROR', {'error': 'aiee'})

    @defer.inlineCallbacks
    def test_create_share(self):
        """Test we can create shares."""
        self.aq.create_share(self.root, 'jane', '', 'View', 'marker:x', '')
        yield self.wait_for('SYS_QUEUE_DONE')
        self.assertInListenerEvents(
            'AQ_CREATE_SHARE_OK', {'marker': 'marker:x', 'share_id': anUUID})

    @defer.inlineCallbacks
    @failure_expected('DOES_NOT_EXIST')
    def test_create_share_failure(self):
        """Test we can survive a failure to create shares."""
        d = self.wait_for('SYS_QUEUE_DONE')
        self.aq.create_share(self.root, 'no such user', '', 'View',
                             'marker:x', '')
        yield d

        self.assertInListenerEvents(
            'AQ_CREATE_SHARE_ERROR',
            {'marker': 'marker:x', 'error': 'DOES_NOT_EXIST'})

    @defer.inlineCallbacks
    def test_share_notification(self):
        """Test we get notified correctly about changes to shares."""
        d1 = defer.Deferred()
        timeout = reactor.callLater(3, d1.errback, Exception("timeout"))

        def on_notification(*a):
            """our custom share changed callback"""
            self.client.factory._share_change_callback(*a)
            timeout.cancel()
            d1.callback('ok!')
        self.client.set_share_change_callback(on_notification)

        # sharing to yourself will stop working at some point, but
        # meanwhile it's handy to test notifications
        self.aq.create_share(self.root, 'jack', '', 'View', 'marker:x', '')
        d2 = self.wait_for('SYS_QUEUE_DONE')

        yield d1
        yield d2
        self.assertInListenerEvents('SV_SHARE_CHANGED', {'info': aShareInfo})

    @defer.inlineCallbacks
    def test_accept_share(self):
        """Test we get notified correctly about answers to shares."""
        d1 = defer.Deferred()
        d2 = defer.Deferred()

        def on_change_notification(*a):
            """our custom share changed callback"""
            self.client.factory._share_change_callback(*a)
            d1.callback('ok!')
            self.aq.answer_share(a[0].share_id, "Yes")
        self.client.set_share_change_callback(on_change_notification)

        def on_answer_notification(*a):
            """our custom share answer callback"""
            self.client.factory._share_answer_callback(*a)
            d2.callback('ok!')
        self.client.set_share_answer_callback(on_answer_notification)

        # sharing to yourself will stop working at some point, but
        # meanwhile it's handy to test notifications
        self.aq.create_share(self.root, 'jack', '', 'View', 'marker:x', '')
        d3 = self.wait_for('SYS_QUEUE_DONE')

        yield d1
        yield d2
        self.assertInListenerEvents(
            'SV_SHARE_ANSWERED', {'answer': 'Yes', 'share_id': anUUID})
        yield d3


class TestFSM(TestWithDatabase):
    """Test the AQ follows its FSM."""
    client = None

    def tearDown(self):
        self.eq.push('SYS_USER_DISCONNECT')
        return super(TestFSM, self).tearDown()

    def connect(self, do_connect=True):
        """Encourage the AQ to connect. Get the resulting client, if any."""
        d = super(TestFSM, self).connect(do_connect)
        if d is not None:
            d.addCallback(lambda client: setattr(self, 'client', client))
            d.addCallback(lambda _: self.wait_for_nirvana(.5))
        return d

    @defer.inlineCallbacks
    def test_connection_lost(self):
        """Try to connect."""
        dd = defer.Deferred()

        yield self.connect()
        yield self.wait_for_nirvana(.5)
        yield self.aq.connector.transport.loseConnection()
        yield reactor.callLater(1, dd.callback, None)
        yield dd
        # check that the connection lost event is issued:
        self.assertInListenerEvents('SYS_CONNECTION_LOST', {})
        # test that we reconnect:
        yield lambda _: self.wait_for_nirvana(.5)

    def test_init(self):
        """Check that, when started, state is INIT."""
        self.assertEqual(self.state.state, StateManager.INIT)

    def test_synced(self):
        """Immediately after connecting, with no LR nor SR, must be IDLE."""
        d = self.connect()

        def _assert(_):
            """do the check"""
            self.assertEqual(self.state.queues.state, QueueManager.IDLE)
        d.addCallback(_assert)
        return d

    @defer.inlineCallbacks
    def test_syncing(self):
        """When working, state is WORKING, when finished is IDLE."""
        yield self.connect()
        wait_for_queue_done = self.wait_for('SYS_QUEUE_DONE')
        command_deferred = self.aq.rescan_from_scratch('')

        # check
        self.assertEqual(self.state.queues.state, QueueManager.WORKING)
        yield command_deferred
        yield wait_for_queue_done
        self.assertEqual(self.state.queues.state, QueueManager.IDLE)

    def test_disconnect(self):
        """When the user say 'disconnect', the state should go to STANDOFF."""
        d = self.connect()

        def _assert(_):
            """do the check"""
            self.eq.push('SYS_USER_DISCONNECT')
            self.assertEqual(self.state.state, StateManager.STANDOFF)
        d.addCallback(_assert)
        return d

    def test_net_disconnected(self):
        """When the user network disconnects, state should go to STANDOFF."""
        d = self.connect()

        def _assert(_):
            """do the check"""
            self.eq.push('SYS_NET_DISCONNECTED')
            self.assertEqual(self.state.state, StateManager.STANDOFF)
        d.addCallback(_assert)
        return d

    def test_net_connected(self):
        """Lose and gain network connection.

        When we're WAITING and the network tells us it's connected, we
        should go ahead and connect (and go to IDLE).
        """
        d = self.connect()
        d.addCallback(lambda _: self.eq.push('SYS_NET_DISCONNECTED'))
        d.addCallback(lambda _: self.main.wait_for('SYS_CONNECTION_LOST'))
        d.addCallback(lambda _: self.eq.push('SYS_NET_CONNECTED'))

        def _assert(_):
            """Do the check."""
            self.assertEqual(self.state.state, StateManager.QUEUE_MANAGER)
            self.assertEqual(self.state.queues.state, QueueManager.IDLE)
        d1 = self.wait_for_nirvana()
        d1.addCallback(_assert)
        return d1

    def test_reconnect(self):
        """Disconnect and then reconnect.

        When we're OFFLINE and the user tells us to connect, we should
        go ahead and connect (and go to IDLE).
        """
        d = self.connect()
        d.addCallback(lambda _: self.eq.push('SYS_USER_DISCONNECT'))
        d.addCallback(lambda _: self.main.wait_for('SYS_CONNECTION_LOST'))
        d.addCallback(lambda _: self.eq.push(
            'SYS_USER_CONNECT', access_token=self.access_tokens['jack']))

        def _assert(_):
            """do the check"""
            self.assertEqual(self.state.state, StateManager.QUEUE_MANAGER)
            self.assertEqual(self.state.queues.state, QueueManager.IDLE)
        d1 = self.wait_for_nirvana()
        d1.addCallback(_assert)
        return d1

    def test_disconnected_during_waiting(self):
        """If we're WAITING and get a SYS_NET_DISCONNECTED, do nothing."""
        self.connect(do_connect=False)
        self.eq.push('SYS_NET_DISCONNECTED')
        self.assertEqual(self.state.state, StateManager.READY)
        self.assertEqual(self.state.connection.state, ConnectionManager.WU_NN)

    def test_disconnected_during_offline(self):
        """If we're OFFLINE and get a SYS_NET_DISCONNECTED, do nothing."""
        self.connect(do_connect=False)
        ready = StateManager.READY
        self.assertEqual(self.state.state, ready)
        self.assertEqual(self.state.connection.state, ConnectionManager.WU_NN)
        self.eq.push('SYS_USER_DISCONNECT')
        self.assertEqual(self.state.state, ready)
        self.assertEqual(self.state.connection.state, ConnectionManager.NU_NN)
        self.eq.push('SYS_NET_DISCONNECTED')
        self.assertEqual(self.state.state, ready)
        self.assertEqual(self.state.connection.state, ConnectionManager.NU_NN)

    def test_unknown_error(self):
        """If we get SYS_UNKNOWN_ERROR, we should go to UNKNOWN_ERROR."""
        d = defer.Deferred()
        self.main.restart = lambda *_: d.callback(None)
        self.connect()
        self.eq.push('SYS_UNKNOWN_ERROR')
        self.assertEqual(self.state.state, StateManager.UNKNOWN_ERROR)
        return d


class TestMulticon(TestWithDatabase):
    """Test the AQ follows its FSM."""

    def test_multicon_caps(self):
        """Test 'caps' works OK when the client disconnects."""
        query_caps = StorageClient.query_caps

        def my_query_caps(s, c):
            """Disconnect the client before the calling original method."""
            self.main.action_q.disconnect()
            return query_caps(s, c)

        self.patch(StorageClient, 'query_caps', my_query_caps)
        self.state.connection.handshake_timeout = 10
        self.connect()
        d = self.main.wait_for('SYS_CONNECTION_LOST')
        d.addBoth(lambda _: setattr(StorageClient, 'query_caps', query_caps))
        d.addBoth(lambda _: self.main.wait_for_nirvana())
        d.addBoth(lambda _: self.eq.push('SYS_USER_DISCONNECT'))
        return d

    def test_multicon_check_version(self):
        """Test 'check_version' works OK when the client disconnects."""
        protocol_version = StorageClient.protocol_version

        def my_protocol_version(s):
            """Disconnect the client before the calling original method."""
            self.main.action_q.disconnect()
            return protocol_version(s)
        StorageClient.protocol_version = my_protocol_version
        self.state.connection.handshake_timeout = 10
        self.connect()
        d = self.main.wait_for('SYS_CONNECTION_LOST')
        d.addBoth(lambda _: setattr(StorageClient, 'protocol_version',
                                    protocol_version))
        d.addBoth(lambda _: self.main.wait_for_nirvana())
        d.addBoth(lambda _: self.eq.push('SYS_USER_DISCONNECT'))
        return d

    def test_multicon_auth(self):
        """Test 'auth' works OK when the client disconnects."""
        authenticate = StorageClient.simple_authenticate

        def my_authenticate(*a):
            """Disconnect the client before the calling original method."""
            self.main.action_q.disconnect()
            return authenticate(*a)
        StorageClient.simple_authenticate = my_authenticate
        self.state.connection.handshake_timeout = 10
        self.connect()
        d = self.main.wait_for('SYS_CONNECTION_LOST')
        d.addBoth(lambda _: setattr(StorageClient, 'simple_authenticate',
                                    authenticate))
        d.addBoth(lambda _: self.main.wait_for_nirvana())
        d.addBoth(lambda _: self.eq.push('SYS_USER_DISCONNECT'))
        return d
