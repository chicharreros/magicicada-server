# -*- coding: utf-8 -*-
#
# Copyright 2009-2012 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
"""Tests for the syncdaemon tools module."""

import os

from collections import defaultdict

from twisted.internet import defer, reactor
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipTest, skipIfNotOS

from contrib.testing.testcase import FakeCommand

from ubuntuone.syncdaemon import (
    action_queue,
    event_queue,
    interaction_interfaces,
    states,
    volume_manager,
    RECENT_TRANSFERS,
    UPLOADING,
)
from ubuntuone.platform import tools
from ubuntuone.platform.tests import IPCTestCase


SOME_ERROR = 'CRASH BOOM BANG'


class TestToolsBase(IPCTestCase):
    """Base test case for SyncDaemonTool tests."""

    service_class = interaction_interfaces.SyncdaemonService
    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestToolsBase, self).setUp()
        self.tool = tools.SyncDaemonTool(self.bus)
        self.addCleanup(self.tool.shutdown)

        self.handler = MementoHandler()
        self.tool.log.addHandler(self.handler)
        self.addCleanup(self.tool.log.removeHandler, self.handler)

        self.called = []
        self.patch(self.tool.proxy, 'start',
                   lambda: self.called.append('start') or defer.succeed(None))
        self.patch(self.main, 'quit',
                   lambda: self.called.append('quit') or defer.succeed(None))

        self.patch(tools, 'is_already_running',
                   lambda bus: defer.succeed(True))
        yield self.main.wait_for_nirvana(last_event_interval=0.001)

    def _create_share(self, accepted=True, subscribed=True):
        """Return a newly created Share."""
        share_path = os.path.join(self.shares_dir, 'share_name')
        share = volume_manager.Share(path=share_path, volume_id='share_vol_id')
        return share

    def _create_udf(self, suggested_path=None, subscribed=True):
        """Create an UDF and returns it and the volume"""
        volume_id = 'volume_id'
        node_id = 'node_id'
        if suggested_path is None:
            suggested_path = u'~/ñoño'
        else:
            assert isinstance(suggested_path, unicode)
        path = volume_manager.get_udf_path(suggested_path)
        udf = volume_manager.UDF(str(volume_id), str(node_id), suggested_path,
                                 path, subscribed)
        return udf

    def assert_dict_is_subset(self, actual, expected):
        """Check that the 'actual' dict is a subset of 'expected' dict.

        So:

        {'a': 1} is subset of {'a': 1, 'b': 2}
        {'a': 1} is not subset of {'a': 10, 'b': 2}

        """
        actual_set = set(actual.iteritems())
        expected_set = set(expected.iteritems())
        self.assertTrue(actual_set.issubset(expected_set),
                        '%r is not a subset of %r' % (actual, expected))


class TestToolsBasic(TestToolsBase):
    """Basic test of SyncDaemonTool."""

    @defer.inlineCallbacks
    def test_wait_connected(self):
        """Test wait_connected."""
        self.action_q.connect()
        result = yield self.tool.wait_connected()
        self.assertEqual(True, result)

    def test_all_downloads(self):
        """ test wait_all_downloads """
        d = self.tool.wait_all_downloads()

        # test callback, pylint: disable-msg=C0111
        def downloads(result):
            self.assertEqual(True, result)
        d.addBoth(downloads)
        return d

    def test_all_uploads(self):
        """ test wait_all_uploads """
        d = self.tool.wait_all_uploads()

        # test callback, pylint: disable-msg=C0111
        def uploads(result):
            self.assertEqual(True, result)
        d.addBoth(uploads)
        return d

    def test_wait_for_nirvana(self):
        """Test wait_for_nirvana."""
        # setup States to be in Nirvana condition
        self.main.state_manager.state = states.StateManager.QUEUE_MANAGER
        self.main.state_manager.queues.state = states.QueueManager.IDLE

        # unsubscribe VM and States to not receive everything
        self.event_q.unsubscribe(self.main.vm)
        self.event_q.unsubscribe(self.main.state_manager)
        d = self.tool.wait_for_nirvana(last_event_interval=.1)

        # test callback, pylint: disable-msg=C0111
        def callback(result):
            self.assertEqual(True, result)
        d.addBoth(callback)

        # clear downloading
        reactor.callLater(0, self.action_q.connect)

        def fire_events():
            for event_name in event_queue.EVENTS.keys():
                args = event_queue.EVENTS[event_name]
                self.event_q.push(event_name, **dict((x, x) for x in args))

        # fire fake events to keep the deferred running
        reactor.callLater(0, fire_events)
        # 1 sec later, clear the download queue, and wait to reach nirvana
        d.addCallback(lambda _: self.event_q.subscribe(self.main.vm))
        return d

    @defer.inlineCallbacks
    def test_get_metadata(self):
        """Check that get_metadata works as expected."""
        path = os.path.join(self.root_dir, "foo")
        self.fs.create(path, "")
        self.fs.set_node_id(path, "node_id")

        result = yield self.tool.get_metadata(path)

        self.assertEqual(path, str(result['path']))
        self.assertEqual('', str(result['share_id']))
        self.assertEqual('node_id', result['node_id'])

    @skipTest('Fails in nightlies: bug #1071466')
    @defer.inlineCallbacks
    def test_search_files(self):
        """Check that get_metadata works as expected."""
        mdid = 'id'
        path = os.path.join(self.root_dir, u'path/to/file_test')
        mdobj = {'server_hash': 'asdqwe123'}
        mdid2 = 'id2'
        path2 = os.path.join(self.root_dir, u'path/to/my_files')
        mdobj2 = {'server_hash': 'asdqwe456'}
        mdid3 = 'id3'
        path3 = u'/home2/to/my_files'
        mdobj3 = {'server_hash': 'asdqwe456'}
        self.fs._idx_path = {path: mdid, path2: mdid2, path3: mdid3}
        self.fs.fs = {mdid: mdobj, mdid2: mdobj2, mdid3: mdobj3}

        result = yield self.tool.search_files('file')
        expected = [
            os.path.join(self.root_dir, 'path/to/file_test'),
            os.path.join(self.root_dir, 'path/to/my_files')]
        self.assertEqual(result, expected)

    @defer.inlineCallbacks
    def test_quit_when_running(self):
        """Test the quit method when the daemon is running."""
        self.patch(tools, 'is_already_running',
                   lambda bus: defer.succeed(True))
        yield self.tool.quit()
        self.assertEqual(self.called, ['quit'])

    @defer.inlineCallbacks
    def test_quit_not_running(self):
        """Test the quit method when the daemon is not running."""
        self.patch(tools, 'is_already_running',
                   lambda bus: defer.succeed(False))
        yield self.tool.quit()
        self.assertEqual(self.called, [])

    @defer.inlineCallbacks
    def test_accept_share(self):
        """Test accept_share method."""
        share_path = os.path.join(self.main.shares_dir, 'share')
        yield self.main.vm.add_share(volume_manager.Share(path=share_path,
                                     volume_id='share_id', access_level='Read',
                                     accepted=False, node_id="node_id"))
        self.assertEqual(False, self.main.vm.shares['share_id'].accepted)
        result = yield self.tool.accept_share('share_id')

        self.assertEqual('Yes', result['answer'])
        self.assertEqual('share_id', result['volume_id'])
        self.assertEqual(True, self.main.vm.shares['share_id'].accepted)

    @defer.inlineCallbacks
    def test_reject_share(self):
        """Test the reject_share method."""
        share_path = os.path.join(self.main.shares_dir, 'share')
        yield self.main.vm.add_share(volume_manager.Share(path=share_path,
                                     volume_id='share_id', access_level='Read',
                                     accepted=False))
        self.assertEqual(False, self.main.vm.shares['share_id'].accepted)
        result = yield self.tool.reject_share('share_id')

        self.assertEqual('No', result['answer'])
        self.assertEqual('share_id', result['volume_id'])
        self.assertEqual(False, self.main.vm.shares['share_id'].accepted)

    @defer.inlineCallbacks
    def test_sync_menu(self):
        """Test accept_share method."""
        result = yield self.tool.sync_menu()
        self.assertIn(RECENT_TRANSFERS, result)
        self.assertIn(UPLOADING, result)


class TestWaitForSignals(TestToolsBase):
    """Test case for the wait_for_signals method from SyncDaemonTool."""

    signal_ok = 'Foo'
    signal_error = 'Bar'

    target_signal = signal_ok
    target_filter = 'success_filter'

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestWaitForSignals, self).setUp()
        self.success_filter = self.return_true
        self.error_filter = self.return_true
        self.signals = defaultdict(list)
        self.patch(self.tool, 'connect_signal', self.connect_signal)
        self.patch(self.tool, 'disconnect_signal', self.disconnect_signal)

    def return_true(self, *a):
        return True

    def connect_signal(self, signal_name, handler):
        """Fake signal connection."""
        self.signals[signal_name].append(handler)
        return handler

    def disconnect_signal(self, signal_name, handler_or_match):
        """Fake signal disconnection."""
        self.signals[signal_name].remove(handler_or_match)

    def emit_signal(self, signal_name, *args, **kwargs):
        """Fake signal emission."""
        for handler in self.signals[signal_name]:
            handler(*args, **kwargs)

    @defer.inlineCallbacks
    def test_filter_yes(self):
        """Test emitting signal with filter returning True."""
        d = self.tool.wait_for_signals(
            self.signal_ok, self.signal_error,
            **{self.target_filter: lambda *a: True})
        expected = object()
        self.emit_signal(self.target_signal, expected)

        result, = yield d
        self.assertEqual(expected, result)
        for signal in (self.signal_ok, self.signal_error):
            if signal is not None:
                self.assertEqual(len(self.signals[signal]), 0,
                                 '%s should be disconnected.' % signal)

    def test_filter_no(self):
        """Test emitting signal with filter returning False."""
        d = self.tool.wait_for_signals(
            self.signal_ok, self.signal_error,
            **{self.target_filter: lambda *a: False})
        expected = object()
        self.emit_signal(self.target_signal, expected)

        self.assertFalse(d.called)
        for signal in (self.signal_ok, self.signal_error):
            if signal is not None:
                self.assertEqual(len(self.signals[signal]), 1,
                                 '%s should be connected.' % signal)

    @defer.inlineCallbacks
    def test_failing_filter(self):
        """Test emitting signal with filter failing."""

        def some_filter(*args):
            """Broken filter"""
            raise ValueError('DIE!!!!')

        d = self.tool.wait_for_signals(
            self.signal_ok, self.signal_error,
            **{self.target_filter: some_filter})
        args = (object(), 123456789)
        self.emit_signal(self.target_signal, *args)

        result = yield self.assertFailure(d, tools.IPCError)
        self.assertEqual(result.name, ValueError.__name__)
        self.assertEqual(result.info, args)
        self.assertEqual(result.details, 'DIE!!!!')

        for signal in (self.signal_ok, self.signal_error):
            self.assertEqual(len(self.signals[signal]), 0,
                             '%s should be disconnected.' % signal)


class TestWaitForSignalsSignalErrorNone(TestWaitForSignals):
    """Test case for the wait_for_signal method from SyncDaemonTool."""

    signal_error = None


class TestWaitForSignalsEmitSignalError(TestWaitForSignals):
    """Test case for the wait_for_signals method from SyncDaemonTool."""

    target_signal = TestWaitForSignals.signal_error
    target_filter = 'error_filter'

    @defer.inlineCallbacks
    def test_filter_yes(self):
        """Test emitting signal with filter returning True."""
        d = self.tool.wait_for_signals(
            self.signal_ok, self.signal_error,
            **{self.target_filter: lambda *a: True})
        expected = object()
        self.emit_signal(self.target_signal, expected)

        result = yield self.assertFailure(d, tools.IPCError)
        self.assertEqual(result.name, self.signal_error)
        self.assertEqual(result.info, (expected,))


class TestWaitForSignal(TestWaitForSignals):
    """Test case for the wait_for_signal method from SyncDaemonTool."""

    signal_error = None

    @defer.inlineCallbacks
    def test_filter_yes(self):
        """Test wait_for_signal method."""
        d = self.tool.wait_for_signal(self.signal_ok, lambda *a: True)

        expected = object()
        self.emit_signal(self.signal_ok, expected)

        result, = yield d
        self.assertEqual(expected, result)

    def test_filter_no(self):
        """Test wait_for_signal method."""
        d = self.tool.wait_for_signal(self.signal_ok, lambda *a: False)

        expected = object()
        self.emit_signal(self.signal_ok, expected)

        self.assertFalse(d.called)

    @defer.inlineCallbacks
    def test_failing_filter(self):
        """Test (with error) wait_for_signal method."""

        def some_filter(*args):
            """Broken filter"""
            raise ValueError('DIE!!!!')

        d = self.tool.wait_for_signal(self.signal_ok, some_filter)

        args = (object(), 123456789)
        self.emit_signal(self.signal_ok, *args)

        result = yield self.assertFailure(d, tools.IPCError)
        self.assertEqual(result.name, ValueError.__name__)
        self.assertEqual(result.info, args)
        self.assertEqual(result.details, 'DIE!!!!')


class TestToolsSomeMore(TestToolsBase):
    """Basic test of SyncDaemonTool."""

    def test_connect(self):
        """Test the connect method."""
        self.assertEqual(self.main.state_manager.state,
                         states.StateManager.QUEUE_MANAGER)
        d = self.main.wait_for('SYS_USER_DISCONNECT')
        self.tool.disconnect()

        def connect(r):
            d = self.main.wait_for('SYS_USER_CONNECT')
            self.tool.connect()
            d.addCallbacks(lambda x: x, self.fail)
            return d

        d.addCallbacks(connect, self.fail)
        return d

    def test_disconnect(self):
        """Test the disconnect method."""
        self.assertEqual(self.main.state_manager.state,
                         states.StateManager.QUEUE_MANAGER)
        d = self.main.wait_for('SYS_USER_DISCONNECT')
        self.tool.disconnect()
        d.addCallbacks(self.assertFalse, self.fail)
        return d

    @defer.inlineCallbacks
    def test_get_status(self):
        """Test the status method."""
        result = yield self.tool.get_status()

        state = states.StateManager.QUEUE_MANAGER
        self.assertEqual(state.name, result['name'])
        self.assertEqual(state.description, result['description'])
        self.assertEqual(state.is_error, bool(result['is_error']))
        self.assertEqual(state.is_connected, bool(result['is_connected']))
        self.assertEqual(state.is_online, bool(result['is_online']))

    @defer.inlineCallbacks
    def test_free_space(self):
        """Test SyncDaemonTool.waiting."""
        share_path = os.path.join(self.main.shares_dir, 'share')
        share = volume_manager.Share(path=share_path, volume_id='vol_id')
        yield self.main.vm.add_share(share)

        self.main.vm.update_free_space('vol_id', 12345)
        result = yield self.tool.free_space('vol_id')
        self.assertEqual(result, 12345)

    @defer.inlineCallbacks
    def test_waiting_simple(self):
        """Test SyncDaemonTool.waiting."""
        # inject the fake data
        c1 = FakeCommand("node_a_foo", "node_a_bar", path='path')
        c2 = FakeCommand("node_b_foo", "node_b_bar")
        c2.running = False
        self.action_q.queue.waiting.extend([c1, c2])
        result = yield self.tool.waiting()

        self.assertEqual(2, len(result))

        pl = dict(share_id='node_a_foo', node_id='node_a_bar',
                  other='', path='path', running='True')
        self.assertEqual(result[0], ('FakeCommand', str(id(c1)), pl))

        pl = dict(share_id='node_b_foo', node_id='node_b_bar',
                  other='', running='')
        self.assertEqual(result[1], ('FakeCommand', str(id(c2)), pl))

    @defer.inlineCallbacks
    def test_waiting_metadata(self):
        """Test SyncDaemonTool.waiting_metadata."""
        # inject the fake data
        self.action_q.queue.waiting.extend([
                FakeCommand("node_a_foo", "node_a_bar", path='path'),
                FakeCommand("node_b_foo", "node_b_bar")])
        result = yield self.tool.waiting_metadata()

        self.assertEqual(2, len(result))

        pl = dict(share_id='node_a_foo', node_id='node_a_bar',
                  other='', path='path', running='True')
        self.assertEqual(result[0], ('FakeCommand', pl))

        pl = dict(share_id='node_b_foo', node_id='node_b_bar',
                  other='', running='True')
        self.assertEqual(result[1], ('FakeCommand', pl))

    @defer.inlineCallbacks
    def test_waiting_content(self):
        """Test waiting_content."""

        class FakeContentCommand(FakeCommand, action_queue.Upload):
            """Fake command that goes in content queue."""
            def __init__(self, *args, **kwargs):
                FakeCommand.__init__(self, *args, **kwargs)

        # inject the fake data
        self.action_q.queue.waiting.extend([
                FakeContentCommand("", "node_id", path='/some/path'),
                FakeContentCommand("", "node_id_1", path='/other/path')])

        result = yield self.tool.waiting_content()

        node, node_1 = result
        self.assertEqual('/some/path', str(node['path']))
        self.assertEqual('/other/path', str(node_1['path']))
        self.assertEqual('', str(node['share']))
        self.assertEqual('', str(node_1['share']))
        self.assertEqual('node_id', str(node['node']))
        self.assertEqual('node_id_1', str(node_1['node']))
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_start_when_running(self):
        """Test the start method when the daemon is running."""
        self.patch(tools, 'is_already_running',
                   lambda bus: defer.succeed(True))
        self.patch(self.tool, 'wait_for_signals',
                   lambda *a: defer.fail(AssertionError(a)))
        yield self.tool.start()
        self.assertEqual(self.called, [])

    @defer.inlineCallbacks
    def test_start_not_running(self):
        """Test the start method when the daemon is not running."""
        d = defer.Deferred()

        def succed_status_changed(signal_name, *a):
            """Returned a fired deferred if signal_name is StatusChanged."""
            if signal_name == 'StatusChanged':
                return d.callback(True)
            else:
                return d.errback(AssertionError(signal_name))

        self.patch(tools, 'is_already_running',
                   lambda bus: defer.succeed(False))
        self.patch(self.tool, 'wait_for_signals', succed_status_changed)
        assert not d.called

        yield self.tool.start()
        yield d  # d is fired when wait_for_signals on StatusChanged was called

        self.assertEqual(self.called, ['start'])

    @defer.inlineCallbacks
    def test_create_folder(self):
        """Test for Folders.create."""
        path = os.path.join(self.home_dir, u'ñoño')
        volume_id = 'volume_id'
        node_id = 'node_id'

        def create_udf(path, name, marker):
            """Fake create_udf."""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=volume_id,
                                   node_id=node_id, marker=marker)

        self.patch(self.main.action_q, 'create_udf', create_udf)

        result = yield self.tool.create_folder(path)
        minimal = dict(volume_id=volume_id, node_id=node_id, path=path)
        self.assert_dict_is_subset(minimal, result)

    @defer.inlineCallbacks
    def test_create_folder_error(self):
        """Test for Folders.create with error."""
        path = os.path.join(self.home_dir, u'ñoño')

        def create_udf(path, name, marker):
            """Fake create_udf."""
            self.main.event_q.push("AQ_CREATE_UDF_ERROR", marker=marker,
                                   error=SOME_ERROR)

        self.patch(self.main.action_q, 'create_udf', create_udf)

        result = yield self.assertFailure(self.tool.create_folder(path),
                                          tools.IPCError)
        self.assertEqual('FolderCreateError', result.name)
        self.assertEqual(dict(path=path), result.info[0])
        self.assertEqual(SOME_ERROR, result.info[1])

    @defer.inlineCallbacks
    def test_delete_folder(self):
        """Test for Folders.delete."""
        udf = self._create_udf()
        volume_id = udf.volume_id

        def delete_volume(volume_id, path):
            """Fake delete_volume."""
            self.main.event_q.push("AQ_DELETE_VOLUME_OK",
                                   volume_id=volume_id)

        self.patch(self.main.action_q, 'delete_volume', delete_volume)
        yield self.main.vm.add_udf(udf)

        result = yield self.tool.delete_folder(volume_id)
        minimal = dict(volume_id=volume_id, suggested_path=udf.suggested_path)
        self.assert_dict_is_subset(minimal, result)

    @defer.inlineCallbacks
    def test_delete_folder_error(self):
        """Test for Folders.delete with error."""
        udf = self._create_udf()
        volume_id = udf.volume_id

        def delete_volume(volume_id, path):
            """Fake delete_volume."""
            self.main.event_q.push("AQ_DELETE_VOLUME_ERROR",
                                   volume_id=volume_id, error=SOME_ERROR)

        self.patch(self.main.action_q, 'delete_volume', delete_volume)
        yield self.main.vm.add_udf(udf)

        result = yield self.assertFailure(self.tool.delete_folder(volume_id),
                                          tools.IPCError)
        self.assertEqual('FolderDeleteError', result.name)
        self.assert_dict_is_subset(dict(volume_id=volume_id), result.info[0])
        self.assertEqual(SOME_ERROR, result.info[1])

    @defer.inlineCallbacks
    def test_subscribe_folder(self):
        """Test for Folders.subscribe and that it fires a signal."""
        udf = self._create_udf(subscribed=False)
        yield self.main.vm.add_udf(udf)
        yield self.tool.subscribe_folder(udf.id)

        self.assertTrue(self.main.vm.udfs[udf.id].subscribed,
                        "UDF %s isn't subscribed" % udf.id)

    @defer.inlineCallbacks
    def test_unsubscribe_folder(self):
        """Test for Folders.unsubscribe."""
        udf = self._create_udf(subscribed=True)
        yield self.main.vm.add_udf(udf)
        yield self.tool.unsubscribe_folder(udf.id)

        self.assertFalse(self.main.vm.udfs[udf.id].subscribed,
                         "UDF %s is subscribed" % udf.id)

    @defer.inlineCallbacks
    def test_validate_path(self):
        """Test for Folders.validate_path."""
        result = yield self.tool.validate_path(self.root_dir)
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_subscribe_share(self):
        """Test for Shares.subscribe."""
        share = self._create_share(accepted=True, subscribed=False)
        yield self.main.vm.add_share(share)
        yield self.tool.subscribe_share(share.volume_id)

        self.assertTrue(self.main.vm.shares[share.id].subscribed,
                        "share %s should be subscribed" % share)

    @defer.inlineCallbacks
    def test_unsubscribe_share(self):
        """Test for Shares.unsubscribe."""
        share = self._create_share(accepted=True, subscribed=False)
        yield self.main.vm.add_share(share)
        yield self.tool.unsubscribe_share(share.volume_id)

        self.assertFalse(self.main.vm.shares[share.id].subscribed,
                         "share %s should not be subscribed" % share)

    @defer.inlineCallbacks
    def test_change_public_access(self):
        """Test change_public_access."""
        # XXX: change public access is the only class that expects uuid's as
        # params this may indicate that we need to refactor that class to be
        # consistent with the rest of syncdaemon where ID's are always strings
        node_id = '59809aae-9c5a-47e0-b37c-5abbfbe7c50a'
        share_id = ""
        path = os.path.join(self.root_dir, "foo")
        self.fs.create(path, "")
        self.fs.set_node_id(path, node_id)

        def change_public_access(share_id, node_id, is_public):
            """Fake change_public_access"""
            self.main.event_q.push("AQ_CHANGE_PUBLIC_ACCESS_OK",
                                   share_id=share_id, node_id=node_id,
                                   is_public=True,
                                   public_url='http://example.com')
        self.patch(self.main.action_q, 'change_public_access',
                   change_public_access)

        file_info = yield self.tool.change_public_access(path, True)

        self.assertEqual(path, file_info['path'])
        self.assertEqual(share_id, file_info['share_id'])
        self.assertEqual(node_id, file_info['node_id'])
        self.assertEqual('True', file_info['is_public'])
        self.assertEqual('http://example.com', file_info['public_url'])

    @defer.inlineCallbacks
    def test_change_public_access_with_unicode(self):
        """Test change_public_access."""
        # XXX: change public access is the only class that expects uuid's as
        # params this may indicate that we need to refactor that class to be
        # consistent with the rest of syncdaemon where ID's are always strings
        node_id = '59809aae-9c5a-47e0-b37c-5abbfbe7c50a'
        share_id = ""
        path = os.path.join(self.root_dir, u"ñoño")
        path = path.encode('utf-8')
        self.fs.create(path, "")
        self.fs.set_node_id(path, node_id)

        def change_public_access(share_id, node_id, is_public):
            """Fake change_public_access"""
            self.main.event_q.push("AQ_CHANGE_PUBLIC_ACCESS_OK",
                                   share_id=share_id, node_id=node_id,
                                   is_public=True,
                                   public_url='http://example.com')
        self.patch(self.main.action_q, 'change_public_access',
                   change_public_access)

        file_info = yield self.tool.change_public_access(path, True)

        self.assertEqual(path.decode('utf-8'), file_info['path'])
        self.assertEqual(share_id, file_info['share_id'])
        self.assertEqual(node_id, file_info['node_id'])
        self.assertEqual('True', file_info['is_public'])
        self.assertEqual('http://example.com', file_info['public_url'])

    @defer.inlineCallbacks
    def test_get_public_files(self):
        """Get the public files."""
        node_id = '59809aae-9c5a-47e0-b37c-5abbfbe7c50a'
        vol_id = ""
        path = os.path.join(self.root_dir, "foo")
        self.fs.create(path, vol_id, node_id)
        fake_response = dict(volume_id=vol_id, node_id=node_id,
                             public_url='public_url')

        def fake_call():
            """Fake get public files."""
            self.main.event_q.push("AQ_PUBLIC_FILES_LIST_OK",
                                   public_files=[fake_response])
        self.patch(self.main.action_q, 'get_public_files', fake_call)

        # get and check
        public_files = yield self.tool.get_public_files()
        self.assertEqual(len(public_files), 1)
        pf = public_files[0]
        self.assertEqual(pf['node_id'], node_id)
        self.assertEqual(pf['volume_id'], vol_id)
        self.assertEqual(pf['public_url'], 'public_url')
        self.assertEqual(pf['path'], path)

    @defer.inlineCallbacks
    def test_get_throttling_limits(self):
        """Test for get_throttling_limits."""
        yield self.tool.set_throttling_limits(-1, -1)
        limits = yield self.tool.get_throttling_limits()
        self.assertEqual(-1, limits[u'download'])
        self.assertEqual(-1, limits[u'upload'])

    @defer.inlineCallbacks
    def test_set_throttling_limits(self):
        """Test for set_throttling_limits."""
        yield self.tool.set_throttling_limits(10, 20)
        limits = yield self.tool.get_throttling_limits()
        self.assertEqual(10, limits[u'download'])
        self.assertEqual(20, limits[u'upload'])

    @defer.inlineCallbacks
    def test_is_throttling_enabled(self):
        """Test for is_throttling_enabled."""
        yield self.tool.enable_throttling(False)
        enabled = yield self.tool.is_throttling_enabled()
        self.assertFalse(enabled)

        yield self.tool.enable_throttling(True)
        enabled = yield self.tool.is_throttling_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_enable_throttling(self):
        """Test for enable_throttling."""
        yield self.tool.enable_throttling(True)
        enabled = yield self.tool.is_throttling_enabled()
        self.assertTrue(enabled)

        yield self.tool.enable_throttling(False)
        enabled = yield self.tool.is_throttling_enabled()
        self.assertFalse(enabled)

    @defer.inlineCallbacks
    def test_is_files_sync_enabled(self):
        """Test for is_files_sync_enabled."""
        yield self.tool.enable_files_sync(False)
        enabled = yield self.tool.is_files_sync_enabled()
        self.assertFalse(enabled)

        yield self.tool.enable_files_sync(True)
        enabled = yield self.tool.is_files_sync_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_enable_files_sync(self):
        """Test for enable_files_sync."""
        yield self.tool.enable_files_sync(True)
        enabled = yield self.tool.is_files_sync_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_enable_files_sync_when_disabled(self):
        """Test for enable_files_sync."""
        self.patch(self.tool, 'start',
                   lambda: self.called.append('start') or defer.succeed(None))
        self.patch(tools, 'is_already_running',
                   lambda bus: defer.succeed(False))
        # be sure file sync is disabled and clear called
        yield self.tool.enable_files_sync(False)
        self.called = []

        yield self.tool.enable_files_sync(True)
        # assert that the services was started
        self.assertEqual(self.called, ['start'])

    @defer.inlineCallbacks
    def test_disable_files_sync(self):
        """Test for enable_files_sync."""
        yield self.tool.enable_files_sync(False)
        enabled = yield self.tool.is_files_sync_enabled()
        self.assertFalse(enabled)

    @defer.inlineCallbacks
    def test_disable_files_sync_when_disabled(self):
        """Test for enable_files_sync."""
        yield self.tool.enable_files_sync(False)

        yield self.tool.enable_files_sync(False)
        enabled = yield self.tool.is_files_sync_enabled()
        self.assertFalse(enabled)

    @defer.inlineCallbacks
    def test_disable_files_sync_when_enabled(self):
        """Test for enable_files_sync."""
        # be sure file sync is enabled and clear called
        yield self.tool.enable_files_sync(True)
        self.called = []

        yield self.tool.enable_files_sync(False)
        # assert that the services was stopped
        self.assertEqual(self.called, ['quit'])

    @defer.inlineCallbacks
    def test_is_autoconnect_enabled(self):
        """Test for is_autoconnect_enabled."""
        yield self.tool.enable_autoconnect(False)
        enabled = yield self.tool.is_autoconnect_enabled()
        self.assertFalse(enabled)

        yield self.tool.enable_autoconnect(True)
        enabled = yield self.tool.is_autoconnect_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_enable_autoconnect(self):
        """Test for enable_autoconnect."""
        yield self.tool.enable_autoconnect(True)
        enabled = yield self.tool.is_autoconnect_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_disable_autoconnect(self):
        """Test for disable_autoconnect."""
        yield self.tool.enable_autoconnect(False)
        enabled = yield self.tool.is_autoconnect_enabled()
        self.assertFalse(enabled)

    @defer.inlineCallbacks
    def test_is_share_autosubscribe_enabled(self):
        """Test for is_share_autosubscribe_enabled."""
        yield self.tool.enable_share_autosubscribe(False)
        enabled = yield self.tool.is_share_autosubscribe_enabled()
        self.assertFalse(enabled)

        yield self.tool.enable_share_autosubscribe(True)
        enabled = yield self.tool.is_share_autosubscribe_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_enable_share_autosubscribe(self):
        """Test for enable_share_autosubscribe."""
        yield self.tool.enable_share_autosubscribe(True)
        enabled = yield self.tool.is_share_autosubscribe_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_disable_share_autosubscribe(self):
        """Test for disable_share_autosubscribe."""
        yield self.tool.enable_share_autosubscribe(False)
        enabled = yield self.tool.is_share_autosubscribe_enabled()
        self.assertFalse(enabled)

    @defer.inlineCallbacks
    def test_is_udf_autosubscribe_enabled(self):
        """Test for is_udf_autosubscribe_enabled."""
        yield self.tool.enable_udf_autosubscribe(False)
        enabled = yield self.tool.is_udf_autosubscribe_enabled()
        self.assertFalse(enabled)

        yield self.tool.enable_udf_autosubscribe(True)
        enabled = yield self.tool.is_udf_autosubscribe_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_enable_udf_autosubscribe(self):
        """Test for enable_udf_autosubscribe."""
        yield self.tool.enable_udf_autosubscribe(True)
        enabled = yield self.tool.is_udf_autosubscribe_enabled()
        self.assertTrue(enabled)

    @defer.inlineCallbacks
    def test_disable_udf_autosubscribe(self):
        """Test for disable_udf_autosubscribe."""
        yield self.tool.enable_udf_autosubscribe(False)
        enabled = yield self.tool.is_udf_autosubscribe_enabled()
        self.assertFalse(enabled)

    @defer.inlineCallbacks
    def test_refresh_volumes(self):
        """Test for refresh_volumes method."""
        udf = self._create_udf()
        yield self.main.vm.add_udf(udf)

        share = self._create_share()
        yield self.main.vm.add_share(share)

        volumes = list(self.main.vm.get_volumes(all_volumes=True))

        def volumes_changed():
            """Fake volumes_changed."""
            self.main.event_q.push('VM_VOLUMES_CHANGED', volumes=volumes)

        self.patch(self.main.vm, 'refresh_volumes', volumes_changed)
        result = yield self.tool.refresh_volumes()

        str_volumes = []
        for volume in volumes:
            if isinstance(volume, volume_manager.UDF):
                str_vol = interaction_interfaces.get_udf_dict(volume)
            else:
                str_vol = interaction_interfaces.get_share_dict(volume)
            str_volumes.append(str_vol)
        self.assertEqual(result, str_volumes)

    @defer.inlineCallbacks
    def test_rescan_from_scratch(self):
        """Test for rescan_from_scratch method."""
        udf = self._create_udf(subscribed=True)
        yield self.main.vm.add_udf(udf)
        d = defer.Deferred()
        self.patch(self.main.action_q, 'rescan_from_scratch', d.callback)

        yield self.tool.rescan_from_scratch(udf.volume_id)
        vol_id = yield d
        self.assertEqual(vol_id, udf.volume_id)

    @skipIfNotOS('linux2',
                 "Exception is raised twice from PB in same process.")
    @defer.inlineCallbacks
    def test_rescan_from_scratch_missing_volume(self):
        """Test for rescan_from_scratch method with a non-existing volume.."""
        result = yield self.assertFailure(self.tool.rescan_from_scratch('foo'),
                                          tools.IPCError)
        self.assertIn('VolumeDoesNotExist', result.name)
        self.assertIn('DOES_NOT_EXIST', result.info[0])

    @defer.inlineCallbacks
    def test_get_dirty_nodes(self):
        """Test for get_dirty_nodes method."""
        # create some nodes
        path1 = os.path.join(self.root_dir, u'ñoño-1'.encode('utf-8'))
        mdid1 = self.main.fs.create(path1, "")
        path2 = os.path.join(self.root_dir, u'ñoño-2'.encode('utf-8'))
        mdid2 = self.main.fs.create(path2, "")
        path3 = os.path.join(self.root_dir, "path3")
        mdid3 = self.main.fs.create(path3, "")
        path4 = os.path.join(self.root_dir, "path4")
        mdid4 = self.main.fs.create(path4, "")

        # dirty some
        self.main.fs.set_by_mdid(mdid2, dirty=True)
        self.main.fs.set_by_mdid(mdid4, dirty=True)

        # check
        all_dirty = yield self.tool.get_dirty_nodes()
        dirty_mdids = dict((n['mdid'], n) for n in all_dirty)
        self.assertEqual(len(all_dirty), 2)
        self.assertIn(mdid2, dirty_mdids)
        self.assertIn(mdid4, dirty_mdids)
        self.assertNotIn(mdid1, dirty_mdids)
        self.assertNotIn(mdid3, dirty_mdids)
        # check that path de/encoding is done correctly
        self.assertEqual(repr(self.main.fs.get_by_mdid(mdid2).path),
                         repr(dirty_mdids[mdid2]['path'].encode('utf-8')))

    @defer.inlineCallbacks
    def test_get_home_dir(self):
        """Test the get_home_dir method."""
        result = yield self.tool.get_home_dir()
        self.assertEqual(self.main.get_homedir().decode('utf-8'), result)

    @defer.inlineCallbacks
    def test_get_root_dir(self):
        """Test the get_root_dir method."""
        result = yield self.tool.get_root_dir()
        self.assertEqual(self.main.root_dir, result)

    @defer.inlineCallbacks
    def test_get_shares_dir(self):
        """Test the get_shares_dir method."""
        result = yield self.tool.get_shares_dir()
        self.assertEqual(self.main.shares_dir, result)

    @defer.inlineCallbacks
    def test_get_shares_dir_link(self):
        """Test the get_shares_dir_link method."""
        result = yield self.tool.get_shares_dir_link()
        self.assertEqual(self.main.shares_dir_link, result)
