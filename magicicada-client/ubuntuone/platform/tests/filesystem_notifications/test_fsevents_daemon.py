# -*- coding: utf-8 *-*
#
# Copyright 2012 Canonical Ltd.
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
"""Tests for the fseventsd daemon integration."""

import os

from twisted.internet import defer, protocol

from contrib.testing.testcase import BaseTwistedTestCase
from ubuntuone import fseventsd
try:
    from ubuntuone.devtools.testcases import skipIf
    from ubuntuone.devtools.testcases.txsocketserver import TidyUnixServer
except ImportError:
    from ubuntuone.devtools.testcase import skipIf
    TidyUnixServer = None
from ubuntuone.platform.filesystem_notifications.monitor.darwin import (
    fsevents_daemon,
)
from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    IN_CREATE,
    IN_DELETE,
    IN_MODIFY,
    IN_MOVED_FROM,
    IN_MOVED_TO,
)


class FakeServerProtocol(protocol.Protocol):
    """A test protocol."""

    def dataReceived(self, data):
        """Echo the data received."""
        self.transport.write(data)


class FakeServerFactory(protocol.ServerFactory):
    """A factory for the test server."""

    protocol = FakeServerProtocol


class FakeDaemonEvent(object):
    """A fake daemon event."""

    def __init__(self):
        self.event_paths = []
        self.is_directory = False
        self.event_type = None


class FakeProcessor(object):
    """A fake processor."""

    def __init__(self, *args):
        """Create a new instance."""
        self.processed_events = []

    def __call__(self, event):
        """Process and event."""
        self.processed_events.append(event)


class FakePyInotifyEventsFactory(object):
    """Fake factory."""

    def __init__(self):
        """Create a new instance."""
        self.processor = FakeProcessor()
        self.called = []
        self.watched_paths = []
        self.ignored_paths = []


class FakeTransport(object):
    """A fake transport for the protocol."""

    def __init__(self):
        """Create a new instance."""
        self.called = []

    def loseConnection(self):
        """Lost the connection."""
        self.called.append('loseConnection')


class FakeProtocol(object):
    """A fake protocol object to interact with the daemon."""

    def __init__(self):
        """Create a new instance."""
        self.called = []
        self.transport = FakeTransport()

    def remove_user(self):
        """Remove the user."""
        self.called.append('remove_user')
        return defer.succeed(None)

    def remove_path(self, path):
        """Remove a path."""
        self.called.extend(['remove_path', path])
        return defer.succeed(True)

    def add_path(self, path):
        """Add a path."""
        self.called.extend(['add_path', path])


class PyInotifyEventsFactoryTestCase(BaseTwistedTestCase):
    """Test the factory used to receive events."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set the diff tests."""
        yield super(PyInotifyEventsFactoryTestCase, self).setUp()
        self.processor = FakeProcessor()
        self.factory = fsevents_daemon.PyInotifyEventsFactory(self.processor)

    def test_path_interesting_not_watched_or_ignored(self):
        """Test that we do know if the path is not interesting."""
        path = u'/not/watched/path'
        self.assertTrue(self.factory.path_is_not_interesting(path))

    def test_path_interesting_watched_not_ignored(self):
        """Test that we do not know if the path is not interesting."""
        path = u'/watched/path'
        self.factory.watched_paths.append(path)
        self.assertFalse(self.factory.path_is_not_interesting(path))

    def test_path_interesting_watched_but_ignored(self):
        """Test that we do not know if the path is not interesting."""
        path = u'/ignored/path'
        self.factory.watched_paths.append(path)
        self.factory.ignored_paths.append(path)
        self.assertTrue(self.factory.path_is_not_interesting(path))

    def test_path_interesting_not_watched_but_ignored(self):
        """Test that we do not know if the path is not interesting."""
        path = u'/ignored/path'
        self.factory.ignored_paths.append(path)
        self.assertTrue(self.factory.path_is_not_interesting(path))

    def test_is_create_false_rename(self):
        """Test if we do know when an event is a create."""
        source_path = u'/other/watched/path'
        destination_path = u'/watched/path'
        source_head, _ = os.path.split(source_path)
        destination_head, _ = os.path.split(destination_path)
        self.factory.watched_paths.extend([source_head, destination_head])
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        self.assertFalse(self.factory.is_create(event))

    def test_is_create_false_delete(self):
        """Test if we do know when an event is a create."""
        source_path = u'/watched/path'
        destination_path = u'/not/watched/path'
        source_head, _ = os.path.split(source_path)
        self.factory.watched_paths.append(source_head)
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        self.assertFalse(self.factory.is_create(event))

    def test_is_create_true(self):
        """Test is we do know when an event is a create."""
        source_path = u'/not/watched/path'
        destination_path = u'/watched/path'
        destination_head, _ = os.path.split(destination_path)
        self.factory.watched_paths.append(destination_head)
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        self.assertTrue(self.factory.is_create(event))

    def test_is_delete_false_rename(self):
        """Test if we do know when an event is a delete."""
        source_path = u'/other/watched/path'
        destination_path = u'/watched/path'
        source_head, _ = os.path.split(source_path)
        destination_head, _ = os.path.split(destination_path)
        self.factory.watched_paths.extend([source_head, destination_head])
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        self.assertFalse(self.factory.is_delete(event))

    def test_is_delete_false_create(self):
        """Test if we do know when an event is a delete."""
        source_path = u'/not/watched/path'
        destination_path = u'/watched/path'
        destination_head, _ = os.path.split(destination_path)
        self.factory.watched_paths.append(destination_head)
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        self.assertFalse(self.factory.is_delete(event))

    def test_is_delete_true(self):
        """Test if we do know when an event is a delete."""
        source_path = u'/watched/path'
        destination_path = u'/not/watched/path'
        source_head, _ = os.path.split(source_path)
        self.factory.watched_paths.append(source_head)
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        self.assertTrue(self.factory.is_delete(event))

    def test_generate_from_event(self):
        """Test the creation of a fake from event."""
        cookie = 'cookie'
        source_path = u'/source/path'
        destination_path = u'/destination/path'
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        pyinotify_event = self.factory.generate_from_event(event, cookie)
        self.assertEqual(cookie, pyinotify_event.cookie)
        self.assertEqual(0, pyinotify_event.wd)
        self.assertEqual(event.is_directory, pyinotify_event.dir)
        self.assertEqual(IN_MOVED_FROM, pyinotify_event.mask)
        self.assertEqual(source_path, pyinotify_event.pathname)

    def test_generate_to_event(self):
        """Test the creation of a fake to event."""
        cookie = 'cookie'
        source_path = u'/source/path'
        destination_path = u'/destination/path'
        event = FakeDaemonEvent()
        event.event_paths.extend([source_path, destination_path])
        pyinotify_event = self.factory.generate_to_event(event, cookie)
        self.assertEqual(cookie, pyinotify_event.cookie)
        self.assertEqual(0, pyinotify_event.wd)
        self.assertEqual(event.is_directory, pyinotify_event.dir)
        self.assertEqual(IN_MOVED_TO, pyinotify_event.mask)
        self.assertEqual(destination_path, pyinotify_event.pathname)

    def test_convert_in_pyinotify_event_no_rename(self):
        """Test the creation of a no rename event."""
        event_path = u'/path/of/the/event'
        for action in fsevents_daemon.DARWIN_ACTIONS:
            event = FakeDaemonEvent()
            event.event_paths.append(event_path)
            event.event_type = action
            converted_events = self.factory.convert_in_pyinotify_event(event)
            self.assertEqual(1, len(converted_events))
            pyinotify_event = converted_events[0]
            self.assertEqual(0, pyinotify_event.wd)
            self.assertEqual(event.is_directory, pyinotify_event.dir)
            self.assertEqual(
                fsevents_daemon.DARWIN_ACTIONS[action],
                pyinotify_event.mask)
            self.assertEqual(event_path, pyinotify_event.pathname)

    def test_convert_in_pyinotify_event_rename_create(self):
        """Test the creation of a rename which is a create/modify pair."""
        source_path = u'/not/watched/path'
        destination_path = u'/watched/path'
        head, _ = os.path.split(destination_path)
        self.factory.watched_paths.append(head)
        event = FakeDaemonEvent()
        event.event_type = fseventsd.FSE_RENAME
        event.event_paths.extend([source_path, destination_path])
        converted_events = self.factory.convert_in_pyinotify_event(event)
        self.assertEqual(2, len(converted_events))
        pyi_create_event = converted_events[0]
        self.assertEqual(0, pyi_create_event.wd)
        self.assertEqual(event.is_directory, pyi_create_event.dir)
        self.assertEqual(IN_CREATE, pyi_create_event.mask)
        self.assertEqual(destination_path, pyi_create_event.pathname)

        pyi_modify_event = converted_events[1]
        self.assertEqual(0, pyi_modify_event.wd)
        self.assertEqual(event.is_directory, pyi_modify_event.dir)
        self.assertEqual(IN_MODIFY, pyi_modify_event.mask)
        self.assertEqual(destination_path, pyi_modify_event.pathname)

    def test_convert_in_pyinotify_event_rename_delete(self):
        """Test the creation of a rename which is a delete."""
        source_path = u'/watched/path'
        destination_path = u'/not/watched/path'
        head, _ = os.path.split(source_path)
        self.factory.watched_paths.append(head)
        event = FakeDaemonEvent()
        event.event_type = fseventsd.FSE_RENAME
        event.event_paths.extend([source_path, destination_path])
        converted_events = self.factory.convert_in_pyinotify_event(event)
        self.assertEqual(1, len(converted_events))
        pyinotify_event = converted_events[0]
        self.assertEqual(0, pyinotify_event.wd)
        self.assertEqual(event.is_directory, pyinotify_event.dir)
        self.assertEqual(IN_DELETE, pyinotify_event.mask)
        self.assertEqual(source_path, pyinotify_event.pathname)

    def test_convert_in_pyinotify_event_rename(self):
        """Test the creation of a rename event."""
        source_path = u'/watched/path1'
        destination_path = u'/watched/path2'
        head, _ = os.path.split(source_path)
        self.factory.watched_paths.append(head)
        event = FakeDaemonEvent()
        event.event_type = fseventsd.FSE_RENAME
        event.event_paths.extend([source_path, destination_path])
        converted_events = self.factory.convert_in_pyinotify_event(event)
        self.assertEqual(2, len(converted_events))
        from_event = converted_events[0]
        to_event = converted_events[1]
        # assert from event
        self.assertEqual(0, from_event.wd)
        self.assertEqual(event.is_directory, from_event.dir)
        self.assertEqual(IN_MOVED_FROM, from_event.mask)
        self.assertEqual(source_path, from_event.pathname)
        # assert to event
        self.assertEqual(0, to_event.wd)
        self.assertEqual(event.is_directory, to_event.dir)
        self.assertEqual(IN_MOVED_TO, to_event.mask)
        self.assertEqual(destination_path, to_event.pathname)
        # assert cookie
        self.assertEqual(from_event.cookie, to_event.cookie)

    def test_process_event_ignored_type(self):
        """Test processing the event of an ignored type."""
        for action in fsevents_daemon.DARWIN_IGNORED_ACTIONS:
            event = FakeDaemonEvent()
            event.event_type = action
            self.factory.process_event(event)
        self.assertEqual(0, len(self.processor.processed_events))

    def test_process_event_dropped(self):
        """Test processing the drop of the events."""
        func_called = []
        event = FakeDaemonEvent()
        event.event_type = fseventsd.FSE_EVENTS_DROPPED

        def fake_events_dropped():
            """A fake events dropped implementation."""
            func_called.append('fake_events_dropped')

        self.patch(self.factory, 'events_dropper', fake_events_dropped)
        self.factory.process_event(event)
        self.assertIn('fake_events_dropped', func_called)

    def test_process_ignored_path(self):
        """Test processing events from an ignored path."""
        event_path = u'/path/of/the/event'
        head, _ = os.path.split(event_path)
        self.factory.ignored_paths.append(head)
        event = FakeDaemonEvent()
        event.event_paths.append(event_path)
        event.event_type = fseventsd.FSE_CREATE_FILE
        self.factory.process_event(event)
        self.assertEqual(0, len(self.processor.processed_events))

    def test_process_not_ignored_path(self):
        """Test processing events that are not ignored."""
        event_path = u'/path/of/the/event'
        head, _ = os.path.split(event_path)
        self.factory.watched_paths.append(head)
        event = FakeDaemonEvent()
        event.event_paths.append(event_path)
        event.event_type = fseventsd.FSE_CREATE_FILE
        self.factory.process_event(event)
        self.assertEqual(1, len(self.processor.processed_events))
        self.assertEqual(
            event_path, self.processor.processed_events[0].pathname)


class FilesystemMonitorTestCase(BaseTwistedTestCase):
    """Test the notify processor."""

    def fake_connect_to_daemon(self):
        """A fake connection to daemon call."""
        self.monitor._protocol = self.protocol
        defer.succeed(self.protocol)

    @defer.inlineCallbacks
    def setUp(self):
        """Set the tests."""
        yield super(FilesystemMonitorTestCase, self).setUp()
        self.patch(fsevents_daemon, 'NotifyProcessor', FakeProcessor)
        self.factory = FakePyInotifyEventsFactory()
        self.protocol = FakeProtocol()
        self.monitor = fsevents_daemon.FilesystemMonitor(None, None)
        self.processor = self.monitor._processor

        # override default objects
        self.monitor._factory = self.factory

        # patch the connect
        self.patch(
            fsevents_daemon.FilesystemMonitor, '_connect_to_daemon',
            self.fake_connect_to_daemon)

    @defer.inlineCallbacks
    def test_shutdown_protocol(self):
        """Test shutdown with a protocol."""
        self.monitor._protocol = self.protocol
        yield self.monitor.shutdown()
        self.assertIn('remove_user', self.protocol.called)

    @defer.inlineCallbacks
    def test_shutdown_no_protocol(self):
        """Test shutdown without a protocol."""
        stopped = yield self.monitor.shutdown()
        self.assertTrue(stopped)

    @defer.inlineCallbacks
    def test_rm_path_not_root(self):
        """Test removing a path."""
        dirpath = '/path/to/remove/'
        self.factory.watched_paths.append('/path')
        yield self.monitor.rm_watch(dirpath)
        self.assertIn(dirpath, self.factory.ignored_paths)

    @defer.inlineCallbacks
    def test_rm_path_root(self):
        """Test removing a path that is a root path."""
        dirpath = '/path/to/remove/'
        self.factory.watched_paths.append(dirpath)
        yield self.monitor.rm_watch(dirpath)
        self.assertIn('remove_path', self.protocol.called)
        self.assertIn(dirpath, self.protocol.called)
        self.assertNotIn(dirpath, self.factory.watched_paths)

    @defer.inlineCallbacks
    def test_add_watch_not_root(self):
        """Test adding a watch."""
        dirpath = '/path/to/remove/'
        self.factory.watched_paths.append('/path')
        yield self.monitor.add_watch(dirpath)
        self.assertNotIn('add_path', self.protocol.called)

    @defer.inlineCallbacks
    def test_add_watch_root(self):
        """Test adding a watch that is a root."""
        dirpath = '/path/to/remove/'
        self.factory.watched_paths.append('/other/path')
        yield self.monitor.add_watch(dirpath)
        self.assertIn('add_path', self.protocol.called)
        self.assertIn(dirpath, self.protocol.called)

    @defer.inlineCallbacks
    def test_add_watch_ignored(self):
        """Test adding a watch that was ignored."""
        dirpath = '/path/to/remove/'
        self.factory.ignored_paths.append(dirpath)
        yield self.monitor.add_watch(dirpath)
        self.assertNotIn('add_path', self.protocol.called)

    @skipIf(TidyUnixServer is None,
            'Testcases from txsocketserver not availble.')
    @defer.inlineCallbacks
    def test_is_available_monitor_running(self):
        """Test the method when it is indeed running."""
        monitor_cls = fsevents_daemon.FilesystemMonitor

        # start a fake server for the test
        server = TidyUnixServer()
        yield server.listen_server(FakeServerFactory)
        self.addCleanup(server.clean_up)

        # set the path
        old_socket = fsevents_daemon.DAEMON_SOCKET
        fsevents_daemon.DAEMON_SOCKET = server.path
        self.addCleanup(setattr, fsevents_daemon, 'DAEMON_SOCKET', old_socket)

        result = yield monitor_cls.is_available_monitor()
        self.assertTrue(result)

    @defer.inlineCallbacks
    def test_is_available_monitor_fail(self):
        """Test the method when the daemon is not running."""
        monitor_cls = fsevents_daemon.FilesystemMonitor
        old_socket = fsevents_daemon.DAEMON_SOCKET
        fsevents_daemon.DAEMON_SOCKET += 'test'
        self.addCleanup(setattr, fsevents_daemon, 'DAEMON_SOCKET', old_socket)

        result = yield monitor_cls.is_available_monitor()
        self.assertFalse(result)
