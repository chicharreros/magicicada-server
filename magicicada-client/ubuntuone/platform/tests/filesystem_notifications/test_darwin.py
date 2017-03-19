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
"""Test the filesystem notifications on MAC OS."""

import itertools
import logging
import os
import tempfile
import thread

from twisted.internet import defer

import fsevents

from contrib.testing.testcase import BaseTwistedTestCase

from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.platform.filesystem_notifications.monitor import (
    common,
)
from ubuntuone.platform.filesystem_notifications.monitor.darwin import (
    fsevents_client as filesystem_notifications,
)
from ubuntuone.platform.filesystem_notifications import notify_processor
from ubuntuone.platform.filesystem_notifications.monitor.common import (
    Watch,
    WatchManager,
)
from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    ProcessEvent,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_OPEN,
)
from ubuntuone.platform.tests.filesystem_notifications import (
    BaseFSMonitorTestCase,
    common as common_tests,
)


# A reverse mapping for the tests
REVERSE_MACOS_ACTIONS = {}
for key, value in common.ACTIONS.items():
    REVERSE_MACOS_ACTIONS[value] = key


class FakeEventsProcessor(object):

    """Handle fake events creation and processing."""

    def create_fake_event(self, filename):
        """Create a fake file event."""
        return FakeFileEvent(256, None, filename)

    def custom_process_events(self, watch, events):
        """Adapt to each platform way to process events."""
        for event in events:
            watch.platform_watch._process_events(event)


class FakeFileEvent(object):
    """A Fake FileEvent from macfsevents"""

    def __init__(self, mask, cookie, name):
        self.mask = mask
        self.cookie = cookie
        self.name = name


class FakeObserver(object):
    """Fake fsevents.py Observer for tests that don't need real events."""

    def __init__(self, latency=0, process_asap=True):
        """Do nothing."""

    def start(self):
        """Do nothing."""

    def stop(self):
        """Do nothing."""

    def join(self):
        """Do nothing."""

    def schedule(self, stream):
        """Ignore"""

    def unschedule(self, stream):
        """Ignore"""


class TestCaseHandler(ProcessEvent):
    """ProcessEvent used for test cases."""

    thread_id = None

    def my_init(self, main_thread_id=None, number_events=None, **kwargs):
        """Init the event notifier."""
        self.processed_events = []
        self.main_thread_id = main_thread_id
        self.deferred = defer.Deferred()
        assert number_events is not None
        self.number_events = number_events

    def append_event(self, event):
        """Control that we received the number of events that we want."""
        self.processed_events.append(event)
        if len(self.processed_events) == self.number_events:
            self.deferred.callback(self.processed_events)

    def process_IN_CREATE(self, event):
        """Process the event and add it to the list."""
        self.append_event(event)
        self._verify_thread_id()

    def process_IN_DELETE(self, event):
        """Process the event and add it to the list."""
        self.append_event(event)
        self._verify_thread_id()

    def process_default(self, event):
        """Process the event and add it to the list."""
        self.append_event(event)
        self._verify_thread_id()

    def _verify_thread_id(self):
        """Verify that the event was processed in the correct thread."""
        if self.main_thread_id:
            assert self.main_thread_id == thread.get_ident()


class TestWatch(common_tests.TestWatch):
    """Test the watch so that it returns the same events as pyinotify."""

    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestWatch, self).setUp()
        self.path = '/Users/username/folder'
        self.common_path = '/Users/username/folder'
        self.invalid_path = '/Users/username/path/to/not/dir'
        self.basedir = self.mktemp('test_root')
        self.mask = None
        self.stream = None
        self.memento = MementoHandler()
        self.memento.setLevel(logging.DEBUG)
        self.raw_events = []
        self.paths_checked = []
        old_is_dir = Watch._path_is_dir
        self.fake_events_processor = FakeEventsProcessor()

        def path_is_dir_wrapper(watch, path):
            """Wrapper that gets the checked paths."""
            result = old_is_dir(watch, path)
            self.paths_checked.append((path, result))
            return result

        self.patch(Watch, '_path_is_dir', path_is_dir_wrapper)

    def test_not_ignore_path(self):
        """Test that we do get the events when they do not match."""
        self.patch(
            filesystem_notifications.reactor, 'callFromThread',
            lambda x, e: x(e))
        super(TestWatch, self).test_not_ignore_path()

    def test_undo_ignore_path_ignored(self):
        """Test that we do deal with events from and old ignored path."""
        self.patch(
            filesystem_notifications.reactor, 'callFromThread',
            lambda x, e: x(e))
        super(TestWatch, self).test_not_ignore_path()

    def test_undo_ignore_path_other_ignored(self):
        """Test that we can undo and the other path is ignored."""
        self.patch(
            filesystem_notifications.reactor, 'callFromThread',
            lambda x, e: x(e))
        super(TestWatch, self).test_not_ignore_path()

    def test_mixed_ignore_path(self):
        """Test that we do get the correct events."""
        self.patch(
            filesystem_notifications.reactor, 'callFromThread',
            lambda x, e: x(e))
        super(TestWatch, self).test_mixed_ignore_path()

    def test_file_create(self):
        """Test that the correct event is returned on a file create."""
        file_name = os.path.join(self.basedir, 'test_file_create')

        def create_file():
            """Action used for the test."""
            # simply create a new file
            fd = open(file_name, 'w')
            fd.flush()
            os.fsync(fd)
            fd.close()

        events = yield self._perform_operations(
            self.basedir, self.mask, create_file, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(common_tests.OP_FLAGS['IN_CREATE'], event.mask)
        self.assertEqual('IN_CREATE', event.maskname)
        self.assertEqual(os.path.split(file_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, file_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_dir_create(self):
        """Test that the correct event is returned on a dir creation."""
        dir_name = os.path.join(self.basedir, 'test_dir_create')

        def create_dir():
            """Action for the test."""
            os.mkdir(dir_name)

        events = yield self._perform_operations(
            self.basedir, self.mask, create_dir, 1)
        event = events[0]
        self.assertTrue(event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_CREATE'] |
            common_tests.IS_DIR, event.mask)
        self.assertEqual('IN_CREATE|IN_ISDIR', event.maskname)
        self.assertEqual(os.path.split(dir_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, dir_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_file_remove(self):
        """Test that the correct event is raised when a file is removed."""
        file_name = os.path.join(self.basedir, 'test_file_remove')
        # create the file before recording
        open(file_name, 'w').close()

        def remove_file():
            """Action for the test."""
            os.remove(file_name)

        events = yield self._perform_operations(self.basedir, self.mask,
                                                remove_file, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(common_tests.OP_FLAGS['IN_DELETE'], event.mask)
        self.assertEqual('IN_DELETE', event.maskname)
        self.assertEqual(os.path.split(file_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, file_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_dir_remove(self):
        """Test that the correct event is raised when a dir is removed."""
        dir_name = os.path.join(self.basedir, 'test_dir_remove')
        # create the dir before recording
        os.mkdir(dir_name)

        def remove_dir():
            """Action for the test."""
            os.rmdir(dir_name)

        events = yield self._perform_operations(self.basedir, self.mask,
                                                remove_dir, 1)
        event = events[0]
        self.assertTrue(event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_DELETE'] |
            common_tests.IS_DIR, event.mask)
        self.assertEqual('IN_DELETE|IN_ISDIR', event.maskname)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, dir_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_file_write(self):
        """Test that the correct event is raised when a file is written."""
        file_name = os.path.join(self.basedir, 'test_file_write')
        # clean behind us by removing the file
        self.addCleanup(os.remove, file_name)

        def write_file():
            """Action for the test."""
            # create the file before recording
            fd = open(file_name, 'w')
            fd.write('test')
            fd.close()

        events = yield self._perform_operations(self.basedir, self.mask,
                                                write_file, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(common_tests.OP_FLAGS['IN_CREATE'], event.mask)
        self.assertEqual('IN_CREATE', event.maskname)
        self.assertEqual(os.path.split(file_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, file_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_file_moved_to_watched_dir_same_watcher(self):
        """Test that the correct event is raised when a file is moved."""
        from_file_name = os.path.join(
            self.basedir, 'test_file_moved_to_watched_dir_same_watcher')
        to_file_name = os.path.join(
            self.basedir, 'test_file_moved_to_watched_dir_same_watcher_2')
        open(from_file_name, 'w').close()
        # create file before recording

        def move_file():
            """Action for the test."""
            os.rename(from_file_name, to_file_name)

        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_file, 2)
        move_from_event = events[0]
        move_to_event = events[1]
        # first test the move from
        self.assertFalse(move_from_event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_MOVED_FROM'], move_from_event.mask)
        self.assertEqual('IN_MOVED_FROM', move_from_event.maskname)
        self.assertEqual(os.path.split(from_file_name)[1],
                         move_from_event.name)
        self.assertEqual('.', move_from_event.path)
        self.assertEqual(
            os.path.join(self.basedir, from_file_name),
            move_from_event.pathname)
        self.assertEqual(0, move_from_event.wd)
        # test the move to
        self.assertFalse(move_to_event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_MOVED_TO'], move_to_event.mask)
        self.assertEqual('IN_MOVED_TO', move_to_event.maskname)
        self.assertEqual(os.path.split(to_file_name)[1], move_to_event.name)
        self.assertEqual('.', move_to_event.path)
        self.assertEqual(
            os.path.join(self.basedir, to_file_name), move_to_event.pathname)
        self.assertEqual(
            os.path.split(from_file_name)[1], move_to_event.src_pathname)
        self.assertEqual(0, move_to_event.wd)
        # assert that both cookies are the same
        self.assertEqual(move_from_event.cookie, move_to_event.cookie)

    @defer.inlineCallbacks
    def test_file_moved_to_not_watched_dir(self):
        """Test that the correct event is raised when a file is moved."""
        from_file_name = os.path.join(
            self.basedir, 'test_file_moved_to_not_watched_dir')
        open(from_file_name, 'w').close()

        def move_file():
            """Action for the test."""
            target = os.path.join(
                tempfile.mkdtemp(), 'test_file_moved_to_not_watched_dir')
            os.rename(from_file_name, target)

        # We need to test that we get a delete operation when moving
        # a file to an unwatched folder
        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_file, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(common_tests.OP_FLAGS['IN_DELETE'], event.mask)
        self.assertEqual('IN_DELETE', event.maskname)
        self.assertEqual(os.path.split(from_file_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, from_file_name),
                         event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_file_move_from_not_watched_dir(self):
        """Test that the correct event is raised when a file is moved."""
        from_file_name = os.path.join(
            tempfile.mkdtemp(), 'test_file_move_from_not_watched_dir')
        to_file_name = os.path.join(
            self.basedir, 'test_file_move_from_not_watched_dir')
        # create file before we record
        open(from_file_name, 'w').close()

        def move_files():
            """Action for the test."""
            os.rename(from_file_name, to_file_name)

        # We need to test that we get a delete operation when moving
        # a file from an unwatched folder
        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_files, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(common_tests.OP_FLAGS['IN_CREATE'], event.mask)
        self.assertEqual('IN_CREATE', event.maskname)
        self.assertEqual(os.path.split(to_file_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(
            os.path.join(self.basedir, to_file_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_dir_moved_to_watched_dir_same_watcher(self):
        """Test that the correct event is raised when a dir is moved."""
        from_dir_name = os.path.join(
            self.basedir, 'test_dir_moved_to_watched_dir_same_watcher')
        to_dir_name = os.path.join(
            self.basedir, 'test_dir_moved_to_watched_dir_same_watcher_2')
        os.mkdir(from_dir_name)

        def move_file():
            """Action for the test."""
            os.rename(from_dir_name, to_dir_name)

        events = yield self._perform_operations(
            self.basedir, self.mask, move_file, 2)
        move_from_event = events[0]
        move_to_event = events[1]
        # first test the move from
        self.assertTrue(move_from_event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_MOVED_FROM'] | common_tests.IS_DIR,
            move_from_event.mask)
        self.assertEqual('IN_MOVED_FROM|IN_ISDIR', move_from_event.maskname)
        self.assertEqual(os.path.split(from_dir_name)[1], move_from_event.name)
        self.assertEqual('.', move_from_event.path)
        self.assertEqual(
            os.path.join(self.basedir, from_dir_name),
            move_from_event.pathname)
        self.assertEqual(0, move_from_event.wd)
        # test the move to
        self.assertTrue(move_to_event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_MOVED_TO'] | common_tests.IS_DIR,
            move_to_event.mask)
        self.assertEqual('IN_MOVED_TO|IN_ISDIR', move_to_event.maskname)
        self.assertEqual(os.path.split(to_dir_name)[1], move_to_event.name)
        self.assertEqual('.', move_to_event.path)
        self.assertEqual(
            os.path.join(self.basedir, to_dir_name), move_to_event.pathname)
        self.assertEqual(os.path.split(from_dir_name)[1],
                         move_to_event.src_pathname)
        self.assertEqual(0, move_to_event.wd)
        # assert that both cookies are the same
        self.assertEqual(move_from_event.cookie, move_to_event.cookie)

    @defer.inlineCallbacks
    def test_dir_moved_to_not_watched_dir(self):
        """Test that the correct event is raised when a file is moved."""
        dir_name = os.path.join(
            self.basedir, 'test_dir_moved_to_not_watched_dir')
        os.mkdir(dir_name)

        def move_dir():
            """Action for the test."""
            target = os.path.join(
                tempfile.mkdtemp(), 'test_dir_moved_to_not_watched_dir')
            os.rename(dir_name, target)

        # We need to test that we get a delete operation when moving
        # a file to an unwatched folder
        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_dir, 1)
        event = events[0]
        self.assertTrue(event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_DELETE'] | common_tests.IS_DIR,
            event.mask)
        self.assertEqual('IN_DELETE|IN_ISDIR', event.maskname)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, dir_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_dir_move_from_not_watched_dir(self):
        """Test that the correct event is raised when a file is moved."""
        from_dir_name = os.path.join(
            tempfile.mkdtemp(), 'test_dir_move_from_not_watched_dir')
        to_dir_name = os.path.join(
            self.basedir, 'test_dir_move_from_not_watched_dir')
        # create file before we record
        os.mkdir(from_dir_name)

        def move_dir():
            """Action for the test."""
            os.rename(from_dir_name, to_dir_name)

        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_dir, 1)
        event = events[0]
        self.assertTrue(event.dir)
        self.assertEqual(
            common_tests.OP_FLAGS['IN_CREATE'] | common_tests.IS_DIR,
            event.mask)
        self.assertEqual('IN_CREATE|IN_ISDIR', event.maskname)
        self.assertEqual(os.path.split(from_dir_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, to_dir_name),
                         event.pathname)
        self.assertEqual(0, event.wd)

    def test_exclude_filter(self):
        """Test that the exclude filter works as expectd."""
        handler = TestCaseHandler(number_events=0)
        manager = WatchManager(handler)
        self.addCleanup(manager.stop)
        # add a watch that will always exclude all actions
        manager.add_watch(
            self.basedir, self.mask, exclude_filter=lambda x: True)
        # execution the actions
        file_name = os.path.join(self.basedir, 'test_file_create')
        open(file_name, 'w').close()
        # give some time for the system to get the events
        self.assertEqual(0, len(handler.processed_events))
    test_exclude_filter.skip = "we must rethink this test."

    def test_stream_created(self):
        """Test that the stream is created."""
        def fake_call(*args, **kwargs):
            """Fake call."""

        path = '/Users/username/folder/'
        watch = Watch(1, path, None)
        self.assertEqual(
            watch.platform_watch._process_events,
            watch.platform_watch.stream.callback)
        self.assertEqual(watch.platform_watch.stream.paths, [path])
        self.assertEqual(watch.platform_watch.stream.file_events, True)

    def test_watching_property(self):
        """Test that the stopped property returns the stopped deferred."""
        path = '/Users/username/folder'
        watch = Watch(1, path, None)
        self.assertFalse(watch.watching)

    def random_error(self, *args):
        """Throw a fake exception."""
        raise common_tests.FakeException()

    def test_is_path_dir_missing_no_subdir(self):
        """Test when the path does not exist and is no a subdir."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: False)
        watch = Watch(1, test_path, None)
        self.assertFalse(watch._path_is_dir(path))

    def test_is_path_dir_missing_in_subdir(self):
        """Test when the path does not exist and is a subdir."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: False)
        watch = Watch(1, test_path, None)
        watch._subdirs.add(path)
        self.assertTrue(watch._path_is_dir(path))

    def test_is_path_dir_present_is_dir(self):
        """Test when the path is present and is dir."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: True)
        self.patch(os.path, 'isdir', lambda path: True)
        watch = Watch(1, test_path, None)
        watch._subdirs.add(path)
        self.assertTrue(watch._path_is_dir(path))

    def test_is_path_dir_present_no_dir(self):
        """Test when the path is present but not a dir."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: True)
        self.patch(os.path, 'isdir', lambda path: False)
        watch = Watch(1, test_path, None)
        watch._subdirs.add(path)
        self.assertFalse(watch._path_is_dir(path))

    def test_update_subdirs_create_not_present(self):
        """Test when we update on a create event and not present."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._update_subdirs(path, REVERSE_MACOS_ACTIONS[IN_CREATE])
        self.assertTrue(path in watch._subdirs)

    def test_update_subdirs_create_present(self):
        """Test when we update on a create event and is present."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._subdirs.add(path)
        old_length = len(watch._subdirs)
        watch._update_subdirs(path, REVERSE_MACOS_ACTIONS[IN_CREATE])
        self.assertTrue(path in watch._subdirs)
        self.assertEqual(old_length, len(watch._subdirs))

    def test_update_subdirs_delete_not_present(self):
        """Test when we delete and is not present."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._update_subdirs(path, REVERSE_MACOS_ACTIONS[IN_DELETE])
        self.assertTrue(path not in watch._subdirs)

    def test_update_subdirs_delete_present(self):
        """Test when we delete and is present."""
        path = '/Users/username/path/to/not/dir'
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._subdirs.add(path)
        watch._update_subdirs(path, REVERSE_MACOS_ACTIONS[IN_DELETE])
        self.assertTrue(path not in watch._subdirs)


class TestWatchManagerStopping(common_tests.TestWatchManagerStopping):
    """Test stopping the watch manager."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set each of the tests."""
        yield super(TestWatchManagerStopping, self).setUp()
        self.parent_path = '/Users/username/'
        self.path = self.parent_path + 'path'
        self.watch = Watch(1, self.path, None)
        self.manager._wdm = {1: self.watch}
        self.stream = None
        self.fake_events_processor = FakeEventsProcessor()
        self.patch(self.manager.platform_manager.observer, "unschedule",
                   lambda x: None)

    @defer.inlineCallbacks
    def test_stop(self):
        """Test that the different watches are stopped."""
        yield super(TestWatchManagerStopping, self).test_stop()

    def test_stop_multiple(self):
        """Watches should became watching=False and the observer stopped."""
        second_path = self.parent_path + "second_path"
        second_watch = Watch(2, second_path, None)
        second_watch._watching = True
        self.manager._wdm[2] = second_watch
        self.manager.stop()
        self.assertFalse(second_watch.platform_watch.watching)
        self.assertEqual(second_watch._subdirs, set())
        # Give time to the thread to be finished.
        self.manager.platform_manager.observer.join()
        self.assertFalse(self.manager.platform_manager.observer.is_alive())


class TestWatchManager(common_tests.TestWatchManager):
    """Test the watch manager."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup."""

        # Note: patching Observer before super.setUp because it is
        # used by the WatchManager we create there.
        self.patch(fsevents, "Observer", FakeObserver)

        yield super(TestWatchManager, self).setUp()

        self.parent_path = '/Users/username/'
        self.path = self.parent_path + 'path'
        self.watch = Watch(1, self.path, None)
        self.manager._wdm = {1: self.watch}
        self.stream = None
        self.fake_events_processor = FakeEventsProcessor()

    def test_get_present_watch(self):
        """Test that we can get a Watch using is wd."""
        self.assertEqual(self.watch, self.manager.get_watch(1))

    def test_get_missing_watch(self):
        """Test that we get an error when trying to get a missing wd."""
        self.assertRaises(KeyError, self.manager.get_watch, (1,))

    def test_add_single_watch(self):
        """Test the addition of a new single watch."""
        self.was_called = False

        def fake_start_watching(*args):
            """Fake start watch."""
            self.was_called = True

        self.patch(Watch, "start_watching", fake_start_watching)
        self.manager._wdm = {}

        mask = 'bit_mask'
        self.manager.add_watch(self.path, mask)
        self.assertEqual(1, len(self.manager._wdm))
        self.assertTrue(self.was_called, 'The watch start was not called.')
        self.assertEqual(self.path + os.path.sep, self.manager._wdm[0].path)

    def test_get_watch_missing_wd(self):
        """Test that the correct path is returned."""
        self.manager._wdm = {}
        self.assertEqual(None, self.manager.get_path(1))

    def test_get_wd_exact_path(self):
        """Test the wd is returned when there is a watch for the path."""
        self.assertEqual(1, self.manager.get_wd(self.path))

    def test_get_wd_child_path(self):
        """Test the wd is returned when we have a child path."""
        child = os.path.join(self.path, 'child')
        self.assertEqual(1, self.manager.get_wd(child))

    def test_get_wd_unwatched(self):
        """A watch on an unwatched path returns None."""
        self.assertEqual(None, self.manager.get_wd(self.parent_path))

    def test_rm_present_wd(self):
        """Test the removal of a present watch."""
        self.patch(self.manager.platform_manager.observer,
                   "unschedule", lambda x: None)
        super(TestWatchManager, self).test_rm_present_wd()

    def test_rm_child_path(self):
        """Test the removal of a child path."""
        self.patch(
            filesystem_notifications.reactor, 'callFromThread',
            lambda x, e: x(e))
        super(TestWatchManager, self).test_rm_child_path()


class TestWatchManagerAddWatches(BaseTwistedTestCase):
    """Test the watch manager."""
    timeout = 5

    def test_add_watch_twice(self):
        """Adding a watch twice succeeds when the watch is running."""
        self.patch(Watch, "start_watching", lambda self: None)
        self.patch(Watch, "started", lambda self: True)
        manager = WatchManager(None)
        self.addCleanup(manager.stop)

        path = '/Users/username/path'
        mask = 'fake bit mask'
        d1 = manager.add_watch(path, mask)
        d2 = manager.add_watch(path, mask)

        self.assertTrue(d1.result, "Should not be called yet.")
        self.assertTrue(d2, "Should not be called yet.")


class FakeEvent(object):
    """Fake event."""

    def __init__(self, wd=0, dir=True, name=None, path=None, pathname=None,
                 cookie=None):
        """Create fake event."""
        self.dir = dir
        self.wd = wd
        self.name = name
        self.path = path
        self.pathname = pathname
        self.cookie = cookie


class TestNotifyProcessor(common_tests.TestNotifyProcessor):
    """Test the notify processor."""

    @defer.inlineCallbacks
    def setUp(self):
        """set up the different tests."""
        yield super(TestNotifyProcessor, self).setUp()
        self.processor = notify_processor.NotifyProcessor(None)
        self.general = common_tests.FakeGeneralProcessor()
        self.processor.general_processor = self.general

    def test_rm_from_mute_filter(self):
        """Test that we remove the event from the mute filter."""
        event = 'event'
        paths = 'paths'
        self.processor.rm_from_mute_filter(event, paths)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('rm_from_mute_filter',
                         self.general.called_methods[0][0])
        self.assertEqual(event, self.general.called_methods[0][1])
        self.assertEqual(paths, self.general.called_methods[0][2])

    def test_add_to_mute_filter(self):
        """Test that we add the path to the mute filter."""
        event = 'event'
        paths = 'paths'
        self.processor.add_to_mute_filter(event, paths)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('add_to_mute_filter',
                         self.general.called_methods[0][0])
        self.assertEqual(event, self.general.called_methods[0][1])
        self.assertEqual(paths, self.general.called_methods[0][2])

    def test_is_ignored(self):
        """Test that we do ensure that the path is ignored."""
        path = 'path'
        self.processor.is_ignored(path)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('is_ignored',
                         self.general.called_methods[0][0])
        self.assertEqual(path, self.general.called_methods[0][1])

    def test_release_held_event(self):
        """Test that we do release the held event."""
        event = 'event'
        # set the held event to assert that is pushed
        self.processor.held_event = event
        self.processor.release_held_event()
        self.assertEqual('push_event',
                         self.general.called_methods[0][0])
        self.assertEqual(event, self.general.called_methods[0][1])

    def test_process_IN_MODIFY_dir(self):
        """Test that the modify works as exepcted with dirs."""
        event = FakeEvent(dir=True)
        self.processor.process_IN_MODIFY(event)
        # no method should be called
        self.assertEqual(0, len(self.general.called_methods))

    def test_process_IN_MODIFY_file(self):
        """Test that the modify works as expected with files."""
        event = FakeEvent(dir=False, wd=0, name='name',
                          path='path', pathname='pathname')
        self.processor.process_IN_MODIFY(event)
        # we should be getting two different method, and open and a close
        self.assertEqual(2, len(self.general.called_methods))
        self.assertEqual('push_event',
                         self.general.called_methods[0][0])
        self.assertEqual('push_event',
                         self.general.called_methods[1][0])
        self.assertEqual(event.dir, self.general.called_methods[0][1].dir)
        self.assertEqual(event.wd, self.general.called_methods[0][1].wd)
        self.assertEqual(event.name, self.general.called_methods[0][1].name)
        self.assertEqual(event.path, self.general.called_methods[0][1].path)
        self.assertEqual(event.pathname,
                         self.general.called_methods[0][1].pathname)
        self.assertEqual(IN_OPEN,
                         self.general.called_methods[0][1].mask)
        self.assertEqual(event.dir, self.general.called_methods[1][1].dir)
        self.assertEqual(event.wd, self.general.called_methods[1][1].wd)
        self.assertEqual(event.name, self.general.called_methods[1][1].name)
        self.assertEqual(event.path, self.general.called_methods[1][1].path)
        self.assertEqual(event.pathname,
                         self.general.called_methods[1][1].pathname)
        self.assertEqual(IN_CLOSE_WRITE,
                         self.general.called_methods[1][1].mask)

    def test_process_IN_MOVED_FROM(self):
        """Test that the in moved from works as expected."""
        event = FakeEvent(dir=False, wd=0, name='name',
                          path='path', pathname='pathname')
        self.processor.process_IN_MOVED_FROM(event)
        self.assertEqual(event, self.processor.held_event)

    def test_process_IN_MOVED_TO_dir(self):
        """Test that the in moved to works as expected."""
        event = FakeEvent(wd=0, dir=True, name='name', path='path',
                          pathname=os.path.join('test', 'pathname'),
                          cookie='cookie')
        held_event = FakeEvent(wd=0, dir=True, name='hname', path='hpath',
                               pathname=os.path.join('test', 'hpathname'),
                               cookie='cookie')
        self.general.share_id = 'my_share_id'
        self.processor.held_event = held_event
        self.processor.process_IN_MOVED_TO(event)
        self.assertEqual(5, len(self.general.called_methods))
        # assert that the ignores are called
        self.assertEqual('is_ignored', self.general.called_methods[0][0])
        self.assertEqual(held_event.pathname,
                         self.general.called_methods[0][1])
        self.assertEqual('is_ignored', self.general.called_methods[1][0])
        self.assertEqual(event.pathname, self.general.called_methods[1][1])
        # assert that we do request the share_id
        self.assertEqual('get_path_share_id',
                         self.general.called_methods[2][0])
        self.assertEqual(os.path.split(event.pathname)[0],
                         self.general.called_methods[2][1],
                         'Get the share_id for event')
        self.assertEqual('get_path_share_id',
                         self.general.called_methods[3][0])
        self.assertEqual(os.path.split(held_event.pathname)[0],
                         self.general.called_methods[3][1],
                         'Get the share_id for held event.')

        self.assertEqual('eq_push', self.general.called_methods[4][0])
        self.assertEqual('FS_DIR_MOVE', self.general.called_methods[4][1])
        self.assertEqual(event.pathname, self.general.called_methods[4][3])
        self.assertEqual(held_event.pathname,
                         self.general.called_methods[4][4])

    def test_process_IN_MOVED_TO_file(self):
        """Test that the in moved to works as expected."""
        event = FakeEvent(wd=0, dir=False, name='name', path='path',
                          pathname=os.path.join('test', 'pathname'),
                          cookie='cookie')
        held_event = FakeEvent(wd=0, dir=False, name='hname', path='hpath',
                               pathname=os.path.join('test', 'hpathname'),
                               cookie='cookie')
        self.general.share_id = 'my_share_id'
        self.processor.held_event = held_event
        self.processor.process_IN_MOVED_TO(event)
        self.assertEqual(5, len(self.general.called_methods))
        # assert that the ignores are called
        self.assertEqual('is_ignored', self.general.called_methods[0][0])
        self.assertEqual(held_event.pathname,
                         self.general.called_methods[0][1])
        self.assertEqual('is_ignored', self.general.called_methods[1][0])
        self.assertEqual(event.pathname, self.general.called_methods[1][1])
        # assert that we do request the share_id
        self.assertEqual('get_path_share_id',
                         self.general.called_methods[2][0])
        self.assertEqual(os.path.split(event.pathname)[0],
                         self.general.called_methods[2][1],
                         'Get the share_id for event')
        self.assertEqual('get_path_share_id',
                         self.general.called_methods[3][0])
        self.assertEqual(os.path.split(held_event.pathname)[0],
                         self.general.called_methods[3][1],
                         'Get the share_id for held event.')

        self.assertEqual('eq_push', self.general.called_methods[4][0])
        self.assertEqual('FS_FILE_MOVE', self.general.called_methods[4][1])
        self.assertEqual(event.pathname, self.general.called_methods[4][3])
        self.assertEqual(held_event.pathname,
                         self.general.called_methods[4][4])

    def test_fake_create_event_dir(self):
        """Test that the in moved to works as expected."""
        event = FakeEvent(wd=0, dir=True, name='name', path='path',
                          pathname='pathname')
        self.processor._fake_create_event(event)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('eq_push', self.general.called_methods[0][0])
        self.assertEqual('FS_DIR_CREATE', self.general.called_methods[0][1])
        self.assertEqual(event.pathname, self.general.called_methods[0][2])

    def test_fake_create_event_file(self):
        """Test that the in moved to works as expected."""
        event = FakeEvent(wd=0, dir=False, name='name', path='path',
                          pathname='pathname')
        self.processor._fake_create_event(event)
        self.assertEqual(2, len(self.general.called_methods))
        self.assertEqual('eq_push', self.general.called_methods[0][0])
        self.assertEqual('FS_FILE_CREATE', self.general.called_methods[0][1])
        self.assertEqual(event.pathname, self.general.called_methods[0][2])
        self.assertEqual('eq_push', self.general.called_methods[1][0])
        self.assertEqual('FS_FILE_CLOSE_WRITE',
                         self.general.called_methods[1][1])
        self.assertEqual(event.pathname, self.general.called_methods[1][2])

    def test_fake_delete_create_event_dir(self):
        """Test that we do fake a delete and a later delete."""
        event = FakeEvent(wd=0, dir=True, name='name', path='path',
                          pathname='pathname')
        held_event = FakeEvent(wd=0, dir=True, name='hname', path='hpath',
                               pathname='hpathname')
        self.processor.held_event = held_event
        self.processor._fake_delete_create_event(event)
        self.assertEqual(2, len(self.general.called_methods))
        self.assertEqual('eq_push', self.general.called_methods[0][0])
        self.assertEqual('FS_DIR_DELETE', self.general.called_methods[0][1])
        self.assertEqual(held_event.pathname,
                         self.general.called_methods[0][2])
        self.assertEqual('eq_push', self.general.called_methods[1][0])
        self.assertEqual('FS_DIR_CREATE', self.general.called_methods[1][1])
        self.assertEqual(event.pathname, self.general.called_methods[1][2])

    def test_fake_delete_create_event_file(self):
        """Test that we do fake a delete and a later delete."""
        event = FakeEvent(wd=0, dir=False, name='name', path='path',
                          pathname='pathname')
        held_event = FakeEvent(wd=0, dir=False, name='hname', path='hpath',
                               pathname='hpathname')
        self.processor.held_event = held_event
        self.processor._fake_delete_create_event(event)
        self.assertEqual(3, len(self.general.called_methods))
        self.assertEqual('eq_push', self.general.called_methods[0][0])
        self.assertEqual('FS_FILE_DELETE', self.general.called_methods[0][1])
        self.assertEqual(held_event.pathname,
                         self.general.called_methods[0][2])
        self.assertEqual('eq_push', self.general.called_methods[1][0])
        self.assertEqual('FS_FILE_CREATE', self.general.called_methods[1][1])
        self.assertEqual(event.pathname, self.general.called_methods[1][2])
        self.assertEqual('eq_push', self.general.called_methods[2][0])
        self.assertEqual('FS_FILE_CLOSE_WRITE',
                         self.general.called_methods[2][1])
        self.assertEqual(event.pathname, self.general.called_methods[2][2])

    def test_process_default_no_held(self):
        """Test that the process default works as expected."""
        event = 'event'
        self.processor.process_default(event)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('push_event',
                         self.general.called_methods[0][0])
        self.assertEqual(event,
                         self.general.called_methods[0][1])

    def test_process_default_with_held(self):
        """Test that the process default works as expected."""
        event = 'event'
        held_event = 'held_event'
        self.processor.held_event = held_event
        self.processor.process_default(event)
        self.assertEqual(2, len(self.general.called_methods))
        self.assertEqual('push_event',
                         self.general.called_methods[0][0])
        self.assertEqual(held_event,
                         self.general.called_methods[0][1])
        self.assertEqual('push_event',
                         self.general.called_methods[1][0])
        self.assertEqual(event,
                         self.general.called_methods[1][1])

    def test_handle_dir_delete_files(self):
        """Test that the handle dir delete works as expected."""
        path = 'path'
        present_files = 'abcde'
        # create files and dirs to be returned from the get paths
        for file_name in present_files:
            self.general.paths_to_return.append((file_name, False))
        self.processor.handle_dir_delete(path)
        # there are calls for, rm the watch, get paths and then one per file
        self.assertEqual(len(present_files) + 2,
                         len(self.general.called_methods))
        rm_call = self.general.called_methods.pop(0)
        self.assertEqual('rm_watch', rm_call[0])
        self.assertEqual(path, rm_call[1])
        paths_call = self.general.called_methods.pop(0)
        self.assertEqual('get_paths_starting_with', paths_call[0])
        self.assertEqual(path, paths_call[1])
        self.assertFalse(paths_call[2])
        # we need to push the delete events in reverse order because we want
        # to delete children before we delete parents
        present_files = present_files[::-1]
        for i, called_method in enumerate(self.general.called_methods):
            self.assertEqual('eq_push', called_method[0])
            self.assertEqual('FS_FILE_DELETE', called_method[1])
            self.assertEqual(present_files[i], called_method[2])

    def test_handle_dir_delete_dirs(self):
        """Test that the handle dir delete works as expected."""
        path = 'path'
        present_files = 'abcde'
        # create files and dirs to be returned from the get paths
        for file_name in present_files:
            self.general.paths_to_return.append((file_name, True))
        self.processor.handle_dir_delete(path)
        # there are calls for, rm the watch, get paths and then one per file
        self.assertEqual(2 * len(present_files) + 2,
                         len(self.general.called_methods))
        rm_call = self.general.called_methods.pop(0)
        self.assertEqual('rm_watch', rm_call[0])
        self.assertEqual(path, rm_call[1])
        paths_call = self.general.called_methods.pop(0)
        self.assertEqual('get_paths_starting_with', paths_call[0])
        self.assertEqual(path, paths_call[1])
        self.assertFalse(paths_call[2])
        # we need to push the delete events in reverse order because we want
        # to delete children before we delete parents
        present_files = present_files[::-1]

        # from http://docs.python.org/library/itertools.html#recipes
        def grouper(n, iterable, fillvalue=None):
            "grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx"
            args = [iter(iterable)] * n
            return itertools.izip_longest(fillvalue=fillvalue, *args)

        for i, called_methods in enumerate(grouper(2,
                                           self.general.called_methods)):
            rm_call = called_methods[0]
            self.assertEqual('rm_watch', rm_call[0])
            self.assertEqual(present_files[i], rm_call[1])
            push_call = called_methods[1]
            self.assertEqual('eq_push', push_call[0])
            self.assertEqual('FS_DIR_DELETE', push_call[1])
            self.assertEqual(present_files[i], push_call[2])

    def test_freeze_begin(self):
        """Test that the freeze being works as expected."""
        path = 'path'
        self.processor.freeze_begin(path)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('freeze_begin',
                         self.general.called_methods[0][0])
        self.assertEqual(path, self.general.called_methods[0][1])

    def test_freeze_rollback(self):
        """Test that the freeze rollback works as expected."""
        self.processor.freeze_rollback()
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('freeze_rollback',
                         self.general.called_methods[0][0])

    def test_freeze_commit(self):
        """Test that the freeze commit works as expected."""
        path = 'path'
        self.processor.freeze_commit(path)
        self.assertEqual(1, len(self.general.called_methods))
        self.assertEqual('freeze_commit',
                         self.general.called_methods[0][0])
        self.assertEqual(path, self.general.called_methods[0][1])


class FilesystemMonitorTestCase(BaseFSMonitorTestCase):
    """Tests for the FilesystemMonitor."""

    def test_add_watch_twice(self):
        """Check the deferred returned by a second add_watch."""
        self.patch(Watch, "start_watching", lambda self: None)
        self.patch(Watch, "started", lambda self: True)
        manager = WatchManager(None)
        self.addCleanup(manager.stop)

        path = '/Users/username/path'
        mask = 'fake bit mask'
        d1 = manager.add_watch(path, mask)
        d2 = manager.add_watch(path, mask)

        self.assertTrue(d1.result, "Should not be called yet.")
        self.assertTrue(d2, "Should not be called yet.")

    @defer.inlineCallbacks
    def test_is_available_monitor(self):
        """Test test the is_available_monitor method."""
        # we should always return true
        is_available = yield common.FilesystemMonitor.is_available_monitor()
        self.assertTrue(is_available, 'Should always be available.')
