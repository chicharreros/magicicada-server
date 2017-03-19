#
# Authors: Manuel de la Pena <manuel@canonical.com>
#          Alejandro J. Cura <alecu@canonical.com>
#
# Copyright 2011-2012 Canonical Ltd.
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
"""Test the filesystem notifications on windows."""

import logging
import os
import tempfile
import thread
import time
import itertools

from twisted.internet import defer
from contrib.testing.testcase import BaseTwistedTestCase
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    EventsCodes,
    ProcessEvent,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_DELETE,
    IN_OPEN,
)
from ubuntuone.platform.filesystem_notifications import notify_processor
from ubuntuone.platform.filesystem_notifications.monitor.common import (
    FilesystemMonitor,
    Watch,
    WatchManager,
)
from ubuntuone.platform.filesystem_notifications.monitor import ACTIONS
from ubuntuone.platform.os_helper import get_os_valid_path

OP_FLAGS = EventsCodes.FLAG_COLLECTIONS['OP_FLAGS']
IS_DIR = EventsCodes.FLAG_COLLECTIONS['SPECIAL_FLAGS']['IN_ISDIR']

# create a rever mapping to use it in the tests.
REVERSE_OS_ACTIONS = {}
for key, value in ACTIONS.items():
    REVERSE_OS_ACTIONS[value] = key


class FakeEventsProcessor(object):

    """Handle fake events creation and processing."""

    def create_fake_event(self):
        """Create a fake filesystem event."""
        raise NotImplementedError

    def custom_process_events(self):
        """Process a fake event."""
        raise NotImplementedError


class FakeException(Exception):
    """A fake Exception used in tests."""


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


class TestWatch(BaseTwistedTestCase):
    """Test the watch so that it returns the same events as pyinotify."""

    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestWatch, self).setUp()
        self.path = ''
        self.invalid_path = ''
        self.common_path = ''
        self.basedir = self.mktemp('test_root')
        self.mask = None
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

    @defer.inlineCallbacks
    def _perform_operations(self, path, mask, actions, number_events):
        """Perform the file operations and returns the recorded events."""
        handler = TestCaseHandler(number_events=number_events)
        manager = WatchManager(handler)
        yield manager.add_watch(get_os_valid_path(path), mask)
        # change the logger so that we can check the logs if we wanted
        manager._wdm[0].log.addHandler(self.memento)
        # clean logger later
        self.addCleanup(manager._wdm[0].log.removeHandler, self.memento)
        # execution the actions
        actions()
        # process the recorded events
        ret = yield handler.deferred
        self.addCleanup(manager.stop)
        defer.returnValue(ret)

    @defer.inlineCallbacks
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
        self.assertEqual(OP_FLAGS['IN_CREATE'], event.mask)
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
        self.assertEqual(OP_FLAGS['IN_CREATE'] | IS_DIR, event.mask)
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
        self.assertEqual(OP_FLAGS['IN_DELETE'], event.mask)
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
        self.assertEqual(OP_FLAGS['IN_DELETE'] | IS_DIR, event.mask)
        self.assertEqual('IN_DELETE|IN_ISDIR', event.maskname)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, dir_name), event.pathname)
        self.assertEqual(0, event.wd)

    def test_file_write(self):
        """Test that the correct event is raised when a file is written."""
        raise NotImplementedError

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
        self.assertEqual(OP_FLAGS['IN_MOVED_FROM'], move_from_event.mask)
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
        self.assertEqual(OP_FLAGS['IN_MOVED_TO'], move_to_event.mask)
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

        # while on linux we will have to do some sort of magic like facundo
        # did, on windows we will get a deleted event which is much more
        # cleaner, first time ever windows is nicer!
        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_file, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(OP_FLAGS['IN_DELETE'], event.mask)
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

        # while on linux we have to do some magic operations like facundo did
        # on windows we have a created file, hurray!
        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_files, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(OP_FLAGS['IN_CREATE'], event.mask)
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
            OP_FLAGS['IN_MOVED_FROM'] | IS_DIR, move_from_event.mask)
        self.assertEqual('IN_MOVED_FROM|IN_ISDIR', move_from_event.maskname)
        self.assertEqual(os.path.split(from_dir_name)[1], move_from_event.name)
        self.assertEqual('.', move_from_event.path)
        self.assertEqual(
            os.path.join(self.basedir, from_dir_name),
            move_from_event.pathname)
        self.assertEqual(0, move_from_event.wd)
        # test the move to
        self.assertTrue(move_to_event.dir)
        self.assertEqual(OP_FLAGS['IN_MOVED_TO'] | IS_DIR, move_to_event.mask)
        self.assertEqual('IN_MOVED_TO|IN_ISDIR', move_to_event.maskname)
        self.assertEqual(os.path.split(to_dir_name)[1], move_to_event.name)
        self.assertEqual('.', move_to_event.path)
        self.assertEqual(
            os.path.join(self.basedir, to_dir_name), move_to_event.pathname)
        self.assertEqual(
            os.path.split(from_dir_name)[1], move_to_event.src_pathname)
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

        # on windows a move to outside a watched dir translates to a remove
        events = yield self._perform_operations(self.basedir, self.mask,
                                                move_dir, 1)
        event = events[0]
        self.assertTrue(event.dir)
        self.assertEqual(OP_FLAGS['IN_DELETE'] | IS_DIR, event.mask)
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
        self.assertEqual(OP_FLAGS['IN_CREATE'] | IS_DIR, event.mask)
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
        # add a watch that will always exclude all actions
        manager.add_watch(get_os_valid_path(self.basedir),
                          self.mask, auto_add=True,
                          exclude_filter=lambda x: True)
        # execution the actions
        file_name = os.path.join(self.basedir, 'test_file_create')
        open(file_name, 'w').close()
        # give some time for the system to get the events
        time.sleep(1)
        self.assertEqual(0, len(handler.processed_events))
    test_exclude_filter.skip = "we must rethink this test."

    def test_ignore_path(self):
        """Test that events from a path are ignored."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event)

        child = 'child'
        watch = Watch(1, self.path, None)
        watch.ignore_path(os.path.join(self.path, child))
        paths_to_ignore = []
        for file_name in 'abcdef':
            fake_event = self.fake_events_processor.create_fake_event(
                os.path.join(child, file_name))
            paths_to_ignore.append(fake_event)
        # ensure that the watch is watching
        watch.platform_watch.watching = True
        self.fake_events_processor.custom_process_events(
            watch, paths_to_ignore)
        self.assertEqual(0, len(events),
                         'All events should have been ignored.')

    def test_not_ignore_path(self):
        """Test that we do get the events when they do not match."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event)

        child = 'child'
        watch = Watch(1, self.path, fake_processor)
        watch.ignore_path(os.path.join(self.path, child))
        paths_not_to_ignore = []
        for file_name in 'abcdef':
            event = self.fake_events_processor.create_fake_event(
                os.path.join(child + file_name, file_name))
            paths_not_to_ignore.append(event)
        # ensure that the watch is watching
        watch.platform_watch.watching = True
        self.fake_events_processor.custom_process_events(
            watch, paths_not_to_ignore)
        self.assertEqual(len(paths_not_to_ignore), len(events),
                         'No events should have been ignored.')

    def test_mixed_ignore_path(self):
        """Test that we do get the correct events."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event.pathname)

        child = 'child'
        watch = Watch(1, self.path, fake_processor)
        watch.ignore_path(os.path.join(self.path, child))
        paths_not_to_ignore = []
        paths_to_ignore = []
        expected_events = []
        for file_name in 'abcdef':
            valid = os.path.join(child + file_name, file_name)
            paths_to_ignore.append((1, os.path.join(child, file_name)))
            paths_not_to_ignore.append(
                self.fake_events_processor.create_fake_event(valid))
            expected_events.append(os.path.join(self.common_path, valid))
        # ensure that the watch is watching
        watch.platform_watch.watching = True
        self.fake_events_processor.custom_process_events(
            watch, paths_not_to_ignore)
        self.assertEqual(len(paths_not_to_ignore), len(events),
                         'Wrong number of events ignored.')
        self.assertTrue(all([event in expected_events for event in events]),
                        'Paths ignored that should have not been ignored.')

    def test_undo_ignore_path_ignored(self):
        """Test that we do deal with events from and old ignored path."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event)

        child = 'child'
        watch = Watch(1, self.path, fake_processor)
        watch.ignore_path(os.path.join(self.path, child))
        watch.remove_ignored_path(os.path.join(self.path, child))
        paths_not_to_ignore = []
        for file_name in 'abcdef':
            event = self.fake_events_processor.create_fake_event(
                os.path.join(child, file_name))
            paths_not_to_ignore.append(event)
        # ensure that the watch is watching
        watch.platform_watch.watching = True
        self.fake_events_processor.custom_process_events(
            watch, paths_not_to_ignore)
        self.assertEqual(len(paths_not_to_ignore), len(events),
                         'All events should have been accepted.')

    def test_undo_ignore_path_other_ignored(self):
        """Test that we can undo and the other path is ignored."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event.pathname)

        child_a = 'childa'
        child_b = 'childb'
        watch = Watch(1, self.path, fake_processor)
        watch.ignore_path(os.path.join(self.path, child_a))
        watch.ignore_path(os.path.join(self.path, child_b))
        watch.remove_ignored_path(os.path.join(self.path, child_a))
        paths_to_ignore = []
        paths_not_to_ignore = []
        expected_events = []
        for file_name in 'abcdef':
            paths_to_ignore.append((1, os.path.join(child_b, file_name)))
            valid = os.path.join(child_a, file_name)
            event = self.fake_events_processor.create_fake_event(valid)
            paths_not_to_ignore.append(event)
            expected_events.append(os.path.join(self.common_path, valid))
        # ensure that the watch is watching
        watch.platform_watch.watching = True
        self.fake_events_processor.custom_process_events(
            watch, paths_not_to_ignore)
        self.assertEqual(len(paths_not_to_ignore), len(events),
                         'All events should have been accepted.')
        self.assertTrue(all([e in expected_events for e in events]),
                        'Paths ignored that should have not been ignored.')

    def random_error(self, *args):
        """Throw a fake exception."""
        raise FakeException()

    def test_is_path_dir_missing_no_subdir(self):
        """Test when the path does not exist and is no a subdir."""
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: False)
        watch = Watch(1, test_path, None)
        self.assertFalse(watch._path_is_dir(self.invalid_path))

    def test_is_path_dir_missing_in_subdir(self):
        """Test when the path does not exist and is a subdir."""
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: False)
        watch = Watch(1, test_path, None)
        watch._subdirs.add(self.invalid_path)
        self.assertTrue(watch._path_is_dir(self.invalid_path))

    def test_is_path_dir_present_is_dir(self):
        """Test when the path is present and is dir."""
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: True)
        self.patch(os.path, 'isdir', lambda path: True)
        watch = Watch(1, test_path, None)
        watch._subdirs.add(self.invalid_path)
        self.assertTrue(watch._path_is_dir(self.invalid_path))

    def test_is_path_dir_present_no_dir(self):
        """Test when the path is present but not a dir."""
        test_path = self.mktemp("test_directory")
        self.patch(os.path, 'exists', lambda path: True)
        self.patch(os.path, 'isdir', lambda path: False)
        watch = Watch(1, test_path, None)
        watch._subdirs.add(self.invalid_path)
        self.assertFalse(watch._path_is_dir(self.invalid_path))

    def test_update_subdirs_create_not_present(self):
        """Test when we update on a create event and not present."""
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._update_subdirs(self.invalid_path, REVERSE_OS_ACTIONS[IN_CREATE])
        self.assertTrue(self.invalid_path in watch._subdirs)

    def test_update_subdirs_create_present(self):
        """Test when we update on a create event and is present."""
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._subdirs.add(self.invalid_path)
        old_length = len(watch._subdirs)
        watch._update_subdirs(self.invalid_path, REVERSE_OS_ACTIONS[IN_CREATE])
        self.assertTrue(self.invalid_path in watch._subdirs)
        self.assertEqual(old_length, len(watch._subdirs))

    def test_update_subdirs_delete_not_present(self):
        """Test when we delete and is not present."""
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._update_subdirs(self.invalid_path, REVERSE_OS_ACTIONS[IN_DELETE])
        self.assertTrue(self.invalid_path not in watch._subdirs)

    def test_update_subdirs_delete_present(self):
        """Test when we delete and is present."""
        test_path = self.mktemp("test_directory")
        watch = Watch(1, test_path, None)
        watch._subdirs.add(self.invalid_path)
        watch._update_subdirs(self.invalid_path, REVERSE_OS_ACTIONS[IN_DELETE])
        self.assertTrue(self.invalid_path not in watch._subdirs)


class TestWatchManagerStopping(BaseTwistedTestCase):
    """Tests that stop the watch manager themselves."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set each of the tests."""
        yield super(TestWatchManagerStopping, self).setUp()
        self.manager = WatchManager(None)
        self.fake_events_processor = FakeEventsProcessor()

    @defer.inlineCallbacks
    def test_stop(self):
        """Test that the different watches are stopped."""
        self.was_called = False

        def fake_stop_watching(watch):
            """Fake stop watch."""
            self.was_called = True
            return defer.succeed(True)

        self.patch(Watch, "stop_watching", fake_stop_watching)
        yield self.manager.stop()
        self.assertTrue(self.was_called, 'The watch stop should be called.')


class TestWatchManager(BaseTwistedTestCase):
    """Test the watch manager."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set each of the tests."""
        yield super(TestWatchManager, self).setUp()
        self.manager = WatchManager(None)
        self.addCleanup(self.manager.stop)
        self.fake_events_processor = FakeEventsProcessor()

    def test_get_present_watch(self):
        """Test that we can get a Watch using its wd."""
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

    def test_get_path_present_wd(self):
        """Test the path for a present wd."""
        self.assertEqual(self.path + os.path.sep, self.manager.get_path(1))

    def test_get_path_missing_wd(self):
        """Test returning None for a missing wd."""
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
        self.stop_called = False

        def fake_stop_watching():
            """Fake stop watch."""
            self.stop_called = True
            return defer.succeed(True)

        self.platform_rm_watch_wd = None

        def fake_platform_rm_watch(wd):
            """Fake platform_manager.rm_watch."""
            self.platform_rm_watch_wd = wd

        self.patch(self.manager, "stop_watching", fake_stop_watching)
        self.patch(self.manager.platform_manager,
                   "rm_watch", fake_platform_rm_watch)

        yield self.manager.rm_watch(1)
        self.assertTrue(self.stop_called)
        self.assertEqual(None, self.manager._wdm.get(1))
        self.assertEqual(self.platform_rm_watch_wd, 1)

    def test_rm_root_path(self):
        """Test the removal of a root path."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event.pathname)

        self.watch._processor = fake_processor
        self.manager.rm_path(self.path)
        self.assertEqual(self.watch, self.manager._wdm.get(1))
        self.watch._watching = True
        event = self.fake_events_processor.create_fake_event(
            os.path.join(self.path, 'test'))
        self.fake_events_processor.custom_process_events(self.watch, [event])
        self.assertEqual(0, len(events))

    def test_rm_child_path(self):
        """Test the removal of a child path."""
        events = []

        def fake_processor(event):
            """Memorize the processed events."""
            events.append(event.pathname)

        self.watch._processor = fake_processor
        child = os.path.join(self.path, 'child')
        self.manager.rm_path(child)
        self.assertEqual(self.watch, self.manager._wdm[1])
        # assert that the correct event is ignored
        self.watch.platform_watch.watching = True
        event = self.fake_events_processor.create_fake_event(
            os.path.join('child', 'test'))
        self.fake_events_processor.custom_process_events(self.watch, [event])
        self.assertEqual(0, len(events))
        # assert that other events are not ignored
        event2 = self.fake_events_processor.create_fake_event('test')
        self.fake_events_processor.custom_process_events(self.watch, [event2])
        self.assertEqual(1, len(events))


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


class FakeLog(object):
    """A fake log that is used by the general processor."""

    def __init__(self):
        """Create the fake."""
        self.called_methods = []

    def info(self, *args):
        """Fake the info call."""
        self.called_methods.append(('info', args))


class FakeGeneralProcessor(object):
    """Fake implementation of the general processor."""

    def __init__(self):
        """Create the fake."""
        self.called_methods = []
        self.paths_to_return = []
        self.log = FakeLog()
        self.share_id = None
        self.ignore = False

    def rm_from_mute_filter(self, event, paths):
        """Fake rm_from_mute_filter."""
        self.called_methods.append(('rm_from_mute_filter', event, paths))

    def add_to_mute_filter(self, event, paths):
        """Fake add_to_move_filter."""
        self.called_methods.append(('add_to_mute_filter', event, paths))

    def is_ignored(self, path):
        """Fake is_ignored."""
        self.called_methods.append(('is_ignored', path))
        return self.ignore

    def push_event(self, event):
        """Fake push event."""
        self.called_methods.append(('push_event', event))

    def eq_push(self, event, path=None, path_to=None, path_from=None):
        """Fake event to push event."""
        self.called_methods.append(('eq_push', event, path, path_to,
                                    path_from))

    def get_paths_starting_with(self, fullpath, include_base=False):
        """Fake get_paths_starting_with."""
        self.called_methods.append(('get_paths_starting_with', fullpath,
                                    include_base))
        return self.paths_to_return

    def get_path_share_id(self, path):
        """Fake get_path_share_id."""
        self.called_methods.append(('get_path_share_id', path))
        return self.share_id

    def rm_watch(self, path):
        """Fake the remove watch."""
        self.called_methods.append(('rm_watch', path))

    def freeze_begin(self, path):
        """Fake freeze_begin"""
        self.called_methods.append(('freeze_begin', path))

    def freeze_rollback(self):
        """Fake rollback."""
        self.called_methods.append(('freeze_rollback',))

    def freeze_commit(self, path):
        """Fake freeze commit."""
        self.called_methods.append(('freeze_commit', path))


class TestNotifyProcessor(BaseTwistedTestCase):
    """Test the notify processor."""

    @defer.inlineCallbacks
    def setUp(self):
        """set up the diffeent tests."""
        yield super(TestNotifyProcessor, self).setUp()
        self.processor = notify_processor.NotifyProcessor(None)
        self.general = FakeGeneralProcessor()
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


class FilesystemMonitorTestCase(BaseTwistedTestCase):
    """Tests for the FilesystemMonitor."""

    timeout = 5

    def test_add_watch_twice(self):
        """Check the deferred returned by a second add_watch."""
        raise NotImplementedError

    def test_add_watches_to_udf_ancestors(self):
        """Test that the ancestor watches are not added."""
        class FakeVolume(object):
            """A fake UDF."""

            def __init__(self, ancestors):
                """Create a new instance."""
                self.ancestors = ancestors

        ancestors = ['~', '~\\Pictures', '~\\Pictures\\Home', ]
        volume = FakeVolume(ancestors)
        monitor = FilesystemMonitor(None, None)
        added = yield monitor.add_watches_to_udf_ancestors(volume)
        self.assertTrue(added, 'We should always return true.')
        # lets ensure that we never added the watches
        self.assertEqual(0, len(monitor._watch_manager._wdm.values()),
                         'No watches should have been added.')

    @defer.inlineCallbacks
    def test_is_available_monitor(self):
        """Test test the is_available_monitor method."""
        # we should always return true
        is_available = yield FilesystemMonitor.is_available_monitor()
        self.assertTrue(is_available, 'Should always be available.')
