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

import os

from twisted.internet import defer
from win32file import FILE_NOTIFY_INFORMATION

from contrib.testing.testcase import BaseTwistedTestCase

from ubuntuone.platform.filesystem_notifications.monitor import (
    common,
    windows as filesystem_notifications,
)
from ubuntuone.platform.filesystem_notifications.monitor.common import (
    FilesystemMonitor,
    Watch,
    WatchManager,
)
from ubuntuone.platform.filesystem_notifications.monitor.windows import (
    FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_SIZE,
    FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY,
    FILE_NOTIFY_CHANGE_LAST_ACCESS,
)
from ubuntuone.platform.tests.filesystem_notifications import (
    common as common_tests,
)


class FakeEventsProcessor(object):

    """Handle fake events creation and processing."""

    def create_fake_event(self, filename):
        """Create a fake file event."""
        return (1, filename)

    def custom_process_events(self, watch, events):
        """Adapt to each platform way to process events."""
        watch.platform_watch._process_events(events)


class TestWatch(common_tests.TestWatch):
    """Test the watch so that it returns the same events as pyinotify."""

    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestWatch, self).setUp()
        self.path = u'\\\\?\\C:\\path'  # a valid windows path
        self.common_path = u'C:\\path'
        self.invalid_path = u'\\\\?\\C:\\path\\to\\no\\dir'
        self.mask = FILE_NOTIFY_CHANGE_FILE_NAME | \
            FILE_NOTIFY_CHANGE_DIR_NAME | \
            FILE_NOTIFY_CHANGE_ATTRIBUTES | \
            FILE_NOTIFY_CHANGE_SIZE | \
            FILE_NOTIFY_CHANGE_LAST_WRITE | \
            FILE_NOTIFY_CHANGE_SECURITY | \
            FILE_NOTIFY_CHANGE_LAST_ACCESS
        self.fake_events_processor = FakeEventsProcessor()

        def file_notify_information_wrapper(buf, data):
            """Wrapper that gets the events and adds them to the list."""
            events = FILE_NOTIFY_INFORMATION(buf, data)
            # we want to append the list because that is what will be logged.
            # If we use extend we wont have the same logging because it will
            # group all events in a single lists which is not what the COM API
            # does.
            str_events = [
                (common.ACTIONS_NAMES[action], p) for action, p in events]
            self.raw_events.append(str_events)
            return events

        self.patch(filesystem_notifications, 'FILE_NOTIFY_INFORMATION',
                   file_notify_information_wrapper)

    @defer.inlineCallbacks
    def test_file_write(self):
        """Test that the correct event is raised when a file is written."""
        file_name = os.path.join(self.basedir, 'test_file_write')
        # create the file before recording
        fd = open(file_name, 'w')
        # clean behind us by removing the file
        self.addCleanup(os.remove, file_name)

        def write_file():
            """Action for the test."""
            fd.write('test')
            fd.close()

        events = yield self._perform_operations(self.basedir, self.mask,
                                                write_file, 1)
        event = events[0]
        self.assertFalse(event.dir)
        self.assertEqual(0x2, event.mask)
        self.assertEqual('IN_MODIFY', event.maskname)
        self.assertEqual(os.path.split(file_name)[1], event.name)
        self.assertEqual('.', event.path)
        self.assertEqual(os.path.join(self.basedir, file_name), event.pathname)
        self.assertEqual(0, event.wd)

    @defer.inlineCallbacks
    def test_call_deferred_already_called(self):
        """Test that the function is not called."""
        method_args = []

        def fake_call(*args, **kwargs):
            """Execute the call."""
            method_args.append((args, kwargs),)

        watch = Watch(1, self.path, None)
        yield watch.platform_watch._watch_started_deferred.callback(True)
        watch.platform_watch._call_deferred(fake_call, None)
        self.assertEqual(0, len(method_args))

    def test_call_deferred_not_called(self):
        """Test that is indeed called."""
        method_args = []

        def fake_call(*args, **kwargs):
            """Execute the call."""
            method_args.append((args, kwargs),)

        watch = Watch(1, self.path, None)
        watch.platform_watch._call_deferred(fake_call, None)
        self.assertEqual(1, len(method_args))

    def test_started_property(self):
        """Test that the started property returns the started deferred."""
        watch = Watch(1, self.path, None)
        self.assertEqual(
            watch.started, watch.platform_watch._watch_started_deferred)

    def test_stopped_property(self):
        """Test that the stopped property returns the stopped deferred."""
        watch = Watch(1, self.path, None)
        self.assertEqual(
            watch.stopped, watch.platform_watch._watch_stopped_deferred)

    @defer.inlineCallbacks
    def test_start_watching_fails_early_in_thread(self):
        """An early failure inside the thread should errback the deferred."""
        test_path = self.mktemp("test_directory")
        self.patch(filesystem_notifications, "CreateFileW", self.random_error)
        watch = Watch(1, test_path, None)
        d = watch.start_watching()
        yield self.assertFailure(d, common_tests.FakeException)

    @defer.inlineCallbacks
    def test_start_watching_fails_late_in_thread(self):
        """A late failure inside the thread should errback the deferred."""
        test_path = self.mktemp("test_directory")
        self.patch(filesystem_notifications, "ReadDirectoryChangesW",
                   self.random_error)
        watch = Watch(1, test_path, None)
        d = watch.start_watching()
        yield self.assertFailure(d, common_tests.FakeException)

    @defer.inlineCallbacks
    def test_close_handle_is_called_on_error(self):
        """CloseHandle is called when there's an error in the watch thread."""
        test_path = self.mktemp("test_directory")
        close_called = []
        self.patch(filesystem_notifications, "CreateFileW", lambda *_: None)
        self.patch(filesystem_notifications, "CloseHandle",
                   close_called.append)
        self.patch(filesystem_notifications, "ReadDirectoryChangesW",
                   self.random_error)
        watch = Watch(1, test_path, self.mask)
        d = watch.start_watching()
        yield self.assertFailure(d, common_tests.FakeException)
        self.assertEqual(len(close_called), 1)
        yield watch.stop_watching()

    @defer.inlineCallbacks
    def test_stop_watching_fired_when_watch_thread_finishes(self):
        """The deferred returned is fired when the watch thread finishes."""
        test_path = self.mktemp("another_test_directory")
        watch = Watch(1, test_path, self.mask)
        yield watch.start_watching()
        self.assertNotEqual(watch.platform_watch._watch_handle, None)
        yield watch.stop_watching()
        self.assertEqual(watch.platform_watch._watch_handle, None)


class TestWatchManager(common_tests.TestWatchManager):
    """Test the watch manager."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set each of the tests."""
        yield super(TestWatchManager, self).setUp()
        self.parent_path = u'\\\\?\\C:\\'  # a valid windows path
        self.path = self.parent_path + u'path'
        self.watch = Watch(1, self.path, None)
        self.manager._wdm = {1: self.watch}
        self.addCleanup(self.watch.stopped.callback, None)

        self.fake_events_processor = FakeEventsProcessor()

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
        self.assertEqual(
            filesystem_notifications.FILESYSTEM_MONITOR_MASK,
            self.manager._wdm[0].platform_watch._mask)
        self.manager._wdm[0].stopped.callback(None)

    @defer.inlineCallbacks
    def test_stop_multiple(self):
        """Test that stop is fired when *all* watches have stopped."""

        def fake_stop_watching(watch):
            """Another fake stop watch."""
            return watch.stopped

        self.patch(Watch, "stop_watching", fake_stop_watching)

        first_watch = Watch(1, self.path, None)
        self.manager._wdm = {1: first_watch}
        second_path = self.parent_path + u"second_path"
        second_watch = Watch(2, second_path, None)
        self.manager._wdm[2] = second_watch
        d = self.manager.stop()
        self.assertFalse(d.called, "Not fired before all watches end")
        first_watch.stopped.callback(None)
        self.assertFalse(d.called, "Not fired before all watches end")
        second_watch.stopped.callback(None)
        yield d
        self.assertTrue(d.called, "Fired after the watches ended")


class TestWatchManagerAddWatches(BaseTwistedTestCase):
    """Test the watch manager."""
    timeout = 5

    def test_add_watch_twice(self):
        """Adding a watch twice succeeds when the watch is running."""
        self.patch(Watch, "start_watching", lambda self: self.started)
        manager = WatchManager(None)
        # no need to stop watching because start_watching is fake

        path = u'\\\\?\\C:\\test'  # a valid windows path
        mask = 'fake bit mask'
        d1 = manager.add_watch(path, mask)
        d2 = manager.add_watch(path, mask)

        self.assertFalse(d1.called, "Should not be called yet.")
        self.assertFalse(d2.called, "Should not be called yet.")

        manager._wdm.values()[0].started.callback(True)

        self.assertTrue(d1.called, "Should already be called.")
        self.assertTrue(d2.called, "Should already be called.")


class TestNotifyProcessor(common_tests.TestNotifyProcessor):
    """Test the notify processor."""

    @defer.inlineCallbacks
    def setUp(self):
        """set up the diffeent tests."""
        yield super(TestNotifyProcessor, self).setUp()


class FilesystemMonitorTestCase(common_tests.FilesystemMonitorTestCase):
    """Tests for the FilesystemMonitor."""
    timeout = 5

    def test_add_watch_twice(self):
        """Check the deferred returned by a second add_watch."""
        self.patch(Watch, "start_watching", lambda self: self.started)
        monitor = FilesystemMonitor(None, None)
        # no need to stop watching because start_watching is fake

        parent_path = 'C:\\test'  # a valid windows path in utf-8 bytes
        child_path = parent_path + "\\child"
        d1 = monitor.add_watch(parent_path)
        d2 = monitor.add_watch(child_path)

        self.assertFalse(d1.called, "Should not be called yet.")
        self.assertFalse(d2.called, "Should not be called yet.")

        monitor._watch_manager._wdm.values()[0].started.callback(True)

        self.assertTrue(d1.called, "Should already be called.")
        self.assertTrue(d2.called, "Should already be called.")

    @defer.inlineCallbacks
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
