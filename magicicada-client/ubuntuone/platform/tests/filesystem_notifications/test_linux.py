#
# Authors: Facundo Batista <facundo@canonical.com>
#          Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
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
"""Tests for the Event Queue."""

import os

from twisted.internet import defer, reactor
from twisted.trial.unittest import TestCase as PlainTestCase

from contrib.testing import testcase
from ubuntuone.syncdaemon import volume_manager
from ubuntuone.platform.filesystem_notifications import notify_processor
from ubuntuone.platform.filesystem_notifications.monitor import (
    linux as filesystem_notifications,
)
from ubuntuone.platform.tests.filesystem_notifications import (
    BaseFSMonitorTestCase,
)


class FakeVolume(object):
    """A fake volume."""

    def __init__(self, path, ancestors):
        """Create a new instance."""
        super(FakeVolume, self).__init__()
        self.volume_id = path
        self.path = path
        self.ancestors = ancestors


class ShutdownTestCase(testcase.BaseTwistedTestCase):
    """Test the monitor shutdown."""

    def test_call_shutdown_processor(self):
        """Call the shutdown of the processor."""
        monitor = filesystem_notifications.FilesystemMonitor('eq', 'fs')
        called = []
        processor = monitor._processor
        processor.shutdown = lambda: called.append(True)
        monitor.shutdown()
        self.assertTrue(called)

    def test_processor_shutdown_no_timer(self):
        """Shutdown the processor, no timer."""
        processor = notify_processor.NotifyProcessor('mntr')
        processor.shutdown()

    def test_processor_shutdown_timer_inactive(self):
        """Shutdown the processor, timer inactive."""
        processor = notify_processor.NotifyProcessor('mntr')
        d = defer.Deferred()

        def shutdown():
            """Shutdown, being sure the timer is inactive."""
            processor.shutdown()
            d.callback(True)

        processor.timer = reactor.callLater(.1, shutdown)
        return d

    def test_processor_shutdown_timer_active(self):
        """Shutdown the processor, timer going on."""
        processor = notify_processor.NotifyProcessor('mntr')
        processor.timer = reactor.callLater(10, lambda: None)
        processor.shutdown()
        self.assertFalse(processor.timer.active())


class WatchManagerTests(BaseFSMonitorTestCase):
    """Test the structures where we have the path/watch."""

    def test_watch_updated_when_deleting_dir(self):
        """Internal data structures are fixed when deleting the dir."""
        path = os.path.join(self.root_dir, "path")
        os.mkdir(path)
        self.monitor.add_watch(self.root_dir)
        self.monitor.add_watch(path)

        # we have the watch, remove the dir, the watch should be gone
        self.assertIn(path, self.monitor._general_watchs)
        os.rmdir(path)

        def check(_):
            """Check state after the event."""
            self.assertNotIn(path, self.monitor._general_watchs)

        self.deferred.addCallback(check)
        return self.deferred

    def test_watch_updated_when_renaming_dir(self):
        """Internal data structures are fixed when renaming the dir."""
        path1 = os.path.join(self.root_dir, "path1")
        path2 = os.path.join(self.root_dir, "path2")
        os.mkdir(path1)
        self.monitor.add_watch(self.root_dir)
        self.monitor.add_watch(path1)

        # we have the watch, rename the dir, new name should have the watch,
        # old name should not
        self.assertIn(path1, self.monitor._general_watchs)
        os.rename(path1, path2)

        def check(_):
            """Check state after the event."""
            self.assertIn(path2, self.monitor._general_watchs)
            self.assertNotIn(path1, self.monitor._general_watchs)

        self.deferred.addCallback(check)
        return self.deferred

    def test_watch_updated_when_movingout_dir(self):
        """Internal data structures are fixed when moving out the dir."""
        notu1 = os.path.join(self.root_dir, "notu1")
        path1 = os.path.join(self.root_dir, "path1")
        path2 = os.path.join(notu1, "path2")
        os.mkdir(notu1)
        os.mkdir(path1)
        self.monitor.add_watch(self.root_dir)
        self.monitor.add_watch(path1)

        # we have the watch, move it outside watched structure, no more watches
        self.assertIn(path1, self.monitor._general_watchs)
        os.rename(path1, path2)

        def check(_):
            """Check state after the event."""
            self.assertNotIn(path1, self.monitor._general_watchs)
            self.assertNotIn(path2, self.monitor._general_watchs)

        self.deferred.addCallback(check)
        return self.deferred

    def test_fix_path_not_there(self):
        """Try to fix path but it's not there."""
        self.monitor._general_watchs = {}
        self.monitor._ancestors_watchs = {}
        self.monitor.inotify_watch_fix("not-there", "new-one")
        self.assertTrue(self.log_handler.check_warning("Tried to fix",
                                                       "not-there"))

    def test_fix_path_general(self):
        """Fixing path in general watches."""
        self.monitor._general_watchs = {'/path1/foo': 1, '/other': 2}
        self.monitor._ancestors_watchs = {'/foo': 3}
        self.monitor.inotify_watch_fix('/path1/foo', '/path1/new')
        self.assertEqual(
            self.monitor._general_watchs, {'/path1/new': 1, '/other': 2})
        self.assertEqual(self.monitor._ancestors_watchs, {'/foo': 3})

    def test_fix_path_ancestors(self):
        """Fixing path in ancestors watches."""
        self.monitor._general_watchs = {'/bar': 3}
        self.monitor._ancestors_watchs = {'/oth': 1, '/other': 2}
        self.monitor.inotify_watch_fix('/oth', '/baz')
        self.assertEqual(self.monitor._general_watchs, {'/bar': 3})
        self.assertEqual(
            self.monitor._ancestors_watchs, {'/baz': 1, '/other': 2})


class DynamicHitMe(object):
    """Helper class to test a sequence of signals."""

    def __init__(self, should_events, test_machinery):
        self.should_events = []
        for i, info in enumerate(should_events):
            self.should_events.append((i,) + info)
        if self.should_events:
            self.final_step = self.should_events[-1][0]
            self.should_events.reverse()
        self.test_machinery = test_machinery

    def __getattr__(self, name):
        """typical method faker"""
        if not name.startswith("handle_"):
            return

        asked_event = name[7:]

        # to what we should match
        test_info = self.should_events.pop()
        step = test_info[0]
        should_evtname = test_info[1]
        should_args = test_info[2:]

        def to_check(*asked_args):
            """the function that actually be called"""
            if asked_args != should_args:
                self.test_machinery.finished_error(
                    "In step %d received wrong args (%r)" % (step, asked_args))
            else:
                if step == self.final_step:
                    self.test_machinery.finished_ok()

        if should_evtname != asked_event:
            msg = "Event %r asked in bad order (%d)" % (asked_event, step)
            self.test_machinery.finished_error(msg)
        else:
            return to_check


class WatchTests(BaseFSMonitorTestCase):
    """Test the EQ API to add and remove watchs."""

    @defer.inlineCallbacks
    def _create_udf(self, path):
        """Create an UDF and returns it and the volume"""
        os.makedirs(path)
        udf = volume_manager.UDF("vol_id", "node_id", path.decode('utf-8'),
                                 path, True)
        yield self.vm.add_udf(udf)

    def test_add_general_watch(self):
        """Test that general watchs can be added."""
        self.monitor.add_watch(self.root_dir)

        # check only added dir in watchs, and logs
        self.assertIn(self.root_dir, self.monitor._general_watchs)
        self.assertNotIn("not-added-dir", self.monitor._general_watchs)
        self.assertTrue(self.log_handler.check_debug(
                                "Adding general inotify watch", self.root_dir))

        # nothing in the udf ancestors watch
        self.assertEqual(self.monitor._ancestors_watchs, {})

    def test_add_general_watch_twice(self):
        """Test that general watchs can be added."""
        self.monitor.add_watch(self.root_dir)
        self.assertTrue(self.log_handler.check_debug(
                                "Adding general inotify watch", self.root_dir))
        self.assertIn(self.root_dir, self.monitor._general_watchs)

        # go again
        self.monitor.add_watch(self.root_dir)
        self.assertTrue(self.log_handler.check_debug("Watch already there for",
                                                     self.root_dir))
        self.assertIn(self.root_dir, self.monitor._general_watchs)

    @defer.inlineCallbacks
    def test_add_watches_to_udf_ancestors(self):
        """Test that the ancestor watches are added."""
        ancestors = ['~', '~/Picture', '~/Pictures/Work']
        path = 'test_path'
        volume = FakeVolume(path, ancestors)
        self.patch(filesystem_notifications, 'access', lambda path: True)
        self.patch(self.monitor, '_is_udf_ancestor', lambda path: True)
        # lets add the watches, ensure that we do return true and that the new
        # watches are indeed present.
        added = yield self.monitor.add_watches_to_udf_ancestors(volume)
        self.assertTrue(added, 'Watches should have been added.')
        for path in ancestors:
            self.assertTrue(self.log_handler.check_debug(
                "Adding ancestors inotify watch", path))
            self.assertIn(path, self.monitor._ancestors_watchs)

    @defer.inlineCallbacks
    def test_add_watches_to_udf_ancestors_reverted(self):
        """Test that the ancestor watches are reverted."""
        ancestors = ['~', '~/Picture', '~/Pictures/Work']
        path = 'test_path'
        volume = FakeVolume(path, ancestors)
        self.patch(filesystem_notifications, 'access',
                   lambda path: path != ancestors[2])
        self.patch(self.monitor, '_is_udf_ancestor', lambda path: True)
        # lets ensure that we did not added any of the watches.
        added = yield self.monitor.add_watches_to_udf_ancestors(volume)
        self.assertFalse(added, 'Watches should NOT have been added.')
        for path in ancestors:
            if path != ancestors[2]:
                self.assertTrue(self.log_handler.check_debug(
                    "Adding ancestors inotify watch", path))
            self.assertNotIn(path, self.monitor._ancestors_watchs)

    @defer.inlineCallbacks
    def test_add_watch_on_udf_ancestor(self):
        """Test that ancestors watchs can be added."""
        # create the udf and add the watch
        path_udf = os.path.join(self.home_dir, "path/to/UDF")
        yield self._create_udf(path_udf)
        path_ancestor = os.path.join(self.home_dir, "path")
        self.monitor.add_watch(path_ancestor)

        # check only added dir in watchs
        self.assertTrue(path_ancestor in self.monitor._ancestors_watchs)
        self.assertTrue("not-added-dir" not in self.monitor._ancestors_watchs)

        # nothing in the general watch
        self.assertEqual(self.monitor._general_watchs, {})

    @defer.inlineCallbacks
    def test_add_watch_on_udf_exact(self):
        """Test adding the watch exactly on UDF."""
        # create the udf and add the watch
        path_udf = os.path.join(self.home_dir, "path/to/UDF")
        yield self._create_udf(path_udf)
        self.monitor.add_watch(path_udf)

        self.assertTrue(path_udf in self.monitor._general_watchs)
        self.assertEqual(self.monitor._ancestors_watchs, {})

    @defer.inlineCallbacks
    def test_add_watch_on_udf_child(self):
        """Test adding the watch inside UDF."""
        # create the udf and add the watch
        path_udf = os.path.join(self.home_dir, "path/to/UDF")
        yield self._create_udf(path_udf)
        path_ancestor = os.path.join(self.home_dir, "path/to/UDF/inside")
        os.mkdir(path_ancestor)
        self.monitor.add_watch(path_ancestor)

        self.assertTrue(path_ancestor in self.monitor._general_watchs)
        self.assertEqual(self.monitor._ancestors_watchs, {})

    def test_rm_watch_not_dir_anymore(self):
        """Test that a watch can be removed even not having the dir anymore.

        This is the case where the directory is deleted from the filesystem,
        the watch is automatically removed in pyinotify but we need to take
        care of it from our own data structures.
        """
        not_existing_dir = "not-added-dir"
        self.monitor.add_watch(not_existing_dir)
        self.assertIn(not_existing_dir, self.monitor._general_watchs)
        self.monitor.rm_watch(not_existing_dir)
        self.assertNotIn(not_existing_dir, self.monitor._general_watchs)

    @defer.inlineCallbacks
    def test_rm_watch_wrong(self):
        """Test that general watchs can be removed."""
        # add two types of watchs
        self.monitor.add_watch(self.root_dir)
        path_udf = os.path.join(self.home_dir, "path/to/UDF")
        yield self._create_udf(path_udf)
        path_ancestor = os.path.join(self.home_dir, "path")
        self.monitor.add_watch(path_ancestor)

        # remove different stuff
        self.monitor.rm_watch("not-added-dir")
        self.assertTrue(self.log_handler.check_warning('remove', 'watch',
                                                       'not-added-dir'))

    def test_rm_watch_general(self):
        """Test that general watchs can be removed."""
        # remove what we added
        self.monitor.add_watch(self.root_dir)
        self.monitor.rm_watch(self.root_dir)

        self.assertEqual(self.monitor._general_watchs, {})
        self.assertEqual(self.monitor._ancestors_watchs, {})

    @defer.inlineCallbacks
    def test_rm_watch_ancestor(self):
        """Test that ancestor watchs can be removed."""
        # create the udf and add the watch
        path_udf = os.path.join(self.home_dir, "path/to/UDF")
        yield self._create_udf(path_udf)
        path_ancestor = os.path.join(self.home_dir, "path")
        self.monitor.add_watch(path_ancestor)

        # remove what we added
        self.monitor.rm_watch(path_ancestor)
        self.assertEqual(self.monitor._general_watchs, {})
        self.assertEqual(self.monitor._ancestors_watchs, {})

    @defer.inlineCallbacks
    def test_is_available_monitor(self):
        """Test test the is_available_monitor method."""
        # we should always return true
        monitor_cls = filesystem_notifications.FilesystemMonitor
        is_available = yield monitor_cls.is_available_monitor()
        self.assertTrue(is_available, 'Should always be available.')


class FakeEvent(object):
    """A fake event."""

    mask = 0
    name = ""


class ECryptFsTestCase(PlainTestCase):
    """Tests for the eCryptFS weirdness."""

    def test_close_write_on_folders_is_ignored(self):
        """When eCryptFS sends CLOSE_WRITE on folders, ignore it"""
        result = []
        monitor = None
        processor = notify_processor.NotifyProcessor(monitor)
        self.patch(processor.general_processor, "push_event", result.append)

        fake_event = FakeEvent()
        fake_event.mask = filesystem_notifications.pyinotify.IN_ISDIR
        fake_event.name = "/fake/directory/path"
        processor.process_IN_CLOSE_WRITE(fake_event)

        self.assertNotIn(fake_event, result)

    def test_close_write_on_files_is_handled(self):
        """When anything sends CLOSE_WRITE on files, handle it."""
        result = []
        monitor = None
        processor = notify_processor.NotifyProcessor(monitor)
        self.patch(processor.general_processor, "push_event", result.append)

        fake_event = FakeEvent()
        fake_event.mask = filesystem_notifications.pyinotify.IN_CLOSE_WRITE
        fake_event.name = "/fake/directory/path"
        processor.process_IN_CLOSE_WRITE(fake_event)

        self.assertIn(fake_event, result)
