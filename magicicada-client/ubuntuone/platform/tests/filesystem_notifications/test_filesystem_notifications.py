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
"""Commong filesystem notifications tests."""

import logging
import os

from twisted.internet import defer, reactor
from twisted.trial import unittest
from ubuntuone.devtools.handlers import MementoHandler

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    FakeVolumeManager,
    skip_if_win32_missing_fs_event,
    skip_if_darwin_missing_fs_event,
)
from ubuntuone.platform import (
    remove_file,
    remove_dir,
    rename,
)
from ubuntuone.platform.filesystem_notifications import notify_processor
from ubuntuone.syncdaemon.tritcask import Tritcask
from ubuntuone.syncdaemon import (
    event_queue,
    filesystem_manager,
    filesystem_notifications,
)


class IgnoreFileTests(unittest.TestCase):
    """Tests the ignore files behaviour."""

    def test_filter_none(self):
        """Still works ok even if not receiving a regex to ignore."""
        p = notify_processor.NotifyProcessor(None)
        self.assertFalse(p.is_ignored("froo.pyc"))

    def test_filter_one(self):
        """Filters stuff that matches (or not) this one regex."""
        p = notify_processor.NotifyProcessor(None, ['\A.*\\.pyc\Z'])
        self.assertTrue(p.is_ignored("froo.pyc"))
        self.assertFalse(p.is_ignored("froo.pyc.real"))
        self.assertFalse(p.is_ignored("otherstuff"))

    def test_filter_two_simple(self):
        """Filters stuff that matches (or not) these simple regexes."""
        p = notify_processor.NotifyProcessor(None, ['\A.*foo\Z', '\A.*bar\Z'])
        self.assertTrue(p.is_ignored("blah_foo"))
        self.assertTrue(p.is_ignored("blah_bar"))
        self.assertFalse(p.is_ignored("bar_xxx"))
        self.assertFalse(p.is_ignored("--foo--"))
        self.assertFalse(p.is_ignored("otherstuff"))

    def test_filter_two_complex(self):
        """Filters stuff that matches (or not) these complex regexes."""
        p = notify_processor.NotifyProcessor(
            None, ['\A.*foo\Z|\Afoo.*\Z', '\A.*bar\Z'])
        self.assertTrue(p.is_ignored("blah_foo"))
        self.assertTrue(p.is_ignored("blah_bar"))
        self.assertTrue(p.is_ignored("foo_xxx"))
        self.assertFalse(p.is_ignored("--foo--"))
        self.assertFalse(p.is_ignored("otherstuff"))

    def test_is_ignored_uses_access(self):
        """Test that the right access function is called."""
        sample_path = "sample path"
        calls = []

        def store_call(*args):
            return calls.append(args)

        self.patch(filesystem_notifications, "access", store_call)
        self.patch(filesystem_notifications, "path_exists", lambda _: True)
        p = notify_processor.NotifyProcessor(None)
        p.is_ignored(sample_path)
        self.assertEqual(calls, [(sample_path,)])


class BaseFSMonitorTestCase(BaseTwistedTestCase):
    """Test the structures where we have the path/watch."""

    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(BaseFSMonitorTestCase, self).setUp()
        fsmdir = self.mktemp('fsmdir')
        partials_dir = self.mktemp('partials_dir')
        self.root_dir = self.mktemp('root_dir')
        self.vm = FakeVolumeManager(self.root_dir)
        self.tritcask_dir = self.mktemp("tritcask_dir")
        self.db = Tritcask(self.tritcask_dir)
        self.addCleanup(self.db.shutdown)
        self.fs = filesystem_manager.FileSystemManager(fsmdir, partials_dir,
                                                       self.vm, self.db)
        self.fs.create(path=self.root_dir, share_id='', is_dir=True)
        self.fs.set_by_path(path=self.root_dir,
                            local_hash=None, server_hash=None)
        eq = event_queue.EventQueue(self.fs)

        self.deferred = deferred = defer.Deferred()

        class HitMe(object):
            # class-closure, cannot use self, pylint: disable-msg=E0213
            def handle_default(innerself, event, **args):
                deferred.callback(True)

        eq.subscribe(HitMe())
        self.monitor = eq.monitor
        self.addCleanup(self.monitor.shutdown)
        self.log_handler = MementoHandler()
        self.log_handler.setLevel(logging.DEBUG)
        self.monitor.log.addHandler(self.log_handler)
        self.addCleanup(self.monitor.log.removeHandler, self.log_handler)


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


class BaseTwisted(BaseFSMonitorTestCase):
    """Base class for twisted tests."""

    # this timeout must be bigger than the one used in event_queue
    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(BaseTwisted, self).setUp()

        # create the deferred for the tests
        self._deferred = defer.Deferred()

    def finished_ok(self):
        """Called to indicate that the tests finished ok."""
        self._deferred.callback(True)

    def finished_error(self, msg):
        """Called to indicate that the tests finished badly."""
        self._deferred.errback(Exception(msg))

    def failUnlessEqual(self, first, second, msg=''):
        """Fail the test if C{first} and C{second} are not equal.

        @param msg: A string describing the failure that's included in the
            exception.

        """
        if not first == second:
            if msg is None:
                msg = ''
            if len(msg) > 0:
                msg += '\n'
            exception = self.failureException(
                '%snot equal:\na = %s\nb = %s\n'
                % (msg, repr(first), repr(second)))
            self.finished_error(exception)
            raise exception
        return first

    assertEqual = assertEquals = failUnlessEquals = failUnlessEqual


class MutedSignalsTests(BaseTwisted):
    """Test that EQ filter some signals on demand."""

    def check_filter(self, _=None):
        self.assertFalse(self.monitor._processor.mute_filter._cnt)
        self.finished_ok()

    def test_mute_and_remove(self):
        """Test add and remove the mute."""
        # add
        self.monitor.add_to_mute_filter('FS_FILE_OPEN', path='somepath')
        self.assertEqual(self.monitor._processor.mute_filter._cnt,
                         {'FS_FILE_OPEN': [{'path': 'somepath'}]})
        self.monitor.add_to_mute_filter('FS_FILE_OPEN', path='somepath')
        self.assertEqual(self.monitor._processor.mute_filter._cnt,
                         {'FS_FILE_OPEN': [{'path': 'somepath'},
                                           {'path': 'somepath'}]})
        self.monitor.add_to_mute_filter('FS_FILE_OPEN', path='otherpath')
        self.assertEqual(self.monitor._processor.mute_filter._cnt,
                         {'FS_FILE_OPEN': [{'path': 'somepath'},
                                           {'path': 'somepath'},
                                           {'path': 'otherpath'}]})

        # remove
        self.monitor.rm_from_mute_filter('FS_FILE_OPEN', path='somepath')
        self.assertEqual(self.monitor._processor.mute_filter._cnt,
                         {'FS_FILE_OPEN': [{'path': 'somepath'},
                                           {'path': 'otherpath'}]})
        self.monitor.rm_from_mute_filter('FS_FILE_OPEN', path='otherpath')
        self.assertEqual(self.monitor._processor.mute_filter._cnt,
                         {'FS_FILE_OPEN': [{'path': 'somepath'}]})
        self.monitor.rm_from_mute_filter('FS_FILE_OPEN', path='somepath')
        self.assertEqual(self.monitor._processor.mute_filter._cnt, {})

    def _how_many_muted(self):
        """Return how many events are muted."""
        mute_filter = self.monitor._processor.mute_filter
        return sum(len(x) for x in mute_filter._cnt.values())

    @skip_if_darwin_missing_fs_event
    @skip_if_win32_missing_fs_event
    @defer.inlineCallbacks
    def test_file_open(self):
        """Test receiving the open signal on files."""
        testfile = os.path.join(self.root_dir, "foo")
        open(testfile, "w").close()
        self.monitor.add_to_mute_filter("FS_FILE_OPEN", path=testfile)
        self.monitor.add_to_mute_filter("FS_FILE_CLOSE_NOWRITE", path=testfile)
        self.assertEqual(self._how_many_muted(), 2)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        open(testfile)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @skip_if_darwin_missing_fs_event
    @skip_if_win32_missing_fs_event
    @defer.inlineCallbacks
    def test_file_close_nowrite(self):
        """Test receiving the close_nowrite signal on files."""
        testfile = os.path.join(self.root_dir, "foo")
        open(testfile, "w").close()
        fh = open(testfile)
        self.monitor.add_to_mute_filter("FS_FILE_CLOSE_NOWRITE", path=testfile)
        self.assertEqual(self._how_many_muted(), 1)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        fh.close()
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @skip_if_darwin_missing_fs_event
    @defer.inlineCallbacks
    def test_file_create_close_write(self):
        """Test receiving the create and close_write signals on files."""
        testfile = os.path.join(self.root_dir, "foo")
        self.monitor.add_to_mute_filter("FS_FILE_CREATE", path=testfile)
        self.monitor.add_to_mute_filter("FS_FILE_OPEN", path=testfile)
        self.monitor.add_to_mute_filter("FS_FILE_CLOSE_WRITE", path=testfile)
        self.assertEqual(self._how_many_muted(), 3)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        fd = open(testfile, "w")
        fd.write('test')
        fd.close()
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @defer.inlineCallbacks
    def test_dir_create(self):
        """Test receiving the create signal on dirs."""
        testdir = os.path.join(self.root_dir, "foo")
        self.monitor.add_to_mute_filter("FS_DIR_CREATE", path=testdir)
        self.assertEqual(self._how_many_muted(), 1)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        os.mkdir(testdir)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @defer.inlineCallbacks
    def test_file_delete(self):
        """Test the delete signal on a file."""
        testfile = os.path.join(self.root_dir, "foo")
        open(testfile, "w").close()
        self.monitor.add_to_mute_filter("FS_FILE_DELETE", path=testfile)
        self.assertEqual(self._how_many_muted(), 1)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        remove_file(testfile)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @defer.inlineCallbacks
    def test_dir_delete(self):
        """Test the delete signal on a dir."""
        testdir = os.path.join(self.root_dir, "foo")
        os.mkdir(testdir)
        self.monitor.add_to_mute_filter("FS_DIR_DELETE", path=testdir)
        self.assertEqual(self._how_many_muted(), 1)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        remove_dir(testdir)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @defer.inlineCallbacks
    def test_file_moved_inside(self):
        """Test the synthesis of the FILE_MOVE event."""
        fromfile = os.path.join(self.root_dir, "foo")
        self.fs.create(fromfile, "")
        self.fs.set_node_id(fromfile, "from_node_id")
        tofile = os.path.join(self.root_dir, "bar")
        self.fs.create(tofile, "")
        self.fs.set_node_id(tofile, "to_node_id")
        open(fromfile, "w").close()
        self.monitor.add_to_mute_filter("FS_FILE_MOVE",
                                        path_from=fromfile, path_to=tofile)
        self.assertEqual(self._how_many_muted(), 1)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        rename(fromfile, tofile)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @defer.inlineCallbacks
    def test_dir_moved_inside(self):
        """Test the synthesis of the DIR_MOVE event."""
        fromdir = os.path.join(self.root_dir, "foo")
        self.fs.create(fromdir, "")
        self.fs.set_node_id(fromdir, "from_node_id")
        todir = os.path.join(self.root_dir, "bar")
        self.fs.create(todir, "")
        self.fs.set_node_id(todir, "to_node_id")
        os.mkdir(fromdir)
        self.monitor.add_to_mute_filter("FS_DIR_MOVE",
                                        path_from=fromdir, path_to=todir)
        self.assertEqual(self._how_many_muted(), 1)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        rename(fromdir, todir)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @defer.inlineCallbacks
    def test_file_moved_from_conflict(self):
        """Test the handling of the FILE_MOVE event when source is conflict."""
        fromfile = os.path.join(self.root_dir, "foo.u1conflict")
        self.fs.create(fromfile, "")
        self.fs.set_node_id(fromfile, "from_node_id")
        tofile = os.path.join(self.root_dir, "foo")
        self.fs.create(tofile, "")
        self.fs.set_node_id(tofile, "to_node_id")
        open(fromfile, "w").close()
        self.monitor.add_to_mute_filter("FS_FILE_MOVE",
                                        path_from=fromfile, path_to=tofile)
        self.assertEqual(self._how_many_muted(), 2)
        yield self.monitor.add_watch(self.root_dir)

        # generate the event
        rename(fromfile, tofile)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)

    @skip_if_darwin_missing_fs_event
    @defer.inlineCallbacks
    def test_file_moved_from_partial(self):
        """Test the handling of the FILE_MOVE event when source is partial."""
        fromfile = os.path.join(self.root_dir, "mdid.u1partial.foo")
        root_dir = os.path.join(self.root_dir, "my_files")
        tofile = os.path.join(root_dir, "foo")
        os.mkdir(root_dir)
        open(fromfile, "w").close()
        self.monitor.add_to_mute_filter("FS_FILE_CREATE", path=tofile)
        self.monitor.add_to_mute_filter("FS_FILE_CLOSE_WRITE", path=tofile)
        self.assertEqual(self._how_many_muted(), 2)
        yield self.monitor.add_watch(root_dir)

        # generate the event
        rename(fromfile, tofile)
        reactor.callLater(self.timeout - 0.2, self.check_filter)
        test_result = yield self._deferred
        defer.returnValue(test_result)
