# tests.syncdaemon.test_eq_inotify
#
# Authors: Facundo Batista <facundo@canonical.com>
#          Manuel de la Pena <manuel@canonical.com>
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
"""Tests for the Event Queue part that uses inotify."""

import functools
import logging
import os
import sys

from twisted.internet import defer, reactor
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipIfOS, skipIfNotOS

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    FakeMain,
    Listener,
    skip_if_darwin_missing_fs_event,
    skip_if_win32_missing_fs_event,
)
from ubuntuone.syncdaemon.tests.test_eventqueue import BaseEQTestCase
from ubuntuone.platform import (
    make_link,
    make_dir,
    open_file,
    path_exists,
    remove_file,
    remove_dir,
    rename,
    set_no_rights,
    set_file_readwrite,
    set_dir_readwrite,
)
from ubuntuone.syncdaemon import event_queue, volume_manager

# our logging level
TRACE = logging.getLevelName('TRACE')


class DontHitMe(object):
    """We shouldn't be called."""

    def __init__(self, test_instance):
        self.test_instance = test_instance

    def handle_default(self, *a, **k):
        """Something here? Error!"""
        self.test_instance.finished_error("Don't hit me! Received %s %s" %
                                          (a, k))


class FakedVolume(object):

    path = __file__


class WatchTests(BaseEQTestCase):
    """Test the EQ API to add and remove watchs."""

    @defer.inlineCallbacks
    def test_add_watch(self):
        """Test that watchs can be added."""
        called = []
        method_resp = object()
        method_arg = object()

        def add_watch(path):
            """Fake it."""
            called.append(path)
            return defer.succeed(method_resp)

        self.eq.monitor.add_watch = add_watch
        res = yield self.eq.add_watch(method_arg)
        self.assertEqual(called, [method_arg])
        self.assertEqual(res, method_resp)

    @defer.inlineCallbacks
    def test_add_watches_to_udf_ancestors(self):
        """Test that ancestors watches can be added."""
        called = []
        method_resp = True
        method_arg = FakedVolume()

        def add_watches_to_udf_ancestors(path):
            """Fake it."""
            called.append(path)
            return defer.succeed(method_resp)

        self.patch(self.eq.monitor, 'add_watches_to_udf_ancestors',
                   add_watches_to_udf_ancestors)
        res = yield self.eq.add_watches_to_udf_ancestors(method_arg)
        self.assertEqual(called, [method_arg])
        self.assertEqual(res, method_resp)

    @defer.inlineCallbacks
    def test_add_watches_to_udf_ancestors_no_access(self):
        """Test that ancestors watches are not added."""
        called = []
        method_resp = True
        method_arg = FakedVolume()

        def add_watches_to_udf_ancestors(path):
            """Fake it."""
            called.append(path)
            return defer.succeed(method_resp)

        self.patch(event_queue, 'access', lambda path: False)
        self.patch(self.eq.monitor, 'add_watches_to_udf_ancestors',
                   add_watches_to_udf_ancestors)
        added = yield self.eq.add_watches_to_udf_ancestors(method_arg)
        self.assertFalse(added, 'Watches should have not been added.')
        self.assertEqual(0, len(called))

    def test_rm_watch(self):
        """Test that watchs can be removed."""
        called = []
        self.eq.monitor.rm_watch = lambda *a: called.append(a)
        self.eq.rm_watch('foo')
        self.assertEqual(called, [('foo',)])


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
        """Typical method faker."""
        if not name.startswith("handle_"):
            return
        asked_event = name[7:]

        def to_check(asked_event, **asked_args):
            """The function that actually be called."""
            # to what we should match
            step, should_evtname, should_args = self.should_events.pop()

            if should_evtname != asked_event:
                msg = "Event %r asked in bad order (%d)" % (asked_event, step)
                self.test_machinery.finished_error(msg)

            if asked_args != should_args:
                self.test_machinery.finished_error(
                    "In step %d received wrong args (%r)" % (step, asked_args))
            else:
                if step == self.final_step:
                    self.test_machinery.finished_ok()

        return functools.partial(to_check, asked_event)


class BaseTwisted(BaseEQTestCase):
    """Base class for twisted tests."""

    # this timeout must be bigger than the one used in event_queue
    timeout = 2

    # use the default FSMonitor
    _monitor_class = None

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(BaseTwisted, self).setUp()

        # create the deferred for the tests
        self._deferred = defer.Deferred()

    def finished_ok(self, data=True):
        """Called to indicate that the tests finished ok."""
        reactor.callLater(.1, self._deferred.callback, data)

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
    assertEqual = failUnlessEqual


class FreezeTests(BaseTwisted):
    """Test the freeze mechanism."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(FreezeTests, self).setUp()
        self.handler = MementoHandler()
        self.handler.setLevel(TRACE)
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)

    def test_api(self):
        """API for freeze/freeze_commit stuff."""
        # bad args
        self.assertRaises(TypeError, self.eq.freeze_begin)
        self.assertRaises(TypeError, self.eq.freeze_begin, 1, 2)
        self.assertRaises(TypeError, self.eq.freeze_commit)
        self.assertRaises(TypeError, self.eq.freeze_commit, 1, 2)
        self.assertRaises(TypeError, self.eq.freeze_rollback, 1)
        self.assertRaises(TypeError, self.eq.is_frozen, 1)

        # nothing frozen
        self.assertRaises(ValueError, self.eq.freeze_commit, [])
        self.assertRaises(ValueError, self.eq.freeze_rollback)
        self.assertFalse(self.eq.is_frozen())

        # freeze, no-double-freeze, freeze_commit, no post-commit or rollback
        self.eq.freeze_begin('1')
        self.assertRaises(ValueError, self.eq.freeze_begin, '1')
        self.assertTrue(self.eq.is_frozen())
        self.eq.freeze_commit([])
        self.assertRaises(ValueError, self.eq.freeze_commit, [])
        self.assertRaises(ValueError, self.eq.freeze_rollback)
        self.assertFalse(self.eq.is_frozen())

        # freeze, rollback, no post-commit or rollback
        self.eq.freeze_begin('1')
        self.assertRaises(ValueError, self.eq.freeze_begin, '1')
        self.assertTrue(self.eq.is_frozen())
        self.eq.freeze_rollback()
        self.assertRaises(ValueError, self.eq.freeze_commit, [])
        self.assertRaises(ValueError, self.eq.freeze_rollback)
        self.assertFalse(self.eq.is_frozen())

    def test_log_begin(self):
        """Test the log when freeze begins."""
        self.eq.freeze_begin("path")
        self.assertTrue(self.handler.check(TRACE, "Freeze begin", "path"))

    def test_log_rollback(self):
        """Test the log when freeze rollbacks."""
        self.eq.freeze_begin("path")
        self.eq.freeze_rollback()
        self.assertTrue(self.handler.check_debug("Freeze rollback", "path"))

    def test_log_commit_ok(self):
        """Test the log when freeze is commited ok."""
        self.eq.freeze_begin("path")
        self.eq.freeze_commit([])
        self.handler.debug = True
        self.assertTrue(self.handler.check(TRACE, "Freeze commit", "path",
                                           "0 events"))

    def test_log_commit_dirty(self):
        """Test the log when freeze is commited but dirty."""
        self.eq.freeze_begin("path")
        self.eq.monitor._processor.general_processor.frozen_evts = ('event',
                                                                    'otherpth')
        self.eq.freeze_commit([])
        self.handler.debug = True
        self.assertTrue(self.handler.check_debug("Dirty by", "otherpth",
                                                 "event"))

    @defer.inlineCallbacks
    def test_commit_no_middle_events(self):
        """Commit behaviour when nothing happened in the middle."""
        testdir = os.path.join(self.root_dir, "foo")
        make_dir(testdir)

        class HitMe(object):

            def handle_FS_DIR_DELETE(innerself, path):
                if path != "foobar":
                    self.finished_error("received a wrong path")
                else:
                    self.finished_ok()

        def freeze_commit():
            """release with handcrafted event and check result."""
            d = self.eq.freeze_commit([("FS_DIR_DELETE", "foobar")])

            def check(dirty):
                """check dirty"""
                if dirty:
                    self.finished_error("should not be dirty here")
            d.addCallback(check)

        # set up everything and freeze
        yield self.eq.add_watch(testdir)
        listener = HitMe()
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)
        self.eq.freeze_begin(testdir)

        reactor.callLater(.1, freeze_commit)
        yield self._deferred

    @skip_if_win32_missing_fs_event
    @skip_if_darwin_missing_fs_event
    @defer.inlineCallbacks
    def test_commit_middle_events(self):
        """Commit behaviour when something happened in the middle."""
        testdir = os.path.join(self.root_dir, "foo")
        testfile = os.path.join(testdir, "bar")
        make_dir(testdir)

        def freeze_commit():
            """Release and check result."""
            d = self.eq.freeze_commit([("FS_DIR_DELETE", "foobar")])

            def check(dirty):
                """check dirty"""
                if not dirty:
                    self.finished_error("it *should* be dirty here")
                else:
                    self.finished_ok()
            d.addCallback(check)

        # set up everything and freeze
        yield self.eq.add_watch(testdir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)
        self.eq.freeze_begin(testdir)

        open_file(testfile, "w").close()
        reactor.callLater(.1, freeze_commit)
        yield self._deferred

    @defer.inlineCallbacks
    def test_rollback(self):
        """Check rollback."""
        testdir = os.path.join(self.root_dir, "foo")
        testfile = os.path.join(testdir, "bar")
        make_dir(testdir)

        class HitMe(object):

            def handle_FS_DIR_DELETE(innerself, path):
                if path != "foobar":
                    self.finished_error("received a wrong path")
                else:
                    self.finished_ok()

        def freeze_rollback():
            """release with handcrafted event and check result."""
            self.eq.freeze_rollback()
            self.eq.freeze_begin(testdir)
            reactor.callLater(
                .1, self.eq.freeze_commit, [("FS_DIR_DELETE", "foobar")])

        # set up everything and freeze
        yield self.eq.add_watch(testdir)
        listener = HitMe()
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)
        self.eq.freeze_begin(testdir)

        # don't matter if had changes, rollback cleans them
        open_file(testfile, "w").close()
        reactor.callLater(.1, freeze_rollback)
        yield self._deferred

    @skip_if_win32_missing_fs_event
    @skip_if_darwin_missing_fs_event
    @defer.inlineCallbacks
    def test_selective(self):
        """Check that it's frozen only for a path."""
        testdir = os.path.join(self.root_dir, "foo")
        make_dir(testdir)
        testfile = os.path.join(self.root_dir, "bar")

        class HitMe(object):

            def __init__(innerself):
                innerself.hist = []

            def handle_FS_FILE_CREATE(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                else:
                    innerself.hist.append("create")

            def handle_FS_FILE_CLOSE_WRITE(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                else:
                    if innerself.hist == ["create"]:
                        remove_file(testfile)
                        self.finished_ok()
                    else:
                        msg = "Finished in bad condition: %s" % innerself.hist
                        self.finished_error(msg)

        # set up everything
        yield self.eq.add_watch(self.root_dir)
        yield self.eq.add_watch(testdir)
        listener = HitMe()
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # only freeze one path
        self.eq.freeze_begin(testdir)

        # generate events in the nonfrozen path
        open_file(testfile, "w").close()

        yield self._deferred


class MutedSignalsTests(BaseTwisted):
    """Test that EQ filter some signals on demand."""

    def check_filter(self, _=None):
        """Check the filter content."""
        self.assertFalse(self.eq._processor._to_mute._cnt)
        self.finished_ok()

    @defer.inlineCallbacks
    def test_file_open(self):
        """Test receiving the open signal on files."""
        testfile = os.path.join(self.root_dir, "foo")
        open_file(testfile, "w").close()
        self.eq.add_to_mute_filter("FS_FILE_OPEN", path=testfile)
        self.eq.add_to_mute_filter("FS_FILE_CLOSE_NOWRITE", path=testfile)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        open_file(testfile)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_close_nowrite(self):
        """Test receiving the close_nowrite signal on files."""
        testfile = os.path.join(self.root_dir, "foo")
        open_file(testfile, "w").close()
        fh = open_file(testfile)
        self.eq.add_to_mute_filter("FS_FILE_CLOSE_NOWRITE", path=testfile)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        fh.close()
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_create_close_write(self):
        """Test receiving the create and close_write signals on files."""
        testfile = os.path.join(self.root_dir, "foo")
        self.eq.add_to_mute_filter("FS_FILE_CREATE", path=testfile)
        self.eq.add_to_mute_filter("FS_FILE_OPEN", path=testfile)
        self.eq.add_to_mute_filter("FS_FILE_CLOSE_WRITE", path=testfile)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        open_file(testfile, "w").close()
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_create(self):
        """Test receiving the create signal on dirs."""
        testdir = os.path.join(self.root_dir, "foo")
        self.eq.add_to_mute_filter("FS_DIR_CREATE", path=testdir)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        make_dir(testdir)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_delete(self):
        """Test the delete signal on a file."""
        testfile = os.path.join(self.root_dir, "foo")
        open_file(testfile, "w").close()
        self.eq.add_to_mute_filter("FS_FILE_DELETE", path=testfile)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        remove_file(testfile)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_delete(self):
        """Test the delete signal on a dir."""
        testdir = os.path.join(self.root_dir, "foo")
        make_dir(testdir)
        self.eq.add_to_mute_filter("FS_DIR_DELETE", path=testdir)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        remove_dir(testdir)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @skip_if_win32_missing_fs_event
    @defer.inlineCallbacks
    def test_file_moved_inside(self):
        """Test the synthesis of the FILE_MOVE event."""
        fromfile = os.path.join(self.root_dir, "foo")
        self.fs.create(fromfile, "")
        self.fs.set_node_id(fromfile, "from_node_id")
        tofile = os.path.join(self.root_dir, "bar")
        self.fs.create(tofile, "")
        self.fs.set_node_id(tofile, "to_node_id")
        open_file(fromfile, "w").close()
        self.eq.add_to_mute_filter("FS_FILE_MOVE",
                                   path_from=fromfile, path_to=tofile)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        rename(fromfile, tofile)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_moved_inside(self):
        """Test the synthesis of the DIR_MOVE event."""
        fromdir = os.path.join(self.root_dir, "foo")
        self.fs.create(fromdir, "")
        self.fs.set_node_id(fromdir, "from_node_id")
        todir = os.path.join(self.root_dir, "bar")
        self.fs.create(todir, "")
        self.fs.set_node_id(todir, "to_node_id")
        make_dir(fromdir)
        self.eq.add_to_mute_filter("FS_DIR_MOVE",
                                   path_from=fromdir, path_to=todir)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        rename(fromdir, todir)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_moved_to_conflict(self):
        """Test the handling of the FILE_MOVE event when dest is conflict."""
        fromfile = os.path.join(self.root_dir, "foo")
        self.fs.create(fromfile, "")
        self.fs.set_node_id(fromfile, "from_node_id")
        tofile = os.path.join(self.root_dir, "foo.u1conflict")
        self.fs.create(tofile, "")
        self.fs.set_node_id(tofile, "to_node_id")
        open_file(fromfile, "w").close()
        self.eq.add_to_mute_filter("FS_FILE_DELETE", path=fromfile)

        yield self.eq.add_watch(self.root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        rename(fromfile, tofile)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred

    @skip_if_win32_missing_fs_event
    @defer.inlineCallbacks
    def test_file_moved_from_partial(self):
        """Test the handling of the FILE_MOVE event when source is partial."""
        fromfile = os.path.join(self.root_dir, "mdid.u1partial.foo")
        root_dir = os.path.join(self.root_dir, "my_files")
        tofile = os.path.join(root_dir, "foo")
        make_dir(root_dir)
        open_file(fromfile, "w").close()
        self.eq.add_to_mute_filter("FS_FILE_CREATE", path=tofile)
        if sys.platform == 'darwin':
            self.eq.add_to_mute_filter("FS_FILE_OPEN", path=tofile)
        self.eq.add_to_mute_filter("FS_FILE_CLOSE_WRITE", path=tofile)

        yield self.eq.add_watch(root_dir)
        listener = DontHitMe(self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        rename(fromfile, tofile)
        reactor.callLater(.1, self._deferred.callback, True)
        yield self._deferred


@skipIfNotOS('linux2', "Only Linux watches UDF ancestors")
class AncestorsUDFTestCase(BaseTwistedTestCase):
    """Events over UDF's ancestor are properly handled."""

    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(AncestorsUDFTestCase, self).setUp()
        self._deferred = defer.Deferred()
        self.root_dir = self.mktemp('root_dir')
        self.data_dir = self.mktemp('data_dir')
        self.shares_dir = self.mktemp('shares_dir')
        self.partials_dir = self.mktemp('partials_dir')
        self.patch(FakeMain, '_monitor_class', None)
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.addCleanup(self.main.shutdown)
        self.eq = self.main.event_q
        assert self.eq is self.eq.fs.vm.m.event_q

        self.listener = Listener()
        self.eq.subscribe(self.listener)
        self.addCleanup(self.eq.unsubscribe, self.listener)

        # create UDF
        suggested_path = u'~/Documents/Reading/Books/PDFs'
        udf_id, node_id = 'udf_id', 'node_id'
        path = volume_manager.get_udf_path(suggested_path)
        self.udf = volume_manager.UDF(udf_id, node_id,
                                      suggested_path, path, True)
        make_dir(path, recursive=True)
        yield self.eq.fs.vm.add_udf(self.udf)

        # create a second UDF
        suggested_path = u'~/Documents/Reading/Magazines/Text'
        udf_id2, node_id2 = 'udf_id_2', 'node_id_2'
        path = volume_manager.get_udf_path(suggested_path)
        self.udf2 = volume_manager.UDF(udf_id2, node_id2,
                                       suggested_path, path, True)
        make_dir(path, recursive=True)
        yield self.eq.fs.vm.add_udf(self.udf2)

        # every ancestor has a watch already, added by LocalRescan. Copy that.
        yield self.eq.add_watch(self.udf.path)
        for path in self.udf.ancestors:
            yield self.eq.add_watch(path)

        yield self.eq.add_watch(self.udf2.path)
        for path in self.udf2.ancestors:
            yield self.eq.add_watch(path)

        # reset events up to now
        self.listener.events = []

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
            self._deferred.errback(msg)
            raise exception
        return first
    assertEqual = failUnlessEqual

    @defer.inlineCallbacks
    def test_file_events_are_ignored_on_udf_ancestor(self):
        """Events on UDF ancestors are ignored."""
        for path in self.udf.ancestors:
            assert path in self.eq.monitor._ancestors_watchs

            fname = os.path.join(path, 'testit')
            # generate FS_FILE_CREATE, FS_FILE_OPEN, FS_FILE_CLOSE_WRITE
            open_file(fname, 'w').close()
            # generate FS_FILE_CLOSE_NOWRITE
            f = open_file(fname)
            f.read()
            f.close()
            # generate FS_FILE_DELETE
            remove_file(fname)

            fnamedir = os.path.join(path, 'testit.dir')
            # generate FS_DIR_CREATE
            make_dir(fnamedir)
            # generate FS_DIR_DELETE
            remove_dir(fnamedir)

        def check():
            """Check."""
            self.assertEqual([], self.listener.events)
            self._deferred.callback(True)

        reactor.callLater(.1, check)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_events_are_not_ignored_on_others(self):
        """Events in the UDF are not ignored."""
        path = self.udf.path

        fname = os.path.join(path, 'testit')
        # generate FS_FILE_CREATE, FS_FILE_OPEN, FS_FILE_CLOSE_WRITE
        open_file(fname, 'w').close()
        # generate FS_FILE_CLOSE_NOWRITE
        f = open_file(fname)
        f.read()
        f.close()
        # generate FS_FILE_DELETE
        remove_file(fname)

        fnamedir = os.path.join(path, 'testit.dir')
        # generate FS_DIR_CREATE
        make_dir(fnamedir)
        # generate FS_DIR_DELETE
        remove_dir(fnamedir)

        expected = [('FS_FILE_CREATE', {'path': fname}),
                    ('FS_FILE_OPEN', {'path': fname}),
                    ('FS_FILE_CLOSE_WRITE', {'path': fname}),
                    ('FS_FILE_OPEN', {'path': fname}),
                    ('FS_FILE_CLOSE_NOWRITE', {'path': fname}),
                    ('FS_FILE_DELETE', {'path': fname}),
                    ('FS_DIR_CREATE', {'path': fnamedir}),
                    ('FS_DIR_DELETE', {'path': fnamedir})]

        def check():
            """Check."""
            self.assertEqual(expected, self.listener.events)
            self._deferred.callback(True)

        reactor.callLater(.1, check)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_events_are_not_ignored_on_common_prefix_name(self):
        """Events in a UDF with similar name to ancestor are not ignored."""
        fname = os.path.join(self.udf2.path, 'testit')
        expected = [('FS_FILE_CREATE', {'path': fname}),
                    ('FS_FILE_OPEN', {'path': fname}),
                    ('FS_FILE_CLOSE_WRITE', {'path': fname}),
                    ('FS_FILE_OPEN', {'path': fname}),
                    ('FS_FILE_CLOSE_NOWRITE', {'path': fname})]

        def check():
            """Check."""
            self.assertEqual(expected, self.listener.events)
            self._deferred.callback(True)

        # generate FS_FILE_CREATE, FS_FILE_OPEN, FS_FILE_CLOSE_WRITE
        open_file(fname, 'w').close()

        # generate FS_FILE_CLOSE_NOWRITE
        f = open_file(fname)
        f.read()
        f.close()

        reactor.callLater(.1, check)
        yield self._deferred

    def test_move_udf_ancestor(self):
        """UDF is unsubscribed on ancestor move."""
        path = self.udf.ancestors[-2]  # an ancestor common to both UDFs
        # generate IN_MOVED_FROM and IN_MOVED_TO
        newpath = path + '.old'  # no unicode, paths are always a byte sequence

        # nessita: shouldn't this rename fails in windows since we lock the
        # path by having a watch inside 'path'?
        rename(path, newpath)
        self.log.info('Renamed %r to %r so we can test UDF unsubscribal.')
        assert not path_exists(path)
        assert path_exists(newpath)

        unsubscribed = []

        def check():
            """Check."""
            self.assertEqual(len(unsubscribed), 2)
            for uid in unsubscribed:
                if uid == self.udf.id:
                    udf = self.udf
                elif uid == self.udf2.id:
                    udf = self.udf2
                else:
                    self._deferred.errback(ValueError("uid %s is wrong" % uid))
                self.assertNotIn(udf.path, self.eq.monitor._ancestors_watchs,
                                 'watch must be removed')
                self.assertEqual(False, self.eq.fs.vm.udfs[udf.id].subscribed)
            self._deferred.callback(True)

        original = self.eq.fs.vm.unsubscribe_udf

        def unsubsc(uid):
            original(uid)
            unsubscribed.append(uid)

        self.patch(self.eq.fs.vm, 'unsubscribe_udf', unsubsc)

        reactor.callLater(.1, check)
        return self._deferred

    def test_move_udf_itself(self):
        """UDF is unsubscribed if renamed."""
        newpath = self.udf.path + '.old'
        # nessita: shouldn't this rename fails in windows since we lock the
        # path by having a watch inside 'path'?
        rename(self.udf.path, newpath)
        assert path_exists(newpath)

        unsubscribed = []

        def check():
            """Check."""
            self.assertEqual(len(unsubscribed), 1)
            uid = unsubscribed[0]
            self.assertEqual(uid, self.udf.id, "wrong UDF removed!")
            self.assertNotIn(
                self.udf.path, self.eq.monitor._ancestors_watchs,
                'watch must be removed')
            self.assertEqual(
                False, self.eq.fs.vm.udfs[self.udf.id].subscribed)
            self._deferred.callback(True)

        original = self.eq.fs.vm.unsubscribe_udf

        def unsubsc(uid):
            original(uid)
            unsubscribed.append(uid)
        self.patch(self.eq.fs.vm, 'unsubscribe_udf', unsubsc)

        reactor.callLater(.1, check)
        return self._deferred

    def test_remove_udf_per_se_subsc(self):
        """Removing an UDF should generate VOLUME_DELETED, if subscribed."""
        expected = []
        self.patch(self.eq.fs.vm, 'delete_volume', expected.append)

        uid = self.udf.volume_id
        fnamedir = self.udf.path
        remove_dir(fnamedir)

        def check():
            """Check."""
            self.assertEqual([], self.listener.events)
            self.assertEqual(expected, [uid], 'udf deleted')
            self._deferred.callback(True)

        reactor.callLater(.1, check)
        return self._deferred

    def test_remove_udf_per_se_unsubsc(self):
        """If not subscribed, removing an UDF should do nothing."""
        expected = []
        self.patch(self.eq.fs.vm, 'delete_volume', expected.append)

        # unsubscribe and reset listener events
        self.eq.fs.vm.unsubscribe_udf(self.udf.volume_id)
        self.listener.events = []

        fnamedir = self.udf.path
        remove_dir(fnamedir)

        def check():
            """Check."""
            self.assertEqual([], self.listener.events)
            self.assertEqual(expected, [], 'udf should not be deleted')
            self._deferred.callback(True)

        reactor.callLater(.1, check)
        return self._deferred

    def test_removeudf_removeancestors(self):
        """If an UDF is removed, also the watches in its ancestors."""
        removed_watches = []
        self.patch(self.eq.monitor, 'rm_watch', removed_watches.append)

        # only the parent, as the other ancestors are shared with other UDFs
        # and should not be removed
        expected = os.path.dirname(self.udf.path)

        def check():
            self.assertEqual([expected], removed_watches,
                             "Removed watches don't match the expected")
            self._deferred.callback(True)

        remove_dir(self.udf.path)
        reactor.callLater(.1, check)
        return self._deferred

    def test_unsubscribe_removeancestors(self):
        """Remove the watches of the ancestors in an unsubscription."""
        removed_watches = []
        original = self.eq.monitor.rm_watch

        def remove_watch(path):
            """Store the path."""
            original(path)
            removed_watches.append(path)

        self.patch(self.eq.monitor, 'rm_watch', remove_watch)

        # only the parent, as the other ancestors are shared with other UDFs
        # and should not be removed, and the path of the udf itself
        expected = [os.path.dirname(self.udf.path), self.udf.path]

        def check():
            self.assertEqual(sorted(expected), sorted(removed_watches),
                             "Removed watches don't match the expected")
            self._deferred.callback(True)

        rename(self.udf.path, self.udf.path + ".old")
        reactor.callLater(.1, check)
        return self._deferred

    def test_unsubscribe_rename_removeancestors(self):
        """Mix of unsubscription and further renaming."""
        removed_watches = []
        original = self.eq.monitor.rm_watch

        def remove_watch(path):
            """Store the path."""
            original(path)
            removed_watches.append(path)

        self.patch(self.eq.monitor, 'rm_watch', remove_watch)

        # all should be removed
        expected = list(set(self.udf.ancestors) | set(self.udf2.ancestors))
        expected += [self.udf.path, self.udf2.path]

        def check():
            self.assertEqual(sorted(expected), sorted(removed_watches),
                             "Removed watches don't match the expected")
            self._deferred.callback(True)

        path = self.udf.ancestors[-2]  # an ancestor common to both UDFs

        rename(self.udf.path, self.udf.path + ".old")
        rename(path, path + ".old")
        reactor.callLater(.1, check)
        return self._deferred


@skipIfOS('win32', "we can't create files with invalid utf8 byte sequences.")
@skipIfOS('darwin', "fsevents daemon ignores events with invalid filenames")
class NonUTF8NamesTests(BaseTwisted):
    """Test the non-utf8 name handling."""

    invalid_name = "invalid \xff\xff name"

    @defer.inlineCallbacks
    def setUp(self):
        yield super(NonUTF8NamesTests, self).setUp()
        self.invalid_path = os.path.join(self.root_dir, self.invalid_name)

    @defer.inlineCallbacks
    def test_file_open(self):
        """Test invalid_filename after open a file."""
        open_file(self.invalid_path, "w").close()
        self.addCleanup(remove_file, self.invalid_path)

        yield self.eq.add_watch(self.root_dir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # open
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # close
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        open_file(self.invalid_path)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_close_nowrite(self):
        """Test invalid_filename after a close no write."""
        open_file(self.invalid_path, "w").close()
        self.addCleanup(remove_file, self.invalid_path)
        fh = open_file(self.invalid_path)

        yield self.eq.add_watch(self.root_dir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # close
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        fh.close()
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_create_close_write(self):
        """Test invalid_filename after a create, open and close write."""
        yield self.eq.add_watch(self.root_dir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # new
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # open
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # close
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        open_file(self.invalid_path, "w").close()
        self.addCleanup(remove_file, self.invalid_path)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_create(self):
        """Test invalid_filename after a dir create."""
        yield self.eq.add_watch(self.root_dir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # new
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        make_dir(self.invalid_path)
        self.addCleanup(remove_dir, self.invalid_path)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_delete(self):
        """Test invalid_filename after a file delete."""
        open_file(self.invalid_path, "w").close()

        yield self.eq.add_watch(self.root_dir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # del
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        remove_file(self.invalid_path)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_delete(self):
        """Test invalid_filename after a dir delete."""
        make_dir(self.invalid_path)

        yield self.eq.add_watch(self.root_dir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=self.root_dir, filename=self.invalid_name)),  # del
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        remove_dir(self.invalid_path)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_move_to(self):
        """Test invalid_filename after moving a file into a watched dir."""
        open_file(self.invalid_path, "w").close()
        destdir = os.path.join(self.root_dir, "watched_dir")
        make_dir(destdir)
        destfile = os.path.join(destdir, self.invalid_name)

        yield self.eq.add_watch(destdir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=destdir, filename=self.invalid_name)),  # move to
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        rename(self.invalid_path, destfile)
        self.addCleanup(remove_file, destfile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_move_from(self):
        """Test invalid_filename after moving a file from a watched dir."""
        fromdir = os.path.join(self.root_dir, "watched_dir")
        make_dir(fromdir)
        fromfile = os.path.join(fromdir, self.invalid_name)
        open_file(fromfile, "w").close()
        destfile = os.path.join(self.root_dir, self.invalid_name)

        yield self.eq.add_watch(fromdir)
        should_events = [
            ('FS_INVALID_NAME',
             dict(dirname=fromdir, filename=self.invalid_name)),  # move from
        ]
        listener = DynamicHitMe(should_events, self)
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # generate the event
        rename(fromfile, destfile)
        self.addCleanup(remove_file, destfile)
        yield self._deferred


@skip_if_win32_missing_fs_event
@skip_if_darwin_missing_fs_event
class SignalingTests(BaseTwisted):
    """Test the whole stuff to receive signals."""

    @defer.inlineCallbacks
    def test_file_open(self):
        """Test receiving the open signal on files."""
        testfile = os.path.join(self.root_dir, "foo")

        class HitMe(object):

            def handle_FS_FILE_OPEN(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                else:
                    remove_file(testfile)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        open_file(testfile, "w")
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_close_nowrite(self):
        """Test receiving the close_nowrite signal on files."""
        testfile = os.path.join(self.root_dir, "foo")
        open_file(testfile, "w").close()
        fh = open_file(testfile)

        class HitMe(object):

            def handle_FS_FILE_CLOSE_NOWRITE(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                else:
                    remove_file(testfile)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        fh.close()
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_create_close_write(self):
        """Test receiving the create and close_write signals on files."""
        testfile = os.path.join(self.root_dir, "foo")

        class HitMe(object):

            def __init__(innerself):
                innerself.hist = []

            def handle_FS_FILE_CREATE(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                else:
                    innerself.hist.append("create")

            def handle_FS_FILE_CLOSE_WRITE(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                else:
                    if innerself.hist == ["create"]:
                        remove_file(testfile)
                        self.finished_ok()
                    else:
                        msg = "Finished in bad condition: %s" % innerself.hist
                        self.finished_error(msg)

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        open_file(testfile, "w").close()
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_create(self):
        """Test receiving the create signal on dirs."""
        testdir = os.path.join(self.root_dir, "foo")

        class HitMe(object):

            def handle_FS_DIR_CREATE(innerself, path):
                if path != testdir:
                    self.finished_error("received a wrong path")
                else:
                    remove_dir(testdir)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        make_dir(testdir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_delete(self):
        """Test the delete signal on a file."""
        testfile = os.path.join(self.root_dir, "foo")
        open_file(testfile, "w").close()

        class HitMe(object):

            def handle_FS_FILE_DELETE(innerself, path):
                if path != testfile:
                    self.finished_error("received a wrong path")
                    return

                if not self.log_handler.check_info('FS_FILE_DELETE', testfile):
                    self.finished_error("FS_FILE_DELETE must appear in INFO.")
                    return

                self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        remove_file(testfile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_delete(self):
        """Test the delete signal on a dir."""
        testdir = os.path.join(self.root_dir, "foo")
        make_dir(testdir)

        class HitMe(object):

            def handle_FS_DIR_DELETE(innerself, path):
                if path != testdir:
                    self.finished_error("received a wrong path")
                    return

                if not self.log_handler.check_info('FS_DIR_DELETE', testdir):
                    self.finished_error("FS_DIR_DELETE must appear in INFO.")
                    return

                # file deletion should remove its watch
                self.assertNotIn(testdir, self.eq.monitor._general_watchs)

                self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        remove_dir(testdir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_symlink(self):
        """Test that symlinks are ignored."""
        testdir = os.path.join(self.root_dir, "foo")
        make_dir(testdir)
        fromfile = os.path.join(self.root_dir, "from")
        open_file(fromfile, "w").close()
        symlpath = os.path.join(testdir, "syml")

        def confirm():
            """check result."""
            self.finished_ok()

        # set up everything and freeze
        yield self.eq.add_watch(testdir)
        self.eq.subscribe(DontHitMe(self))

        make_link(fromfile, symlpath)
        reactor.callLater(.1, confirm)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_moved_from(self):
        """Test receiving the delete signal on a file when moved_from."""
        fromfile = os.path.join(self.root_dir, "foo")
        helpdir = os.path.join(self.root_dir, "dir")
        tofile = os.path.join(helpdir, "foo")
        open_file(fromfile, "w").close()
        make_dir(helpdir)

        class HitMe(object):

            def handle_FS_FILE_DELETE(innerself, path):
                if path != fromfile:
                    self.finished_error("received a wrong path")
                else:
                    remove_file(tofile)
                    remove_dir(helpdir)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(fromfile, tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_moved_from(self):
        """Test receiving the delete signal on a dir when it's moved_from."""
        fromdir = os.path.join(self.root_dir, "foo")
        helpdir = os.path.join(self.root_dir, "dir")
        todir = os.path.join(helpdir, "foo")
        make_dir(fromdir)
        make_dir(helpdir)

        class HitMe(object):

            def handle_FS_DIR_DELETE(innerself, path):
                self.eq.rm_watch(self.root_dir)
                if path != fromdir:
                    self.finished_error("received a wrong path")
                else:
                    # file deletion should remove its watch
                    self.assertNotIn(path, self.eq.monitor._general_watchs)

                    remove_dir(todir)
                    remove_dir(helpdir)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(fromdir, todir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_moved_to(self):
        """Test receiving the create signal on a file when it's moved_to."""
        fromfile = os.path.join(self.root_dir, "dir", "foo")
        tofile = os.path.join(self.root_dir, "foo")
        helpdir = os.path.join(self.root_dir, "dir")
        make_dir(helpdir)
        open_file(fromfile, "w").close()

        class HitMe(object):

            def handle_FS_FILE_CREATE(innerself, path):
                if path != tofile:
                    self.finished_error("received a wrong path")
                else:
                    remove_file(tofile)
                    remove_dir(helpdir)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(fromfile, tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_moved_to(self):
        """Test receiving the create signal on a file when it's moved_to."""
        fromdir = os.path.join(self.root_dir, "dir", "foo")
        todir = os.path.join(self.root_dir, "foo")
        helpdir = os.path.join(self.root_dir, "dir")
        make_dir(helpdir)
        make_dir(fromdir)

        class HitMe(object):

            def handle_FS_DIR_CREATE(innerself, path):
                if path != todir:
                    self.finished_error("received a wrong path")
                else:
                    remove_dir(todir)
                    remove_dir(helpdir)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(fromdir, todir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_moved_from_ignored(self):
        """Test moving a dir from ignored name."""
        fromdir = os.path.join(self.root_dir, "bar")
        todir = os.path.join(self.root_dir, "foo")
        make_dir(fromdir)

        # patch the general processor to ignore all that ends with bar
        self.patch(self.eq.monitor._processor.general_processor, "is_ignored",
                   lambda path: path.endswith("bar"))

        should_events = [("FS_DIR_CREATE", dict(path=todir))]

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(DynamicHitMe(should_events, self))

        # generate the event
        rename(fromdir, todir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_moved_to_ignored(self):
        """Test moving a dir to ignored name."""
        fromdir = os.path.join(self.root_dir, "foo")
        todir = os.path.join(self.root_dir, "bar")
        make_dir(fromdir)

        # patch to check proper dir deletion is handled
        called = []
        self.patch(self.eq.monitor._processor.general_processor,
                   'handle_dir_delete', lambda p: called.append(p))

        # patch the general processor to ignore all that ends with bar
        self.patch(self.eq.monitor._processor.general_processor, "is_ignored",
                   lambda path: path.endswith("bar"))

        should_events = [("FS_DIR_DELETE", dict(path=fromdir))]

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(DynamicHitMe(should_events, self))

        # generate the event
        rename(fromdir, todir)
        yield self._deferred
        self.assertEqual(called, [fromdir])

    @defer.inlineCallbacks
    def test_file_moved_from_ignored(self):
        """Test moving a file from ignored name."""
        fromfile = os.path.join(self.root_dir, "bar")
        tofile = os.path.join(self.root_dir, "foo")
        open_file(fromfile, 'w').close()

        # patch the general processor to ignore all that ends with bar
        self.patch(self.eq.monitor._processor.general_processor, "is_ignored",
                   lambda path: path.endswith("bar"))

        should_events = [
            ("FS_FILE_CREATE", dict(path=tofile)),
            ("FS_FILE_CLOSE_WRITE", dict(path=tofile)),
        ]
        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(DynamicHitMe(should_events, self))

        # generate the event
        rename(fromfile, tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_moved_to_ignored(self):
        """Test moving a file to ignored name."""
        fromfile = os.path.join(self.root_dir, "foo")
        tofile = os.path.join(self.root_dir, "bar")
        open_file(fromfile, 'w').close()

        # patch the general processor to ignore all that ends with bar
        self.patch(self.eq.monitor._processor.general_processor, "is_ignored",
                   lambda path: path.endswith("bar"))

        should_events = [("FS_FILE_DELETE", dict(path=fromfile))]

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(DynamicHitMe(should_events, self))

        # generate the event
        rename(fromfile, tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_lots_of_changes(self):
        """Test doing several operations on files."""
        helpdir = os.path.join(self.root_dir, "dir")
        make_dir(helpdir)
        mypath = functools.partial(os.path.join, self.root_dir)

        yield self.eq.add_watch(self.root_dir)

        should_events = [
            ("FS_FILE_CREATE", dict(path=mypath("foo"))),
            ("FS_FILE_OPEN", dict(path=mypath("foo"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("foo"))),
            ("FS_FILE_DELETE", dict(path=mypath("foo"))),
            ("FS_FILE_CREATE", dict(path=mypath("bar"))),
            ("FS_FILE_OPEN", dict(path=mypath("bar"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("bar"))),
            ("FS_FILE_CREATE", dict(path=mypath("foo"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("foo"))),
            ("FS_FILE_DELETE", dict(path=mypath("bar"))),
            ("FS_FILE_DELETE", dict(path=mypath("foo"))),
            ("FS_FILE_CREATE", dict(path=mypath("bar"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("bar"))),
            ("FS_FILE_DELETE", dict(path=mypath("bar"))),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))

        # generate the events
        open_file(mypath("foo"), "w").close()
        rename(mypath("foo"), mypath("dir", "foo"))
        open_file(mypath("bar"), "w").close()
        rename(mypath("dir", "foo"), mypath("foo"))
        rename(mypath("bar"), mypath("dir", "bar"))
        remove_file(mypath("foo"))
        rename(mypath("dir", "bar"), mypath("bar"))
        remove_file(mypath("bar"))
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_moved_inside(self):
        """Test the synthesis of the FILE_MOVE event."""
        fromfile = os.path.join(self.root_dir, "foo")
        self.fs.create(fromfile, "")
        self.fs.set_node_id(fromfile, "from_node_id")
        tofile = os.path.join(self.root_dir, "bar")
        self.fs.create(tofile, "")
        self.fs.set_node_id(tofile, "to_node_id")
        open_file(fromfile, "w").close()

        class HitMe(object):

            def handle_FS_FILE_MOVE(innerself, path_from, path_to):
                if path_from != fromfile:
                    self.finished_error("received a wrong path in from")
                elif path_to != tofile:
                    self.finished_error("received a wrong path in to")
                else:
                    remove_file(tofile)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(fromfile, tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_moved_inside(self):
        """Test the synthesis of the DIR_MOVE event."""
        fromdir = os.path.join(self.root_dir, "foo")
        self.fs.create(fromdir, "")
        self.fs.set_node_id(fromdir, "from_node_id")
        todir = os.path.join(self.root_dir, "bar")
        self.fs.create(todir, "")
        self.fs.set_node_id(todir, "to_node_id")
        make_dir(fromdir)

        class HitMe(object):

            def handle_FS_DIR_MOVE(innerself, path_from, path_to):
                if path_from != fromdir:
                    self.finished_error("received a wrong path in from")
                elif path_to != todir:
                    self.finished_error("received a wrong path in to")
                else:
                    remove_dir(todir)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(fromdir, todir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_file_moved_inside_mixed(self):
        """Test the synthesis of the FILE_MOVE event with more events."""
        helpdir = os.path.join(self.root_dir, "dir")
        make_dir(helpdir)
        mypath = functools.partial(os.path.join, self.root_dir)
        self.fs.create(mypath('foo'), "")
        self.fs.set_node_id(mypath('foo'), "foo_node_id")
        self.fs.create(mypath('bar'), "")
        self.fs.set_node_id(mypath('bar'), "bar_node_id")

        yield self.eq.add_watch(self.root_dir)

        should_events = [
            ("FS_FILE_CREATE", dict(path=mypath("foo"))),
            ("FS_FILE_OPEN", dict(path=mypath("foo"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("foo"))),
            ("FS_FILE_CREATE", dict(path=mypath("bar"))),
            ("FS_FILE_OPEN", dict(path=mypath("bar"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("bar"))),
            ("FS_FILE_DELETE", dict(path=mypath("foo"))),
            ("FS_FILE_CREATE", dict(path=mypath("foo"))),
            ("FS_FILE_MOVE", dict(path_from=mypath("bar"),
                                  path_to=mypath("baz"))),
            ("FS_FILE_DELETE", dict(path=mypath("foo"))),
            ("FS_FILE_DELETE", dict(path=mypath("baz"))),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))

        # generate the events
        open_file(mypath("foo"), "w").close()
        open_file(mypath("bar"), "w").close()
        rename(mypath("foo"), mypath("dir", "foo"))
        rename(mypath("dir", "foo"), mypath("foo"))
        rename(mypath("bar"), mypath("baz"))
        remove_file(mypath("foo"))
        remove_file(mypath("baz"))
        yield self._deferred

    @defer.inlineCallbacks
    def test_dir_with_contents_moved_outside(self):
        """ test the move of a dir outside the watched diresctory."""
        root = os.path.join(self.root_dir, "watched_root")
        make_dir(root)
        trash = os.path.join(self.root_dir, "trash")
        make_dir(trash)

        testdir = os.path.join(root, "testdir")
        self.eq.fs.create(testdir, '')
        self.eq.fs.set_node_id(testdir, 'testdir_id')
        make_dir(testdir)
        testfile = os.path.join(testdir, "testfile")
        self.eq.fs.create(testfile, '')
        self.eq.fs.set_node_id(testfile, 'testfile_id')
        open_file(testfile, 'w').close()

        paths = [testdir, testfile]

        class HitMe(object):

            def handle_FS_DIR_DELETE(innerself, path):
                expected = paths.pop()
                if path != expected:
                    self.finished_error("received a wrong path, expected:"
                                        " %s was: %s " % (expected, path))
                elif len(paths) == 0:
                    self.finished_ok()

            def handle_FS_FILE_DELETE(innerself, path):
                self.assertEqual(paths.pop(), path)

        yield self.eq.add_watch(root)
        self.eq.subscribe(HitMe())

        # generate the event
        rename(testdir, os.path.join(trash, os.path.basename(testdir)))
        yield self._deferred

    @defer.inlineCallbacks
    def test_creation_inside_a_moved_directory(self):
        """Test that renaming a directory is supported."""
        testdir = os.path.join(self.root_dir, "testdir")
        self.eq.fs.create(testdir, '')
        self.eq.fs.set_node_id(testdir, 'testdir_id')
        make_dir(testdir)
        newdirname = os.path.join(self.root_dir, "newdir")

        class HitMe(object):

            def handle_FS_FILE_CREATE(innerself, path):
                if path != newfilepath:
                    self.finished_error("received a wrong path")
                else:
                    remove_file(newfilepath)
                    remove_dir(newdirname)
                    self.finished_ok()

        yield self.eq.add_watch(self.root_dir)
        yield self.eq.add_watch(testdir)
        self.eq.subscribe(HitMe())

        # rename the dir
        rename(testdir, newdirname)

        # generate the event
        newfilepath = os.path.join(newdirname, "afile")
        open_file(newfilepath, "w").close()
        yield self._deferred

    @defer.inlineCallbacks
    def test_outside_file_moved_to(self):
        """Test receiving the create signal on a file when it's moved_to."""
        fromfile = os.path.join(self.root_dir, "foo")
        root_dir = os.path.join(self.root_dir, "my_files")
        tofile = os.path.join(root_dir, "foo")
        mypath = functools.partial(os.path.join, root_dir)
        make_dir(root_dir)
        open_file(fromfile, "w").close()

        should_events = [
            ("FS_FILE_CREATE", dict(path=mypath("foo"))),
            ("FS_FILE_CLOSE_WRITE", dict(path=mypath("foo"))),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(root_dir)

        # generate the event
        rename(fromfile, tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_outside_dir_with_contents_moved_to(self):
        """Test receiving the create signal on a file when it's moved_to."""
        fromdir = os.path.join(self.root_dir, "foo_dir")
        fromfile = os.path.join(fromdir, "foo")
        root_dir = os.path.join(self.root_dir, "my_files")
        mypath = functools.partial(os.path.join, root_dir)
        todir = os.path.join(root_dir, "foo_dir")
        make_dir(root_dir)
        make_dir(fromdir)
        open_file(fromfile, "w").close()

        should_events = [
            ("FS_DIR_CREATE", dict(path=mypath("foo_dir"))),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(root_dir)

        # generate the event
        rename(fromdir, todir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_delete_inside_moving_directory(self):
        """Test to assure that the DELETE signal has the correct path."""
        # basedir
        basedir = os.path.join(self.root_dir, "basedir")
        make_dir(basedir)
        self.fs.create(path=basedir, share_id='', is_dir=True)

        # working stuff
        dir1 = os.path.join(basedir, "inside_d")
        dir2 = os.path.join(basedir, "new_d")
        fromfile = os.path.join(dir1, "test_f")
        tofile = os.path.join(dir2, "test_f")
        make_dir(dir1)
        open_file(fromfile, "w").close()

        should_events = [
            ("FS_DIR_MOVE", dict(path_from=dir1, path_to=dir2)),
            ("FS_FILE_DELETE", dict(path=tofile)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)
        yield self.eq.add_watch(basedir)
        yield self.eq.add_watch(dir1)

        # generate the event
        rename(dir1, dir2)
        remove_file(tofile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_move_conflict_to_new_file(self):
        """Test to assure the signal wents through as a new file."""
        testfile = os.path.join(self.root_dir, "testfile")
        destfile = os.path.join(self.root_dir, "destfile")
        mdid = self.fs.create(testfile, '')
        open_file(testfile, "w").close()
        self.fs.move_to_conflict(mdid)

        should_events = [
            ("FS_FILE_CREATE", dict(path=destfile)),
            ("FS_FILE_CLOSE_WRITE", dict(path=destfile)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)

        # generate the event
        rename(testfile + ".u1conflict", destfile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_move_conflict_over_file(self):
        """Test to assure the signal wents through as a the file."""
        testfile = os.path.join(self.root_dir, "testfile")
        mdid = self.fs.create(testfile, '')
        open_file(testfile, "w").close()
        self.fs.move_to_conflict(mdid)

        should_events = [
            ("FS_FILE_CREATE", dict(path=testfile)),
            ("FS_FILE_CLOSE_WRITE", dict(path=testfile)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)

        # generate the event
        rename(testfile + ".u1conflict", testfile)
        yield self._deferred

    @defer.inlineCallbacks
    def test_move_conflict_over_dir(self):
        """Test to assure the signal wents through as a the dir."""
        testdir = os.path.join(self.root_dir, "testdir")
        mdid = self.fs.create(testdir, '', is_dir=True)
        make_dir(testdir, recursive=True)
        self.fs.move_to_conflict(mdid)

        should_events = [
            ("FS_DIR_CREATE", dict(path=testdir)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)

        # generate the event
        rename(testdir + ".u1conflict", testdir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_move_conflict_to_new_dir(self):
        """Test to assure the signal wents through as a new dir."""
        testdir = os.path.join(self.root_dir, "testdir")
        destdir = os.path.join(self.root_dir, "destdir")
        mdid = self.fs.create(testdir, '')
        make_dir(testdir, recursive=True)
        self.fs.move_to_conflict(mdid)

        should_events = [
            ("FS_DIR_CREATE", dict(path=destdir)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)

        # generate the event
        rename(testdir + ".u1conflict", destdir)
        yield self._deferred

    @defer.inlineCallbacks
    def test_no_read_perms_file(self):
        """Test to assure the signal wents through as a the file."""
        testfile = os.path.join(self.root_dir, "testfile")
        self.fs.create(testfile, '')

        should_events = []
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)

        log = self.eq.monitor._processor.log

        class Handler(logging.Handler):
            """Handler that trigger the deferred callback."""

            def emit(innerself, record):
                """Dummy emit."""
                # cleanup, remove the handler
                log.removeHandler(innerself)
                self.finished_ok(record)

        hdlr = Handler()
        hdlr.setLevel(logging.WARNING)
        log.addHandler(hdlr)

        # generate the event
        open_file(testfile, "w").close()
        # and change the permissions so it's ignored
        set_no_rights(testfile)
        self.addCleanup(set_file_readwrite, testfile)

        def check(record):
            self.assertIn(testfile, record.args)
            self.assertEqual(1, len(record.args))
        self._deferred.addCallback(check)
        yield self._deferred

    @defer.inlineCallbacks
    def test_no_read_perms_dir(self):
        """Test to assure the signal wents through as a the file."""
        testdir = os.path.join(self.root_dir, "testdir")
        self.fs.create(testdir, '', is_dir=True)

        should_events = []
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(self.root_dir)

        log = self.eq.monitor._processor.log

        class Handler(logging.Handler):
            """Handler that trigger the deferred callback."""

            def emit(innerself, record):
                """Dummy emit."""
                # cleanup, remove the handler
                log.removeHandler(innerself)
                self.finished_ok(record)

        hdlr = Handler()
        hdlr.setLevel(logging.WARNING)
        log.addHandler(hdlr)

        # generate the event
        make_dir(testdir, recursive=True)
        # and change the permissions so it's ignored
        set_no_rights(testdir)
        self.addCleanup(set_dir_readwrite, testdir)

        def check(record):
            self.assertIn(testdir, record.args)
            self.assertEqual(1, len(record.args))
        self._deferred.addCallback(check)
        yield self._deferred

    @defer.inlineCallbacks
    def _create_udf(self, vol_id, path):
        """Create an UDF and returns it and the volume"""
        make_dir(path, recursive=True)
        udf = volume_manager.UDF(vol_id, "node_id", path.decode('utf-8'),
                                 path, True)
        yield self.vm.add_udf(udf)

    @defer.inlineCallbacks
    def test_move_dir_across_volumes(self):
        """Dir move between volumes is deletion and creation."""
        # base dir 1
        base1 = os.path.join(self.home_dir, "dir1")
        yield self._create_udf('vol1', base1)
        self.fs.create(path=base1, share_id='vol1', is_dir=True)

        # base dir 2
        base2 = os.path.join(self.home_dir, "dir2")
        yield self._create_udf('vol2', base2)
        self.fs.create(path=base2, share_id='vol2', is_dir=True)

        # patch to check proper dir deletion is handled
        called = []
        self.patch(self.eq.monitor._processor.general_processor,
                   'handle_dir_delete', lambda p: called.append(p))

        # working stuff
        moving1 = os.path.join(base1, "test")
        moving2 = os.path.join(base2, "test")
        make_dir(moving1)

        should_events = [
            ("FS_DIR_DELETE", dict(path=moving1)),
            ("FS_DIR_CREATE", dict(path=moving2)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(base1)
        yield self.eq.add_watch(base2)

        # generate the event
        rename(moving1, moving2)
        yield self._deferred
        self.assertEqual(called, [moving1])

    @defer.inlineCallbacks
    def test_move_file_across_volumes(self):
        """File ove between volumes is deletion and creation (and write)."""
        # base dir 1
        base1 = os.path.join(self.home_dir, "dir1")
        yield self._create_udf('vol1', base1)
        self.fs.create(path=base1, share_id='vol1', is_dir=True)

        # base dir 2
        base2 = os.path.join(self.home_dir, "dir2")
        yield self._create_udf('vol2', base2)
        self.fs.create(path=base2, share_id='vol2', is_dir=True)

        # working stuff
        moving1 = os.path.join(base1, "test")
        moving2 = os.path.join(base2, "test")
        open_file(moving1, 'w').close()

        should_events = [
            ("FS_FILE_DELETE", dict(path=moving1)),
            ("FS_FILE_CREATE", dict(path=moving2)),
            ("FS_FILE_CLOSE_WRITE", dict(path=moving2)),
        ]
        self.eq.subscribe(DynamicHitMe(should_events, self))
        yield self.eq.add_watch(base1)
        yield self.eq.add_watch(base2)

        # generate the event
        rename(moving1, moving2)
        yield self._deferred
