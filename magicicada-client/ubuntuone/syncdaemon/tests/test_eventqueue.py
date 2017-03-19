#
# Author: Facundo Batista <facundo@canonical.com>
#
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
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

import logging

from twisted.internet import defer
from twisted.trial.unittest import TestCase

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    FakeMonitor,
    FakeVolumeManager,
)
from ubuntuone.platform.filesystem_notifications.monitor import (
    FilesystemMonitor,
)
from ubuntuone.syncdaemon import (
    event_queue,
    filesystem_manager,
    tritcask,
)
from ubuntuone.devtools.handlers import MementoHandler


class BaseEQTestCase(BaseTwistedTestCase):
    """Setup an EQ for test."""

    _monitor_class = FakeMonitor

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(BaseEQTestCase, self).setUp()
        self.fsmdir = self.mktemp('fsmdir')
        self.partials_dir = self.mktemp('partials_dir')
        self.root_dir = self.mktemp('root_dir')
        self.vm = FakeVolumeManager(self.root_dir)
        self.db = tritcask.Tritcask(self.mktemp('tritcask'))
        self.addCleanup(self.db.shutdown)
        self.fs = filesystem_manager.FileSystemManager(
            self.fsmdir, self.partials_dir, self.vm, self.db)
        self.fs.create(
            path=self.root_dir, share_id='', is_dir=True)
        self.fs.set_by_path(
            path=self.root_dir, local_hash=None, server_hash=None)
        self.eq = event_queue.EventQueue(
            self.fs, monitor_class=self._monitor_class)
        self.eq.listener_map = {}
        self.addCleanup(self.eq.shutdown)
        self.fs.register_eq(self.eq)

        # add a Memento handler to the logger
        self.log_handler = MementoHandler()
        self.log_handler.setLevel(logging.DEBUG)
        self.eq.log.addHandler(self.log_handler)


class SubscriptionTests(BaseEQTestCase):
    """Test to subscribe and unsubscribe to the EQ."""

    def test_subscription_simple(self):
        """Subscribe creating the listener map."""
        class Listener(object):
            """Listener."""

            def handle_FS_FILE_CREATE(self, path):
                """Handle FS_FILE_CREATE."""

            def handle_default(self, *a):
                """Handle all."""

        # subscribe
        listener = Listener()
        self.eq.subscribe(listener)

        # for FS_FILE_CREATE, it should have picked up the method
        self.assertEqual(self.eq.listener_map['FS_FILE_CREATE'][listener],
                         listener.handle_FS_FILE_CREATE)

        # for any other event, it should have picked up the method
        self.assertEqual(self.eq.listener_map['FS_DIR_DELETE'][listener].func,
                         listener.handle_default)

    def test_subscription_nodefault(self):
        """Don't subscribe if there's no default."""

        class Listener(object):
            """Listener."""

            def handle_FS_FILE_CREATE(self, path):
                """Handle FS_FILE_CREATE."""

        # subscribe
        listener = Listener()
        self.eq.subscribe(listener)

        # for FS_FILE_CREATE, it should have picked up the method
        self.assertEqual(self.eq.listener_map['FS_FILE_CREATE'][listener],
                         listener.handle_FS_FILE_CREATE)

        # for any other event, nothing
        self.assertFalse('FS_DIR_DELETE' in self.eq.listener_map)

    def test_subscription_two_listeners(self):
        """Subscribe several listeners."""

        class Listener1(object):
            """Listener 1."""

            def handle_FS_FILE_CREATE(self, path):
                """Handle FS_FILE_CREATE."""

            def handle_FS_DIR_CREATE(self, path):
                """Handle FS_DIR_CREATE."""

        class Listener2(object):
            """Listener 2."""

            def handle_FS_FILE_CREATE(self, path):
                """Handle FS_FILE_CREATE."""

            def handle_FS_DIR_DELETE(self, path):
                """Handle FS_DIR_CREATE."""

        # subscribe
        listener1 = Listener1()
        self.eq.subscribe(listener1)
        listener2 = Listener2()
        self.eq.subscribe(listener2)

        # for FS_FILE_CREATE, both listeners should be there
        lmap = self.eq.listener_map['FS_FILE_CREATE']
        self.assertEqual(lmap[listener1], listener1.handle_FS_FILE_CREATE)
        self.assertEqual(lmap[listener2], listener2.handle_FS_FILE_CREATE)

        # for FS_DIR_CREATE and FS_DIR_DELETE, each one accordingly
        self.assertEqual(self.eq.listener_map['FS_DIR_CREATE'][listener1],
                         listener1.handle_FS_DIR_CREATE)
        self.assertEqual(self.eq.listener_map['FS_DIR_DELETE'][listener2],
                         listener2.handle_FS_DIR_DELETE)

    def test_unsubscription(self):
        """Test that unsubscription works."""
        class Listener1(object):
            """Listener 1."""

            def handle_FS_FILE_CREATE(self, path):
                """Handle FS_FILE_CREATE."""

            def handle_FS_DIR_CREATE(self, path):
                """Handle FS_DIR_CREATE."""

        class Listener2(object):
            """Listener 2."""

            def handle_FS_FILE_CREATE(self, path):
                """Handle FS_FILE_CREATE."""

            def handle_FS_DIR_DELETE(self, path):
                """Handle FS_DIR_CREATE."""

        # subscribe two listeners
        listener1 = Listener1()
        self.eq.subscribe(listener1)
        listener2 = Listener2()
        self.eq.subscribe(listener2)

        # unsubscribe listener 1 only
        self.eq.unsubscribe(listener1)

        # check
        self.assertFalse(listener1 in self.eq.listener_map['FS_FILE_CREATE'])
        self.assertFalse('FS_DIR_CREATE' in self.eq.listener_map)
        self.assertEqual(self.eq.listener_map['FS_FILE_CREATE'][listener2],
                         listener2.handle_FS_FILE_CREATE)
        self.assertEqual(self.eq.listener_map['FS_DIR_DELETE'][listener2],
                         listener2.handle_FS_DIR_DELETE)


class PushTests(BaseEQTestCase):
    """Test the event distribution machinery."""

    def test_push_simple(self):
        """Test that events can be pushed (not listening yet)."""
        # not even an event
        self.assertRaises(TypeError, self.eq.push)

        # incorrect args, only kwargs supported
        self.assertRaises(TypeError, self.eq.push, "FS_FILE_MOVE", 1)
        self.assertRaises(
            TypeError, self.eq.push, "FS_FILE_MOVE", 1, path_to=2)

        # ok: just kwargs
        self.eq.push("FS_FILE_MOVE", path_from=1, path_to=2)

    def test_events_kwargs(self):
        """Test that all events are defined correctly with tuples or lists.

        This is to avoid a typical mistake of making it a "(param)", not
        a "(param,)".
        """
        for name, params in event_queue.EVENTS.iteritems():
            self.assertTrue(isinstance(params, (tuple, list)),
                            "%s event has params bad defined!" % name)

    def test_listened_pushs(self):
        """Push events and listem them."""

        # helper class
        class Create(object):

            def __init__(self):
                self.a = None

            def handle_FS_FILE_CREATE(self, path):
                self.a = path

        # it get passed!
        c = Create()
        self.eq.subscribe(c)
        self.eq.push("FS_FILE_CREATE", path=1)
        self.assertEqual(c.a, 1)
        self.eq.unsubscribe(c)

        # don't get what don't listen
        c = Create()
        self.eq.subscribe(c)
        self.eq.push("FS_FILE_DELETE", path=1)
        self.assertEqual(c.a, None)
        self.eq.unsubscribe(c)

    def test_signatures(self):
        """Check that the handle signatures are forced when passing."""

        # helper class
        class Create(object):

            def handle_FS_FILE_CREATE(self, notpath):  # it should be path here
                pass

        # it get passed!
        c = Create()
        self.eq.subscribe(c)

        # the listener has a wrong signature
        # this is logged as an error/exception
        self.eq.push("FS_FILE_CREATE", path=1)
        self.assertTrue(self.log_handler.check_error('FS_FILE_CREATE',
                                                     'Create object'))

        self.eq.unsubscribe(c)

    def test_log_pushing_data(self):
        """Pushed event and info should be logged."""
        self.eq.push("AQ_QUERY_ERROR", item='item', error='err')
        self.assertTrue(self.log_handler.check_debug(
                        "push_event: AQ_QUERY_ERROR, kwargs: "
                        "{'item': 'item', 'error': 'err'}"))

    def test_log_delete_in_info(self):
        """Pushed any deletion event should be logged in info."""
        self.eq.push("FS_DIR_DELETE", path='path')
        self.assertTrue(self.log_handler.check_info(
                        "push_event: FS_DIR_DELETE"))

    def test_log_pushing_private_data(self):
        """SYS_USER_CONNECT event info must not be logged."""
        self.eq.push("SYS_USER_CONNECT", access_token='foo')
        self.assertTrue(self.log_handler.check_debug(
            "push_event: SYS_USER_CONNECT, kwargs: *"))


class PushTestsWithCallback(BaseEQTestCase):
    """Test the error handling in the event distribution machinery."""

    def test_keep_going(self):
        """Checks.

        If a listener raises an Exception or have a wrong signature, the next
        listeners are called.

        """
        d = defer.Deferred()

        # helper class
        class BadListener(object):

            def handle_FS_FILE_CREATE(self, notpath):  # it should be path here
                d.callback(False)

        class GoodListener(object):

            def handle_FS_FILE_CREATE(self, path):
                d.callback(path)

        bl = BadListener()
        gl = GoodListener()
        self.eq.subscribe(bl)
        self.eq.subscribe(gl)

        def cleanup():
            """unsubscribe the listeners """
            self.eq.unsubscribe(bl)
            self.eq.unsubscribe(gl)

        self.addCleanup(cleanup)

        # one listener has a wrong signature
        self.eq.push("FS_FILE_CREATE", path=1)

        def callback(result):
            """Assert that GoodListener was called."""
            self.assertTrue(result)
            self.assertEqual(1, result)

        d.addCallback(callback)
        return d

    def test_default_handler(self):
        """Check that handler_default is called."""
        d = defer.Deferred()

        # helper class
        class Listener(object):

            def handle_default(self, event, **kwargs):
                d.callback((event, kwargs))

        l = Listener()
        self.eq.subscribe(l)

        def cleanup():
            """Unsubscribe the listeners."""
            self.eq.unsubscribe(l)
        self.addCleanup(cleanup)

        # push some event and expect it'll be handled by handle_default
        self.eq.push("FS_FILE_CREATE", path=1)

        def callback(result):
            """Assert that GoodListener was called."""
            self.assertEqual(2, len(result))
            self.assertEqual('FS_FILE_CREATE', result[0])
            self.assertEqual({'path': 1}, result[1])

        d.addCallback(callback)
        return d

    def test_ordered_dispatch(self):
        """Check that the events are pushed to all listeners in order."""
        d = defer.Deferred()

        # helper class
        class Listener(object):

            def __init__(self, eq):
                self.eq = eq
                self.events = []

            def handle_FS_FILE_CREATE(self, path):
                self.events.append('FS_FILE_CREATE')
                self.eq.push('FS_FILE_MOVE', path_from=path, path_to=2)

            def handle_FS_FILE_DELETE(self, path):
                self.events.append('FS_FILE_DELETE')

            def handle_FS_FILE_MOVE(self, path_from, path_to):
                self.events.append('FS_FILE_MOVE')
                d.callback(True)

        # create 10 listeners in order to create an event madness
        listeners = []
        for i in xrange(0, 10):
            l = Listener(self.eq)
            listeners.append(l)
            self.eq.subscribe(l)

        # push some events to unleash the event madness
        self.eq.push("FS_FILE_CREATE", path=1)
        self.eq.push('FS_FILE_DELETE', path=2)

        def callback(result):
            """Assert that Listener was called in the right order."""
            listeners_events = [listener.events for listener in listeners]
            for l_events in listeners_events:
                for other_l_events in listeners_events:
                    self.assertEqual(l_events, other_l_events)

        d.addCallback(callback)
        return d


class SimpleFakeMonitor(object):
    """A fake FilesystemMonitor."""

    def __init__(self, *args):
        """Initialize this fake."""
        self.shutdown_d = defer.Deferred()

    def shutdown(self):
        """Get the shutdown deferred."""
        return self.shutdown_d


class EventQueueInitTestCase(TestCase):
    """Test the init of the EQ."""

    def test_default_monitor(self):
        """Test the init with the default monitor."""
        eq = event_queue.EventQueue(None)
        self.assertIsInstance(eq.monitor, FilesystemMonitor)
        return eq.shutdown()

    def test_passed_monitor(self):
        """Test the init with a custom monitor."""
        eq = event_queue.EventQueue(None, monitor_class=FakeMonitor)
        self.assertIsInstance(eq.monitor, FakeMonitor)


class EventQueueShutdownTestCase(TestCase):
    """Test the shutdown method in EQ."""

    timeout = 2

    @defer.inlineCallbacks
    def test_shutdown_defers(self):
        """The shutdown method in eq defers on the shutdown of the monitor."""
        self.patch(event_queue, "FilesystemMonitor", SimpleFakeMonitor)
        eq = event_queue.EventQueue(None)
        d = eq.shutdown()
        self.assertFalse(d.called, "shutdown is fired after the monitor.")
        eq.monitor.shutdown_d.callback(True)
        self.assertTrue(d.called, "shutdown is fired after the monitor.")
        yield d
