# -*- coding: utf-8 -*-
#
# Copyright 2009-2015 Canonical Ltd.
# Copyright 2016-2017 Chicharreros (https://launchpad.net/~chicharreros)
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
"""Tests for the action queue module."""

from __future__ import with_statement

import collections
import inspect
import itertools
import logging
import operator
import os
import unittest
import uuid

from functools import wraps
from StringIO import StringIO

import OpenSSL.SSL

from mocker import Mocker, MockerTestCase, ANY, expect
from twisted.internet import defer, reactor
from twisted.internet import error as twisted_error
from twisted.python.failure import DefaultException, Failure
from twisted.web import server
from twisted.trial.unittest import TestCase as TwistedTestCase
from zope.interface.verify import verifyObject, verifyClass

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    DummyClass,
    FakeActionQueue,
    FakeCommand,
    FakeMain,
    FakeUpload,
)
from ubuntuone.devtools import handlers
from ubuntuone.devtools.testcases import skipTest
from ubuntuone import logger, clientdefs
from ubuntuone.platform import open_file, platform, path_exists
from ubuntuone.storageprotocol import (
    client,
    content_hash,
    errors,
    protocol_pb2,
    request,
)
from ubuntuone.syncdaemon import interfaces, config
from ubuntuone.syncdaemon import action_queue
from ubuntuone.syncdaemon.action_queue import (
    ActionQueue, ActionQueueCommand, ChangePublicAccess, CreateUDF,
    DeleteVolume, Download, ListVolumes, ActionQueueProtocol, ListShares,
    RequestQueue, UploadProgressWrapper, Upload,
    CreateShare, DeleteShare, GetPublicFiles, GetDelta, GetDeltaFromScratch,
    TRANSFER_PROGRESS_THRESHOLD, Unlink, Move, MakeFile, MakeDir, DeltaList,
    ZipQueue, DeferredMap, ThrottlingStorageClient, PathLockingTree,
    InterruptibleDeferred, DeferredInterrupted, ConditionsLocker,
    NamedTemporaryFile, PingManager,
)
from ubuntuone.syncdaemon.event_queue import EventQueue, EVENTS
from ubuntuone.syncdaemon import offload_queue
from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.syncdaemon.volume_manager import ACCESS_LEVEL_RO

PATH = os.path.join(u'~', u'Documents', u'pdfs', u'moño', u'')
NAME = u'UDF-me'
VOLUME = uuid.UUID('12345678-1234-1234-1234-123456789abc')
NODE = uuid.UUID('FEDCBA98-7654-3211-2345-6789ABCDEF12')
USER = u'Dude'
SHARE = uuid.uuid4()


def fire_and_check(f, deferred, check):
    """Callback a deferred."""
    @wraps(f)
    def inner(*args, **kwargs):
        """Execute f and fire the deferred."""
        result = f(*args, **kwargs)
        error = check()
        if not error:
            deferred.callback(True)
        else:
            deferred.errback(error)
        return result
    return inner


class MementoHandler(handlers.MementoHandler):
    """Wrapper to handle custom logger levels."""

    def check_note(self, *msgs):
        """Shortcut for checking in ERROR."""
        return self.check(logger.NOTE, *msgs)


class FakeOffloadQueue(object):
    """Fake replacemente for offload_queue."""
    def __init__(self):
        self.queue = collections.deque()

    def push(self, item):
        """Push it."""
        self.queue.append(item)

    def pop(self):
        """Pop it."""
        return self.queue.popleft()

    def __len__(self):
        return len(self.queue)

    def __getitem__(self, idx):
        return self.queue[idx]


class FakeMagicHash(object):
    """Fake magic hash."""
    _magic_hash = '666'


class FakeTempFile(object):
    """Fake temporary file."""

    def __init__(self, tmpdir):
        self.closed = 0  # be able to count how may close calls we had
        self.name = os.path.join(tmpdir, 'remove-me.zip')
        open_file(self.name, 'w').close()
        self.close = lambda: setattr(self, 'closed', self.closed + 1)


class FakedEventQueue(EventQueue):
    """Faked event queue."""

    def __init__(self, fs=None):
        """Initialize a faked event queue."""
        super(FakedEventQueue, self).__init__(fs=fs)
        self.events = []

    def push(self, event_name, **kwargs):
        """Faked event pushing."""
        self.events.append((event_name, kwargs))
        super(FakedEventQueue, self).push(event_name, **kwargs)


class FakedVolume(object):
    """Faked volume."""
    volume_id = None
    generation = None
    free_bytes = None


class FakeSemaphore(object):
    """Fake semaphore."""

    def __init__(self):
        self.count = 0

    def acquire(self):
        """Increase the count."""
        self.count += 1

    def release(self):
        """Decrease the count."""
        self.count -= 1


class FakeRequest(object):
    """Fake Request."""
    def __init__(self, *a, **k):
        self.deferred = defer.succeed(True)
        self.cancelled = False

    def cancel(self):
        """Mark cancelled."""
        self.cancelled = True


class FakeClient(object):
    """Fake Client."""
    def __init__(self):
        self.called = []

    def put_content_request(self, *args, **kwargs):
        """Fake a put content request with its deferred."""
        self.called.append(('put_content_request', args, kwargs))
        return FakeRequest()

    def get_content_request(self, *args, **kwargs):
        """Fake a get content request with its deferred."""
        self.called.append(('get_content_request', args, kwargs))
        return FakeRequest()


class FakeTunnelClient(object):
    """A fake proxy.tunnel_client."""

    def __init__(self):
        """Fake this proxy tunnel."""
        self.tcp_connected = False
        self.ssl_connected = False

    def connectTCP(self, *args, **kwargs):
        """Save the connection thru TCP."""
        self.tcp_connected = True

    def connectSSL(self, *args, **kwargs):
        """Save the connection thru SSL."""
        self.ssl_connected = True


class SavingConnectionTunnelRunner(object):
    """A fake proxy.tunnel_client.TunnelRunner."""

    def __init__(self, host, port):
        """Fake a proxy tunnel."""
        self.client = FakeTunnelClient()
        self.host = host
        self.port = port

    def get_client(self):
        """Always return the reactor."""
        return defer.succeed(self.client)


class TestingProtocol(ActionQueue.protocol):
    """Protocol for testing."""

    max_payload_size = 65536

    def connectionMade(self):
        """connectionMade."""
        ActionQueue.protocol.connectionMade(self)

        # assure we're connected
        events = [x[0] for x in self.factory.event_queue.events]
        assert 'SYS_CONNECTION_MADE' in events

        self.factory.event_queue.events = []  # reset events
        if hasattr(self, 'testing_deferred'):
            self.testing_deferred.callback(True)


class TestActionQueue(ActionQueue):
    """AQ class that uses the testing protocol."""
    protocol = TestingProtocol


class BasicTestCase(BaseTwistedTestCase):
    """Basic test case for ActionQueue."""

    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(BasicTestCase, self).setUp()

        self.home = self.home_dir
        self.root = self.mktemp('root')
        self.data = self.mktemp('data')
        self.shares = self.mktemp('shares')
        self.partials = self.mktemp('partials')

        # set up FakeMain to use the testing AQ, the port will be decided later
        self.patch(FakeMain, '_fake_AQ_class', TestActionQueue)
        connection_info = [dict(host='127.0.0.1', port=0, use_ssl=False)]
        self.patch(FakeMain, '_fake_AQ_params', (connection_info,))
        self.patch(offload_queue, "OffloadQueue", FakeOffloadQueue)

        self.main = FakeMain(root_dir=self.root, shares_dir=self.shares,
                             data_dir=self.data, partials_dir=self.partials)
        self.addCleanup(self.main.shutdown)

        self.action_queue = self.main.action_q
        self.action_queue.connection_timeout = 3
        self.action_queue.event_queue.events = []

        def keep_a_copy(f):
            """Keep a copy of the pushed events."""
            @wraps(f)
            def recording(event_name, **kwargs):
                """Keep a copy of the pushed events."""
                value = (event_name, kwargs)
                if event_name != 'SYS_STATE_CHANGED' and \
                   not event_name.startswith('VM_'):
                    self.action_queue.event_queue.events.append(value)
                return f(event_name, **kwargs)
            return recording

        self.main.event_q.push = keep_a_copy(self.main.event_q.push)

        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)

    def user_connect(self):
        """User requested to connect to server."""
        auth_info = dict(username='test_username', password='test_password')
        self.action_queue.event_queue.push(
            'SYS_USER_CONNECT', access_token=auth_info)


class BasicTests(BasicTestCase):
    """Basic tests to check ActionQueue."""
    fake_host = "fake_host"
    fake_iri = u"http://%s/" % fake_host

    def test_implements_interface(self):
        """Verify ActionQueue and FakeActionQueue interface."""
        verifyObject(interfaces.IActionQueue, self.action_queue)
        verifyClass(interfaces.IActionQueue, FakeActionQueue)

    @defer.inlineCallbacks
    def test_get_root_and_demark(self):
        """Get the received Root and demark its mdid."""
        # get the marker
        d = self.action_queue.uuid_map.get('mdid')

        # we received a root!
        self.main.event_q.push('SYS_ROOT_RECEIVED',
                               root_id='node_id', mdid='mdid')

        # it should be demarked with the root node_id
        root_node_id = yield d
        self.assertEqual(root_node_id, 'node_id')

    def test_cancelupload_calls_cancelop(self):
        """cancel_upload passes the correct args to the generic method."""
        called = []
        self.action_queue._cancel_op = lambda *a: called.append(a)
        self.action_queue.cancel_upload('share', 'node')
        self.assertEqual(called, [('share', 'node', Upload)])

    def test_canceldownload_calls_cancelop(self):
        """cancel_download passes the correct args to the generic method."""
        called = []
        self.action_queue._cancel_op = lambda *a: called.append(a)
        self.action_queue.cancel_download('share', 'node')
        self.assertEqual(called, [('share', 'node', Download)])

    def test_cancelop_nothing(self):
        """It does not cancel anything, because all empty."""
        assert not self.action_queue.queue.waiting
        self.action_queue._cancel_op('shr', 'node', Upload)
        self.assertFalse(self.handler.check_debug('cancel', 'shr', 'node'))

    def _set_queue(self, *waiting):
        """Set the content queue content."""
        cq = self.action_queue.queue
        for cmd in waiting:
            cq.waiting.append(cmd)
            cq.hashed_waiting[cmd.uniqueness] = cmd

    def test_cancelop_different_sharenode(self):
        """It does not cancel anything, because queue with different stuff."""
        cmd1 = FakeCommand('sh', 'nd1')
        cmd2 = FakeCommand('sh', 'nd2')
        self._set_queue(cmd1, cmd2)
        self.action_queue._cancel_op('sh', 'nd3', FakeCommand)
        self.assertFalse(self.handler.check_debug('external cancel attempt'))
        self.assertFalse(cmd1.cancelled)
        self.assertFalse(cmd2.cancelled)

    def test_cancelop_different_operation(self):
        """It does not cancel anything, because queue with different stuff."""
        cmd1 = FakeCommand('sh', 'nd')
        cmd2 = FakeCommand('sh', 'nd')
        self._set_queue(cmd1, cmd2)
        self.action_queue._cancel_op('sh', 'nd', Upload)
        self.assertFalse(self.handler.check_debug('external cancel attempt'))
        self.assertFalse(cmd1.cancelled)
        self.assertFalse(cmd2.cancelled)

    def test_cancelop_inwaiting(self):
        """Cancel something that is in the waiting queue."""
        cmd = FakeCommand('sh', 'nd')
        self._set_queue(cmd)
        self.action_queue._cancel_op('sh', 'nd', FakeCommand)
        self.assertTrue(self.handler.check_debug('external cancel attempt',
                                                 'sh', 'nd'))
        self.assertTrue(cmd.cancelled)

    def test_node_is_queued_move_api(self):
        """Test that it calls the queue method."""
        called = []
        aq = self.action_queue
        aq.queue.node_is_queued = lambda *a: called.append(a)
        aq.node_is_with_queued_move('share', 'node')
        self.assertEqual(called, [(Move, 'share', 'node')])

    def test_node_is_queued_move_integration(self):
        """Kind of integration test for this method."""
        aq = self.action_queue
        cmd = Move(aq.queue, VOLUME, 'node', 'o_p', 'n_p', 'n_name',
                   "pathfrom", "pathto")
        self.assertFalse(aq.node_is_with_queued_move(VOLUME, 'node'))
        aq.queue.waiting.append(cmd)
        aq.queue.hashed_waiting[cmd.uniqueness] = cmd
        self.assertTrue(aq.node_is_with_queued_move(VOLUME, 'node'))

    def test_event_listener(self):
        """All event listeners should define methods with correct signature."""
        for evtname, evtargs in EVENTS.iteritems():
            meth = getattr(ActionQueue, 'handle_' + evtname, None)
            if meth is not None:
                defined_args = inspect.getargspec(meth)[0]
                self.assertEqual(defined_args[0], 'self')
                self.assertEqual(set(defined_args[1:]), set(evtargs))


class TestLoggingStorageClient(TwistedTestCase):
    """Tests for ensuring magic hash dont show in logs."""

    def get_message(self):
        """Produce an upload message."""
        message = protocol_pb2.Message()
        message.type = protocol_pb2.Message.PUT_CONTENT
        message.put_content.share = "share"
        message.put_content.node = "node"
        message.put_content.previous_hash = "previous hash"
        message.put_content.magic_hash = "magic!"
        message.put_content.hash = "hash"
        return message

    def test_sanitize_messages_nomagic(self):
        """Messages get sanitized and magic hash is removed."""
        message = self.get_message()
        result = action_queue.sanitize_message('test', message)
        text = result[0].__mod__(result[1:])
        self.assertTrue("magic!" not in text)
        self.assertTrue("share" in text)
        self.assertTrue("hash" in text)
        self.assertTrue("previous_hash" in text)

    def test_sanitize_messages_action(self):
        """Log the received action."""
        message = self.get_message()
        result = action_queue.sanitize_message('test_action', message)
        text = result[0].__mod__(result[1:])
        self.assertIn("test_action", text)

    def test_sanitize_messages_bytes(self):
        """Log just BYTES when a message of that type."""
        message = protocol_pb2.Message()
        message.type = protocol_pb2.Message.BYTES
        message.bytes.bytes = "content"
        result = action_queue.sanitize_message('test_action', message)
        text = result[0].__mod__(result[1:])
        self.assertIn("BYTES", text)
        self.assertNotIn("content", text)

    def test_logging_storage_client(self):
        """LoggingStorageClient sanitizes messages."""
        message = self.get_message()
        result = []
        lsc = action_queue.LoggingStorageClient()
        lsc.log.setLevel(action_queue.TRACE)
        lsc.log_trace = lambda *args: result.append(args)
        lsc.log_message('eg', message)
        self.assertTrue(result, [action_queue.sanitize_message('eg', message)])


class TestRequestQueue(TwistedTestCase):
    """Tests for the RequestQueue."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TestRequestQueue, self).setUp()

        class FakeAQ(object):
            """Fake AQ."""
            event_queue = self.eq = FakedEventQueue()

        self.rq = RequestQueue(action_queue=FakeAQ())
        self.addCleanup(self.eq.shutdown)

        # add a Memento handler to the logger
        self.log_handler = MementoHandler()
        self.log_handler.setLevel(logging.DEBUG)
        logger = logging.getLogger('ubuntuone.SyncDaemon')
        logger.addHandler(self.log_handler)
        self.addCleanup(logger.removeHandler, self.log_handler)

    def _add_to_rq(self, *cmds):
        """Add the commands to rq.waiting and hashed_waiting."""
        for cmd in cmds:
            self.rq.waiting.append(cmd)
            self.rq.hashed_waiting[cmd.uniqueness] = cmd

    def test_len_nothing(self):
        """Len with nothing queued."""
        self.assertEqual(len(self.rq), 0)

    def test_len_waiting(self):
        """Len with something in the queue."""
        self.rq.waiting.append(1)
        self.assertEqual(len(self.rq), 1)

    def test_len_bigger(self):
        """Len with several commands."""
        self.rq.waiting.append(1)
        self.rq.waiting.append(1)
        self.assertEqual(len(self.rq), 2)

    def test_queue_adds_to_waiting(self):
        """Command queues is appended to waiting."""
        # set up
        cmd1 = FakeCommand()
        cmd2 = FakeCommand()
        self.rq.waiting.append(cmd1)

        # queue and test
        self.rq.queue(cmd2)
        self.assertEqual(list(self.rq.waiting), [cmd1, cmd2])

    def test_queue_sends_changed_event(self):
        """Alert something changed."""
        cmd = FakeCommand()
        self.rq.queue(cmd)
        evt = ('SYS_QUEUE_ADDED', dict(command=cmd))
        self.assertIn(evt, self.eq.events)

    def test_queue_waiting_if_first(self):
        """It should send the WAITING signal ."""
        # set up
        cmd = FakeCommand()

        # queue and test
        self.rq.queue(cmd)
        self.assertEqual(list(self.rq.waiting), [cmd])
        self.assertIn(('SYS_QUEUE_WAITING', {}), self.eq.events)

    def test_queue_nowaiting_if_not_first(self):
        """It should not send the WAITING signal if no first cmd."""
        # set up
        cmd1 = FakeCommand()
        cmd2 = FakeCommand()
        self.rq.waiting.append(cmd1)

        # queue and test
        self.rq.queue(cmd2)
        self.assertEqual(list(self.rq.waiting), [cmd1, cmd2])
        self.assertNotIn(('SYS_QUEUE_WAITING', {}), self.eq.events)

    def test_with_one_run(self):
        """Run will execute the command."""
        cmd = FakeCommand()
        self.rq.queue(cmd)
        self.assertIn(('SYS_QUEUE_WAITING', {}), self.eq.events)
        self.assertNotIn(('SYS_QUEUE_DONE', {}), self.eq.events)
        self.rq.unqueue(cmd)
        self.assertIn(('SYS_QUEUE_DONE', {}), self.eq.events)

    def test_with_two_run(self):
        """Run will execute both commands."""
        # first queuing, get the event
        cmd1 = FakeCommand()
        self.rq.queue(cmd1)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_WAITING', {})), 1)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_DONE', {})), 0)

        # second queuing, don't get the event
        cmd2 = FakeCommand()
        self.rq.queue(cmd2)

        self.assertEqual(self.eq.events.count(('SYS_QUEUE_WAITING', {})), 1)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_DONE', {})), 0)

        # first run, no new events
        self.rq.unqueue(cmd1)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_WAITING', {})), 1)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_DONE', {})), 0)

        # second run, now we're done
        self.rq.unqueue(cmd2)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_WAITING', {})), 1)
        self.assertEqual(self.eq.events.count(('SYS_QUEUE_DONE', {})), 1)

    def test_init_notactive(self):
        """RQ borns not active."""
        self.assertFalse(self.rq.active)

    def test_init_activedef(self):
        """Just instanced queue has the deferred to take."""
        self.assertTrue(isinstance(self.rq.active_deferred, defer.Deferred))

    def test_run_goes_active(self):
        """Activate on run."""
        self.rq.run()
        self.assertTrue(self.rq.active)

    def test_run_triggers_activedef(self):
        """Trigger the active_deferred on run."""
        assert not self.rq.active_deferred.called
        self.rq.run()
        self.assertTrue(self.rq.active_deferred.called)

    def test_stop_goes_inactive(self):
        """Desactivate on stop."""
        self.rq.active = True
        self.rq.stop()
        self.assertFalse(self.rq.active)

    def test_stop_pauses_commands(self):
        """Pauses all queued commands on stop."""
        # set up
        cmd1 = FakeCommand()
        cmd2 = FakeCommand()
        self.rq.waiting.extend((cmd1, cmd2))
        assert not cmd1.paused and not cmd2.paused

        # stop and test
        self.rq.stop()
        self.assertTrue(cmd1.paused)
        self.assertTrue(cmd2.paused)

    def test_stop_pause_useful_activedef(self):
        """Refresh the active_deferred before pausing."""
        checked = defer.Deferred()

        def fake_pause():
            """Check that RQ has a useful active_deferred."""
            self.assertTrue(isinstance(self.rq.active_deferred,
                                       defer.Deferred))
            self.assertFalse(self.rq.active_deferred.called)
            checked.callback(True)

        cmd = FakeCommand()
        cmd.pause = fake_pause
        self.rq.waiting.append(cmd)

        # stop and test
        self.rq.stop()
        return checked

    def test_unqueue_remove(self):
        """Remove the command from queue on unqueue."""
        # set up a couple of commands
        cmd1 = FakeCommand()
        cmd2 = FakeCommand()
        self.rq.waiting.extend((cmd1, cmd2))
        self.rq.hashed_waiting[cmd1] = cmd1
        self.rq.hashed_waiting[cmd2] = cmd2

        # unqueue and check that 1 was removed from both structures and
        # that cmd2 is still there untouched
        self.rq.unqueue(cmd1)
        self.assertNotIn(cmd1, self.rq.waiting)
        self.assertIn(cmd2, self.rq.waiting)
        self.assertNotIn(cmd1, self.rq.hashed_waiting)
        self.assertIn(cmd2, self.rq.hashed_waiting)

    def test_unqueue_sysqueuedone_if_empty(self):
        """Send SYS_QUEUE_DONE if empty after unqueue."""
        # set up one command
        cmd = FakeCommand()
        self.rq.waiting.append(cmd)
        self.rq.hashed_waiting[cmd] = cmd

        # unqueue it and check
        self.rq.unqueue(cmd)
        self.assertIn(('SYS_QUEUE_DONE', {}), self.eq.events)

    def test_unqueue_sysqueuedone_if_not_empty(self):
        """Do not send SYS_QUEUE_DONE if not empty after unqueue."""
        # set up a couple of commands
        cmd1 = FakeCommand()
        cmd2 = FakeCommand()
        self.rq.waiting.extend((cmd1, cmd2))
        self.rq.hashed_waiting[cmd1] = cmd1
        self.rq.hashed_waiting[cmd2] = cmd2

        # unqueue only one and check
        self.rq.unqueue(cmd1)
        self.assertNotIn(('SYS_QUEUE_DONE', {}), self.eq.events)

    def test_unqueue_sends_changed_event(self):
        """Alert something changed."""
        cmd = FakeCommand()
        self.rq.waiting.append(cmd)
        self.rq.unqueue(cmd)
        evt = ('SYS_QUEUE_REMOVED', dict(command=cmd))
        self.assertIn(evt, self.eq.events)

    def test_remove_empty(self):
        """Don't remove if waiting is empty."""
        assert not self.rq.waiting, "test badly set up"
        cmd = FakeCommand()
        self.rq.remove(cmd)
        self.assertFalse(self.rq.waiting)
        self.assertFalse(self.rq.hashed_waiting)

    def test_remove_other(self):
        """Don't remove if waiting has other command."""
        cmd1 = FakeCommand(1, 2)
        self._add_to_rq(cmd1)
        cmd2 = FakeCommand(2, 3)
        self.rq.remove(cmd2)
        self.assertEqual(list(self.rq.waiting), [cmd1])
        self.assertEqual(self.rq.hashed_waiting.values(), [cmd1])

    def test_remove_command(self):
        """Remove for the command."""
        cmd = FakeCommand()
        self._add_to_rq(cmd)
        self.rq.remove(cmd)
        self.assertFalse(self.rq.waiting)
        self.assertFalse(self.rq.hashed_waiting)

    def test_remove_mixed(self):
        """Remove ok in a mixed situation."""
        cmd1 = FakeCommand(1, 2)
        cmd2 = FakeCommand(2, 3)
        cmd3 = FakeCommand(3, 4)
        self._add_to_rq(cmd1, cmd2, cmd3)
        self.rq.remove(cmd2)
        self.assertEqual(list(self.rq.waiting), [cmd1, cmd3])
        self.assertEqual(set(self.rq.hashed_waiting.values()),
                         set([cmd1, cmd3]))

    def test_hashedwaiting_queue(self):
        """Queue a command and it will be added to hashed waiting."""
        cmd = FakeCommand()
        self.rq.queue(cmd)
        self.assertTrue(self.rq.hashed_waiting.values(), [cmd])

    def test_node_is_queued_nothing(self):
        """Test with empty queues."""
        self.assertFalse(self.rq.node_is_queued(Move, 'share', 'node'))

    def test_node_is_queued_waiting(self):
        """Test with a command in waiting."""
        cmd = FakeCommand('share', 'node')
        self._add_to_rq(cmd)
        self.assertTrue(self.rq.node_is_queued(FakeCommand, 'share', 'node'))

    def test_node_is_queued_different_command(self):
        """The node is queued, but other command on it."""
        cmd = FakeCommand('share', 'node')
        self._add_to_rq(cmd)
        self.assertFalse(self.rq.node_is_queued(Move, 'share', 'node'))

    def test_node_is_queued_different_node(self):
        """The command is queued, but on other node."""
        cmd = FakeCommand('share', 'node')
        self._add_to_rq(cmd)
        self.assertFalse(self.rq.node_is_queued(FakeCommand, 'share', 'other'))

    def test_len_empty(self):
        """Counter return that it's empty."""
        self.assertEqual(len(self.rq), 0)

    def test_len_with_one(self):
        """Counter return that it has one."""
        cmd = FakeCommand()
        self.rq.queue(cmd)
        self.assertEqual(len(self.rq), 1)

    def test_len_with_two(self):
        """Counter return that it has two."""
        cmd = FakeCommand()
        self.rq.queue(cmd)
        self.rq.queue(cmd)
        self.assertEqual(len(self.rq), 2)

    def test_len_run_decreases(self):
        """Counter behaviour when adding/running."""
        cmd1 = FakeCommand()
        cmd2 = FakeCommand()
        self.rq.queue(cmd1)
        self.assertEqual(len(self.rq), 1)
        self.rq.queue(cmd2)
        self.assertEqual(len(self.rq), 2)
        self.rq.unqueue(cmd1)
        self.assertEqual(len(self.rq), 1)
        self.rq.unqueue(cmd2)
        self.assertEqual(len(self.rq), 0)

    def test_init_simult_transfers(self):
        """Configure the transfers semaphore according to config."""
        user_config = config.get_user_config()
        user_config.set_simult_transfers(12345)
        rq = RequestQueue(action_queue=None)
        self.assertEqual(rq.transfers_semaphore.tokens, 12345)


class TestDeferredMap(TwistedTestCase):
    """Test the deferred map."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TestDeferredMap, self).setUp()
        self.dm = DeferredMap()

    def test_one_get_returns_stored_deferred(self):
        """Get will return the stored deferred."""
        d = self.dm.get('foo')
        self.assertEqual(self.dm.waiting, {'foo': [d]})

    def test_two_gets_returns_second_deferred_other_key(self):
        """A second get for other key will return other deferred."""
        d1 = self.dm.get('foo')
        d2 = self.dm.get('bar')
        self.assertEqual(self.dm.waiting, {'foo': [d1], 'bar': [d2]})

    def test_two_gets_returns_second_deferred_same_key(self):
        """A second get for the same key will return other deferred."""
        d1 = self.dm.get('foo')
        d2 = self.dm.get('foo')
        self.assertEqual(self.dm.waiting, {'foo': [d1, d2]})

    def test_mixed_gets(self):
        """Several gets with different keys."""
        d1 = self.dm.get('foo')
        d2 = self.dm.get('bar')
        d3 = self.dm.get('foo')
        d4 = self.dm.get('baz')
        self.assertEqual(self.dm.waiting,
                         {'foo': [d1, d3], 'bar': [d2], 'baz': [d4]})

    def test_set_to_nothing(self):
        """It's ok to set a key that is not being waited."""
        self.dm.set('not there', 'value')

    @defer.inlineCallbacks
    def test_set_fires_deferred_single(self):
        """The set fires the unique waiting deferred with the value."""
        d1 = self.dm.get('foo')
        d2 = self.dm.get('bar')
        d3 = self.dm.get('foo')
        self.assertEqual(self.dm.waiting, {'foo': [d1, d3], 'bar': [d2]})

        self.dm.set('bar', 'value')
        res = yield d2
        self.assertEqual(res, 'value')
        self.assertEqual(self.dm.waiting, {'foo': [d1, d3]})

    @defer.inlineCallbacks
    def test_set_fires_deferred_multiple(self):
        """The set fires the multiple waiting deferreds with the value."""
        d1 = self.dm.get('foo')
        d2 = self.dm.get('bar')
        d3 = self.dm.get('foo')
        self.assertEqual(self.dm.waiting, {'foo': [d1, d3], 'bar': [d2]})

        self.dm.set('foo', 'value')
        res1 = yield d1
        res2 = yield d3
        self.assertEqual(res1, 'value')
        self.assertEqual(res2, 'value')
        self.assertEqual(self.dm.waiting, {'bar': [d2]})

    def test_err_to_nothing(self):
        """It's ok to err a key that is not being waited."""
        self.dm.err('not there', 'failure')

    @defer.inlineCallbacks
    def test_err_fires_deferred_single(self):
        """The set fires the unique waiting deferred with the failure."""
        d1 = self.dm.get('foo')
        d2 = self.dm.get('bar')
        d3 = self.dm.get('foo')
        self.assertEqual(self.dm.waiting, {'foo': [d1, d3], 'bar': [d2]})

        exc = Exception('problem!')
        self.dm.err('bar', Failure(exc))
        try:
            yield d2
        except Exception, e:
            self.assertEqual(e, exc)
        else:
            self.fail("It didn't fired the deferred with a failure!")
        self.assertEqual(self.dm.waiting, {'foo': [d1, d3]})


class TestZipQueue(BasicTestCase):
    """Test the zipping queue."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TestZipQueue, self).setUp()
        self.zq = ZipQueue()

        def fake_call_in_thread(callable, *args, **kwargs):
            callable(*args, **kwargs)
        self.patch(reactor, 'callInThread', fake_call_in_thread)

    @defer.inlineCallbacks
    def test_zip_calls_compress_in_thread(self):
        """Test that self._compress is called in another thread."""
        upload = FakeUpload()

        def fake_compress(deferred, _upload, fileobj):
            """Fake the _compress method."""
            self.assertEqual(upload, _upload)
            deferred.callback(True)

        self.zq._compress = fake_compress
        yield self.zq.zip(upload, StringIO)

    @defer.inlineCallbacks
    def test_zip_calls_compress_with_file_object(self):
        """Test that _compress is called with the result of fileobj factory."""
        upload = FakeUpload()
        orig_fileobj = StringIO()

        def fake_compress(deferred, upload, fileobj):
            """Fake the _compress method."""
            self.assertEqual(fileobj, orig_fileobj)
            deferred.callback(True)

        self.zq._compress = fake_compress
        yield self.zq.zip(upload, lambda: orig_fileobj)

    @defer.inlineCallbacks
    def test_fileobj_factory_error_is_logged(self):
        """Log the error when fileobj_factory fails."""
        def crash():
            """Crash!"""
            raise ValueError("foo")

        upload = FakeUpload()

        # set up the logger
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        upload.log.addHandler(self.handler)

        yield self.zq.zip(upload, crash)
        self.assertTrue(self.handler.check_warning("Unable to build fileobj",
                                                   "ValueError", "foo"))

    @defer.inlineCallbacks
    def test_fileobj_factory_error_cancels_upload(self):
        """Cancel the upload when fileobj_factory fails."""
        upload = FakeUpload()
        yield self.zq.zip(upload, 'willbreak')
        self.assertTrue(upload.cancelled)

    @defer.inlineCallbacks
    def test_fileobj_factory_error_dont_call_compress(self):
        """Stop the execution if fileobj_factory fails."""
        upload = FakeUpload()
        called = []
        self.zq._compress = lambda *a: called.append(True)
        yield self.zq.zip(upload, 'willbreak')
        self.assertEqual(len(called), 0)

    @skipTest('Intermittently failing on twisted 12: LP: #1031815')
    @defer.inlineCallbacks
    def test_zip_acquire_lock(self):
        """Test that it acquires the lock."""
        called = []
        self.zq._compress = lambda deferred, upl, fobj: deferred.callback(True)

        def fake_acquire():
            """Fake the acquire method."""
            self.zq.tokens = 1
            called.append(True)
            return defer.succeed(True)

        self.zq.acquire = fake_acquire
        upload = FakeUpload()
        yield self.zq.zip(upload, StringIO)
        self.assertTrue(called)

    @defer.inlineCallbacks
    def test_zip_release_lock_ok(self):
        """Test that it releases the lock when all ok."""
        called = []
        self.zq._compress = lambda deferred, upl, fobj: deferred.callback(True)
        self.zq.release = lambda: called.append(True)

        upload = FakeUpload()
        yield self.zq.zip(upload, StringIO)
        self.assertTrue(called)

    @defer.inlineCallbacks
    def test_zip_release_lock_compression_error(self):
        """Test that it releases the lock even on compression error."""
        called = []
        exc = Exception('bad')
        self.zq._compress = lambda deferred, upl, fobj: deferred.errback(exc)
        self.zq.release = lambda: called.append(True)
        upload = FakeUpload()

        try:
            yield self.zq.zip(upload, StringIO)
        except Exception, e:
            # need to silent the exception we're generating in the test
            self.assertEqual(e, exc)
        else:
            self.fail("It should have raised the exception!")
        self.assertTrue(called)

    @defer.inlineCallbacks
    def test_zip_release_lock_fileobjfactory_error(self):
        """Test that it releases the lock even on file factory error."""
        called = []
        self.zq.release = lambda: called.append(True)
        upload = FakeUpload()

        yield self.zq.zip(upload, 'willbreak')
        self.assertTrue(called)

    @defer.inlineCallbacks
    def test_fileobj_closed_ok(self):
        """Close the fileobj after compressing ok."""
        self.zq._compress = lambda deferred, upl, fobj: deferred.callback(True)
        upload = FakeUpload()
        fileobj = StringIO()
        yield self.zq.zip(upload, lambda: fileobj)

        self.assertTrue(fileobj.closed)

    @defer.inlineCallbacks
    def test_fileobj_closed_error(self):
        """Close the fileobj after compressing with error."""
        exc = Exception('bad')
        self.zq._compress = lambda deferred, upl, fobj: deferred.errback(exc)

        upload = FakeUpload()
        s = StringIO()
        e = yield self.assertFailure(self.zq.zip(upload, lambda: s), Exception)
        self.assertEqual(e, exc)
        self.assertTrue(s.closed)

    @defer.inlineCallbacks
    def test_compress_gets_compressed_data(self):
        """Compressed data is generated by _compress."""
        upload = FakeUpload()
        data = "a lot of data to compress"

        # call and wait
        d = defer.Deferred()
        reactor.callInThread(self.zq._compress, d, upload, StringIO(data))
        yield d

        with open_file(upload.tempfile.name) as f:
            compressed = f.read()
        self.assertEqual(compressed, data.encode('zip'))

    @defer.inlineCallbacks
    def test_compress_gets_magic_hash(self):
        """The magic hash is generated by _compress."""
        upload = FakeUpload()
        data = "a lot of data to compress"

        # what the hash should give us
        mh = content_hash.magic_hash_factory()
        mh.update(data)
        should_hash = mh.content_hash()._magic_hash

        # call and wait
        d = defer.Deferred()
        reactor.callInThread(self.zq._compress, d, upload, StringIO(data))
        yield d

        hashed = upload.magic_hash._magic_hash
        self.assertEqual(hashed, should_hash)

    def test_compress_release_deferred_cancelled_command(self):
        """Release the deferred if the command is cancelled."""
        upload = FakeUpload()
        upload.cancelled = True

        # call and wait
        d = defer.Deferred()
        reactor.callInThread(self.zq._compress, d, upload, None)
        return d

    @defer.inlineCallbacks
    def test_compress_release_deferred_on_error(self):
        """Release the deferred on an error."""
        upload = None  # _compress will fail because want to access .cancelled

        # call and wait
        d = defer.Deferred()
        reactor.callInThread(self.zq._compress, d, upload, None)
        yield self.assertFailure(d, AttributeError)

    @defer.inlineCallbacks
    def test_compress_closes_and_removes_tempfile_on_error(self):
        """Close and delete the temp file on error."""
        upload = FakeUpload()
        upload.cancelled = False  # force temp file creation

        # call and wait
        d = defer.Deferred()
        # patch NamedTemporaryFile so we can query status over it
        tempfile = FakeTempFile(self.tmpdir)
        self.patch(action_queue, 'NamedTemporaryFile', lambda: tempfile)
        # since fileobj is None, the try-except block will trigger an exception
        reactor.callInThread(self.zq._compress, d, upload, None)
        yield self.assertFailure(d, AttributeError)

        self.assertTrue(tempfile.closed)
        self.assertFalse(path_exists(tempfile.name))
        self.assertTrue(upload.tempfile is None)


class FactoryBaseTestCase(BasicTestCase):
    """Helper for by-pass Twisted."""

    def _patch_connection_info(self, **attrvalues):
        """Helper to patch the ActionQueue connection_info.

        This assumes there is only one item in the connection_info, which
        is the case for the tests.
        """
        connection_info = self.action_queue.connection_info.next()
        for attr, value in attrvalues.items():
            connection_info[attr] = value
        self.action_queue.connection_info = itertools.cycle([connection_info])

    def _start_sample_webserver(self):
        """Start a web server serving content at its root"""
        # start listening on `decide yourself` port, and fix AQ with it
        website = server.Site(None)
        webport = reactor.listenTCP(0, website)
        self._patch_connection_info(port=webport.getHost().port)

        server_transport_deferred = defer.Deferred()
        transport_class = webport.transport

        def save_an_instance(skt, protocol, addr, sself, s, sreactor):
            self.server_transport = transport_class(skt, protocol, addr, sself,
                                                    s, sreactor)
            server_transport_deferred.callback(None)
            return self.server_transport

        webport.transport = save_an_instance
        self.addCleanup(webport.stopListening)
        return webport, server_transport_deferred

    def _connect_factory(self):
        """Connect the instance factory."""
        self.server, server_transport_deferred = self._start_sample_webserver()
        orig = self.action_queue.buildProtocol

        d = defer.Deferred()

        def faked_buildProtocol(*args, **kwargs):
            """Override buildProtocol to hook a deferred."""
            protocol = orig(*args, **kwargs)
            protocol.testing_deferred = d
            return protocol

        self.action_queue.buildProtocol = faked_buildProtocol
        self.action_queue.connect()
        return defer.DeferredList([d, server_transport_deferred])

    def _disconnect_factory(self):
        """Disconnect the instance factory."""
        if self.action_queue.client is not None:
            orig = self.action_queue.client.connectionLost

            d = defer.Deferred()

            def faked_connectionLost(reason):
                """Receive connection lost and fire tearDown."""
                orig(reason)
                d.callback(True)

            self.action_queue.client.connectionLost = faked_connectionLost
        else:
            d = defer.succeed(True)

        if self.action_queue.connect_in_progress:
            self.action_queue.disconnect()

        return d


class ConnectionTestCase(FactoryBaseTestCase):
    """Test TCP/SSL connection mechanism for ActionQueue."""

    def assert_connection_state_reset(self):
        """Test connection state is properly reset."""
        self.assertTrue(self.action_queue.client is None)
        self.assertTrue(self.action_queue.connector is None)
        self.assertEqual(False, self.action_queue.connect_in_progress)

    def test_init(self):
        """Test connection init state."""
        self.assert_connection_state_reset()

    @defer.inlineCallbacks
    def test_connect_if_already_connected(self):
        """Test that double connections are avoided."""
        yield self._connect_factory()

        assert self.action_queue.connector is not None
        assert self.action_queue.connect_in_progress

        # double connect, it returns None instead of a Deferred
        result = self.action_queue.connect()
        self.assertTrue(result is None, 'not connecting again')

        yield self._disconnect_factory()

    @defer.inlineCallbacks
    def test_disconnect_if_connected(self):
        """self.action_queue.connector.disconnect was called."""
        yield self._connect_factory()

        self.action_queue.event_queue.events = []  # cleanup events
        assert self.action_queue.connector.state == 'connected'
        self.action_queue.disconnect()

        self.assert_connection_state_reset()
        self.assertEqual([], self.action_queue.event_queue.events)

        yield self._disconnect_factory()

    @defer.inlineCallbacks
    def test_clientConnectionFailed(self):
        """Test clientConnectionFailed.

        The connection will not be completed since the server will be down. So,
        self.action_queue.connector will never leave the 'connecting' state.
        When interrupting the connection attempt, twisted automatically calls
        self.action_queue.clientConnectionFailed.

        """
        self.action_queue.event_queue.events = []
        orig = self.action_queue.clientConnectionFailed

        d = defer.Deferred()

        def faked_clientConnectionFailed(connector, reason):
            """Receive connection failed and check."""
            orig(connector, reason)
            self.assert_connection_state_reset()
            self.assertEqual([('SYS_CONNECTION_FAILED', {})],
                             self.action_queue.event_queue.events)
            self.action_queue.clientConnectionFailed = orig
            d.callback(True)

        self.action_queue.clientConnectionFailed = faked_clientConnectionFailed
        # factory will never finish the connection, server was never started
        self.action_queue.connect()
        # stopConnecting() will be called since the connection is in progress
        assert self.action_queue.connector.state == 'connecting'
        self.action_queue.connector.disconnect()

        yield d

    @defer.inlineCallbacks
    def test_clientConnectionLost(self):
        """Test clientConnectionLost

        The connection will be completed successfully.
        So, self.action_queue.connector will be in the 'connected' state.
        When disconnecting the connector, twisted automatically calls
        self.action_queue.clientConnectionLost.

        """
        yield self._connect_factory()

        self.action_queue.event_queue.events = []
        orig = self.action_queue.clientConnectionLost

        d = defer.Deferred()

        def faked_clientConnectionLost(connector, reason):
            """Receive connection lost and check."""
            orig(connector, reason)
            self.assert_connection_state_reset()
            self.assertEqual([('SYS_CONNECTION_LOST', {})],
                             self.action_queue.event_queue.events)
            self.action_queue.clientConnectionLost = orig
            d.callback(True)

        self.action_queue.clientConnectionLost = faked_clientConnectionLost
        # loseConnection() will be called since the connection was completed
        assert self.action_queue.connector.state == 'connected'
        self.action_queue.connector.disconnect()
        yield d

        yield self._disconnect_factory()

    @defer.inlineCallbacks
    def test_server_disconnect(self):
        """Test factory's connection when the server goes down."""

        yield self._connect_factory()

        self.action_queue.event_queue.events = []
        orig = self.action_queue.clientConnectionLost

        d = defer.Deferred()

        def faked_connectionLost(*args, **kwargs):
            """Receive connection lost and check."""
            orig(*args, **kwargs)
            self.assert_connection_state_reset()
            self.assertEqual([('SYS_CONNECTION_LOST', {})],
                             self.action_queue.event_queue.events)
            self.action_queue.clientConnectionLost = orig
            d.callback(True)

        self.action_queue.clientConnectionLost = faked_connectionLost
        # simulate a server failure!
        yield self.server_transport.loseConnection()
        yield d
        yield self._disconnect_factory()

    def test_buildProtocol(self):
        """Test buildProtocol."""
        protocol = self.action_queue.buildProtocol(addr=None)
        self.assertTrue(protocol is self.action_queue.client)
        self.assertTrue(self.action_queue is self.action_queue.client.factory)

        aq = self.action_queue
        self.assertEqual(aq.client._share_change_callback,
                         aq._share_change_callback)
        self.assertEqual(aq.client._share_answer_callback,
                         aq._share_answer_callback)
        self.assertEqual(aq.client._free_space_callback,
                         aq._free_space_callback)
        self.assertEqual(aq.client._account_info_callback,
                         aq._account_info_callback)
        self.assertEqual(aq.client._volume_created_callback,
                         aq._volume_created_callback)
        self.assertEqual(aq.client._volume_deleted_callback,
                         aq._volume_deleted_callback)
        self.assertEqual(aq.client._volume_new_generation_callback,
                         aq._volume_new_generation_callback)

    @defer.inlineCallbacks
    def test_connector_gets_assigned_on_connect(self):
        """Test factory's connector gets assigned on connect."""
        yield self._connect_factory()

        self.assertTrue(self.action_queue.connector is not None)

        yield self._disconnect_factory()

    def test_connection_started_logging(self):
        """Test that the connection started logs connector info, not AQ's."""
        connection_info = self.action_queue.connection_info.next()
        assert connection_info['host'] == '127.0.0.1'
        assert connection_info['port'] == 0

        class FakeConnector(object):
            """Fake connector."""
            host = '1.2.3.4'
            port = 4321

        self.action_queue.startedConnecting(FakeConnector())
        self.assertTrue(self.handler.check_info("Connection started",
                                                "host 1.2.3.4", "port 4321"))

    @defer.inlineCallbacks
    def test_connection_info_rotation(self):
        """It tries to connect to different servers."""

        multiple_conn = [
            {'host': 'host1', 'port': 'port1', 'use_ssl': False},
            {'host': 'host2', 'port': 'port2', 'use_ssl': False},
        ]
        self.action_queue.connection_info = itertools.cycle(multiple_conn)

        self.tunnel_runner = None

        def mitm(*args):
            tunnel_runner = SavingConnectionTunnelRunner(*args)
            self.tunnel_runner = tunnel_runner
            return tunnel_runner

        self.action_queue._get_tunnel_runner = mitm

        yield self.action_queue._make_connection()
        self.assertEqual(self.tunnel_runner.host, 'host1')
        self.assertEqual(self.tunnel_runner.port, 'port1')

        yield self.action_queue._make_connection()
        self.assertEqual(self.tunnel_runner.host, 'host2')
        self.assertEqual(self.tunnel_runner.port, 'port2')

        yield self.action_queue._make_connection()
        self.assertEqual(self.tunnel_runner.host, 'host1')
        self.assertEqual(self.tunnel_runner.port, 'port1')


class TunnelRunnerTestCase(FactoryBaseTestCase):
    """Tests for the tunnel runner."""

    tunnel_runner_class = SavingConnectionTunnelRunner

    def setUp(self):
        result = super(TunnelRunnerTestCase, self).setUp()
        self.tunnel_runner = None
        orig_get_tunnel_runner = self.action_queue._get_tunnel_runner

        def mitm(*args):
            tunnel_runner = orig_get_tunnel_runner(*args)
            self.tunnel_runner = tunnel_runner
            return tunnel_runner

        self.action_queue._get_tunnel_runner = mitm
        return result

    @defer.inlineCallbacks
    def test_make_connection_uses_tunnelrunner_non_ssl(self):
        """Check that _make_connection uses TunnelRunner."""
        self._patch_connection_info(use_ssl=False)
        yield self.action_queue._make_connection()
        self.assertTrue(self.tunnel_runner.client.tcp_connected,
                        "connectTCP is called on the client.")

    @defer.inlineCallbacks
    def test_make_connection_uses_tunnelrunner_ssl(self):
        """Check that _make_connection uses TunnelRunner."""
        self._patch_connection_info(use_ssl=True, disable_ssl_verify=False)
        yield self.action_queue._make_connection()
        self.assertTrue(self.tunnel_runner.client.ssl_connected,
                        "connectSSL is called on the client.")


class ContextRequestedWithHost(FactoryBaseTestCase):
    """Test that the context is requested passing the host."""

    tunnel_runner_class = SavingConnectionTunnelRunner

    @defer.inlineCallbacks
    def test_context_request_passes_host(self):
        """The context is requested passing the host."""
        fake_host = "fake_host"
        fake_disable_ssl_verify = False

        def fake_get_ssl_context(disable_ssl_verify, host):
            """The host is used to call get_ssl_context."""
            self.assertEqual(disable_ssl_verify, fake_disable_ssl_verify)
            self.assertEqual(host, fake_host)

        self.patch(action_queue, "get_ssl_context", fake_get_ssl_context)
        self._patch_connection_info(
            host=fake_host, use_ssl=True,
            disable_ssl_verify=fake_disable_ssl_verify)
        yield self.action_queue._make_connection()


class ConnectedBaseTestCase(FactoryBaseTestCase):
    """Base test case generating a connected factory."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(ConnectedBaseTestCase, self).setUp()
        yield self._connect_factory()
        assert self.action_queue.connector.state == 'connected'

    @defer.inlineCallbacks
    def tearDown(self):
        """Clean up."""
        yield self._disconnect_factory()
        yield super(ConnectedBaseTestCase, self).tearDown()

    def silent_connection_lost(self, failure):
        """Some tests will generate connection lost, support it."""
        if not failure.check(twisted_error.ConnectionDone,
                             twisted_error.ConnectionLost):
            return failure


class VolumeManagementTestCase(ConnectedBaseTestCase):
    """Test Volume managemenr for ActionQueue."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(VolumeManagementTestCase, self).setUp()

        # silence the event to avoid propagation
        listener_map = self.action_queue.event_queue.listener_map
        del listener_map['SV_VOLUME_DELETED']

    def test_volume_created_push_event(self):
        """Volume created callback push proper event."""
        volume = FakedVolume()
        self.action_queue._volume_created_callback(volume)
        self.assertEqual([('SV_VOLUME_CREATED', {'volume': volume})],
                         self.action_queue.event_queue.events)

    def test_volume_deleted_push_event(self):
        """Volume deleted callback push proper event."""
        volume_id = VOLUME
        self.action_queue._volume_deleted_callback(volume_id)
        self.assertEqual([('SV_VOLUME_DELETED', {'volume_id': volume_id})],
                         self.action_queue.event_queue.events)

    def test_volume_new_generation_push_event_root(self):
        """Volume New Generation callback push proper event with root."""
        volume = request.ROOT
        self.action_queue._volume_new_generation_callback(volume, 77)
        event = ('SV_VOLUME_NEW_GENERATION',
                 {'volume_id': volume, 'generation': 77})
        self.assertTrue(event in self.action_queue.event_queue.events)

    def test_volume_new_generation_push_event_uuid(self):
        """Volume New Generation callback push proper event with uuid."""
        volume = uuid.uuid4()
        self.action_queue._volume_new_generation_callback(volume, 77)
        event = ('SV_VOLUME_NEW_GENERATION',
                 {'volume_id': volume, 'generation': 77})
        self.assertTrue(event in self.action_queue.event_queue.events)

    def test_valid_events(self):
        """Volume events are valid in EventQueue."""
        new_events = ('SV_VOLUME_CREATED', 'SV_VOLUME_DELETED',
                      'AQ_CREATE_UDF_OK', 'AQ_CREATE_UDF_ERROR',
                      'AQ_LIST_VOLUMES', 'AQ_LIST_VOLUMES_ERROR',
                      'AQ_DELETE_VOLUME_OK', 'AQ_DELETE_VOLUME_ERROR',
                      'SV_VOLUME_NEW_GENERATION')
        for event in new_events:
            self.assertTrue(event in EVENTS)

        self.assertEqual(('volume',), EVENTS['SV_VOLUME_CREATED'])
        self.assertEqual(('volume_id',), EVENTS['SV_VOLUME_DELETED'])
        self.assertEqual(('volume_id', 'node_id', 'marker'),
                         EVENTS['AQ_CREATE_UDF_OK'])
        self.assertEqual(('error', 'marker'), EVENTS['AQ_CREATE_UDF_ERROR'])
        self.assertEqual(('volumes',), EVENTS['AQ_LIST_VOLUMES'])
        self.assertEqual(('error',), EVENTS['AQ_LIST_VOLUMES_ERROR'])
        self.assertEqual(('volume_id',), EVENTS['AQ_DELETE_VOLUME_OK'])
        self.assertEqual(('volume_id', 'error',),
                         EVENTS['AQ_DELETE_VOLUME_ERROR'])
        self.assertEqual(('volume_id', 'generation',),
                         EVENTS['SV_VOLUME_NEW_GENERATION'])

    def test_create_udf(self):
        """Test volume creation."""
        path = PATH
        name = NAME
        self.action_queue.create_udf(path, name, marker=None)

    def test_list_volumes(self):
        """Test volume listing."""
        self.action_queue.list_volumes()

    def test_delete_volume(self):
        """Test volume deletion."""
        volume_id = VOLUME
        self.action_queue.delete_volume(volume_id, 'path')


class ActionQueueCommandTestCase(ConnectedBaseTestCase):
    """Test for the generic functionality of ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(ActionQueueCommandTestCase, self).setUp()

        class MyCommand(ActionQueueCommand):
            logged_attrs = ('a', 'b', 'c', 'd')
            a = 3
            b = 'foo'
            c = u'año'

            def _run(self):
                return defer.succeed(True)

            @property
            def uniqueness(self):
                return (self.a, self.b, self.c)

        self.rq = RequestQueue(action_queue=self.action_queue)
        self.rq.active = True
        self.cmd = MyCommand(self.rq)
        self.cmd.make_logger()
        self.rq.queue(self.cmd)

    def test_runnable(self):
        """All commands are runnable by default."""
        self.assertTrue(self.cmd.is_runnable)

    def test_cancelled(self):
        """All commands are not cancelled by default."""
        self.assertFalse(self.cmd.cancelled)

    def test_dump_to_dict(self):
        """Test to dict dumping."""
        d = self.cmd.to_dict()
        self.assertEqual(d, dict(a=3, b='foo', c=u'año', d=None))

    @defer.inlineCallbacks
    def test_demark_not_marker(self):
        """Test demark with not a marker."""
        self.cmd.possible_markers = 'foo',
        self.cmd.foo = 'not a marker'
        yield self.cmd.demark()
        self.assertEqual(self.cmd.foo, 'not a marker')

    @defer.inlineCallbacks
    def test_demark_with_marker_future(self):
        """Test demark with a marker not ready.

        Here, on purpose, set up everything and trigger later.
        """
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'foo',
        self.cmd.foo = marker
        d = self.cmd.demark()

        self.action_queue.uuid_map.set(marker, 'node_id')
        yield d
        self.assertEqual(self.cmd.foo, 'node_id')
        self.assertTrue(self.handler.check_debug(
                        "waiting for the real value of marker"))

    @defer.inlineCallbacks
    def test_demark_with_marker_ready(self):
        """Test demark with a marker that had data."""
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'foo',
        self.cmd.foo = marker
        d = self.cmd.demark()
        self.action_queue.uuid_map.set(marker, 'node_id')
        yield d
        self.assertEqual(self.cmd.foo, 'node_id')
        self.assertTrue(self.handler.check_debug(
                        "waiting for the real value of marker"))

    @defer.inlineCallbacks
    def test_demark_with_marker_solved(self):
        """Test demark with a marker that points to a node already with id."""
        mdid = self.main.fs.create(os.path.join(self.root, 'file'),
                                   '', node_id='node_id')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'foo',
        self.cmd.foo = marker
        yield self.cmd.demark()
        self.assertEqual(self.cmd.foo, 'node_id')
        self.assertTrue(self.handler.check_debug(
                        "shortcutting the real value of marker"))

    @defer.inlineCallbacks
    def test_demark_mixed_markers(self):
        """Test demark with both a marker and not."""
        # call demark with both
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'foo', 'bar'
        self.cmd.foo = 'notamarker'
        self.cmd.bar = marker
        d = self.cmd.demark()
        self.action_queue.uuid_map.set(marker, 'node_id')
        yield d

        # check
        self.assertEqual(self.cmd.foo, 'notamarker')
        self.assertEqual(self.cmd.bar, 'node_id')
        self.assertTrue(self.handler.check_debug(
                        "waiting for the real value of marker"))
        self.assertFalse(self.handler.check_debug(
                         "waiting for the real value of 'notamarker'"))

    @defer.inlineCallbacks
    def test_demark_marker_future_got_ok(self):
        """Test demark getting a marker triggered ok later."""
        # don't have the info now
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'foo',
        self.cmd.foo = marker
        d = self.cmd.demark()
        self.assertFalse(self.handler.check_debug("for marker"))

        # set and check
        self.action_queue.uuid_map.set(marker, 'node_id')
        yield d
        self.assertEqual(self.cmd.foo, 'node_id')
        self.assertTrue(self.handler.check_debug(
                        "for marker", "got value 'node_id'"))

    @defer.inlineCallbacks
    def test_demark_marker_future_got_failure(self):
        """Test demark getting a marker triggered with failure later."""
        # don't have the info now
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'foo',
        self.cmd.foo = marker
        d = self.cmd.demark()
        self.assertFalse(self.handler.check_error("failed marker"))

        # set the marker and check
        self.action_queue.uuid_map.err(marker, Failure(Exception('bad')))
        yield d
        self.assertTrue(self.handler.check_error("failed marker"))
        try:
            yield self.cmd.markers_resolved_deferred
        except Exception, e:
            self.assertEqual(str(e), 'bad')
        else:
            self.fail("An exception should have been raised!")

    @defer.inlineCallbacks
    def test_demark_two_markers_ok(self):
        """Test demark with two markers that finish ok."""
        # call demark with both
        mdid1 = self.main.fs.create(os.path.join(self.root, 'file1'), '')
        mdid2 = self.main.fs.create(os.path.join(self.root, 'file2'), '')
        marker1 = MDMarker(mdid1)
        marker2 = MDMarker(mdid2)
        self.cmd.possible_markers = 'foo', 'bar'
        self.cmd.foo = marker1
        self.cmd.bar = marker2
        d = self.cmd.demark()
        self.action_queue.uuid_map.set(marker1, 'data1')
        self.action_queue.uuid_map.set(marker2, 'data2')
        yield d

        # check
        self.assertEqual(self.cmd.foo, 'data1')
        self.assertEqual(self.cmd.bar, 'data2')
        yield self.cmd.markers_resolved_deferred

    @defer.inlineCallbacks
    def test_demark_two_markers_one_fail(self):
        """Test demark with two markers that one ends in failure."""
        # call demark with both
        mdid1 = self.main.fs.create(os.path.join(self.root, 'file1'), '')
        mdid2 = self.main.fs.create(os.path.join(self.root, 'file2'), '')
        marker1 = MDMarker(mdid1)
        marker2 = MDMarker(mdid2)
        self.cmd.possible_markers = 'foo', 'bar'
        self.cmd.foo = marker1
        self.cmd.bar = marker2
        d = self.cmd.demark()
        self.action_queue.uuid_map.set(marker1, 'data ok')
        self.action_queue.uuid_map.err(marker2, Failure(Exception('data bad')))
        yield d

        # check
        try:
            yield self.cmd.markers_resolved_deferred
        except Exception, e:
            self.assertEqual(str(e), 'data bad')
        else:
            self.fail("An exception should have been raised!")

    @defer.inlineCallbacks
    def test_demark_fixes_hashedwaiting_active(self):
        """The attribute changes: it also need to change the hashed_waiting."""
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.b = marker
        queue = self.cmd._queue
        queue.hashed_waiting[self.cmd.uniqueness] = self.cmd
        d = self.cmd.demark()

        self.action_queue.uuid_map.set(marker, 'node_id')
        yield d
        self.assertTrue(queue.hashed_waiting[self.cmd.uniqueness], self.cmd)

    @defer.inlineCallbacks
    def test_demark_fixes_hashedwaiting_cancelled(self):
        """The attribute changes: no change because cancelled."""
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        marker = MDMarker(mdid)
        self.cmd.possible_markers = 'b',
        self.cmd.b = marker
        self.cmd.cancelled = True
        queue = self.cmd._queue
        queue.hashed_waiting[self.cmd.uniqueness] = self.cmd
        d = self.cmd.demark()

        self.action_queue.uuid_map.set(marker, 'node_id')
        yield d
        self.assertFalse(self.cmd.uniqueness in queue.hashed_waiting)

    def test_go_demarks(self):
        """Make the logger and demark."""
        called = []
        self.cmd.demark = lambda: called.append(True)

        self.cmd.go()
        self.assertTrue(called)

    def test_go_pathlock_run(self):
        """Acquire the pathlock and run."""
        called = []
        self.cmd._acquire_pathlock = lambda: called.append(1)
        self.cmd.run = lambda: called.append(2)

        self.cmd.go()
        self.assertEqual(called, [1, 2])

    def test_go_stop_cancels_while_pathlocking(self):
        """If the command is cancelled while locked, stop."""
        called = []
        self.cmd.run = lambda: called.append(True)
        d = defer.Deferred()
        d.addErrback(lambda _: None)
        self.cmd._acquire_pathlock = lambda: d

        self.cmd.go()
        self.cmd.cancel()

        self.assertFalse(called)

    def test_go_release_cancelled_while_pathlocking(self):
        """If the command is cancelled while locked, release the pathlock."""
        called = []
        self.cmd.run = lambda: called.append(1)
        d = defer.Deferred()
        d.addErrback(lambda _: called.append(2))
        self.cmd._acquire_pathlock = lambda: d

        self.cmd.go()
        self.cmd.cancel()

        self.assertEqual(called, [2])
        self.assertTrue(self.handler.check_debug(
                        'command not run because of cancelled'))

    def test_go_run_ok_release_pathlock(self):
        """If run went ok, release the pathlock."""
        called = []
        self.cmd.run = lambda: defer.succeed(True)
        self.cmd._acquire_pathlock = lambda: defer.succeed(
            lambda: called.append(True))

        self.cmd.go()
        self.assertTrue(called)

    @defer.inlineCallbacks
    def test_go_run_bad_release_pathlock(self):
        """If run went bad, release the pathlock."""
        called = []
        self.cmd.run = lambda: defer.fail(ValueError("error message"))
        self.cmd._acquire_pathlock = lambda: defer.succeed(
            lambda: called.append(True))

        yield self.cmd.go()
        self.assertTrue(called)

        # check exception to assure a traceback was logged, and check the
        # messages in ERROR (the real logging level); finally, clean the
        # records as if we leave them with the exception the test will fail
        self.assertTrue(self.handler.check_exception(ValueError))
        self.assertTrue(self.handler.check_error("Error running the command",
                                                 "error message"))
        self.handler.records = []

    def test_run_initial(self):
        """Call ._start, log, and set running."""
        called = []
        d = defer.Deferred()
        self.cmd._start = lambda: called.append(True) or d

        # run, and will lock in the _start
        self.cmd.run()
        self.assertTrue(called)
        self.assertTrue(self.handler.check_debug('starting'))

        # release the _start, check log and that it still not running
        d.callback(True)
        self.assertTrue(self.handler.check_debug('started'))
        self.assertFalse(self.cmd.running)

    def test_run_stop_if_cancelled_while_start(self):
        """Cancelled while _start."""
        self.rq.queue(self.cmd)
        assert self.rq.active
        assert self.cmd.is_runnable
        self.cmd.markers_resolved_deferred.callback(True)

        called = []
        self.cmd._run = lambda: called.append(True)
        d = defer.Deferred()
        self.cmd._start = lambda: d

        # run, cancel, and unlock start
        self.cmd.run()
        self.cmd.cancel()
        d.callback(True)

        self.assertFalse(called)
        self.assertTrue(self.handler.check_debug(
                        'cancelled before trying to run'))

    def test_run_queue_not_active(self):
        """Waiting cycle for queue not active."""
        self.rq.queue(self.cmd)
        assert self.cmd.is_runnable
        self.cmd.markers_resolved_deferred.callback(True)

        self.rq.active = False
        called = []
        self.cmd._run = lambda: called.append(True) or defer.Deferred()

        # run first time
        self.cmd.run()
        self.assertFalse(called)
        self.assertTrue(self.handler.check_debug(
                        'not running because of inactive queue'))
        self.assertFalse(self.handler.check_debug('unblocked: queue active'))

        # active the queue
        self.rq.run()
        self.assertTrue(called)
        self.assertTrue(self.handler.check_debug('unblocked: queue active'))

    def test_run_command_not_runnable(self):
        """Waiting cycle for command not runnable."""
        self.rq.queue(self.cmd)
        assert self.rq.active
        self.cmd.markers_resolved_deferred.callback(True)

        self.cmd.is_runnable = False
        called = []
        self.cmd._run = lambda: called.append(True) or defer.Deferred()

        # run first time
        self.cmd.run()
        self.assertFalse(called)
        self.assertTrue(self.handler.check_debug(
                        'not running because of conditions'))
        self.assertFalse(self.handler.check_debug('unblocked: conditions ok'))

        # active the command
        self.cmd.is_runnable = True
        self.action_queue.conditions_locker.check_conditions()
        self.assertTrue(called)
        self.assertTrue(self.handler.check_debug('unblocked: conditions ok'))

    def test_run_notrunnable_inactivequeue(self):
        """Mixed behaviour between both stoppers."""
        self.rq.queue(self.cmd)
        self.cmd.markers_resolved_deferred.callback(True)
        assert self.cmd.is_runnable
        self.rq.active = False
        called = []
        self.cmd._run = lambda: called.append(True) or defer.Deferred()

        # run first time
        self.cmd.run()
        self.assertFalse(called)

        # active the queue but inactive the command
        self.cmd.is_runnable = False
        self.rq.run()
        self.assertFalse(called)

        # active the command but inactive the queue again!
        self.rq.stop()
        self.cmd.is_runnable = True
        self.action_queue.conditions_locker.check_conditions()
        self.assertFalse(called)

        # finally resume the queue
        self.rq.run()
        self.assertTrue(called)

    def test_run_inactivequeue_cancel(self):
        """Got cancelled while waiting the queue to resume."""
        self.rq.queue(self.cmd)
        assert self.cmd.is_runnable
        self.cmd.markers_resolved_deferred.callback(True)

        self.rq.active = False
        called = []
        self.cmd._run = lambda: called.append(True)

        # run and cancel
        self.cmd.run()
        self.cmd.cancel()

        # active the queue
        self.rq.run()
        self.assertFalse(called)
        self.assertTrue(self.handler.check_debug(
                        'cancelled before trying to run'))

    def test_run_notrunnable_cancel(self):
        """Got cancelled while waiting the conditions to run."""
        self.rq.queue(self.cmd)
        assert self.rq.active
        self.cmd.markers_resolved_deferred.callback(True)

        self.cmd.is_runnable = False
        called = []
        self.cmd._run = lambda: called.append(True)

        # run and cancel
        self.cmd.run()
        self.cmd.cancel()

        # active the command
        self.cmd.is_runnable = True
        self.action_queue.conditions_locker.check_conditions()
        self.assertFalse(called)
        self.handler.debug = True
        self.assertTrue(self.handler.check_debug(
                        'cancelled before trying to run'))

    def test_run_waits_markers_dereferencing(self):
        """Don't call _run_command until have the markers."""
        self.rq.queue(self.cmd)
        assert self.cmd.is_runnable
        assert self.rq.active

        called = []
        self.cmd._run = lambda: called.append(True) or defer.Deferred()

        # run first time
        self.cmd.run()
        self.assertFalse(called)

        # resolve the markers
        self.cmd.markers_resolved_deferred.callback(True)
        self.assertTrue(called)
        self.assertTrue(self.cmd.running)

    def test_run_endok_calls_finishing_stuff_not_cancelled(self):
        """Call finish on end ok."""
        self.rq.queue(self.cmd)
        called = []
        self.cmd.finish = lambda: called.append(2)
        self.cmd.handle_success = lambda a: called.append(a)
        self.cmd._run = lambda: defer.succeed(1)
        self.cmd.markers_resolved_deferred = defer.succeed(True)
        self.cmd.run()

        # check that handle_success was called *before* finish
        self.assertEqual(called, [1, 2])
        self.assertTrue(self.handler.check_debug('success'))

    def test_run_endok_calls_finishing_stuff_cancelled(self):
        """Call finish on end ok, cancelled while running."""
        self.rq.queue(self.cmd)
        called = []
        self.cmd.handle_success = lambda a: called.append(a)
        d = defer.Deferred()
        self.cmd._run = lambda: d
        self.cmd.markers_resolved_deferred = defer.succeed(True)
        self.cmd.run()

        # cancel and let _run finish
        self.cmd.cancel()
        d.callback(True)
        self.assertFalse(called)
        self.assertTrue(self.handler.check_debug('cancelled while running'))

    def test_run_enderr_calls_finish(self):
        """Call finish on end_errback."""
        called = []
        self.cmd.finish = lambda: called.append(1)
        self.cmd.handle_failure = lambda f: called.append(f.value)
        self.cmd.markers_resolved_deferred = defer.succeed(True)
        self.cmd.suppressed_error_messages.append(ValueError)
        exc = ValueError()
        self.cmd._run = lambda: defer.fail(exc)
        self.cmd.run()

        # check that handle_failure was called *before* finish
        self.assertEqual(called, [exc, 1])

    def test_run_enderr_retry(self):
        """Command retried, call the handle and retry."""
        called = []
        self.cmd.finish = lambda: called.append('should not')
        self.cmd.handle_failure = lambda: called.append('should not')
        self.cmd.handle_retryable = lambda f: called.append('ok')
        self.cmd.markers_resolved_deferred = defer.succeed(True)
        assert self.rq.active

        def fake_run():
            """Set the queue inactive to avoid retry loop and fail."""
            self.rq.active = False
            raise twisted_error.ConnectionDone()

        # set up and test
        self.cmd._run = fake_run

        # run and check finish was not called
        self.cmd.run()
        self.assertEqual(called, ['ok'])

    def test_run_retry_on_commandpaused(self):
        """Command retried because of pausing."""
        called = []
        self.cmd.finish = lambda: called.append(True)
        self.cmd.markers_resolved_deferred = defer.succeed(True)
        self.rq.waiting.append(self.cmd)
        assert self.rq.active

        # deferreds, first one stucks, the second allows to continue
        deferreds = [defer.Deferred(), defer.succeed(True)]
        self.cmd._run = lambda: deferreds.pop(0)

        # run and check finish was not called
        self.cmd.run()
        self.assertFalse(called)

        # pause, still nothing called
        self.rq.stop()
        self.assertFalse(called)

        # resume, now it finished!
        self.rq.run()
        self.assertTrue(called)

    @defer.inlineCallbacks
    def test_start_default(self):
        """Default _start just returns a triggered deferred and sets done."""
        yield self.cmd._start()

    def test_possible_markers_default(self):
        """Default value for possible markers."""
        self.assertEqual(self.cmd.possible_markers, ())

    @defer.inlineCallbacks
    def test_path_locking(self):
        """Test it has a generic _acquire_pathlock."""
        r = yield self.cmd._acquire_pathlock()
        self.assertIdentical(r, None)

    def test_finish_running(self):
        """Set running to False when finish."""
        self.cmd.running = True
        self.rq.unqueue = lambda c: None  # don't do anything
        self.cmd.finish()
        self.assertFalse(self.cmd.running)

    @defer.inlineCallbacks
    def test_pause_running(self):
        """Pause while running."""
        self.cmd.running_deferred = InterruptibleDeferred(defer.Deferred())
        called = []
        self.cmd.cleanup = lambda: called.append(True)

        self.cmd.pause()
        self.assertTrue(self.handler.check_debug("pausing"))
        self.assertTrue(called)

        try:
            yield self.cmd.running_deferred
        except DeferredInterrupted:
            pass   # this is handled by run() to retry
        else:
            self.fail("Test should have raised an exception")

    def test_pause_norunning(self):
        """Pause while not running."""
        assert self.cmd.running_deferred is None
        called = []
        self.cmd.cleanup = lambda: called.append(True)

        self.cmd.pause()
        self.assertTrue(self.handler.check_debug("pausing"))
        self.assertTrue(called)

    def test_cancel_works(self):
        """Do default cleaning."""
        called = []
        self.cmd.cleanup = lambda: called.append(1)
        self.cmd.finish = lambda: called.append(2)
        assert not self.cmd.cancelled
        did_cancel = self.cmd.cancel()
        self.assertTrue(did_cancel)
        self.assertEqual(called, [1, 2])
        self.assertTrue(self.cmd.cancelled)
        self.assertTrue(self.handler.check_debug('cancelled'))

    def test_cancel_releases_conditions(self):
        """Cancel calls the conditions locker for the command."""
        self.cmd.finish = lambda: None  # don't try to unqueue!
        d = self.action_queue.conditions_locker.get_lock(self.cmd)
        self.cmd.cancel()
        self.assertTrue(d.called)

    def test_cancel_cancelled(self):
        """Don't do anything if command already cancelled."""
        called = []
        self.cmd.cleanup = lambda: called.append(True)
        self.cmd.finish = lambda: called.append(True)
        self.cmd.cancelled = True
        did_cancel = self.cmd.cancel()
        self.assertFalse(did_cancel)
        self.assertFalse(called)
        self.assertTrue(self.cmd.cancelled)

    def test_slots(self):
        """Inherited commands must have __slot__ (that is not inherited)."""
        for obj_name in dir(action_queue):
            obj = getattr(action_queue, obj_name)
            if isinstance(obj, type) and issubclass(obj, ActionQueueCommand) \
               and obj is not ActionQueueCommand:
                self.assertNotIdentical(obj.__slots__,
                                        ActionQueueCommand.__slots__,
                                        "class %s has no __slots__" % obj)

    def test_should_be_queued_calls(self):
        """Create the logger and call the aux method."""
        called = []
        self.cmd.make_logger = lambda: called.append(1)
        self.cmd._should_be_queued = lambda: called.append(2)
        self.cmd.should_be_queued()
        self.assertEqual(called, [1, 2])

    def test_should_be_queued_default(self):
        """Aux method default."""
        self.assertTrue(self.cmd._should_be_queued())


class CreateUDFTestCase(ConnectedBaseTestCase):
    """Test for CreateUDF ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(CreateUDFTestCase, self).setUp()

        request_queue = RequestQueue(action_queue=self.action_queue)
        self.marker = VOLUME
        self.command = CreateUDF(request_queue, PATH, NAME, marker=self.marker)

        # silence the event to avoid propagation
        listener_map = self.action_queue.event_queue.listener_map
        del listener_map['AQ_CREATE_UDF_OK']
        del listener_map['AQ_CREATE_UDF_ERROR']

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        self.assertTrue(isinstance(self.command, ActionQueueCommand))

    def test_init(self):
        """Test creation."""
        self.assertEqual(PATH, self.command.path)
        self.assertEqual(NAME, self.command.name)
        self.assertEqual(self.marker, self.command.marker)

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        res = self.command._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's create_udf is called."""
        original = self.command.action_queue.client.create_udf
        self.called = False

        def check(path, name):
            """Take control over client's feature."""
            self.called = True
            self.assertEqual(PATH, path)
            self.assertEqual(NAME, name)

        self.command.action_queue.client.create_udf = check

        self.command._run()

        self.assertTrue(self.called, 'command was called')

        self.command.action_queue.client.create_udf = original

    def test_handle_success_push_event(self):
        """Test AQ_CREATE_UDF_OK is pushed on success."""
        request = client.CreateUDF(self.action_queue.client, PATH, NAME)
        request.volume_id = VOLUME
        request.node_id = NODE
        self.command.handle_success(success=request)
        events = [('AQ_CREATE_UDF_OK', {'volume_id': VOLUME,
                                        'node_id': NODE,
                                        'marker': self.marker})]
        self.assertEqual(events, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_CREATE_UDF_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        events = [('AQ_CREATE_UDF_ERROR',
                  {'error': msg, 'marker': self.marker})]
        self.assertEqual(events, self.command.action_queue.event_queue.events)

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        self.command._acquire_pathlock()
        self.assertEqual(t, [tuple(PATH.split(os.path.sep)), {'logger': None}])


class ActionQueueCommandErrorsTestCase(ConnectedBaseTestCase):
    """Test the error handling in ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(ActionQueueCommandErrorsTestCase, self).setUp()

        self.deferred = defer.Deferred()

        class MyLogger(object):
            """Fake logger that just stores error and warning calls."""
            def __init__(self):
                self.logged = None

            def exception(self, *a):
                """Mark that this method was called."""
                self.logged = "exception"

            def warn(self, *a):
                """Mark that this method was called."""
                self.logged = "warn"

            def debug(self, *a):
                """Nothing."""

        class MyCommand(ActionQueueCommand):
            """Patchable."""

        self.rq = RequestQueue(action_queue=self.action_queue)
        self.rq.unqueue = lambda c: None
        self.rq.active = True
        self.command = MyCommand(self.rq)
        self.command.markers_resolved_deferred = defer.succeed(True)
        self.command.log = MyLogger()

    def test_suppressed_yes_knownerrors(self):
        """Check that the log is in warning for the known errors."""
        def send_failure_and_check(errnum, exception_class):
            """Send the failure."""
            # prepare what to send
            protocol_msg = protocol_pb2.Message()
            protocol_msg.type = protocol_pb2.Message.ERROR
            protocol_msg.error.type = errnum
            err = exception_class("request", protocol_msg)

            def fake_run():
                """Set the queue inactive to avoid retry loops and fail."""
                self.rq.active = False
                raise err

            # set up and test
            self.command.log.logged = None
            self.command._run = fake_run
            self.command.run()
            self.assertEqual(self.command.log.logged, "warn",
                             "Bad log in exception %s" % (exception_class,))

        known_errors = [x for x in errors._error_mapping.items()
                        if x[1] != errors.InternalError]
        for errnum, exception_class in known_errors:
            self.rq.active = True
            send_failure_and_check(errnum, exception_class)

    def test_suppressed_no_internalerror(self):
        """Check that the log is in error for InternalError."""
        # prepare what to send
        protocol_msg = protocol_pb2.Message()
        protocol_msg.type = protocol_pb2.Message.ERROR
        protocol_msg.error.type = protocol_pb2.Error.INTERNAL_ERROR
        err = errors.InternalError("request", protocol_msg)

        self.command._run = lambda: defer.fail(err)
        self.command.run()
        self.assertEqual(self.command.log.logged, "exception")

    def test_suppressed_yes_cancelled(self):
        """Check that the log is in warning for Cancelled."""
        err = errors.RequestCancelledError("CANCELLED")
        self.command._run = lambda: defer.fail(err)
        self.command.run()
        self.assertEqual(self.command.log.logged, "warn")

    def test_suppressed_yes_and_retry_when_connectiondone(self):
        """Check that the log is in warning and retries for ConnectionDone."""
        self.handle_success = self.deferred.callback(True)
        err = twisted_error.ConnectionDone()
        runs = [defer.fail(err), defer.succeed(True)]
        self.command._run = lambda: runs.pop(0)
        self.command.run()
        self.assertEqual(self.command.log.logged, "warn")
        return self.deferred

    def test_retry_connectionlost(self):
        """Check that it retries when ConnectionLost."""
        self.handle_success = self.deferred.callback(True)
        err = twisted_error.ConnectionLost()
        runs = [defer.fail(err), defer.succeed(True)]
        self.command._run = lambda: runs.pop(0)
        self.command.run()
        return self.deferred

    def test_retry_tryagain(self):
        """Check that it retries when TryAgain."""
        self.handle_success = self.deferred.callback(True)
        protocol_msg = protocol_pb2.Message()
        protocol_msg.type = protocol_pb2.Message.ERROR
        protocol_msg.error.type = protocol_pb2.Error.TRY_AGAIN
        err = errors.TryAgainError("request", protocol_msg)
        runs = [defer.fail(err), defer.succeed(True)]
        self.command._run = lambda: runs.pop(0)
        self.command.run()
        return self.deferred


class ListSharesTestCase(ConnectedBaseTestCase):
    """Test for ListShares ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(ListSharesTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_queued_mixed_types(self):
        """Command gets queued if other command is waiting."""
        cmd1 = FakeCommand()
        self.rq.queue(cmd1)
        cmd2 = ListShares(self.rq)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two(self):
        """Two queued commands is not ok."""
        cmd1 = ListShares(self.rq)
        self.rq.queue(cmd1)
        cmd2 = ListShares(self.rq)
        self.assertFalse(cmd2._should_be_queued())

    def test_uniqueness(self):
        """Info used for uniqueness."""
        cmd = ListShares(self.rq)
        self.assertEqual(cmd.uniqueness, 'ListShares')


class ListVolumesTestCase(ConnectedBaseTestCase):
    """Test for ListVolumes ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(ListVolumesTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)
        self.command = ListVolumes(self.rq)

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        self.assertTrue(isinstance(self.command, ActionQueueCommand))

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        res = self.command._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's list_volumes is called."""
        original = self.command.action_queue.client.list_volumes
        self.called = False

        def check():
            """Take control over client's feature."""
            self.called = True

        self.command.action_queue.client.list_volumes = check

        self.command._run()

        self.assertTrue(self.called, 'command was called')

        self.command.action_queue.client.list_volumes = original

    def test_handle_success_push_event(self):
        """Test AQ_LIST_VOLUMES is pushed on success."""
        request = client.ListVolumes(self.action_queue.client)
        request.volumes = [FakedVolume(), FakedVolume()]
        self.command.handle_success(success=request)
        event = ('AQ_LIST_VOLUMES', {'volumes': request.volumes})
        self.assertIn(event, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_LIST_VOLUMES_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        event = ('AQ_LIST_VOLUMES_ERROR', {'error': msg})
        self.assertIn(event, self.command.action_queue.event_queue.events)

    def test_queued_mixed_types(self):
        """Command gets queued if other command is waiting."""
        cmd1 = FakeCommand()
        self.rq.queue(cmd1)
        cmd2 = ListVolumes(self.rq)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two(self):
        """Two queued commands is not ok."""
        cmd1 = ListVolumes(self.rq)
        self.rq.queue(cmd1)
        cmd2 = ListVolumes(self.rq)
        self.assertFalse(cmd2._should_be_queued())

    def test_uniqueness(self):
        """Info used for uniqueness."""
        cmd = ListVolumes(self.rq)
        self.assertEqual(cmd.uniqueness, 'ListVolumes')


class DeleteVolumeTestCase(ConnectedBaseTestCase):
    """Test for DeleteVolume ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(DeleteVolumeTestCase, self).setUp()

        request_queue = RequestQueue(action_queue=self.action_queue)
        self.command = DeleteVolume(request_queue, VOLUME, PATH)

        # silence the event to avoid propagation
        listener_map = self.action_queue.event_queue.listener_map
        del listener_map['AQ_DELETE_VOLUME_OK']
        del listener_map['AQ_DELETE_VOLUME_ERROR']

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        self.assertTrue(isinstance(self.command, ActionQueueCommand))

    def test_init(self):
        """Test creation."""
        self.assertEqual(VOLUME, self.command.volume_id)

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        res = self.command._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's delete_volume is called."""
        original = self.command.action_queue.client.delete_volume
        self.called = False

        def check(volume_id):
            """Take control over client's feature."""
            self.called = True
            self.assertEqual(VOLUME, volume_id)

        self.command.action_queue.client.delete_volume = check

        self.command._run()

        self.assertTrue(self.called, 'command was called')

        self.command.action_queue.client.delete_volume = original

    def test_handle_success_push_event(self):
        """Test AQ_DELETE_VOLUME_OK is pushed on success."""
        request = client.DeleteVolume(self.action_queue.client,
                                      volume_id=VOLUME)
        self.command.handle_success(success=request)
        events = [('AQ_DELETE_VOLUME_OK', {'volume_id': VOLUME})]
        self.assertEqual(events, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_DELETE_VOLUME_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        event = ('AQ_DELETE_VOLUME_ERROR', {'volume_id': VOLUME, 'error': msg})
        self.assertTrue(event in self.command.action_queue.event_queue.events)

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        self.command._acquire_pathlock()
        self.assertEqual(t, [tuple(PATH.split(os.path.sep)), {'logger': None}])


class FilterEventsTestCase(BasicTestCase):
    """Tests for event filtering when a volume is not of our interest."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(FilterEventsTestCase, self).setUp()
        self.vm = self.main.vm


class ChangePublicAccessTests(ConnectedBaseTestCase):
    """Tests for the ChangePublicAccess ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(ChangePublicAccessTests, self).setUp()
        self.rq = request_queue = RequestQueue(action_queue=self.action_queue)
        self.command = ChangePublicAccess(request_queue, VOLUME, NODE, True)

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        res = self.command._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's list_public_files is called."""
        self.called = False

        def check(volume_id, node_id, is_public):
            """Take control over client's feature."""
            self.assertEqual(volume_id, VOLUME)
            self.assertEqual(node_id, NODE)
            self.assertEqual(is_public, True)
            self.called = True
        self.patch(
            self.command.action_queue.client, 'change_public_access', check)
        self.command._run()
        self.assertTrue(self.called, "command wasn't called")

    def test_change_public_access(self):
        """Test the change_public_access method.."""
        self.action_queue.change_public_access(VOLUME, NODE, True)

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        self.assertTrue(isinstance(self.command, ActionQueueCommand))

    def test_init(self):
        """Test creation."""
        self.assertEqual(VOLUME, self.command.share_id)
        self.assertEqual(NODE, self.command.node_id)
        self.assertEqual(True, self.command.is_public)

    def test_handle_success_push_event(self):
        """Test AQ_CHANGE_PUBLIC_ACCESS_OK is pushed on success."""
        request = client.ChangePublicAccess(self.action_queue.client,
                                            VOLUME, NODE, True)
        request.public_url = 'http://example.com'

        self.command.handle_success(request)
        event = ('AQ_CHANGE_PUBLIC_ACCESS_OK',
                 {'share_id': VOLUME, 'node_id': NODE, 'is_public': True,
                  'public_url': 'http://example.com'})
        self.assertIn(event, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_CHANGE_PUBLIC_ACCESS_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        event = ('AQ_CHANGE_PUBLIC_ACCESS_ERROR',
                 {'share_id': VOLUME, 'node_id': NODE, 'error': msg})
        self.assertIn(event, self.command.action_queue.event_queue.events)

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        res = [getattr(self.command, x) for x in self.command.possible_markers]
        self.assertEqual(res, [NODE])


class GetPublicFilesTestCase(ConnectedBaseTestCase):
    """Tests for GetPublicFiles ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(GetPublicFilesTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)
        self.command = GetPublicFiles(self.rq)

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        res = self.command._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's list_public_files is called."""
        self.called = False

        def check():
            """Take control over client's feature."""
            self.called = True
        self.patch(
            self.command.action_queue.client, 'list_public_files', check)
        self.command._run()
        self.assertTrue(self.called, "command wasn't called")

    def test_get_public_files(self):
        """Test the get_public_files method.."""
        self.action_queue.get_public_files()

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        self.assertTrue(isinstance(self.command, ActionQueueCommand))

    def test_handle_success_push_event(self):
        """Test AQ_PUBLIC_FILES_LIST_OK is pushed on success."""
        request = client.ListPublicFiles(self.action_queue.client)
        response = [{'node_id': uuid.uuid4(), 'volume_id': None,
                    'public_url': 'http://example.com'}]
        request.public_files = response
        self.command.handle_success(request)
        event = ('AQ_PUBLIC_FILES_LIST_OK', {'public_files': response})
        self.assertIn(event, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_PUBLIC_FILES_LIST_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        event = ('AQ_PUBLIC_FILES_LIST_ERROR', {'error': msg})
        self.assertIn(event, self.command.action_queue.event_queue.events)

    def test_queued_mixed_types(self):
        """Command gets queued if other command is waiting."""
        cmd1 = FakeCommand()
        self.rq.queue(cmd1)
        cmd2 = GetPublicFiles(self.rq)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two(self):
        """Two queued commands is not ok."""
        cmd1 = GetPublicFiles(self.rq)
        self.rq.queue(cmd1)
        cmd2 = GetPublicFiles(self.rq)
        self.assertFalse(cmd2._should_be_queued())

    def test_uniqueness(self):
        """Info used for uniqueness."""
        cmd = GetPublicFiles(self.rq)
        self.assertEqual(cmd.uniqueness, 'GetPublicFiles')


class DownloadUnconnectedTestCase(FactoryBaseTestCase):
    """Test for Download ActionQueueCommand, no connection"""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(DownloadUnconnectedTestCase, self).setUp()

        self.rq = request_queue = RequestQueue(action_queue=self.action_queue)
        self.test_path = os.path.join(self.root, 'file')
        self.mdid = self.main.fs.create(self.test_path, '')
        self.command = Download(request_queue, share_id='a_share_id',
                                node_id='a_node_id', server_hash='server_hash',
                                mdid=self.mdid)
        self.command.make_logger()

    def test_progress_information_setup(self):
        """Test the setting up of the progress information in ._run()."""
        self.patch(self.main.fs, 'get_partial_for_writing',
                   lambda n, s: StringIO())

        self.command.action_queue.connect_in_progress = False
        self.command.action_queue.client = FakeClient()
        self.command._run()
        self.assertEqual(self.command.n_bytes_read_last, 0)

        self.command.n_bytes_read = 20
        self.command._run()
        self.assertEqual(len(self.action_queue.client.called), 2)
        meth, args, kwargs = self.action_queue.client.called[1]
        self.assertEqual(meth, 'get_content_request')
        self.assertEqual(kwargs['offset'], 0)  # resumable is not there yet

    def test_has_path(self):
        """All Downloads must have a path."""
        expected = os.path.join('test_has_path', 'root', 'file')
        self.assertIn(expected, self.command.path)


class DownloadTestCase(ConnectedBaseTestCase):
    """Test for Download ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(DownloadTestCase, self).setUp()

        self.rq = RequestQueue(action_queue=self.action_queue)
        self.rq.transfers_semaphore = FakeSemaphore()
        self.test_path = os.path.join(self.root, 'file')
        self.mdid = self.main.fs.create(self.test_path, '')

        class MyDownload(Download):
            """Just to allow monkeypatching."""

            def sync(s):
                return None

        self.command = MyDownload(self.rq, share_id='a_share_id',
                                  node_id='a_node_id',
                                  server_hash='server_hash', mdid=self.mdid)
        self.command.make_logger()
        self.rq.waiting.append(self.command)

    def test_AQ_DOWNLOAD_FILE_PROGRESS_is_valid_event(self):
        """AQ_DOWNLOAD_FILE_PROGRESS is a valid event."""
        event = 'AQ_DOWNLOAD_FILE_PROGRESS'
        self.assertTrue(event in EVENTS)
        self.assertEqual(('share_id', 'node_id', 'n_bytes_read',
                          'deflated_size'), EVENTS[event])

    def test_progress(self):
        """Test the progress machinery."""
        # would first get the node attribute including this
        class FakeDecompressor(object):
            """Fake decompressor."""

            def decompress(self, data):
                """Nothing!"""
                return ""

        self.command.fileobj = StringIO()
        self.command._run()
        self.command.gunzip = FakeDecompressor()
        self.assertEqual(self.command.n_bytes_read, 0)
        self.assertEqual(self.command.n_bytes_read_last, 0)
        self.command.node_attr_cb(
            deflated_size=TRANSFER_PROGRESS_THRESHOLD * 2)

        self.command.downloaded_cb('x' * 5)
        events = self.command.action_queue.event_queue.events
        self.assertFalse('AQ_DOWNLOAD_FILE_PROGRESS' in [x[0] for x in events])
        self.assertEqual(self.command.n_bytes_read, 5)
        self.assertEqual(self.command.n_bytes_read_last, 0)

        self.command.downloaded_cb('x' * (TRANSFER_PROGRESS_THRESHOLD - 10))
        self.assertFalse('AQ_DOWNLOAD_FILE_PROGRESS' in [x[0] for x in events])
        self.assertEqual(self.command.n_bytes_read,
                         TRANSFER_PROGRESS_THRESHOLD - 5)
        self.assertEqual(self.command.n_bytes_read_last, 0)

        self.command.downloaded_cb('x' * 10)
        kwargs = {'share_id': 'a_share_id', 'node_id': 'a_node_id',
                  'deflated_size': TRANSFER_PROGRESS_THRESHOLD * 2,
                  'n_bytes_read': TRANSFER_PROGRESS_THRESHOLD + 5}
        expected = ('AQ_DOWNLOAD_FILE_PROGRESS', kwargs)
        self.assertTrue(expected in events)
        self.assertEqual(self.command.n_bytes_read,
                         TRANSFER_PROGRESS_THRESHOLD + 5)
        self.assertEqual(self.command.n_bytes_read_last,
                         self.command.n_bytes_read)

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        res = [getattr(self.command, x) for x in self.command.possible_markers]
        self.assertEqual(res, ['a_node_id'])

    def test_cancel_set_cancelled(self):
        """Set the command to cancelled."""
        assert not self.command.cancelled, "test badly set up"
        did_cancel = self.command.cancel()
        self.assertTrue(did_cancel)
        self.assertTrue(self.command.cancelled)

    def test_cancel_download_req_is_none(self):
        """It's ok to have download_req in None when cancelling."""
        assert self.command.download_req is None, "test badly set up"
        did_cancel = self.command.cancel()
        self.assertTrue(did_cancel)

    def test_cancel_download_req_is_something(self):
        """download_req is also cancelled."""
        # set up the mocker
        mocker = Mocker()
        obj = mocker.mock()
        obj.cancel()

        # test
        with mocker:
            self.command.download_req = obj
            self.command.cancel()

    def test_cancel_clean_up(self):
        """Clean up."""
        called = []
        self.command.cleanup = lambda: called.append(True)
        self.command.cancel()
        self.assertTrue(called)

    def test_uniqueness(self):
        """Info used for uniqueness."""
        u = self.command.uniqueness
        self.assertEqual(u, ('MyDownload', 'a_share_id', 'a_node_id'))

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        self.command._acquire_pathlock()
        should = [tuple(self.test_path.split(os.path.sep)),
                  {'logger': self.command.log}]
        self.assertEqual(t, should)

    def test_upload_download_uniqueness(self):
        """There should be only one upload/download for a specific node."""
        # totally fake, we don't care: the messages are only validated on run
        self.action_queue.download('foo', 'bar', 0, self.mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.upload('foo', 'bar', 0, 0, 0, 0, self.mdid)
        self.assertTrue(first_cmd.cancelled)

    def test_uniqueness_upload(self):
        """There should be only one upload/download for a specific node."""
        # totally fake, we don't care: the messages are only validated on run
        self.patch(Upload, 'run', lambda self: defer.Deferred())
        self.action_queue.upload('foo', 'bar', 0, 0, 0, 0, self.mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.download('foo', 'bar', 0, self.mdid)
        self.assertTrue(first_cmd.cancelled)
        self.assertTrue(self.handler.check_debug("Previous command cancelled",
                                                 "Upload", "foo", "bar"))

    def test_uniqueness_download(self):
        """There should be only one upload/download for a specific node."""
        # totally fake, we don't care: the messages are only validated on run
        self.action_queue.download('foo', 'bar', 0, self.mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.download('foo', 'bar', 1, self.mdid)
        self.assertTrue(first_cmd.cancelled)
        self.assertTrue(self.handler.check_debug("Previous command cancelled",
                                                 "Download", "foo", "bar"))

    def test_uniqueness_even_with_markers(self):
        """Only one upload/download per node, even using markers."""
        mdid = self.main.fs.create(os.path.join(self.root, 'file2'), '')
        m = MDMarker(mdid)
        self.action_queue.download('share', m, 0, mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.uuid_map.set(mdid, 'bah')
        self.action_queue.download('share', 'bah', 0, self.mdid)
        self.assertTrue(first_cmd.cancelled)

    def test_uniqueness_tried_to_cancel_but_no(self):
        """Previous command didn't cancel even if we tried it."""
        # the first command will refuse to cancel (patch the class because
        # the instance is not patchable)
        self.action_queue.download('foo', 'bar', 0, self.mdid)
        self.action_queue.queue.waiting[0]
        self.patch(Download, 'cancel', lambda instance: False)

        self.action_queue.download('foo', 'bar', 1, self.mdid)
        self.assertEqual(len(self.action_queue.queue.waiting), 2)
        self.assertTrue(self.handler.check_debug("Tried to cancel", "couldn't",
                                                 "Download", "foo", "bar"))

    def test_start_locks_on_semaphore(self):
        """_start acquire the semaphore and locks."""
        lock = defer.Deferred()
        self.rq.transfers_semaphore.acquire = lambda: lock

        # _start and check it locked
        started = self.command._start()
        self.assertFalse(started.called)

        # release the lock and check it finished
        o = object()
        lock.callback(o)
        self.assertTrue(started.called)
        self.assertTrue(self.handler.check_debug('semaphore acquired'))
        self.assertIdentical(o, self.command.tx_semaphore)

    def test_start_releases_semaphore_if_cancelled(self):
        """Release the semaphore if cancelled while locking."""
        lock = defer.Deferred()
        self.rq.transfers_semaphore.acquire = lambda: lock

        # call start and cancel the command
        self.command._start()
        self.command.cancelled = True

        # release the lock
        mocker = Mocker()
        req = mocker.mock()
        req.release()
        with mocker:
            lock.callback(req)

        # check it released the semaphore
        self.assertTrue(self.handler.check_debug('semaphore released',
                                                 'cancelled'))
        self.assertIdentical(self.command.tx_semaphore, None)

    def test_finish_releases_semaphore_if_acquired(self):
        """Test semaphore is released on finish if it was acquired."""
        s = FakeSemaphore()
        s.count = 1
        self.command.tx_semaphore = s

        # finish and check
        self.command.finish()
        self.assertEqual(s.count, 0)
        self.assertTrue(self.handler.check_debug('semaphore released'))

    def test_finish_releases_semaphore_not_there(self):
        """Test semaphore is not released on finish if it was not acquired.

        This tests the situation where the command is finished before the lock
        was acquired (cancelled even before its _start).
        """
        assert self.command.tx_semaphore is None
        self.command.finish()

    def test_decompressor_restarted(self):
        """Restart the decompressor on each _run (because of retries!)."""
        # don't use the real protocol
        obj = Mocker().mock()
        obj.deferred
        self.action_queue.client.get_content_request = lambda *a, **k: obj

        self.patch(self.main.fs, 'get_partial_for_writing',
                   lambda n, s: StringIO())
        self.command._run()
        decompressor1 = self.command.gunzip
        self.command._run()
        decompressor2 = self.command.gunzip
        self.assertNotIdentical(decompressor1, decompressor2)

    def test_fileobj_in_run(self):
        """Create it first time, reset after that."""
        # don't use the real protocol
        self.action_queue.client.get_content_request = FakeRequest

        class FakeFileObj(object):
            """Fake class to check behaviour."""
            def __init__(self):
                self.seek_count = 0
                self.truncate_count = 0

            def seek(self, a, b):
                """Fake seek."""
                self.seek_count += 1

            def truncate(self, a):
                """Fake truncate."""
                self.truncate_count += 1

        self.patch(self.main.fs, 'get_partial_for_writing',
                   lambda n, s: FakeFileObj())
        test_path = os.path.join(self.root, 'foo', 'bar')
        mdid = self.main.fs.create(test_path, '')
        cmd = Download(self.rq, 'a_share_id', 'a_node_id', 'server_hash',
                       mdid)

        # first run, it is just instantiated
        cmd._run()
        self.assertTrue(isinstance(cmd.fileobj, FakeFileObj))
        self.assertEqual(cmd.fileobj.seek_count, 0)
        self.assertEqual(cmd.fileobj.truncate_count, 0)

        # next times it is reset
        cmd._run()
        self.assertEqual(cmd.fileobj.seek_count, 1)
        self.assertEqual(cmd.fileobj.truncate_count, 1)

        cmd._run()
        self.assertEqual(cmd.fileobj.seek_count, 2)
        self.assertEqual(cmd.fileobj.truncate_count, 2)

    def test_has_path(self):
        """All Downloads must have a path."""
        expected = os.path.join('test_has_path', 'root', 'file')
        self.assertIn(expected, self.command.path)

    def test_to_dict_info(self):
        """Some info should be in to_dict."""
        info = self.command.to_dict()
        self.assertEqual(info['path'], self.test_path)


class UploadUnconnectedTestCase(FactoryBaseTestCase):
    """Test for Upload ActionQueueCommand, no connection"""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(UploadUnconnectedTestCase, self).setUp()
        self.test_path = os.path.join(self.root, 'file')
        self.mdid = self.main.fs.create(self.test_path, '')

        self.rq = request_queue = RequestQueue(action_queue=self.action_queue)
        self.command = Upload(request_queue, share_id='a_share_id',
                              node_id='a_node_id', previous_hash='prev_hash',
                              hash='yadda', crc32=0, size=0, mdid=self.mdid)
        self.command.make_logger()
        self.command.magic_hash = FakeMagicHash()
        self.client = FakeClient()
        self.command.action_queue.client = self.client

    def test_upload_progress_wrapper_setup(self):
        """Test the setting up of the progress wrapper in ._run()."""
        self.command.action_queue.connect_in_progress = False
        self.command.tempfile = StringIO()
        self.command._run()

        self.assertEqual(len(self.client.called), 1)
        meth, args, kwargs = self.client.called[0]
        self.assertEqual(meth, 'put_content_request')
        upload_wrapper = args[7]
        self.assertEqual(upload_wrapper.command, self.command)

    @defer.inlineCallbacks
    def test_client_request(self):
        """Request the corrent operation on the client."""

        data = "content to be sent in the upload"
        self.command.tempfile = StringIO(data)
        self.command.deflated_size = 123
        yield self.command._run()

        self.assertEqual(len(self.client.called), 1)
        meth, args, kwargs = self.client.called[0]
        self.assertEqual(meth, 'put_content_request')
        self.assertEqual(args[0], 'a_share_id')
        self.assertEqual(args[1], 'a_node_id')
        self.assertEqual(args[2], 'prev_hash')
        self.assertEqual(args[3], 'yadda')
        self.assertEqual(args[4], 0)
        self.assertEqual(args[5], 0)
        self.assertEqual(args[6], 123)
        self.assertTrue(isinstance(args[7], UploadProgressWrapper))
        self.assertEqual(kwargs['magic_hash'], '666')

    def test_has_path(self):
        """All Uploads must have a path."""
        expected = os.path.join('test_has_path', 'root', 'file')
        self.assertIn(expected, self.command.path)


class UploadProgressWrapperTestCase(BaseTwistedTestCase):
    """Test for the UploadProgressWrapper helper class."""

    def test_reset(self):
        """Reset the values at start."""
        f = StringIO("x" * 10 + "y" * 5)
        cmd = FakeCommand()

        # first time
        UploadProgressWrapper(f, cmd)
        self.assertEqual(cmd.n_bytes_written, 0)
        self.assertEqual(cmd.n_bytes_written_last, 0)

        # fake as it worked a little, was interrupted, and tried again
        cmd.n_bytes_written_last = 1234
        cmd.n_bytes_written = 1248
        UploadProgressWrapper(f, cmd)
        self.assertEqual(cmd.n_bytes_written, 0)
        self.assertEqual(cmd.n_bytes_written_last, 0)

    def test_read(self):
        """Test the read method."""
        class FakeCommand(object):
            """Fake command."""

            def __init__(self):
                self.n_bytes_written = 0
                self._progress_hook_called = 0

            def progress_hook(innerself):
                """Count how many times it was called."""
                innerself._progress_hook_called += 1

        f = StringIO("x" * 10 + "y" * 5)
        cmd = FakeCommand()
        upw = UploadProgressWrapper(f, cmd)

        res = upw.read(10)
        self.assertEqual(res, "x" * 10)
        self.assertEqual(cmd.n_bytes_written, 10)
        self.assertEqual(cmd._progress_hook_called, 1)

        res = upw.read(10)
        self.assertEqual(res, "y" * 5)
        self.assertEqual(cmd.n_bytes_written, 15)
        self.assertEqual(cmd._progress_hook_called, 2)

    def test_seek(self):
        """Test the seek method."""
        class FakeCommand(object):
            """Fake command."""

            def __init__(self):
                self.n_bytes_written = 0
                self.n_bytes_written_last = 0
                self._progress_hook_called = 0

            def progress_hook(innerself):
                """Count how many times it was called."""
                innerself._progress_hook_called += 1

        f = StringIO("v" * 10 + "w" * 10 + "x" * 5 + "y" * 5)
        cmd = FakeCommand()
        upw = UploadProgressWrapper(f, cmd)

        upw.seek(10)
        self.assertEqual(cmd.n_bytes_written, 10)
        self.assertEqual(cmd._progress_hook_called, 0)
        res = upw.read(10)
        self.assertEqual(res, "w" * 10)
        self.assertEqual(cmd.n_bytes_written, 20)
        self.assertEqual(cmd._progress_hook_called, 1)

        upw.seek(25)
        self.assertEqual(cmd.n_bytes_written, 25)
        self.assertEqual(cmd._progress_hook_called, 1)
        res = upw.read(10)
        self.assertEqual(res, "y" * 5)
        self.assertEqual(cmd.n_bytes_written, 30)
        self.assertEqual(cmd._progress_hook_called, 2)


class UploadTestCase(ConnectedBaseTestCase):
    """Test for Upload ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(UploadTestCase, self).setUp()

        self.rq = RequestQueue(action_queue=self.action_queue)
        self.rq.transfers_semaphore = FakeSemaphore()
        self.rq.unqueue = lambda c: None
        self.rq.active = True
        self.test_path = os.path.join(self.root, 'foo', 'bar')
        self.mdid = self.main.fs.create(self.test_path, '')

        class MyUpload(Upload):
            """Just to allow monkeypatching."""

        self.share_id = str(uuid.uuid4())
        self.command = MyUpload(self.rq, share_id=self.share_id,
                                node_id='a_node_id', previous_hash='prev_hash',
                                hash='yadda', crc32=0, size=0, mdid=self.mdid)
        self.command.make_logger()

    @defer.inlineCallbacks
    def test_upload_in_progress(self):
        """Test Upload retries on UploadInProgress."""
        # prepare the failure
        protocol_msg = protocol_pb2.Message()
        protocol_msg.type = protocol_pb2.Message.ERROR
        protocol_msg.error.type = protocol_pb2.Error.UPLOAD_IN_PROGRESS
        err = errors.UploadInProgressError("request", protocol_msg)

        # mock fsm
        mocker = Mocker()
        mdobj = mocker.mock()
        expect(mdobj.share_id).result('share_id')
        expect(mdobj.path).result('path')
        fsm = mocker.mock()
        expect(fsm.get_by_mdid(self.mdid)).result(mdobj)
        expect(fsm.get_abspath('share_id', 'path')).result('/abs/path')
        expect(fsm.open_file(self.mdid)).result(StringIO())
        self.patch(self.main, 'fs', fsm)

        # first fails with UploadInProgress, then finishes ok
        called = []
        run_deferreds = [defer.fail(err), defer.succeed(True)]
        self.command._run = lambda: called.append(':)') or run_deferreds.pop(0)

        # wait handle_success
        d = defer.Deferred()
        self.command.handle_success = lambda _: d.callback(True)

        # go and check
        with mocker:
            self.command.go()
        yield d
        self.assertEqual(called, [':)', ':)'])

    def test_handle_success_push_event(self):
        """Test AQ_UPLOAD_FINISHED is pushed on success."""
        # create a request and fill it with succesful information
        aq_client = TestingProtocol()
        request = client.PutContent(aq_client, VOLUME, 'node',
                                    'prvhash', 'newhash', 'crc32', 'size',
                                    'deflated', 'fd')
        request.new_generation = 13
        self.command.tempfile = FakeTempFile(self.tmpdir)

        # trigger success in the command
        self.command.handle_success(request)

        # check for successful event
        kwargs = dict(share_id=self.command.share_id, node_id='a_node_id',
                      hash='yadda', new_generation=13)
        events = [('AQ_UPLOAD_FINISHED', kwargs)]
        self.assertEqual(events, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_UPLOAD_ERROR is pushed on failure."""
        self.command.tempfile = FakeTempFile(self.tmpdir)
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        kwargs = dict(share_id=self.command.share_id, node_id='a_node_id',
                      hash='yadda', error=msg)
        events = [('AQ_UPLOAD_ERROR', kwargs)]
        self.assertEqual(events, self.command.action_queue.event_queue.events)

    def test_finish_closes_temp_file(self):
        """Test temp file is closed when the command finishes."""
        self.command.tempfile = FakeTempFile(self.tmpdir)
        assert self.command.tempfile.closed == 0

        self.command.finish()
        self.assertEqual(1, self.command.tempfile.closed)

    def test_finish_removes_temp_file(self):
        """Test temp file is removed when the command finishes."""
        self.command.tempfile = FakeTempFile(self.tmpdir)
        assert path_exists(self.command.tempfile.name)

        self.command.finish()
        self.assertFalse(path_exists(self.command.tempfile.name))

    def test_finish_handles_temp_file_none(self):
        """Test temp file can be None when calling finish."""
        self.command.tempfile = None

        self.command.finish()
        self.assertEqual(self.command.tempfile, None)  # nothing changed

    def test_retryable_failure_push_quota_exceeded_if_that_error(self):
        """Test SYS_QUOTA_EXCEEDED is pushed on QuotaExceededError."""
        protocol_msg = protocol_pb2.Message()
        protocol_msg.type = protocol_pb2.Message.ERROR
        protocol_msg.error.type = protocol_pb2.Error.QUOTA_EXCEEDED
        protocol_msg.free_space_info.share_id = self.command.share_id
        protocol_msg.free_space_info.free_bytes = 1331564676
        error = errors.QuotaExceededError("request", protocol_msg)
        failure = Failure(error)

        self.command.handle_retryable(failure)
        event = ('SYS_QUOTA_EXCEEDED', {'volume_id': self.command.share_id,
                                        'free_bytes': 1331564676})
        self.assertTrue(event in self.command.action_queue.event_queue.events)

    def test_retryable_failure_nothing_on_other_errors(self):
        """Test nothing is pushed on other errors."""
        failure = Failure(twisted_error.ConnectionLost())
        self.command.handle_retryable(failure)
        event_names = [x[0]
                       for x in self.command.action_queue.event_queue.events]
        self.assertFalse('SYS_QUOTA_EXCEEDED' in event_names)

    def test_AQ_UPLOAD_FILE_PROGRESS_is_valid_event(self):
        """AQ_UPLOAD_FILE_PROGRESS is a valid event."""
        event = 'AQ_UPLOAD_FILE_PROGRESS'
        self.assertTrue(event in EVENTS)
        self.assertEqual(('share_id', 'node_id', 'n_bytes_written',
                          'deflated_size'), EVENTS[event])

    def test_progress_hook(self):
        """Test the progress hook."""
        self.command.deflated_size = 2*TRANSFER_PROGRESS_THRESHOLD
        self.command.n_bytes_written_last = 0

        self.command.n_bytes_written = 5
        self.command.progress_hook()
        self.assertEqual([], self.command.action_queue.event_queue.events)
        self.assertEqual(self.command.n_bytes_written_last, 0)

        self.command.n_bytes_written = TRANSFER_PROGRESS_THRESHOLD - 5
        self.command.progress_hook()
        self.assertEqual([], self.command.action_queue.event_queue.events)
        self.assertEqual(self.command.n_bytes_written_last, 0)

        self.command.n_bytes_written = TRANSFER_PROGRESS_THRESHOLD + 5
        self.command.progress_hook()
        kwargs = {'share_id': self.command.share_id, 'node_id': 'a_node_id',
                  'deflated_size': 2*TRANSFER_PROGRESS_THRESHOLD,
                  'n_bytes_written': 5+TRANSFER_PROGRESS_THRESHOLD}
        events = [('AQ_UPLOAD_FILE_PROGRESS', kwargs)]
        self.assertEqual(events, self.command.action_queue.event_queue.events)
        self.assertEqual(self.command.n_bytes_written_last,
                         TRANSFER_PROGRESS_THRESHOLD + 5)

    def test_runnable_space_ok(self):
        """The upload is runnable if space ok."""
        self.action_queue.have_sufficient_space_for_upload = lambda *a: True
        self.assertTrue(self.command.is_runnable)

    def test_runnable_space_bad(self):
        """The upload is not runnable without free space."""
        self.action_queue.have_sufficient_space_for_upload = lambda *a: False
        self.assertFalse(self.command.is_runnable)

    def test_runnable_space_bad_cancelled(self):
        """The upload is runnable if cancelled even with no free space."""
        self.action_queue.have_sufficient_space_for_upload = lambda *a: False
        self.command.cancelled = True
        self.assertTrue(self.command.is_runnable)

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        res = [getattr(self.command, x) for x in self.command.possible_markers]
        self.assertEqual(res, ['a_node_id'])

    def test_cancel_set_cancelled(self):
        """Set the command to cancelled."""
        assert not self.command.cancelled, "test badly set up"
        self.command.cancel()
        self.assertTrue(self.command.cancelled)

    def test_cancel_upload_req_is_none(self):
        """It's ok to have upload_req in None when cancelling."""
        assert self.command.upload_req is None, "test badly set up"
        did_cancel = self.command.cancel()
        self.assertTrue(did_cancel)

    def test_cancel_abort_when_producer_finished(self):
        """If the producer already finished, don't really cancel."""
        called = []
        self.patch(ActionQueueCommand, 'cancel', lambda s: called.append(1))

        class FakeProducer(object):
            """Fake producer."""
            finished = True

        fake_request = FakeRequest()
        fake_request.producer = FakeProducer()
        self.command.upload_req = fake_request

        did_cancel = self.command.cancel()
        self.assertFalse(did_cancel)
        self.assertFalse(called)
        self.assertFalse(fake_request.cancelled)

    def test_cancel_cancels_when_producer_not_finished(self):
        """If the producer didn't finished, really cancel."""
        called = []
        self.patch(ActionQueueCommand, 'cancel',
                   lambda s: called.append(True) or True)

        class FakeProducer(object):
            """Fake producer."""
            finished = False

        fake_request = FakeRequest()
        fake_request.producer = FakeProducer()
        self.command.upload_req = fake_request

        did_cancel = self.command.cancel()
        self.assertTrue(did_cancel)
        self.assertTrue(called)
        self.assertTrue(fake_request.cancelled)

    def test_cancel_upload_req_is_something(self):
        """upload_req is also cancelled."""
        # set up the mocker
        mocker = Mocker()
        obj = mocker.mock()
        obj.cancel()
        obj.producer
        obj.producer

        # test
        with mocker:
            self.command.upload_req = obj
            self.command.cancel()

    def test_cancel_remove(self):
        """Remove the command from the queue."""
        # set up the mocker
        mocker = Mocker()
        obj = mocker.mock()

        # test
        with mocker:
            self.command._queue = obj
            self.command.cancel()

    def test_cancel_clean_up(self):
        """Clean up."""
        called = []
        self.command.cleanup = lambda: called.append(True)
        self.command.cancel()
        self.assertTrue(called)

    def test_uniqueness(self):
        """Info used for uniqueness."""
        u = self.command.uniqueness
        self.assertEqual(u, ('MyUpload', self.share_id, 'a_node_id'))

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        self.command._acquire_pathlock()
        should = [tuple(self.test_path.split(os.path.sep)),
                  {'logger': self.command.log}]
        self.assertEqual(t, should)

    def test_uniqueness_upload(self):
        """There should be only one upload/download for a specific node."""
        # totally fake, we don't care: the messages are only validated on run
        self.patch(Upload, 'run', lambda self: defer.Deferred())
        self.action_queue.upload('foo', 'bar', 0, 0, 0, 0, self.mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.upload('foo', 'bar', 1, 1, 1, 1, self.mdid)
        self.assertTrue(first_cmd.cancelled)
        self.assertTrue(self.handler.check_debug("Previous command cancelled",
                                                 "Upload", "foo", "bar"))

    def test_uniqueness_download(self):
        """There should be only one upload/download for a specific node."""
        # totally fake, we don't care: the messages are only validated on run
        self.action_queue.download('foo', 'bar', 0, self.mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.upload('foo', 'bar', 0, 0, 0, 0, self.mdid)
        self.assertTrue(first_cmd.cancelled)
        self.assertTrue(self.handler.check_debug("Previous command cancelled",
                                                 "Download", "foo", "bar"))

    def test_uniqueness_even_with_markers(self):
        """Only one upload/download per node, even using markers."""
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        m = MDMarker(mdid)
        self.action_queue.download('share', m, 0, self.mdid)
        first_cmd = self.action_queue.queue.waiting[0]
        self.action_queue.uuid_map.set(mdid, 'bah')
        self.action_queue.upload('share', 'bah', 0, 0, 0, 0, self.mdid)
        self.assertTrue(first_cmd.cancelled)

    def test_uniqueness_tried_to_cancel_but_no(self):
        """Previous command didn't cancel even if we tried it."""
        # the first command will refuse to cancel
        self.patch(Upload, 'run', lambda self: defer.Deferred())
        self.action_queue.upload('foo', 'bar', 0, 0, 0, 0, self.mdid, StringIO)
        self.action_queue.queue.waiting[0]
        self.patch(Upload, 'cancel', lambda instance: False)

        self.action_queue.upload('foo', 'bar', 1, 1, 1, 1, self.mdid, StringIO)
        self.assertEqual(len(self.action_queue.queue.waiting), 2)
        self.assertTrue(self.handler.check_debug("Tried to cancel", "couldn't",
                                                 "Upload", "foo", "bar"))

    def test_start_locks_on_semaphore(self):
        """_start acquire the semaphore and locks."""
        lock = defer.Deferred()
        self.rq.transfers_semaphore.acquire = lambda: lock
        self.action_queue.zip_queue.zip = lambda u, f: defer.succeed(True)

        # mock fsm
        mocker = Mocker()
        mdobj = mocker.mock()
        expect(mdobj.mdid).result('mdid')
        fsm = mocker.mock()
        expect(fsm.get_by_node_id(self.command.share_id, self.command.node_id)
               ).result(mdobj)
        expect(fsm.open_file('mdid')).result(StringIO())
        self.patch(self.main, 'fs', fsm)

        # _start and check it locked
        started = self.command._start()
        self.assertFalse(started.called)

        # release the lock and check it finished
        o = object()
        lock.callback(o)
        self.assertTrue(started.called)
        self.assertTrue(self.handler.check_debug('semaphore acquired'))
        self.assertIdentical(o, self.command.tx_semaphore)

    def test_start_releases_semaphore_if_cancelled(self):
        """Release the semaphore if cancelled while locking."""
        lock = defer.Deferred()
        self.rq.transfers_semaphore.acquire = lambda: lock

        # call start and cancel the command
        self.command._start()
        self.command.cancelled = True

        # release the lock
        mocker = Mocker()
        req = mocker.mock()
        req.release()
        with mocker:
            lock.callback(req)

        # check it released the semaphore
        self.assertTrue(self.handler.check_debug('semaphore released',
                                                 'cancelled'))
        self.assertIdentical(self.command.tx_semaphore, None)

    def test_finish_releases_semaphore_if_acquired(self):
        """Test semaphore is released on finish if it was acquired."""
        s = FakeSemaphore()
        s.count = 1
        self.command.tx_semaphore = s

        # finish and check
        self.command.finish()
        self.assertEqual(s.count, 0)
        self.assertTrue(self.handler.check_debug('semaphore released'))

    def test_finish_releases_semaphore_not_there(self):
        """Test semaphore is not released on finish if it was not acquired.

        This tests the situation where the command is finished before the lock
        was acquired (cancelled even before its _start).
        """
        assert self.command.tx_semaphore is None
        self.command.finish()

    def test_handle_upload_id(self):
        """Test the handling of upload_id."""
        # change the share_id of the command
        self.command.share_id = request.ROOT
        # create the node
        path = os.path.join(self.main.root_dir, 'foo')
        self.main.fs.create(path=path, share_id=self.command.share_id,
                            is_dir=False)
        self.main.fs.set_node_id(path, self.command.node_id)
        self.command._upload_id_cb('hola', 1234)
        mdobj = self.main.fs.get_by_node_id(self.command.share_id,
                                            self.command.node_id)
        self.assertEqual('hola', mdobj.upload_id)
        self.assertTrue(self.handler.check_debug(
            'upload_id', 'hola', 'offset', '1234'))

    def test_start_paused_use_upload_id(self):
        """Test that starting a paused command make use of the upload_id."""
        mh = content_hash.magic_hash_factory()
        self.command.magic_hash = mh.content_hash()
        # patch the client to check the args
        self.command.action_queue.client = FakeClient()
        self.command.tempfile = StringIO()
        # change the share_id of the command
        self.command.share_id = request.ROOT
        # create the node
        path = os.path.join(self.main.root_dir, 'foo')
        self.main.fs.create(path=path, share_id=self.command.share_id,
                            is_dir=False)
        self.main.fs.set_node_id(path, self.command.node_id)
        self.action_queue.queue.queue(self.command)
        self.command._run()
        # set the producer attribute
        self.command.upload_req.producer = None
        # upload id is None as this is the first upload
        upload_id = self.command.action_queue.client.called[0][2]['upload_id']
        self.assertEqual(upload_id, None)
        # set the upload id via the callback
        self.command._upload_id_cb('hola', 1234)
        # pause it
        self.command.pause()
        # make it run again
        self.command._run()
        upload_id = self.command.action_queue.client.called[1][2]['upload_id']
        self.assertEqual(upload_id, 'hola')
        self.addCleanup(setattr, self.command.action_queue, 'client', None)

    def test_uses_rb_flags_when_creating_temp_file(self):
        """Check that the 'b' flag is used for the temporary file."""
        tempfile = NamedTemporaryFile()
        self.assertEqual(tempfile.mode, 'w+b')

    def test_fileobj_in_run(self):
        """Create it first time, reset after that."""
        # don't use the real protocol or magic hash
        self.action_queue.client.put_content_request = FakeRequest
        self.command.magic_hash = FakeMagicHash()

        called = []
        self.command.tempfile = StringIO()
        self.command.tempfile.seek = lambda *a: called.extend(a)
        self.command._run()
        self.assertEqual(called, [0])

    def test_has_path(self):
        """All Uploads must have a path."""
        expected = os.path.join('test_has_path', 'root', 'foo', 'bar')
        self.assertIn(expected, self.command.path)

    def test_to_dict_info(self):
        """Some info should be in to_dict."""
        info = self.command.to_dict()
        self.assertEqual(info['path'], self.test_path)


class CreateShareTestCase(ConnectedBaseTestCase):
    """Test for CreateShare ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(CreateShareTestCase, self).setUp()
        self.request_queue = RequestQueue(action_queue=self.action_queue)

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        cmd = CreateShare(self.request_queue, 'node_id', 'shareto@example.com',
                          'share_name', ACCESS_LEVEL_RO, 'marker', 'path')
        res = [getattr(cmd, x) for x in cmd.possible_markers]
        self.assertEqual(res, ['node_id'])

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        cmd = CreateShare(self.request_queue, NODE, 'share_to',
                          'share_name', ACCESS_LEVEL_RO, 'marker_id',
                          os.path.join('foo', 'bar'))
        cmd._acquire_pathlock()
        self.assertEqual(t, [('foo', 'bar'), {'logger': None}])

    def test_handle_failure_push_event(self):
        """Test AQ_CREATE_SHARE_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        cmd = CreateShare(self.request_queue, NODE, 'share_to',
                          'share_name', ACCESS_LEVEL_RO, 'marker_id',
                          os.path.join('foo', 'bar'))
        cmd.handle_failure(failure=failure)
        events = [('AQ_CREATE_SHARE_ERROR',
                  {'marker': 'marker_id', 'error': msg})]
        self.assertEqual(events, cmd.action_queue.event_queue.events)


class DeleteShareTestCase(ConnectedBaseTestCase):
    """Test for DeleteShare ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(DeleteShareTestCase, self).setUp()
        request_queue = RequestQueue(action_queue=self.action_queue)
        self.command = DeleteShare(request_queue, SHARE)

        # silence the event to avoid propagation
        listener_map = self.action_queue.event_queue.listener_map
        del listener_map['AQ_DELETE_SHARE_OK']
        del listener_map['AQ_DELETE_SHARE_ERROR']

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        res = self.command._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's delete_volume is called."""
        self.called = False

        def check(share_id):
            """Take control over client's feature."""
            self.called = True
            self.assertEqual(SHARE, share_id)
        self.patch(self.command.action_queue.client, 'delete_share', check)
        self.command._run()
        self.assertTrue(self.called, "command wasn't called")

    def test_handle_success_push_event(self):
        """Test AQ_DELETE_SHARE_OK is pushed on success."""
        request = client.DeleteShare(self.action_queue.client, SHARE)
        self.command.handle_success(success=request)
        events = [('AQ_DELETE_SHARE_OK', {'share_id': SHARE})]
        self.assertEqual(events, self.command.action_queue.event_queue.events)

    def test_handle_failure_push_event(self):
        """Test AQ_DELETE_SHARE_ERROR is pushed on failure."""
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))
        self.command.handle_failure(failure=failure)
        events = [('AQ_DELETE_SHARE_ERROR',
                  {'share_id': SHARE, 'error': msg})]
        self.assertEqual(events, self.command.action_queue.event_queue.events)


class SimpleAQTestCase(BasicTestCase):
    """Simple tests for AQ API."""

    def test_aq_query_volumes(self):
        """Check the API of AQ.query_volumes."""
        self.main.start()
        d = defer.Deferred()

        def list_volumes():
            """Fake list_volumes."""
            result = DummyClass()
            result.volumes = ['foo', 'bar']
            return defer.succeed(result)

        self.action_queue.client = DummyClass()
        self.action_queue.client.list_volumes = list_volumes
        d = self.action_queue.query_volumes()

        def check(result):
            self.assertIn('foo', result)
            self.assertIn('bar', result)
            return result
        d.addCallback(check)
        return d

    def test_have_sufficient_space_for_upload_if_free_space_is_none(self):
        """Check have_sufficient_space_for_upload.

        If free_space is None, SYS_QUOTA_EXCEEDED is not pushed.

        """
        self.patch(self.action_queue.main.vm, 'get_free_space',
                   lambda share_id: None)  # free space is None
        volume_id = 'test share'
        res = self.action_queue.have_sufficient_space_for_upload(volume_id,
                                                                 upload_size=1)
        self.assertTrue(res, "Must have enough space to upload.")
        events = map(operator.itemgetter(0),
                     self.action_queue.event_queue.events)
        self.assertNotIn('SYS_QUOTA_EXCEEDED', events)

    def test_have_sufficient_space_for_upload_if_no_free_space(self):
        """Check have_sufficient_space_for_upload pushes SYS_QUOTA_EXCEEDED."""
        self.patch(self.action_queue.main.vm, 'get_free_space',
                   lambda share_id: 0)  # no free space, always
        volume_id = 'test share'
        res = self.action_queue.have_sufficient_space_for_upload(volume_id,
                                                                 upload_size=1)
        self.assertEqual(res, False, "Must not have enough space to upload.")
        msg = 'SYS_QUOTA_EXCEEDED must have been pushed to event queue.'
        expected = ('SYS_QUOTA_EXCEEDED',
                    {'volume_id': volume_id, 'free_bytes': 0})
        self.assertTrue(expected in self.action_queue.event_queue.events, msg)

    def test_have_sufficient_space_for_upload_if_free_space(self):
        """Check have_sufficient_space_for_upload doesn't push any event."""
        self.patch(self.action_queue.main.vm, 'get_free_space',
                   lambda share_id: 1)  # free space, always
        res = self.action_queue.have_sufficient_space_for_upload(share_id=None,
                                                                 upload_size=0)
        self.assertEqual(res, True, "Must have enough space to upload.")
        msg = 'No event must have been pushed to event queue.'
        self.assertEqual(self.action_queue.event_queue.events, [], msg)

    def test_SYS_QUOTA_EXCEEDED_is_valid_event(self):
        """SYS_QUOTA_EXCEEDED is a valid event."""
        event = 'SYS_QUOTA_EXCEEDED'
        self.assertTrue(event in EVENTS)
        self.assertEqual(('volume_id', 'free_bytes'), EVENTS[event])

    def test_SYS_USER_CONNECT_is_valid_event(self):
        """SYS_USER_CONNECT is a valid event."""
        event = 'SYS_USER_CONNECT'
        self.assertIn(event, EVENTS)
        self.assertEqual(('access_token',), EVENTS[event])

    def test_handle_SYS_USER_CONNECT(self):
        """handle_SYS_USER_CONNECT stores credentials."""
        self.assertEqual(self.action_queue.credentials, {})
        self.user_connect()
        self.assertEqual(
            self.action_queue.credentials,
            {'password': 'test_password', 'username': 'test_username'})


class SpecificException(Exception):
    """The specific exception."""


class SillyClass(object):
    """Silly class that accepts the set of any attribute.

    We can't use object() directly, since its raises AttributeError.

    """


class ErrorHandlingTestCase(BasicTestCase):
    """Error handling tests for ActionQueue."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(ErrorHandlingTestCase, self).setUp()

        self.called = False
        self.action_queue.client = SillyClass()
        self.patch(self.main, 'restart', lambda: None)

        self.main.start()

    def fail_please(self, an_exception):
        """Raise the given exception."""
        def inner(*args, **kwargs):
            """A request to the server that fails."""
            self.called = True
            return defer.fail(an_exception)
        return inner

    def succeed_please(self, result):
        """Return the given result."""
        def inner(*args, **kwargs):
            """A request to the server that succeeds."""
            self.called = True
            return defer.succeed(result)
        return inner

    def mock_caps(self, accepted):
        """Reply to query caps with False."""
        def gset_caps(caps):
            """get/set caps helper."""
            req = SillyClass()
            req.caps = caps
            req.accepted = accepted
            return defer.succeed(req)
        return gset_caps

    def test_valid_event(self):
        """SYS_SERVER_ERROR is valid in EventQueue."""
        event = 'SYS_SERVER_ERROR'
        self.assertTrue(event in EVENTS)
        self.assertEqual(('error',), EVENTS[event])

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_no_error(self):
        """_send_request_and_handle_errors is correct when no error."""

        event = 'SYS_SPECIFIC_OK'
        EVENTS[event] = ()  # add event to the global valid events list
        self.addCleanup(EVENTS.pop, event)

        result = object()
        request = self.succeed_please(result)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error='YADDA_YADDA', event_ok=event,
                      args=(1, 2), kwargs={})
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        actual_result = yield d

        self.assertTrue(self.called, 'the request was called')
        self.assertEqual(actual_result, result)
        self.assertEqual((event, {}),
                         self.action_queue.event_queue.events[-1])

        # assert over logging
        self.assertTrue(self.handler.check_info(request.__name__, 'OK'))

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_with_no_event_ok(self):
        """_send_request_and_handle_errors does not push event if is None."""
        original_events = self.action_queue.event_queue.events[:]

        result = object()
        request = self.succeed_please(result)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error='YADDA_YADDA', event_ok=None)
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        actual_result = yield d

        self.assertTrue(self.called, 'the request was called')
        self.assertEqual(actual_result, result)
        self.assertEqual(original_events,
                         self.action_queue.event_queue.events)

        # assert over logging
        self.assertTrue(self.handler.check_info(request.__name__, 'OK'))

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_valid_error(self):
        """_send_request_and_handle_errors is correct when expected error."""

        event = 'SYS_SPECIFIC_ERROR'
        EVENTS[event] = ('error',)  # add event to the global valid events list
        self.addCleanup(EVENTS.pop, event)

        exc = SpecificException('The request failed! please be happy.')
        request = self.fail_please(exc)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error=event, event_ok='YADDA_YADDA')
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        yield d

        self.assertTrue(self.called, 'the request was called')
        self.assertEqual((event, {'error': str(exc)}),
                         self.action_queue.event_queue.events[-1])

        # assert over logging
        self.assertTrue(self.handler.check_info(request.__name__,
                                                event, str(exc)))

    @defer.inlineCallbacks
    def assert_send_request_and_handle_errors_on_connection_end(self, exc):
        """_send_request_and_handle_errors is ok when connection lost/done."""
        request = self.fail_please(exc)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error='BAR', event_ok='FOO')
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        yield d

        # check that SYS_UNKNOWN_ERROR wasn't sent, and that logged ok
        events = self.action_queue.event_queue.events
        self.assertNotIn('SYS_UNKNOWN_ERROR', [x[0] for x in events])
        self.assertTrue(self.handler.check_info(request.__name__, str(exc)))

    def test_send_request_and_handle_errors_on_connection_lost(self):
        """_send_request_and_handle_errors is correct when connection lost."""
        e = twisted_error.ConnectionLost()
        return self.assert_send_request_and_handle_errors_on_connection_end(e)

    def test_send_request_and_handle_errors_on_connection_done(self):
        """_send_request_and_handle_errors is correct when connection lost."""
        e = twisted_error.ConnectionDone()
        return self.assert_send_request_and_handle_errors_on_connection_end(e)

    def test_send_request_and_handle_errors_on_ssl_error(self):
        """_send_request_and_handle_errors is correct when get a SSL error."""
        e = OpenSSL.SSL.Error()
        return self.assert_send_request_and_handle_errors_on_connection_end(e)

    @defer.inlineCallbacks
    def assert_send_request_and_handle_errors_on_server_error(self, serr):
        """_send_request_and_handle_errors is correct when server error."""
        # XXX: we need to replace this list with and exception list
        # once bug #557718 is resolved
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.ERROR
        msg.error.type = serr
        msg.error.comment = 'Error message for %s.' % serr
        exc = errors.error_to_exception(serr)(request=None, message=msg)

        request = self.fail_please(exc)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error='BAR', event_ok='FOO')
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        yield d

        event = 'SYS_SERVER_ERROR'
        self.assertEqual((event, {'error': str(exc)}),
                         self.action_queue.event_queue.events[-1])

        # assert over logging
        self.assertTrue(self.handler.check_info(request.__name__,
                                                event, str(exc)))

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_try_again(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.TRY_AGAIN
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_internal_error(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.INTERNAL_ERROR
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_protocol_error(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.PROTOCOL_ERROR
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_unsupported_version(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.UNSUPPORTED_VERSION
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_authetication_failed(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.AUTHENTICATION_FAILED
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_no_permission(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.NO_PERMISSION
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_already_exists(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.ALREADY_EXISTS
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_does_not_exist(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.DOES_NOT_EXIST
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_not_a_dir(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.NOT_A_DIRECTORY
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_not_empty(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.NOT_EMPTY
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_not_available(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.NOT_AVAILABLE
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_upload_in_progress(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.UPLOAD_IN_PROGRESS
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_upload_corrupt(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.UPLOAD_CORRUPT
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_upload_canceled(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.UPLOAD_CANCELED
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_conflict(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.CONFLICT
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_quota_exceeded(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.QUOTA_EXCEEDED
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_invalid_filename(self):
        """_send_request_and_handle_errors is correct when server error."""
        serr = protocol_pb2.Error.INVALID_FILENAME
        yield self.assert_send_request_and_handle_errors_on_server_error(serr)

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_unknown_error(self):
        """_send_request_and_handle_errors is correct when unknown error."""
        # XXX: we need to replace this list with and exception list
        # once bug #557718 is resolved
        serr = protocol_pb2.Error.AUTHENTICATION_REQUIRED
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.ERROR
        msg.error.type = serr
        msg.error.comment = 'Error message for %s.' % serr
        exc = errors.error_to_exception(serr)(request=None, message=msg)

        request = self.fail_please(exc)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error='BAR', event_ok='FOO')
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        yield d

        event = 'SYS_UNKNOWN_ERROR'
        self.assertIn((event, {}), self.action_queue.event_queue.events)

        # assert over logging
        self.assertTrue(self.handler.check_info(request.__name__,
                                                event, str(exc)))

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_no_protocol_error(self):
        """_send_request_and_handle_errors is ok when no-protocol error."""

        event = 'SYS_UNKNOWN_ERROR'
        error_msg = 'Error message for any Exception.'
        exc = Exception(error_msg)
        request = self.fail_please(exc)
        kwargs = dict(request=request, request_error=SpecificException,
                      event_error='BAR', event_ok='FOO')
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        yield d

        self.assertIn((event, {}), self.action_queue.event_queue.events)

        # assert over logging
        self.assertTrue(self.handler.check_info(request.__name__,
                                                event, str(exc)))

    @defer.inlineCallbacks
    def test_send_request_and_handle_errors_on_client_mismatch(self):
        """_send_request_and_handle_errors is correct when client mismatch."""

        def change_client(*args, **kwargs):
            """Change AQ's client while doing the request."""
            self.action_queue.client = object()

        self.action_queue.event_queue.events = []  # event cleanup
        kwargs = dict(request=change_client, request_error=SpecificException,
                      event_error='BAR', event_ok='FOO')
        d = self.action_queue._send_request_and_handle_errors(**kwargs)
        yield d

        self.assertEqual([], self.action_queue.event_queue.events)

        # assert over logging
        self.assertTrue(self.handler.check_warning(change_client.__name__,
                                                   'Client mismatch'))

    @defer.inlineCallbacks
    def test_check_version_when_unsupported_version_exception(self):
        """Test error handling after UnsupportedVersionError."""
        # raise a UnsupportedVersionError
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.ERROR
        msg.error.type = protocol_pb2.Error.UNSUPPORTED_VERSION
        msg.error.comment = 'This is a funny comment.'
        exc = errors.UnsupportedVersionError(request=None, message=msg)

        self.action_queue.client.protocol_version = self.fail_please(exc)
        yield self.action_queue.check_version()
        event = ('SYS_PROTOCOL_VERSION_ERROR', {'error': str(exc)})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])

    @defer.inlineCallbacks
    def test_set_capabilities_when_query_caps_not_accepted(self):
        """Test error handling when the query caps are not accepeted."""

        # query_caps returns False
        self.action_queue.client.query_caps = self.mock_caps(accepted=False)

        yield self.action_queue.set_capabilities(caps=None)
        msg = "The server doesn't have the requested capabilities"
        event = ('SYS_SET_CAPABILITIES_ERROR', {'error': msg})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])
        self.assertNotIn(('SYS_SET_CAPABILITIES_OK', {}),
                         self.action_queue.event_queue.events)

    @defer.inlineCallbacks
    def test_set_capabilities_when_set_caps_not_accepted(self):
        """Test error handling when the query caps are not accepted."""

        # query_caps returns True and set_caps returns False
        self.action_queue.client.query_caps = self.mock_caps(accepted=True)
        self.action_queue.client.set_caps = self.mock_caps(accepted=False)

        caps = 'very difficult cap'
        yield self.action_queue.set_capabilities(caps=caps)
        msg = "The server denied setting '%s' capabilities" % caps
        event = ('SYS_SET_CAPABILITIES_ERROR', {'error': msg})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])
        self.assertNotIn(('SYS_SET_CAPABILITIES_OK', {}),
                         self.action_queue.event_queue.events)

    @defer.inlineCallbacks
    def test_set_capabilities_when_client_is_none(self):
        """Test error handling when the client is None."""

        self.action_queue.client = None

        yield self.action_queue.set_capabilities(caps=None)
        msg = "'NoneType' object has no attribute 'query_caps'"
        event = ('SYS_SET_CAPABILITIES_ERROR', {'error': msg})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])
        self.assertNotIn(('SYS_SET_CAPABILITIES_OK', {}),
                         self.action_queue.event_queue.events)

    @defer.inlineCallbacks
    def test_set_capabilities_when_set_caps_is_accepted(self):
        """Test error handling when the query caps are not accepeted."""

        # query_caps returns True and set_caps returns True
        self.action_queue.client.query_caps = self.mock_caps(accepted=True)
        self.action_queue.client.set_caps = self.mock_caps(accepted=True)

        yield self.action_queue.set_capabilities(caps=None)
        event = ('SYS_SET_CAPABILITIES_OK', {})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])

    @defer.inlineCallbacks
    def test_authenticate_when_authenticated(self):
        """Test error handling after authenticate with no error."""
        request = client.Authenticate(self.action_queue.client,
                                      {'dummy_token': 'credentials'})
        request.session_id = str(uuid.uuid4())
        self.action_queue.client.simple_authenticate = \
            self.succeed_please(result=request)
        yield self.action_queue.authenticate()
        event = ('SYS_AUTH_OK', {})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])

    @defer.inlineCallbacks
    def test_authenticate_when_authentication_failed_exception(self):
        """Test error handling after AuthenticationFailedError."""
        # raise a AuthenticationFailedError
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.ERROR
        msg.error.type = protocol_pb2.Error.AUTHENTICATION_FAILED
        msg.error.comment = 'This is a funny comment.'
        exc = errors.AuthenticationFailedError(request=None, message=msg)

        self.action_queue.client.simple_authenticate = self.fail_please(exc)
        yield self.action_queue.authenticate()
        event = ('SYS_AUTH_ERROR', {'error': str(exc)})
        self.assertEqual(event, self.action_queue.event_queue.events[-1])


class GetDeltaTestCase(ConnectedBaseTestCase):
    """Test for GetDelta ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(GetDeltaTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_action_queue_get_delta(self):
        """Test AQ get delta."""
        self.action_queue.get_delta(VOLUME, 0)

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        cmd = GetDelta(self.rq, VOLUME, 0)
        self.assertTrue(isinstance(cmd, ActionQueueCommand))

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        cmd = GetDelta(self.rq, VOLUME, 0)
        res = cmd._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's get delta is called."""
        called = []
        self.patch(self.action_queue.client, 'get_delta',
                   lambda *a: called.append(a))

        cmd = GetDelta(self.rq, VOLUME, 35)
        cmd._run()
        self.assertEqual(called[0], (VOLUME, 35))

    def test_handle_success_push_event(self):
        """Test AQ_DELTA_OK is pushed on success."""
        # create a request and fill it with succesful information
        request = client.GetDelta(self.action_queue.client,
                                  share_id=VOLUME, from_generation=21)
        request.response = ['foo', 'bar']
        request.end_generation = 76
        request.full = True
        request.free_bytes = 1231234

        # create a command and trigger it success
        cmd = GetDelta(self.rq, VOLUME, 21)
        cmd.handle_success(request)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        delta_info = dict(volume_id=VOLUME, delta_content=['foo', 'bar'],
                          end_generation=76,
                          full=True, free_bytes=1231234)
        self.assertEqual(received, ('AQ_DELTA_OK', delta_info))
        self.assertTrue(isinstance(received[1]["delta_content"], DeltaList))

    def test_handle_generic_failure_push_event(self):
        """Test AQ_DELTA_ERROR is pushed on failure."""
        # create a failure
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))

        # create a command and trigger it success
        cmd = GetDelta(self.rq, VOLUME, 77)
        cmd.handle_failure(failure=failure)

        # check for event
        received = self.action_queue.event_queue.events[0]
        self.assertEqual(received, ('AQ_DELTA_ERROR',
                                    {'volume_id': VOLUME, 'error': msg}))

    def test_handle_notpossible_failure_push_event(self):
        """Test AQ_DELTA_NOT_POSSIBLE is pushed on that failure."""
        # create a failure
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.ERROR
        msg.error.type = protocol_pb2.Error.CANNOT_PRODUCE_DELTA
        msg.error.comment = 'Something went wrong'
        failure = Failure(errors.CannotProduceDelta(self.rq, msg))

        # create a command and trigger it success
        cmd = GetDelta(self.rq, VOLUME, 2)
        cmd.handle_failure(failure=failure)

        # check for event
        received = self.action_queue.event_queue.events[0]
        self.assertEqual(received, ('AQ_DELTA_NOT_POSSIBLE',
                                    {'volume_id': VOLUME}))

    def test_queued_mixed_types(self):
        """Command gets queued if other command is waiting."""
        cmd1 = FakeCommand()
        self.rq.queue(cmd1)
        cmd2 = GetDelta(self.rq, 'vol2', 0)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two_different(self):
        """Two different queued commands is ok."""
        cmd1 = GetDelta(self.rq, 'vol1', 0)
        self.rq.queue(cmd1)
        cmd2 = GetDelta(self.rq, 'vol2', 0)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two_equal_second_bigger_first_not_running(self):
        """Two equals, first smaller and running, queued."""
        cmd1 = GetDelta(self.rq, 'vol', 3)
        self.rq.queue(cmd1)
        cmd1.running = False
        cmd2 = GetDelta(self.rq, 'vol', 5)
        cmd2.make_logger()
        self.assertIn(cmd1, self.rq.waiting)
        self.assertFalse(cmd2._should_be_queued())
        self.assertTrue(self.handler.check_debug("not queueing self"))

    def test_queued_two_equal_second_bigger_first_running(self):
        """Two equals, first smaller and running, queued."""
        cmd1 = GetDelta(self.rq, 'vol', 3)
        self.rq.queue(cmd1)
        cmd1.running = True
        cmd2 = GetDelta(self.rq, 'vol', 5)
        cmd2.make_logger()
        self.assertIn(cmd1, self.rq.waiting)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two_equal_second_samegen_first_not_running(self):
        """Two equals, first smaller and running, queued."""
        cmd1 = GetDelta(self.rq, 'vol', 3)
        self.rq.queue(cmd1)
        cmd1.running = False
        cmd2 = GetDelta(self.rq, 'vol', 3)
        cmd2.make_logger()
        self.assertIn(cmd1, self.rq.waiting)
        self.assertFalse(cmd2._should_be_queued())
        self.assertTrue(self.handler.check_debug("not queueing self"))

    def test_queued_two_equal_second_samegen_first_running(self):
        """Two equals, first smaller and running, queued."""
        cmd1 = GetDelta(self.rq, 'vol', 3)
        self.rq.queue(cmd1)
        cmd1.running = True
        cmd2 = GetDelta(self.rq, 'vol', 3)
        cmd2.make_logger()
        self.assertIn(cmd1, self.rq.waiting)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two_equal_second_smaller_first_not_running(self):
        """Two equals, survive the one with smaller gen, second, not run."""
        cmd1 = GetDelta(self.rq, 'vol', 5)
        self.rq.queue(cmd1)
        cmd1.running = False
        cmd2 = GetDelta(self.rq, 'vol', 3)
        cmd2.make_logger()
        self.assertTrue(cmd2._should_be_queued())
        self.assertNotIn(cmd1, self.rq.waiting)
        self.assertTrue(self.handler.check_debug("removing previous command"))

    def test_queued_two_equal_second_smaller_first_running(self):
        """Two equals, survive the one with smaller gen, second, running."""
        cmd1 = GetDelta(self.rq, 'vol', 5)
        self.rq.queue(cmd1)
        cmd1.running = True
        cmd2 = GetDelta(self.rq, 'vol', 3)
        cmd2.make_logger()
        self.assertIn(cmd1, self.rq.waiting)
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_three_equal(self):
        """When several equals, only survive the one with smaller gen."""
        cmd1 = GetDelta(self.rq, 'vol', 5)
        self.rq.queue(cmd1)
        cmd1.running = False
        cmd2 = GetDelta(self.rq, 'vol', 3)
        cmd2.make_logger()
        assert cmd2._should_be_queued()
        self.rq.queue(cmd2)
        cmd3 = GetDelta(self.rq, 'vol', 7)
        cmd3.make_logger()
        self.assertFalse(cmd3._should_be_queued())
        self.assertFalse(cmd1 in self.rq.waiting)

    def test_uniqueness(self):
        """Info used for uniqueness."""
        cmd = GetDelta(self.rq, 'vol', 1)
        self.assertEqual(cmd.uniqueness, ('GetDelta', 'vol'))

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        cmd = GetDelta(self.rq, 'volume_id', 123)
        cmd._acquire_pathlock()
        self.assertEqual(t, [('GetDelta', 'volume_id'), {'logger': None}])


class GetDeltaFromScratchTestCase(ConnectedBaseTestCase):
    """Test for GetDelta ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(GetDeltaFromScratchTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_action_queue_get_delta(self):
        """Test AQ get delta."""
        self.action_queue.rescan_from_scratch(VOLUME)

    def test_is_action_queue_command(self):
        """Test proper inheritance."""
        cmd = GetDeltaFromScratch(self.rq, VOLUME)
        self.assertTrue(isinstance(cmd, ActionQueueCommand))

    def test_run_returns_a_deferred(self):
        """Test a deferred is returned."""
        cmd = GetDelta(self.rq, VOLUME, 0)
        res = cmd._run()
        self.assertIsInstance(res, defer.Deferred)
        res.addErrback(self.silent_connection_lost)

    def test_run_calls_protocol(self):
        """Test protocol's get delta is called."""
        called = []
        self.patch(self.action_queue.client, 'get_delta',
                   lambda *a, **b: called.append((a, b)))

        cmd = GetDeltaFromScratch(self.rq, VOLUME)
        cmd._run()
        self.assertEqual(called[0], ((VOLUME,), {'from_scratch': True}))

    def test_handle_success_push_event(self):
        """Test AQ_DELTA_OK is pushed on success."""
        # create a request and fill it with succesful information
        request = client.GetDelta(self.action_queue.client,
                                  share_id=VOLUME, from_scratch=True)
        request.response = ['foo', 'bar']
        request.end_generation = 76
        request.full = True
        request.free_bytes = 1231234

        # create a command and trigger it success
        cmd = GetDeltaFromScratch(self.rq, VOLUME)
        cmd.handle_success(request)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        delta_info = dict(volume_id=VOLUME, delta_content=['foo', 'bar'],
                          end_generation=76,
                          free_bytes=1231234)
        self.assertEqual(received, ('AQ_RESCAN_FROM_SCRATCH_OK', delta_info))
        self.assertTrue(isinstance(received[1]["delta_content"], DeltaList))

    def test_handle_generic_failure_push_event(self):
        """Test AQ_DELTA_ERROR is pushed on failure."""
        # create a failure
        msg = 'Something went wrong'
        failure = Failure(DefaultException(msg))

        # create a command and trigger it success
        cmd = GetDeltaFromScratch(self.rq, VOLUME)
        cmd.handle_failure(failure=failure)

        # check for event
        received = self.action_queue.event_queue.events[0]
        self.assertEqual(received, ('AQ_RESCAN_FROM_SCRATCH_ERROR',
                                    {'volume_id': VOLUME, 'error': msg}))

    def test_queued_mixed_types(self):
        """Command gets queued if other command is waiting."""
        cmd1 = FakeCommand()
        self.rq.queue(cmd1)
        cmd2 = GetDeltaFromScratch(self.rq, 'vol2')
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two_different(self):
        """Two different queued commands is ok."""
        cmd1 = GetDeltaFromScratch(self.rq, 'vol1')
        self.rq.queue(cmd1)
        cmd2 = GetDeltaFromScratch(self.rq, 'vol2')
        self.assertTrue(cmd2._should_be_queued())

    def test_queued_two_equal(self):
        """When two equals, only survive the first one."""
        cmd1 = GetDeltaFromScratch(self.rq, 'vol')
        self.rq.queue(cmd1)
        cmd2 = GetDeltaFromScratch(self.rq, 'vol')
        cmd2.make_logger()
        self.assertFalse(cmd2._should_be_queued())
        self.assertTrue(self.handler.check_debug("not queueing self"))

    def test_uniqueness(self):
        """Info used for uniqueness."""
        cmd = GetDeltaFromScratch(self.rq, 'vol')
        self.assertEqual(cmd.uniqueness, ('GetDeltaFromScratch', 'vol'))


class UnlinkTestCase(ConnectedBaseTestCase):
    """Test for Unlink ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(UnlinkTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_handle_success_push_event_file(self):
        """Test AQ_UNLINK_OK is pushed on success for a file."""
        sample_path = "sample path"
        # create a request and fill it with succesful information
        request = client.Unlink(self.action_queue.client, VOLUME, 'node_id')
        request.new_generation = 13

        # create a command and trigger it success
        cmd = Unlink(self.rq, VOLUME, 'parent_id', 'node_id', sample_path,
                     False)
        cmd.handle_success(request)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(share_id=VOLUME, parent_id='parent_id',
                    node_id='node_id', new_generation=13,
                    was_dir=False, old_path=sample_path)
        self.assertEqual(received, ('AQ_UNLINK_OK', info))

    def test_handle_success_push_event_directory(self):
        """Test AQ_UNLINK_OK is pushed on success for a directory."""
        # create a request and fill it with succesful information
        request = client.Unlink(self.action_queue.client, VOLUME, 'node_id')
        request.new_generation = 13

        # create a command and trigger it success
        cmd = Unlink(self.rq, VOLUME, 'parent_id', 'node_id', 'test_path',
                     True)
        cmd.handle_success(request)

        full_path = "test_path"

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(share_id=VOLUME, parent_id='parent_id',
                    node_id='node_id', new_generation=13,
                    was_dir=True, old_path=full_path)
        self.assertEqual(received, ('AQ_UNLINK_OK', info))

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        cmd = Unlink(self.rq, VOLUME, 'parent_id', 'node_id', 'path', False)
        res = [getattr(cmd, x) for x in cmd.possible_markers]
        self.assertEqual(res, ['node_id', 'parent_id'])

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        cmd = Unlink(self.rq, VOLUME, 'parent_id', 'node_id',
                     os.path.join('foo', 'bar'), False)
        cmd._acquire_pathlock()
        self.assertEqual(t, [('foo', 'bar'), {'on_parent': True,
                                              'on_children': True,
                                              'logger': None}])

    def test_to_dict_info(self):
        """Some info should be in to_dict."""
        cmd = Unlink(self.rq, VOLUME, 'parent_id', 'node_id', 'path', False)
        info = cmd.to_dict()
        self.assertEqual(info['path'], 'path')


class MoveTestCase(ConnectedBaseTestCase):
    """Test for Move ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(MoveTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_handle_success_push_event(self):
        """Test AQ_MOVE_OK is pushed on success."""
        # create a request and fill it with succesful information
        request = client.Move(self.action_queue.client, VOLUME, 'node',
                              'new_parent', 'new_name')
        request.new_generation = 13

        # create a command and trigger it success
        cmd = Move(self.rq, VOLUME, 'node', 'o_parent', 'n_parent', 'n_name',
                   'path_from', 'path_to')
        cmd.handle_success(request)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(share_id=VOLUME, node_id='node', new_generation=13)
        self.assertEqual(received, ('AQ_MOVE_OK', info))

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        cmd = Move(self.rq, VOLUME, 'node', 'o_parent', 'n_parent', 'n_name',
                   'path_from', 'path_to')
        res = [getattr(cmd, x) for x in cmd.possible_markers]
        self.assertEqual(res, ['node', 'o_parent', 'n_parent'])

    def test_uniqueness(self):
        """Info used for uniqueness."""
        cmd = Move(self.rq, VOLUME, 'node', 'o_parent', 'n_parent', 'n_name',
                   'path_from', 'path_to')
        self.assertEqual(cmd.uniqueness, ('Move', VOLUME, 'node'))

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []

        def fake_acquire(s, *a, **k):
            return t.extend((a, k)) or defer.succeed(None)

        self.patch(PathLockingTree, 'acquire', fake_acquire)
        cmd = Move(self.rq, VOLUME, 'node', 'o_parent', 'n_parent', 'n_name',
                   os.path.join(os.path.sep, 'path', 'from'),
                   os.path.join(os.path.sep, 'path', 'to'))
        cmd._acquire_pathlock()
        should = [
            ("", "path", "from"), {'on_parent': True,
                                   'on_children': True, 'logger': None},
            ("", "path", "to"), {'on_parent': True, 'logger': None},
        ]
        self.assertEqual(t, should)

    def test_pathlock_mergepaths(self):
        """Merge both path lockings."""
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        fake_defers = [d1, d2]
        self.patch(PathLockingTree, 'acquire',
                   lambda *a, **k: fake_defers.pop())
        cmd = Move(self.rq, VOLUME, 'node', 'o_p', 'n_p', 'n_n', 'p/f', 'p/t')

        # get the path lock, and add a callback to get the release function
        dl = cmd._acquire_pathlock()
        merge_release = []
        dl.addCallback(merge_release.append)

        # prepare marks to check both original releases are called
        release_called = []

        # dl is triggered only when d1 and d2
        self.assertFalse(dl.called)
        d1.callback(lambda: release_called.append(1))
        self.assertFalse(dl.called)
        d2.callback(lambda: release_called.append(2))
        self.assertTrue(dl.called)

        # release!
        self.assertFalse(release_called)
        merge_release[0]()
        self.assertEqual(sorted(release_called), [1, 2])

    def test_to_dict_info(self):
        """Some info should be in to_dict."""
        cmd = Move(self.rq, VOLUME, 'node', 'o_parent', 'n_parent', 'n_name',
                   'path_from', 'path_to')
        info = cmd.to_dict()
        self.assertEqual(info['path_from'], 'path_from')
        self.assertEqual(info['path_to'], 'path_to')


class MakeFileTestCase(ConnectedBaseTestCase):
    """Test for MakeFile ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(MakeFileTestCase, self).setUp()
        self.test_path = os.path.join(self.root, 'foo', 'bar')
        self.mdid = self.main.fs.create(self.test_path, '')
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_handle_success_push_event(self):
        """Test AQ_FILE_NEW_OK is pushed on success."""
        # create a request and fill it with succesful information
        request = client.MakeFile(self.action_queue.client, VOLUME,
                                  'parent', 'name')
        request.new_id = 'new_id'
        request.new_generation = 13

        # create a command and trigger it success
        cmd = MakeFile(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        cmd.handle_success(request)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(marker='marker', new_id='new_id', new_generation=13,
                    volume_id=VOLUME)
        self.assertEqual(received, ('AQ_FILE_NEW_OK', info))

    def test_handle_failure_push_event(self):
        """Test AQ_FILE_NEW_ERROR is pushed on error."""
        # create a request and fill it with succesful information
        request = client.MakeFile(self.action_queue.client, VOLUME,
                                  'parent', 'name')
        request.new_id = 'new_id'
        request.new_generation = 13

        # create a command and trigger it fail
        cmd = MakeFile(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        failure = Failure(Exception('foo'))
        cmd.handle_failure(failure)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(marker='marker', failure=failure)
        self.assertEqual(received, ('AQ_FILE_NEW_ERROR', info))

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        cmd = MakeFile(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        res = [getattr(cmd, x) for x in cmd.possible_markers]
        self.assertEqual(res, ['parent'])

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        cmd = MakeFile(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        cmd._acquire_pathlock()
        should = [tuple(self.test_path.split(os.path.sep)),
                  {'on_parent': True, 'logger': None}]
        self.assertEqual(t, should)

    def test_has_path_at_init(self):
        """MakeDir must has a path even at init."""
        cmd = MakeFile(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        self.assertEqual(cmd.path, self.test_path)

    def test_to_dict_info(self):
        """Some info should be in to_dict."""
        cmd = MakeFile(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        info = cmd.to_dict()
        self.assertEqual(info['path'], self.test_path)


class MakeDirTestCase(ConnectedBaseTestCase):
    """Test for MakeDir ActionQueueCommand."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(MakeDirTestCase, self).setUp()
        self.test_path = os.path.join(self.root, 'foo', 'bar')
        self.mdid = self.main.fs.create(self.test_path, '')
        self.rq = RequestQueue(action_queue=self.action_queue)

    def test_handle_success_push_event(self):
        """Test AQ_DIR_NEW_OK is pushed on success."""
        # create a request and fill it with succesful information
        request = client.MakeDir(self.action_queue.client, VOLUME,
                                 'parent', 'name')
        request.new_id = 'new_id'
        request.new_generation = 13

        # create a command and trigger it success
        cmd = MakeDir(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        cmd.handle_success(request)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(marker='marker', new_id='new_id', new_generation=13,
                    volume_id=VOLUME)
        self.assertEqual(received, ('AQ_DIR_NEW_OK', info))

    def test_handle_failure_push_event(self):
        """Test AQ_DIR_NEW_ERROR is pushed on error."""
        # create a request and fill it with succesful information
        request = client.MakeDir(self.action_queue.client, VOLUME,
                                 'parent', 'name')
        request.new_id = 'new_id'
        request.new_generation = 13

        # create a command and trigger it fail
        cmd = MakeDir(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        failure = Failure(Exception('foo'))
        cmd.handle_failure(failure)

        # check for successful event
        received = self.action_queue.event_queue.events[0]
        info = dict(marker='marker', failure=failure)
        self.assertEqual(received, ('AQ_DIR_NEW_ERROR', info))

    def test_possible_markers(self):
        """Test that it returns the correct values."""
        cmd = MakeDir(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        res = [getattr(cmd, x) for x in cmd.possible_markers]
        self.assertEqual(res, ['parent'])

    def test_path_locking(self):
        """Test that it acquires correctly the path lock."""
        t = []
        self.patch(PathLockingTree, 'acquire',
                   lambda s, *a, **k: t.extend((a, k)))
        cmd = MakeDir(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        cmd._acquire_pathlock()
        should = [tuple(self.test_path.split(os.path.sep)),
                  {'on_parent': True, 'logger': None}]
        self.assertEqual(t, should)

    def test_has_path_at_init(self):
        """MakeDir must has a path even at init."""
        cmd = MakeDir(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        self.assertEqual(cmd.path, self.test_path)

    def test_to_dict_info(self):
        """Some info should be in to_dict."""
        cmd = MakeDir(self.rq, VOLUME, 'parent', 'name', 'marker', self.mdid)
        info = cmd.to_dict()
        self.assertEqual(info['path'], self.test_path)


class TestDeltaList(unittest.TestCase):
    """Tests for DeltaList."""

    def test_is_list(self):
        """A DeltaList is a list."""
        l = [1, 2, 3]
        a = DeltaList(l)
        self.assertTrue(isinstance(a, list))

    def test_is_equal_list(self):
        """A DeltaList is equal to the list it represents."""
        l = [1, 2, 3]
        a = DeltaList(l)
        self.assertEqual(a, l)

    def test_repr(self):
        """A DeltaList has a short representation."""
        a = DeltaList(["a"*1000])
        self.assertTrue(len(repr(a)) < 100)
        self.assertTrue(len(str(a)) < 100)


class AuthenticateTestCase(ConnectedBaseTestCase):
    """Tests for authenticate."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(AuthenticateTestCase, self).setUp()
        self.rq = RequestQueue(action_queue=self.action_queue)

    @defer.inlineCallbacks
    def test_session_id_is_logged(self):
        """Test that session_id is logged after auth ok."""
        request = client.Authenticate(self.action_queue.client,
                                      {'dummy_token': 'credentials'})
        request.session_id = str(uuid.uuid4())
        self.action_queue.client.simple_authenticate = (
            lambda *args: defer.succeed(request))

        yield self.action_queue.authenticate()

        self.assertTrue(self.handler.check_note('Session ID: %r' %
                                                str(request.session_id)))

    @defer.inlineCallbacks
    def test_send_platform_and_version(self):
        """Test that platform and version is sent to the server."""
        called = []

        def fake_authenticate(*args, **kwargs):
            called.append((args, kwargs))
            request = client.Authenticate(self.action_queue.client,
                                          {'dummy_token': 'credentials'})
            request.session_id = str(uuid.uuid4())
            return defer.succeed(request)

        self.action_queue.client.simple_authenticate = fake_authenticate
        yield self.action_queue.authenticate()
        self.assertEqual(len(called), 1)
        metadata = called[0][0][2]
        expected_metadata = {
            'platform': platform, 'version': clientdefs.VERSION}
        self.assertEqual(metadata, expected_metadata)


class ActionQueueProtocolTests(TwistedTestCase):
    """Test the ACQ class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(ActionQueueProtocolTests, self).setUp()
        # create an AQP and put a factory to it
        self.aqp = ActionQueueProtocol()
        obj = Mocker().mock()
        obj.event_queue.push('SYS_CONNECTION_MADE')
        self.aqp.factory = obj

        # set up the logger
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        self.aqp.log.addHandler(self.handler)

    @defer.inlineCallbacks
    def tearDown(self):
        """Tear down."""
        yield super(ActionQueueProtocolTests, self).tearDown()
        self.aqp.log.removeHandler(self.handler)
        if self.aqp.ping_manager is not None:
            self.aqp.ping_manager.stop()

    def test_connection_made(self):
        """Connection is made."""
        mocker = Mocker()
        obj = mocker.mock()
        obj.event_queue.push('SYS_CONNECTION_MADE')
        self.aqp.factory = obj
        super_called = []
        self.patch(ThrottlingStorageClient, 'connectionMade',
                   lambda s: super_called.append(True))
        # test
        with mocker:
            self.aqp.connectionMade()
        self.assertTrue(self.handler.check_info('Connection made.'))
        self.assertNotIdentical(self.aqp.ping_manager, None)
        self.assertTrue(super_called)

    def test_connection_lost(self):
        """Connection is lost."""
        super_called = []
        self.patch(ThrottlingStorageClient, 'connectionLost',
                   lambda s, r: super_called.append(True))
        self.aqp.connectionLost('foo')
        self.assertTrue(self.handler.check_info(
                        'Connection lost, reason: foo.'))
        self.assertIdentical(self.aqp.ping_manager, None)
        self.assertTrue(super_called)

    def test_ping_connection_made_twice(self):
        """If connection made is called twice, don't create two tasks."""
        self.aqp.connectionMade()
        task1 = self.aqp.ping_manager
        self.aqp.connectionMade()
        task2 = self.aqp.ping_manager
        self.assertNotIdentical(task1, task2)
        self.assertFalse(task1._running)
        self.assertTrue(task2._running)

    def test_ping_connection_lost_twice(self):
        """If connection lost is called twice, don't stop None."""
        self.aqp.connectionMade()
        self.assertNotIdentical(self.aqp.ping_manager, None)
        self.aqp.connectionLost('reason')
        self.assertIdentical(self.aqp.ping_manager, None)
        self.aqp.connectionLost('reason')
        self.assertIdentical(self.aqp.ping_manager, None)

    def test_init_max_payload_size(self):
        """Configure max_payload_size on init according to config."""
        user_config = config.get_user_config()
        user_config.set_max_payload_size(12345)
        aqp = ActionQueueProtocol()
        self.assertEqual(aqp.max_payload_size, 12345)


class CommandCycleTestCase(BasicTestCase):
    """Test the command behaviour on run, retry, stop, etc.

    These tests are not exactly unit tests, but more about integration
    between the queue and the command, and how the command life cycle is.
    """

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(CommandCycleTestCase, self).setUp()

        class MyCommand(ActionQueueCommand):
            """Monkeypatchable AQC."""

            def _acquire_pathlock(self):
                pathlock = PathLockingTree()
                return pathlock.acquire('foo')

        self.queue = RequestQueue(action_queue=self.action_queue)
        self.queue.run()
        self.cmd = MyCommand(self.queue)
        self.cmd.make_logger()
        self.queue.queue(self.cmd)

    def _check_finished_ok(self, cmd=None):
        """Check that command finished ok."""
        if cmd is None:
            cmd = self.cmd
        self.assertFalse(cmd.running)
        self.assertFalse(self.action_queue.pathlock.count)

    def test_simple_start_end_ok_queue_active(self):
        """Simple normal cycle, ending ok, queued while active."""
        # check _run was called, and returned ok
        called = []
        self.cmd._run = lambda: called.append(1) or defer.succeed(2)

        # check handled success
        self.cmd.handle_success = lambda a: called.append(a)

        # let the command go
        self.cmd.go()

        # all check
        self.assertEqual(called, [1, 2])
        self._check_finished_ok()

    def test_simple_start_end_bad_queue_active(self):
        """Simple normal cycle, ending bad, queued while active.."""
        # check _run was called, and returned bad
        called = []
        exc = ValueError('foo')
        self.cmd._run = lambda: called.append(1) or defer.fail(Failure(exc))
        self.cmd.suppressed_error_messages.append(ValueError)

        # check handled failure
        self.cmd.handle_failure = lambda f: called.append(f.value)

        # let the command go
        self.cmd.go()

        # all check
        self.assertEqual(called, [1, exc])
        self._check_finished_ok()

    def test_simple_start_end_ok_queue_notactive(self):
        """Simple normal cycle, ending ok, queued while not active."""
        # check _run was called, and returned ok
        called = []
        self.cmd._run = lambda: called.append(1) or defer.succeed(2)

        # check handled success
        self.cmd.handle_success = lambda a: called.append(a)

        # stop the queue and let the command go
        self.queue.stop()
        self.cmd.go()

        # active the queue later
        self.queue.run()

        # all check
        self.assertEqual(called, [1, 2])
        self._check_finished_ok()

    def test_simple_start_end_bad_queue_notactive(self):
        """Simple normal cycle, ending bad, queued while not active.."""
        # check _run was called, and returned bad
        called = []
        exc = ValueError('foo')
        self.cmd._run = lambda: called.append(1) or defer.fail(Failure(exc))
        self.cmd.suppressed_error_messages.append(ValueError)

        # check handled failure
        self.cmd.handle_failure = lambda f: called.append(f.value)

        # stop the queue and let the command go
        self.queue.stop()
        self.cmd.go()

        # active the queue later
        self.queue.run()

        # all check
        self.assertEqual(called, [1, exc])
        self._check_finished_ok()

    def test_condition_goes_ok(self):
        """Command not run initially, but yes when conditions are ok."""
        # check _run was called, and returned ok
        called = []
        self.cmd._run = lambda: called.append('run') or defer.succeed('finish')

        # check handled success
        self.cmd.handle_success = lambda a: called.append(a)

        # command not ready to run
        self.cmd.is_runnable = False

        # let the command go, it will not run
        self.cmd.go()
        self.assertEqual(called, [])

        # fix conditions and check them
        self.cmd.is_runnable = True
        self.action_queue.conditions_locker.check_conditions()

        # all check
        self.assertEqual(called, ['run', 'finish'])
        self._check_finished_ok()

    def test_check_conditions_while_running(self):
        """Check conditions while the command is running.

        Check conditions can be executed at any time, we need to avoid
        running the command twice.
        """
        # monkeypatch _run to flag called and test "while running"
        called = []
        d = defer.Deferred()
        self.cmd._run = lambda: called.append(1) or d

        # check handled success
        self.cmd.handle_success = lambda a: called.append(a)

        # let the command go
        self.cmd.go()

        # before the command finishes, all conditions are checked
        self.action_queue.conditions_locker.check_conditions()

        # command finished
        d.callback(2)

        # all check
        self.assertEqual(called, [1, 2])
        self._check_finished_ok()

    def test_disconnect_connect_running_with_error(self):
        """Simulate a disconnection and connection while command running."""

        def f1():
            """Disconnect: stop the queue and fail with connection lost."""
            self.queue.stop()
            failure = Failure(twisted_error.ConnectionLost())
            return defer.fail(failure)

        def f2():
            """Run ok."""
            return defer.succeed('finish')

        called = []
        run_functions = [f1, f2]
        self.cmd._run = lambda: called.append('run') or run_functions.pop(0)()

        # check handled success and cleanup
        self.cmd.handle_success = lambda a: called.append(a)
        self.cmd.cleanup = lambda: called.append('clean')

        # let the command go
        self.cmd.go()

        # reconnect
        self.queue.run()

        # all check
        self.assertEqual(called, ['run', 'clean', 'clean', 'run', 'finish'])
        self._check_finished_ok()

    def test_disconnect_connect_pathlocked(self):
        """Simulate a disconnection and connection while waiting pathlock."""
        # check it called run
        called = []
        self.cmd._run = lambda: called.append('run') or defer.succeed('finish')

        # monkeypatch to test "while waiting pathlock"
        d = defer.Deferred()
        self.cmd._acquire_pathlock = lambda: d

        # check handled success
        self.cmd.handle_success = lambda a: called.append(a)

        # let the command go
        self.cmd.go()

        # before the pathlock is released, we disconnect, and reconnect
        self.queue.stop()
        self.queue.run()

        # release the pathlock
        d.callback(None)

        # all check
        self.assertEqual(called, ['run', 'finish'])
        self._check_finished_ok()

    @defer.inlineCallbacks
    def test_retry_immediate(self):
        """Retry the command immediately."""
        finished = defer.Deferred()
        called = []
        exc = twisted_error.ConnectionDone()  # retryable!
        run_deferreds = [defer.fail(Failure(exc)), defer.succeed('finish')]
        self.cmd._run = lambda: called.append('run') or run_deferreds.pop(0)
        self.cmd.handle_retryable = lambda f: called.append(f.value)

        # check handle success (failure is never called because it's retried)
        self.cmd.handle_success = lambda a: called.append(a)

        # need to wait finish() called, to be sure all ended ok, because of
        # the callLater for the retry
        def fake_finish():
            ActionQueueCommand.finish(self.cmd)
            finished.callback(True)
        self.cmd.finish = fake_finish

        # let the command go
        self.cmd.go()

        # need to wait the callLater
        yield finished

        # all check
        self.assertEqual(called, ['run', exc, 'run', 'finish'])
        self._check_finished_ok()

    @defer.inlineCallbacks
    def test_retry_conditions_solved(self):
        """Retry the command because conditions solved later."""
        finished = defer.Deferred()
        called = []

        def f1():
            """Fail and make conditions not ok to run."""
            self.cmd.is_runnable = False
            failure = Failure(twisted_error.ConnectionDone())  # retryable!
            return defer.fail(failure)

        def f2():
            """Run ok."""
            return defer.succeed('finish')

        run_functions = [f1, f2]
        self.cmd._run = lambda: called.append('run') or run_functions.pop(0)()

        # check handle success (failure is never called because it's retried)
        self.cmd.handle_success = lambda a: called.append(a)

        # need to wait finish() called, to be sure all ended ok, because of
        # the callLater for the retry
        def fake_finish():
            ActionQueueCommand.finish(self.cmd)
            finished.callback(True)
        self.cmd.finish = fake_finish

        # let the command go, it will fail and wait for conditions
        self.cmd.go()
        self.assertEqual(called, ['run'])

        # fix conditions
        self.cmd.is_runnable = True
        self.action_queue.conditions_locker.check_conditions()

        # need to wait the callLater
        yield finished

        # all check
        self.assertEqual(called, ['run', 'run', 'finish'])
        self._check_finished_ok()

    def test_cancel_while_running(self):
        """Cancel the command while running."""
        # monkeypatch _run to flag called and test "while running"
        called = []
        d = defer.Deferred()
        self.cmd._run = lambda: called.append(1) or d

        # check cleanup
        self.cmd.cleanup = lambda: called.append(2)

        def fake_finish():
            """Flag and call the real one."""
            called.append(3)
            ActionQueueCommand.finish(self.cmd)
        self.cmd.finish = fake_finish

        # let the command go
        self.cmd.go()

        # before it finishes, cancel
        self.cmd.cancel()

        # all check
        self.assertTrue(self.cmd.cancelled)
        self.assertEqual(called, [1, 2, 3])
        self._check_finished_ok()

    def test_cancel_while_pathclocked(self):
        """Cancel the command while pathlocked."""
        # monkeypatch _run to flag called and test "while running"
        called = []
        self.cmd.run = lambda: called.append('should not')

        # monkeypatch to test "while waiting pathlock"
        d = defer.Deferred()
        d.addErrback(lambda _: called.append(1))
        self.cmd._acquire_pathlock = lambda: d

        # let the command go, and cancel in the middle
        self.cmd.go()
        self.cmd.cancel()

        # all check
        self.assertEqual(called, [1])
        self._check_finished_ok()

    def test_cancel_while_waiting_conditions(self):
        """Cancel the command while waiting for conditions."""
        # make it not runnable, and fake the pathlock to test releasing
        self.cmd.is_runnable = False
        released = []
        self.cmd._acquire_pathlock = lambda: defer.succeed(
            lambda: released.append(True))

        # let the command go (will stuck because not runnable), and
        # cancel in the middle
        self.cmd.go()
        self.cmd.cancel()

        # all check
        self._check_finished_ok()
        self.assertTrue(released)

    def test_cancel_while_waiting_queue(self):
        """Cancel the command while waiting for queue."""
        # stop the queue, and fake the pathlock to test releasing
        self.queue.stop()
        released = []
        self.cmd._acquire_pathlock = lambda: defer.succeed(
            lambda: released.append(True))

        # let the command go (will stuck because not runnable), and
        # cancel in the middle
        self.cmd.go()
        self.cmd.cancel()

        # now, set the queue active again, it should release everything
        # even if was cancelled before
        self.queue.run()

        # all check
        self._check_finished_ok()
        self.assertTrue(released)

    def test_marker_error_while_pathclocked(self):
        """The marker errbacks while the command is waiting the pathlock."""
        # monkeypatch methods to flag called and test "while running"
        called = []
        self.cmd.cleanup = lambda: called.append('cleanup')
        self.cmd.handle_failure = lambda f: called.append('handle_failure')
        self.cmd.run = lambda: called.append('should not')

        # finish is special as we need to really run it
        def fake_finish():
            """Flag and call the real one."""
            called.append('finish')
            ActionQueueCommand.finish(self.cmd)
        self.cmd.finish = fake_finish

        # do not let demark callback the marker
        self.cmd.demark = lambda: None

        # monkeypatch to test "while waiting pathlock"
        d = defer.Deferred()
        self.cmd._acquire_pathlock = lambda: d

        # let the command go, and errback the marker deferred
        self.cmd.go()
        self.cmd.markers_resolved_deferred.errback(ValueError('foo'))

        # unlock the pathlock
        d.callback(lambda: True)

        # all check
        self.assertEqual(called, ['cleanup', 'handle_failure', 'finish'])
        self._check_finished_ok()

    def test_cancel_while_transfer_locked(self):
        """Cancel the command while waiting for transfer semaphore.

        The semaphore lock must be released! Of course, this test is on
        download/upload commands.
        """
        mdid = self.main.fs.create(os.path.join(self.root, 'file'), '')
        cmd = Upload(self.queue, share_id='a_share_id', node_id='a_node_id',
                     previous_hash='prev_hash', hash='yadda', crc32=0, size=0,
                     mdid=mdid)
        cmd.make_logger()

        # patch the command to simulate a request to an already full
        # transfer semaphore in _start
        transfers_semaphore = self.queue.transfers_semaphore
        semaphores = []
        user_config = config.get_user_config()
        for i in xrange(user_config.get_simult_transfers()):
            s = transfers_semaphore.acquire()
            s.addCallback(semaphores.append)

        # let the command go, and cancel in the middle
        cmd.go()
        cmd.cancel()

        # release previous semaphores
        for s in semaphores:
            s.release()

        # semaphore released
        self.assertIdentical(cmd.tx_semaphore, None)
        self._check_finished_ok(cmd)

    def test_disconnect_connect_running_no_error(self):
        """Simulate a disconnection and connection while running.

        Sometimes there's no error on the command (ConnectionLost) because the
        command got into running after the network was lost :(
        """
        called = []
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        run_deferreds = [d1, d2]
        self.cmd._run = lambda: called.append('run') or run_deferreds.pop(0)

        # check handled success and cleanup
        self.cmd.handle_success = lambda a: called.append(a)
        self.cmd.cleanup = lambda: called.append('clean')

        # let the command go, it will stuck in d1
        self.cmd.go()

        # disconnect and connect, and then trigger d2 for the command to finish
        self.queue.stop()
        self.queue.run()
        d2.callback('finish')

        # all check
        self.assertEqual(called, ['run', 'clean', 'run', 'finish'])
        self._check_finished_ok()


class InterruptibleDeferredTests(TwistedTestCase):
    """Test the InterruptibleDeferred behaviour."""

    @defer.inlineCallbacks
    def test_original_callbacked(self):
        """Original deferred is callbacked."""
        origdef = defer.Deferred()
        intrdef = InterruptibleDeferred(origdef)
        origdef.callback('foo')
        result = yield intrdef
        self.assertEqual(result, 'foo')

        # later we can interrupt, nothing happens
        intrdef.interrupt()
        self.assertFalse(intrdef.interrupted)

    @defer.inlineCallbacks
    def test_original_errbacked(self):
        """Original deferred is errbacked."""
        origdef = defer.Deferred()
        intrdef = InterruptibleDeferred(origdef)
        origdef.errback(ValueError('foo'))
        try:
            yield intrdef
        except ValueError, e:
            self.assertEqual(str(e), 'foo')
        else:
            self.fail("Test should have raised an exception")

        # later we can interrupt, nothing happens
        intrdef.interrupt()
        self.assertFalse(intrdef.interrupted)

    @defer.inlineCallbacks
    def test_interrupt_except(self):
        """Interrupt!"""
        intrdef = InterruptibleDeferred(defer.Deferred())
        intrdef.interrupt()

        try:
            yield intrdef
        except DeferredInterrupted:
            self.assertTrue(intrdef.interrupted)
        else:
            self.fail("Test should have raised an exception")

    @defer.inlineCallbacks
    def test_interrupt_callback_original(self):
        """Interrupt silences further original callbacks."""
        origdef = defer.Deferred()
        intrdef = InterruptibleDeferred(origdef)
        intrdef.interrupt()

        try:
            yield intrdef
        except DeferredInterrupted:
            pass  # just silecen the exception
        else:
            self.fail("Test should have raised an exception")

        # further callback to original deferred is harmless
        origdef.callback("foo")

    @defer.inlineCallbacks
    def test_interrupt_errback_original(self):
        """Interrupt silences further original errbacks."""
        origdef = defer.Deferred()
        intrdef = InterruptibleDeferred(origdef)
        intrdef.interrupt()

        try:
            yield intrdef
        except DeferredInterrupted:
            pass  # just silecen the exception
        else:
            self.fail("Test should have raised an exception")

        # further callback to original deferred is harmless
        origdef.errback(ValueError('foo'))


class ConditionsLockerTests(TwistedTestCase):
    """Test the ConditionsLocker."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(ConditionsLockerTests, self).setUp()
        self.cl = ConditionsLocker()

    def test_get_locking_deferred_returns_deferred(self):
        """The locking is done by a deferred."""
        d = self.cl.get_lock('command')
        d.callback(True)
        return d

    def test_get_locking_different_commands_different_deferreds(self):
        """Asked by two commands, get two deferreds."""
        d1 = self.cl.get_lock('command1')
        d2 = self.cl.get_lock('command2')
        self.assertNotIdentical(d1, d2)

    def test_get_locking_same_command_same_deferred(self):
        """If asked twice by the same command, return the same deferred.

        This is more a safe guard than a feature; if misused by the same
        command we're assuring than we will not overwrite a second deferred
        over the first one (so, never releasing the first one).
        """
        d1 = self.cl.get_lock('command')
        d2 = self.cl.get_lock('command')
        self.assertIdentical(d1, d2)

    def test_check_conditions_simple_runnable(self):
        """Release the command."""
        cmd = FakeCommand()
        locking_d = self.cl.get_lock(cmd)
        self.assertFalse(locking_d.called)
        self.assertIn(cmd, self.cl.locked)

        # release it!
        assert cmd.is_runnable
        self.cl.check_conditions()
        self.assertTrue(locking_d.called)
        self.assertNotIn(cmd, self.cl.locked)

    def test_check_conditions_simple_notrunnable_then_ok(self):
        """First don't release the command, then release it."""
        cmd = FakeCommand()
        locking_d = self.cl.get_lock(cmd)
        self.assertFalse(locking_d.called)

        # check for conditions, do not release
        cmd.is_runnable = False
        self.cl.check_conditions()
        self.assertFalse(locking_d.called)

        # conditions are ok now, release
        cmd.is_runnable = True
        self.cl.check_conditions()
        self.assertTrue(locking_d.called)

    def test_check_conditions_mixed(self):
        """Several commands, mixed situation."""
        cmd1 = FakeCommand()
        cmd1.is_runnable = False
        cmd2 = FakeCommand()
        assert cmd2.is_runnable

        # get lock for both, and check conditions
        locking_d1 = self.cl.get_lock(cmd1)
        locking_d2 = self.cl.get_lock(cmd2)
        self.cl.check_conditions()

        # one should be released, the other should not
        self.assertFalse(locking_d1.called)
        self.assertTrue(locking_d2.called)

    def test_cancel_command_nothold(self):
        """It's ok to cancel a command not there."""
        self.cl.cancel_command('command')

    def test_cancel_releases_cancelled_command(self):
        """It releases the cancelled command, even not runnable."""
        cmd1 = FakeCommand()
        cmd1.is_runnable = False
        cmd2 = FakeCommand()
        assert cmd2.is_runnable

        # get lock for both, and cancel only 1
        locking_d1 = self.cl.get_lock(cmd1)
        locking_d2 = self.cl.get_lock(cmd2)
        self.cl.cancel_command(cmd1)

        # 1 should be released, 2 should not (even with conditions ok)
        self.assertTrue(locking_d1.called)
        self.assertFalse(locking_d2.called)


class OsIntegrationTests(BasicTestCase, MockerTestCase):
    """Ensure that the correct os_helper methods are used."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up for tests."""
        yield super(OsIntegrationTests, self).setUp()
        self.fdopen = self.mocker.replace('os.fdopen')

    def test_fdopen(self):
        """Ensure that we are calling fdopen correctly."""
        # set expectations
        self.fdopen(ANY, 'w+b')
        self.mocker.replay()
        NamedTemporaryFile()

    def test_fdopen_real(self):
        """Do test that the NamedTeporaryFile can read and write."""
        data = 'test'
        self.mocker.replay()
        tmp = NamedTemporaryFile()
        tmp.write(data)
        tmp.seek(0)
        self.assertEqual(data, tmp.read(len(data)))
        tmp.close()


class PingManagerTestCase(TwistedTestCase):
    """Test the Ping manager."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(PingManagerTestCase, self).setUp()

        class FakeActionQueueProtocol(object):
            """Fake object for the tests."""
            log = logging.getLogger("ubuntuone.SyncDaemon.ActionQueue")
            log.setLevel(logger.TRACE)

            def ping(self):
                return defer.Deferred()

        self.fake_aqp = FakeActionQueueProtocol()
        self.handler = MementoHandler()
        self.fake_aqp.log.addHandler(self.handler)
        self.pm = PingManager(self.fake_aqp)

    @defer.inlineCallbacks
    def tearDown(self):
        """Tear down."""
        yield super(PingManagerTestCase, self).tearDown()
        self.fake_aqp.log.removeHandler(self.handler)
        self.pm.stop()

    def test_init(self):
        """On start values."""
        self.assertTrue(self.pm._running)
        self.assertTrue(self.pm._loop.running)
        self.assertIdentical(self.pm._timeout_call, None)

    def test_ping_do_ping(self):
        """Ping and log."""
        # mock the request
        mocker = Mocker()
        req = mocker.mock()
        expect(req.rtt).result(1.123123)
        d = defer.Deferred()
        self.pm.client.ping = lambda: d

        # call and check all is started when the ping is done
        self.pm._do_ping()
        self.assertTrue(self.pm._timeout_call.active())
        self.handler.debug = True
        self.assertTrue(self.handler.check(logger.TRACE, 'Sending ping'))

        # answer the ping, and check
        with mocker:
            d.callback(req)
        self.assertFalse(self.pm._timeout_call.active())
        self.assertTrue(self.handler.check_debug('Ping! rtt: 1.123 segs'))

    def test_stop_if_running(self):
        """Normal stop."""
        assert self.pm._running
        called = []
        self.patch(self.pm, '_stop', lambda: called.append(True))
        self.pm.stop()
        self.assertFalse(self.pm._running)
        self.assertTrue(called)
        self.pm._running = True  # back to True so it's properly stopped later

    def test_stop_if_not_running(self):
        """Stopping the stopped."""
        self.pm.stop()
        assert not self.pm._running
        called = []
        self.pm._stop = lambda: called.append(True)
        self.pm.stop()
        self.assertFalse(self.pm._running)
        self.assertFalse(called)

    def test_real_stop_loop(self):
        """The loop is stopped."""
        assert self.pm._loop.running
        self.pm.stop()
        assert not self.pm._loop.running

    def test_real_stop_timeout_call_None(self):
        """It can be stopped while not having a timeout call."""
        assert self.pm._timeout_call is None
        self.pm.stop()

    def test_real_stop_timeout_call_active(self):
        """The timeout call is cancelled if active."""
        self.pm._do_ping()
        assert self.pm._timeout_call.active()
        self.pm.stop()
        self.assertFalse(self.pm._timeout_call.active())

    def test_real_stop_timeout_call_not_active(self):
        """It can be stopped while the timeout call is not active."""
        self.pm._do_ping()
        self.pm._timeout_call.cancel()
        assert not self.pm._timeout_call.active()
        self.pm.stop()
        self.assertFalse(self.pm._timeout_call.active())

    def test_disconnect(self):
        """Stop machinery, log and disconnect."""
        mocker = Mocker()

        # mock the transport
        transport = mocker.mock()
        expect(transport.loseConnection())
        self.pm.client.transport = transport

        # mock the stop
        stop = mocker.mock()
        expect(stop())
        self.patch(self.pm, 'stop', stop)

        # ping will be called, and req accessed, otherwise mocker will complain
        with mocker:
            self.pm._disconnect()

        self.assertTrue(self.handler.check_info("No Pong response"))


class ActionQueueTestCase(BasicTestCase):
    """Test the queuing/execution of commands from AQ itself."""

    def test_reallyexec_yes(self):
        """Check secuence if command should be queued."""
        aq = self.action_queue
        called = []
        aq.queue.queue = lambda cmd: called.append(('queue', cmd))
        aq.queue.unqueue = lambda cmd: called.append(('unqueue', cmd))

        mocker = Mocker()
        cmd = mocker.mock()
        expect(cmd.should_be_queued()).result(True)
        expect(cmd.log.debug('queueing'))
        d = defer.Deferred()
        expect(cmd.go()).result(d)

        def fake_command_class(queue, *args, **kwargs):
            """Fake the command class, assuring all is received ok."""
            self.assertEqual(queue, aq.queue)
            self.assertEqual(args, ('arg1', 'arg2'))
            self.assertEqual(kwargs, {'kwarg': 'foo'})
            return cmd

        # test
        with mocker:
            aq._really_execute(fake_command_class, 'arg1', 'arg2', kwarg='foo')

            self.assertEqual(called, [('queue', cmd)])
            d.callback(True)
            self.assertEqual(called, [('queue', cmd), ('unqueue', cmd)])

    def test_reallyexec_no(self):
        """Check secuence if command should NOT be queued."""
        mocker = Mocker()
        cmd = mocker.mock()
        expect(cmd.should_be_queued()).result(False)
        expect(cmd.log.debug('queuing')).count(0)

        def fake_command_class(queue, *args, **kwargs):
            """Fake the command class, assuring all is received ok."""
            self.assertEqual(queue, self.action_queue.queue)
            self.assertEqual(args, ('arg',))
            self.assertEqual(kwargs, {'foo': 'bar'})
            return cmd

        # test
        with mocker:
            self.action_queue._really_execute(fake_command_class,
                                              'arg', foo='bar')

    def test_execute_over_limit(self):
        """Check behaviour when we're over the limit."""
        # assure we'll be over the limit
        self.action_queue.memory_pool_limit = -1

        self.action_queue.execute(FakeCommand, 'arg', foo='bar')

        pushed = self.action_queue.disk_queue.pop()
        self.assertEqual(pushed, ("FakeCommand", ('arg',), {'foo': 'bar'}))
        self.assertTrue(self.handler.check_debug("offload push", "FakeCommand",
                                                 "('arg',)", "{'foo': 'bar'}"))

    def test_execute_normal_case(self):
        """Normal execution case."""
        called = []
        aq = self.action_queue
        aq._really_execute = lambda *a, **k: called.append((a, k))
        aq.execute(FakeCommand, 'arg', foo='bar')
        self.assertEqual(called, [((FakeCommand, 'arg'), {'foo': 'bar'})])

    def test_execute_offload_retrieval(self):
        """Check how offloaded stuff is retrieved and executed."""
        # push some stuff into the offloaded queue
        aq = self.action_queue
        aq.disk_queue.push(("FakeCommand", ('arg1',), {'foo': 'bar'}))
        aq.disk_queue.push(("FakeCommand", ('arg2',), {}))

        # execute a new one and check all got really executed
        aq.commands['FakeCommand'] = FakeCommand
        called = []
        aq._really_execute = lambda *a, **k: called.append((a, k))
        aq.execute(FakeCommand, 'arg0', bar='baz')

        self.assertEqual(len(called), 3)
        self.assertEqual(called[0], ((FakeCommand, 'arg0'), {'bar': 'baz'}))
        self.assertEqual(called[1], ((FakeCommand, 'arg1'), {'foo': 'bar'}))
        self.assertEqual(called[2], ((FakeCommand, 'arg2'), {}))

    def test_execute_pushing_popping(self):
        """Exercise the limits when pushing/popping to disk."""
        aq = self.action_queue
        aq.memory_pool_limit = 2

        def _fake_execute(_, cmd):
            """Don't really execute, but store and return deferred.

            It also handles the queue.
            """
            d = defer.Deferred()
            commands.append((cmd, d))
            aq.queue.append(cmd)

            def remove(_):
                aq.queue.remove(cmd)
                commands.remove((cmd, d))

            d.addCallback(remove)
            return d

        commands = []
        self.patch(aq, '_really_execute', _fake_execute)
        aq.queue = []
        aq.commands[FakeCommand.__name__] = FakeCommand

        # send two commands, they should be executed right away
        aq.execute(FakeCommand, 1)
        aq.execute(FakeCommand, 2)
        self.assertEqual(commands[0][0], 1)
        self.assertEqual(commands[1][0], 2)

        # send a third and fourth commands, they should be offloaded
        aq.execute(FakeCommand, 3)
        aq.execute(FakeCommand, 4)
        self.assertEqual(len(commands), 2)
        self.assertEqual(len(aq.disk_queue), 2)
        self.assertEqual(aq.disk_queue[0], ('FakeCommand', (3,), {}))
        self.assertEqual(aq.disk_queue[1], ('FakeCommand', (4,), {}))

        # finish command 1, it should pop and execute command 3
        commands[0][1].callback(True)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][0], 2)
        self.assertEqual(commands[1][0], 3)
        self.assertEqual(len(aq.disk_queue), 1)
        self.assertEqual(aq.disk_queue[0], ('FakeCommand', (4,), {}))

        # other command should go offload
        aq.execute(FakeCommand, 5)
        self.assertEqual(len(commands), 2)
        self.assertEqual(len(aq.disk_queue), 2)
        self.assertEqual(aq.disk_queue[0], ('FakeCommand', (4,), {}))
        self.assertEqual(aq.disk_queue[1], ('FakeCommand', (5,), {}))

        # finish commands 2 and 3... 4 and 5 should go in
        commands[0][1].callback(True)
        commands[0][1].callback(True)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][0], 4)
        self.assertEqual(commands[1][0], 5)
        self.assertEqual(len(aq.disk_queue), 0)

        # even in the edge, another command should be offloaded
        aq.execute(FakeCommand, 6)
        self.assertEqual(len(commands), 2)
        self.assertEqual(len(aq.disk_queue), 1)
        self.assertEqual(aq.disk_queue[0], ('FakeCommand', (6,), {}))

        # finish 4 and 5, we should only have 6 left
        commands[0][1].callback(True)
        commands[0][1].callback(True)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], 6)
        self.assertEqual(len(aq.disk_queue), 0)

        # one below the limit, next op should be executed right away
        aq.execute(FakeCommand, 7)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][0], 6)
        self.assertEqual(commands[1][0], 7)
        self.assertEqual(len(aq.disk_queue), 0)

        # finish 6 and 7, all clean
        commands[0][1].callback(True)
        commands[0][1].callback(True)
        self.assertEqual(len(commands), 0)
        self.assertEqual(len(aq.disk_queue), 0)
