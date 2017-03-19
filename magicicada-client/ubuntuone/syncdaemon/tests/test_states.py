# tests.syncdaemon.test_states.py - States tests
#
# Author: Facundo Batista <facundo@canonical.com>
#
# Copyright 2010-2012 Canonical Ltd.
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
"""Tests for States."""

from twisted.internet import defer, reactor
from twisted.trial.unittest import TestCase as TwistedTestCase

from contrib.testing.testcase import FakeLogger
from ubuntuone.syncdaemon.states import (
    StateManager, ConnectionManager, QueueManager, Node
)


class FakeEventQueue(object):
    """Fake EQ."""
    def __init__(self):
        self.events = []

    def push(self, event, *a, **k):
        """Appends event to the list."""
        self.events.append(event)

    def subscribe(self, _):
        """Fake."""


class FakeRequestQueue(object):
    """Fake object that marks the runs.

    It has the behaviour of the real queues regarding waiting, done,
    and counter.

    - WAITING when command is queued and the queue was empty (first cmd, bah).
    - DONE when command is done and queue is empty

    It does NOT send a WAITING everytime something is queued, and it does
    NOT send a DONE everytime a command finishes.
    """
    def __init__(self):
        self.active = False
        self.jobs = []

    def __len__(self):
        return len(self.jobs)

    def queue(self, job):
        """Inserts a job."""
        self.jobs.append(job)
        if len(self) == 1:
            self.qm.on_event('SYS_QUEUE_WAITING')

    def run(self):
        """Run."""
        self.active = True

    def stop(self):
        """Stop."""
        self.active = False


class FakeActionQueue(object):
    """Fake class to log actions on AQ."""
    def __init__(self):
        self.queue = FakeRequestQueue()
        self.actions = []

    def __getattribute__(self, name):
        """Generic method logger."""
        if name in ("connect", "disconnect", "cleanup"):
            return lambda *a, **k: self.actions.append(name)
        else:
            return object.__getattribute__(self, name)


class FakeMain(object):
    """Fake class to log actions on Main."""
    def __init__(self, aq, eq):
        self.action_q = aq
        self.event_q = eq
        self.actions = []

    def __getattribute__(self, name):
        """Generic method logger."""
        if name in ("local_rescan", "check_version", "authenticate",
                    "set_capabilities", "server_rescan", "restart"):
            return lambda *a, **k: self.actions.append(name)
        else:
            return object.__getattribute__(self, name)


class Base(TwistedTestCase):
    """Base class for state tests."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(Base, self).setUp()
        # create fake classes
        self.eq = FakeEventQueue()
        self.aq = FakeActionQueue()
        self.main = FakeMain(self.aq, self.eq)
        self.sm = StateManager(self.main, handshake_timeout=30)
        self.qm = self.sm.queues
        self.cm = self.sm.connection

        # add QM to queues, to push events for testing
        self.aq.queue.qm = self.qm

        # add logger
        self.fake_logger = FakeLogger()
        self.sm.log = self.fake_logger
        self.qm.log = self.fake_logger

        # some useful info
        self.sm_allnodes = [getattr(StateManager, x) for x in dir(StateManager)
                            if isinstance(getattr(StateManager, x), Node)]
        self.sm_connected = set(x for x in self.sm_allnodes if x.is_connected)
        self.sm_disconnected = set(x for x in self.sm_allnodes
                                   if not x.is_connected and not x.is_error)
        self.sm_nodes_ok = set(x for x in self.sm_allnodes if not x.is_error)
        self.sm_nodes_error = set(x for x in self.sm_allnodes if x.is_error)

    def check_log(self, where, txt):
        for line in self.fake_logger.logged[where]:
            if txt in line:
                return True
        return False

    def wait_event(self, event):
        """Waits for the event in our EQ."""
        d = defer.Deferred()

        def check(count):
            """Check the event."""
            count += 1
            if count > 10:
                d.errback("Not %s found!" % event)

            if event in self.eq.events:
                d.callback(True)
            else:
                reactor.callLater(.1, check, count)

        reactor.callLater(.1, check, 0)
        return d

    @defer.inlineCallbacks
    def tearDown(self):
        yield super(Base, self).tearDown()
        self.sm.connection.shutdown()


class QueueBase(Base):
    """Basic setup for QueueManager."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(QueueBase, self).setUp()
        self.sm.state = StateManager.QUEUE_MANAGER


class TestQueueManagerTransitions(QueueBase):
    """Transitions of QueueManager."""

    def check(self, n_from, event, n_to, in_log=False):
        self.qm.state = getattr(QueueManager, n_from)
        self.qm.on_event(event)
        self.assertEqual(self.qm.state, getattr(QueueManager, n_to),
                         "%s != %s" % (self.qm.state.name, n_to))

        m = "Bad Event received: Got %r while in %s" % (event, n_from)
        self.assertEqual(in_log, self.check_log('warning', m))

    def test_idle_waiting(self):
        """Waiting when in IDLE."""
        self.check('IDLE', 'SYS_QUEUE_WAITING', 'WORKING')

    def test_idle_done(self):
        """Done when in IDLE."""
        self.check('IDLE', 'SYS_QUEUE_DONE', 'IDLE', in_log=True)

    def test_working_waiting(self):
        """Waiting when in WORKING."""
        self.check('WORKING', 'SYS_QUEUE_WAITING', 'WORKING', in_log=True)

    def test_working_done(self):
        """Done when in WORKING."""
        self.check('WORKING', 'SYS_QUEUE_DONE', 'IDLE')


class TestQueueManagerFromOutside(QueueBase):
    """Getting in/out QueueManager."""

    def test_into_idle(self):
        """Entering when IDLE."""
        assert not self.aq.queue.active
        self.qm.state = QueueManager.IDLE
        self.sm.state = StateManager.SERVER_RESCAN
        self.sm.handle_default('SYS_SERVER_RESCAN_DONE')
        self.assertEqual(self.qm.state, QueueManager.IDLE)
        self.assertTrue(self.aq.queue.active)

    def test_into_working(self):
        """Entering when WORKING."""
        assert not self.aq.queue.active
        self.qm.state = QueueManager.WORKING
        self.sm.state = StateManager.SERVER_RESCAN
        self.sm.handle_default('SYS_SERVER_RESCAN_DONE')
        self.assertEqual(self.qm.state, QueueManager.WORKING)
        self.assertTrue(self.aq.queue.active)


class TestConnectionManager(Base):
    """Test the "internal network" transitions."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestConnectionManager, self).setUp()

        # put SM on some state that does not generate further
        # transition-related efforts for this CM
        self.sm.state = StateManager.AUTH_FAILED

    def check(self, n_from, event, n_to):
        self.cm.state = getattr(ConnectionManager, n_from)
        self.cm.on_event(event)
        self.assertEqual(self.cm.state, getattr(ConnectionManager, n_to))

    def test_initial_state(self):
        """The initial state is INIT."""
        self.assertEqual(self.cm.state, ConnectionManager.NU_NN)

    def test_nunn_netconn(self):
        """Receive SYS_NET_CONNECTED while in NotUserNotNetwork."""
        self.check('NU_NN', 'SYS_NET_CONNECTED', 'NU_WN')

    def test_nunn_userconn(self):
        """Receive SYS_USER_CONNECT while in NotUserNotNetwork."""
        self.check('NU_NN', 'SYS_USER_CONNECT', 'WU_NN')

    def test_nunn_netdisconn(self):
        """Receive SYS_NET_DISCONNECTED while in NotUserNotNetwork."""
        self.check('NU_NN', 'SYS_NET_DISCONNECTED', 'NU_NN')

    def test_nunn_userdisconn(self):
        """Receive SYS_USER_DISCONNECT while in NotUserNotNetwork."""
        self.check('NU_NN', 'SYS_USER_DISCONNECT', 'NU_NN')

    def test_nunn_connlost(self):
        """Receive SYS_CONNECTION_LOST while in NotUserNotNetwork."""
        self.check('NU_NN', 'SYS_CONNECTION_LOST', 'NU_NN')

    def test_nuwn_netconn(self):
        """Receive SYS_NET_CONNECTED while in NotUserWithNetwork."""
        self.check('NU_WN', 'SYS_NET_CONNECTED', 'NU_WN')

    def test_nuwn_userconn(self):
        """Receive SYS_USER_CONNECT while in NotUserWithNetwork."""
        self.check('NU_WN', 'SYS_USER_CONNECT', 'WU_WN')

    def test_nuwn_netdisconn(self):
        """Receive SYS_NET_DISCONNECTED while in NotUserWithNetwork."""
        self.check('NU_WN', 'SYS_NET_DISCONNECTED', 'NU_NN')

    def test_nuwn_userdisconn(self):
        """Receive SYS_USER_DISCONNECT while in NotUserWithNetwork."""
        self.check('NU_WN', 'SYS_USER_DISCONNECT', 'NU_WN')

    def test_nuwn_connlost(self):
        """Receive SYS_CONNECTION_LOST while in NotUserWithNetwork."""
        self.check('NU_WN', 'SYS_CONNECTION_LOST', 'NU_WN')

    def test_wunn_netconn(self):
        """Receive SYS_NET_CONNECTED while in WithUserNotNetwork."""
        self.check('WU_NN', 'SYS_NET_CONNECTED', 'WU_WN')

    def test_wunn_userconn(self):
        """Receive SYS_USER_CONNECT while in WithUserNotNetwork."""
        self.check('WU_NN', 'SYS_USER_CONNECT', 'WU_NN')

    def test_wunn_netdisconn(self):
        """Receive SYS_NET_DISCONNECTED while in WithUserNotNetwork."""
        self.check('WU_NN', 'SYS_NET_DISCONNECTED', 'WU_NN')

    def test_wunn_userdisconn(self):
        """Receive SYS_USER_DISCONNECT while in WithUserNotNetwork."""
        self.check('WU_NN', 'SYS_USER_DISCONNECT', 'NU_NN')

    def test_wunn_connlost(self):
        """Receive SYS_CONNECTION_LOST while in WithUserNotNetwork."""
        self.check('WU_NN', 'SYS_CONNECTION_LOST', 'WU_NN')

    def test_wuwn_netconn(self):
        """Receive SYS_NET_CONNECTED while in WithUserWithNetwork."""
        self.check('WU_WN', 'SYS_NET_CONNECTED', 'WU_WN')

    def test_wuwn_userconn(self):
        """Receive SYS_USER_CONNECT while in WithUserWithNetwork."""
        self.check('WU_WN', 'SYS_USER_CONNECT', 'WU_WN')

    def test_wuwn_netdisconn(self):
        """Receive SYS_NET_DISCONNECTED while in WithUserWithNetwork."""
        self.check('WU_WN', 'SYS_NET_DISCONNECTED', 'WU_NN')

    def test_wuwn_userdisconn(self):
        """Receive SYS_USER_DISCONNECT while in WithUserWithNetwork."""
        self.check('WU_WN', 'SYS_USER_DISCONNECT', 'NU_WN')

    def test_wuwn_connlost(self):
        """Receive SYS_CONNECTION_LOST while in WithUserWithNetwork."""
        self.check('WU_WN', 'SYS_CONNECTION_LOST', 'WU_WN')

    def test_shutdown_flag(self):
        """Shutdown puts itself in not working."""
        self.assertTrue(self.cm.working)
        self.cm.shutdown()
        self.assertFalse(self.cm.working)

    def test_not_working_internal(self):
        """Not working, really! (internal check)."""
        self.cm.working = False
        # if working, WU_NN
        self.check('WU_WN', 'SYS_NET_DISCONNECTED', 'WU_WN')

    def test_not_working_external(self):
        """Not working, really! (external check)."""
        self.cm.working = False
        self.sm.state = StateManager.STANDOFF
        new_node = self.cm.on_event('SYS_CONNECTION_LOST')
        # if working, it should return a node
        self.assertTrue(new_node is None)


class TestConnectionManagerTimings(Base):
    """Times handled by ConnectionManager."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestConnectionManagerTimings, self).setUp()

        # set timeout values to really low, to make tests run quicker
        self.sm.connection.handshake_timeout = 0

    def check(self, n_from, event, result):
        """Generic test."""
        self.sm.state = getattr(StateManager, n_from)
        self.sm.handle_default(event)
        return self.wait_event(result)

    def test_handshaketimeout_checkversion(self):
        """Handshake timing is controlled in CheckVersion."""
        self.sm.connection.state = ConnectionManager.WU_WN
        return self.check('READY', 'SYS_CONNECTION_MADE',
                          'SYS_HANDSHAKE_TIMEOUT')

    def test_handshaketimeout_setcapabilities(self):
        """Handshake timing is controlled in SetCapabilities."""
        return self.check('CHECK_VERSION', 'SYS_PROTOCOL_VERSION_OK',
                          'SYS_HANDSHAKE_TIMEOUT')

    def test_handshaketimeout_authenticate(self):
        """Handshake timing is controlled in Authenticate."""
        return self.check('SET_CAPABILITIES', 'SYS_SET_CAPABILITIES_OK',
                          'SYS_HANDSHAKE_TIMEOUT')

    def test_waiting_triggers(self):
        """Check WAITING triggers the event."""
        self.sm.connection.waiting_timeout = 0
        return self.check('READY', 'SYS_CONNECTION_FAILED',
                          'SYS_CONNECTION_RETRY')

    def test_waiting_behaviour(self):
        """Check WAITING increases values ok."""
        timeouts = [2, 4, 8, 16, 32, 64, 120, 120, 120]
        self.sm.connection.waiting_timeout = 1
        for t in timeouts:
            self.sm.state = StateManager.READY
            self.sm.handle_default('SYS_CONNECTION_FAILED')
            self.assertEqual(self.sm.connection.waiting_timeout, t)


class StateManagerTransitions(Base):
    """Base class for all transition tests."""

    timeout = 2

    def check(self, n_from, event, n_to, in_log=False):
        if isinstance(n_from, str):
            n_from = getattr(StateManager, n_from)
        if isinstance(n_to, str):
            n_to = getattr(StateManager, n_to)
        self.sm.state = n_from
        self.sm.handle_default(event)
        self.assertEqual(self.sm.state, n_to, "%s / %s should %s but got %s" %
                         (n_from, event, n_to, self.sm.state))

        m = "Bad Event received: Got %r while in %r" % (event, n_from.name)
        self.assertEqual(in_log, self.check_log('warning', m),
                         "Bad log for %s / %s" % (n_from, event))

        # wait state changed only if the before and after nodes are different
        if n_from == n_to:
            return defer.succeed(True)
        else:
            return self.wait_event('SYS_STATE_CHANGED')


class TestStateManagerHighLevelTransitions(StateManagerTransitions):
    """Test StateManager high level transitions."""

    def test_initial_state(self):
        """The initial state is INIT."""
        self.assertEqual(self.sm.state, StateManager.INIT)

    def test_init_localrescan(self):
        """Transition Init -> LocalRescan."""
        return self.check('INIT', 'SYS_INIT_DONE', 'LOCAL_RESCAN')

    def test_localrescan_ready(self):
        """Transition LocalRescan -> Ready."""
        return self.check('LOCAL_RESCAN', 'SYS_LOCAL_RESCAN_DONE', 'READY')

    def test_ready_standoff_nunn(self):
        """Transition (not) from Ready when connection is NU_NN."""
        self.sm.connection.state = ConnectionManager.NU_NN
        return self.check('READY', 'SYS_CONNECTION_MADE', 'READY', in_log=True)

    def test_ready_standoff_nuwn(self):
        """Transition (not) from Ready when connection is NU_WN."""
        self.sm.connection.state = ConnectionManager.NU_WN
        return self.check('READY', 'SYS_CONNECTION_MADE', 'READY', in_log=True)

    def test_ready_standoff_wunn(self):
        """Transition (not) from Ready when connection is WU_NN."""
        self.sm.connection.state = ConnectionManager.WU_NN
        return self.check('READY', 'SYS_CONNECTION_MADE', 'READY', in_log=True)

    def test_ready_checkversion(self):
        """Transition Ready -> CheckVersion when connection is WU_WN."""
        self.sm.connection.state = ConnectionManager.WU_WN
        return self.check('READY', 'SYS_CONNECTION_MADE', 'CHECK_VERSION')

    def test_ready_waiting(self):
        """Transition Ready -> Waiting."""
        return self.check('READY', 'SYS_CONNECTION_FAILED', 'WAITING')

    def test_waiting_ready(self):
        """Transition Waiting -> Ready."""
        return self.check('WAITING', 'SYS_CONNECTION_RETRY', 'READY')

    def test_checkversion_setcapabilities(self):
        """Transition CheckVersion -> SetCapabilities."""
        return self.check('CHECK_VERSION', 'SYS_PROTOCOL_VERSION_OK',
                          'SET_CAPABILITIES')

    def test_checkversion_error(self):
        """Transition CheckVersion -> Error."""
        return self.check('CHECK_VERSION', 'SYS_PROTOCOL_VERSION_ERROR',
                          'BAD_VERSION')

    def test_checkversion_server_error(self):
        """Transition CheckVersion -> Standoff."""
        return self.check('CHECK_VERSION', 'SYS_SERVER_ERROR', 'STANDOFF')

    def test_setcapabilities_authenticate(self):
        """Transition SetCapabilities -> Authenticate."""
        return self.check('SET_CAPABILITIES', 'SYS_SET_CAPABILITIES_OK',
                          'AUTHENTICATE')

    def test_setcapabilities_error(self):
        """Transition SetCapabilities -> Error."""
        return self.check('SET_CAPABILITIES', 'SYS_SET_CAPABILITIES_ERROR',
                          'CAPABILITIES_MISMATCH')

    def test_setcapabilities_server_error(self):
        """Transition SetCapabilities -> Standoff."""
        return self.check('SET_CAPABILITIES', 'SYS_SERVER_ERROR', 'STANDOFF')

    def test_authenticate_serverrescan(self):
        """Transition Authenticate -> ServerRescan."""
        return self.check('AUTHENTICATE', 'SYS_AUTH_OK', 'SERVER_RESCAN')

    def test_authenticate_error(self):
        """Transition Authenticate -> Error."""
        return self.check('AUTHENTICATE', 'SYS_AUTH_ERROR', 'AUTH_FAILED')

    def test_authenticate_server_error(self):
        """Transition Authenticate -> Standoff."""
        return self.check('AUTHENTICATE', 'SYS_SERVER_ERROR', 'STANDOFF')

    def test_serverrescan_queuemanager(self):
        """Transition ServerRescan -> QueueManager."""
        return self.check('SERVER_RESCAN', 'SYS_SERVER_RESCAN_DONE',
                          'QUEUE_MANAGER')

    def test_serverrescan_standoff(self):
        """Transition ServerRescan -> Standoff."""
        return self.check('SERVER_RESCAN', 'SYS_SERVER_ERROR', 'STANDOFF')

    def test_network_events(self):
        """Don't make transition, and don't log warning."""
        nodes = ['INIT', 'READY', 'STANDOFF', 'QUEUE_MANAGER']  # examples
        d = []
        for event in ('SYS_QUEUE_WAITING', 'SYS_QUEUE_DONE'):
            node = nodes.pop()
            d.append(self.check(node, event, node))
        return defer.DeferredList(d)


class TestStateManagerQueueTransitions(StateManagerTransitions):
    """Test Queue transitions from StateManager POV."""

    def check(self, node_name, event):
        """Checks the transition."""
        self.sm.queues.state = getattr(QueueManager, node_name)
        self.sm.handle_default(event)
        return self.wait_event('SYS_STATE_CHANGED')

    def test_IDLE_SYS_QUEUE_WAITING(self):
        """Transition from IDLE when SYS_QUEUE_WAITING."""
        return self.check('IDLE', 'SYS_QUEUE_WAITING')

    def test_WORKING_SYS_QUEUE_DONE(self):
        """Transition from WORKING when SYS_QUEUE_DONE."""
        return self.check('WORKING', 'SYS_QUEUE_DONE')


class TestStateManagerNetworkTransitions(StateManagerTransitions):
    """Test StateManager network transitions."""

    def test_net_connected(self):
        """The SYS_NET_CONNECTED event never changes from node."""
        d = []
        for node_name in self.sm_nodes_ok:
            d.append(self.check(node_name, 'SYS_NET_CONNECTED', node_name))
        return defer.DeferredList(d)

    def test_user_connect(self):
        """The SYS_USER_CONNECT event never changes from node."""
        d = []
        for node_name in self.sm_nodes_ok:
            d.append(self.check(node_name, 'SYS_USER_CONNECT', node_name))
        return defer.DeferredList(d)

    def test_disconn_net_disconnected(self):
        """Test SYS_NET_DISCONNECTED when disconnected."""
        d = []
        for node_name in self.sm_disconnected:
            d.append(self.check(node_name, 'SYS_NET_DISCONNECTED', node_name))
        return defer.DeferredList(d)

    def test_disconn_user_disconnect(self):
        """Test SYS_USER_DISCONNECT when disconnected."""
        d = []
        for node_name in self.sm_disconnected:
            d.append(self.check(node_name, 'SYS_USER_DISCONNECT', node_name))
        return defer.DeferredList(d)

    def test_disconn_connection_lost(self):
        """Test SYS_CONNECTION_LOST when disconnected."""
        d = []
        for node_name in self.sm_disconnected:
            d.append(self.check(node_name, 'SYS_CONNECTION_LOST', node_name,
                                in_log=True))
        return defer.DeferredList(d)

    def test_conn_connection_lost(self):
        """Test SYS_CONNECTION_LOST when connected."""
        d = []
        for node_name in self.sm_connected:
            d.append(self.check(node_name, 'SYS_CONNECTION_LOST', 'WAITING'))
        return defer.DeferredList(d)

    def test_someconnected_netdisconn_userdisconn(self):
        """Test both DISCONNECT when connected (except standoff)."""
        d = []
        for node_name in self.sm_connected - set([StateManager.STANDOFF]):
            for event in ('SYS_USER_DISCONNECT', 'SYS_NET_DISCONNECTED'):
                d.append(self.check(node_name, event, 'STANDOFF'))
        return defer.DeferredList(d)

    def test_standoff_netdisconn_userdisconn(self):
        """Test both DISCONNECT on StandOff."""
        d = []
        for event in ('SYS_USER_DISCONNECT', 'SYS_NET_DISCONNECTED'):
            d.append(self.check('STANDOFF', event, 'STANDOFF'))
        return defer.DeferredList(d)


class TestStateManagerTimeoutTransitions(StateManagerTransitions):
    """Test StateManager when HandshakeTimeouts."""

    def test_disconn(self):
        """Test when disconnected."""
        d = []
        for node in self.sm_disconnected:
            d.append(self.check(node, 'SYS_HANDSHAKE_TIMEOUT', node, True))
        return defer.DeferredList(d)

    def test_some_connected_events(self):
        """Test on some connected events."""
        d = []
        for node in ('CHECK_VERSION', 'SET_CAPABILITIES', 'AUTHENTICATE'):
            d.append(self.check(node, 'SYS_HANDSHAKE_TIMEOUT', 'STANDOFF'))
        return defer.DeferredList(d)

    def test_serverrescan(self):
        """Test on ServerRescan."""
        return self.check('SERVER_RESCAN', 'SYS_HANDSHAKE_TIMEOUT',
                          'SERVER_RESCAN')

    def test_queuemanager(self):
        """Test on QueueManager."""
        return self.check('QUEUE_MANAGER', 'SYS_HANDSHAKE_TIMEOUT',
                          'QUEUE_MANAGER', True)

    def test_standoff(self):
        """Test on StandOff."""
        return self.check('STANDOFF', 'SYS_HANDSHAKE_TIMEOUT',
                          'STANDOFF', True)


class TestStateManagerShutdown(StateManagerTransitions):
    """Test StateManager when shutting down."""

    def test_shutdown(self):
        """All nodes go to SHUTDOWN."""
        d = []
        for node in self.sm_allnodes:
            d.append(self.check(node, 'SYS_QUIT', 'SHUTDOWN'))
        return defer.DeferredList(d)


class TestStateManagerErrors(StateManagerTransitions):
    """Test StateManager on error conditions."""

    def test_unknown_error(self):
        """All nodes go to unknown_error."""
        d = []
        for node in self.sm_nodes_ok:
            d.append(self.check(node, 'SYS_UNKNOWN_ERROR', 'UNKNOWN_ERROR'))
        return defer.DeferredList(d)

    def test_root_mismatch_error(self):
        """All nodes go to root_mismatch."""
        d = []
        for node in self.sm_nodes_ok:
            d.append(self.check(node, 'SYS_ROOT_MISMATCH', 'ROOT_MISMATCH'))
        return defer.DeferredList(d)

    def test_not_exiting_from_errors(self):
        """No return from errors."""
        d = []
        for node in self.sm_nodes_error:
            d.append(self.check(node, 'SYS_CONNECTION_LOST', node))
            d.append(self.check(node, 'SYS_HANDSHAKE_TIMEOUT', node))
            d.append(self.check(node, 'SYS_CONNECTION_MADE', node))
            d.append(self.check(node, 'SYS_SERVER_ERROR', node))
        return defer.DeferredList(d)


class TestStateManagerEnterExit(Base):
    """Test StateManager on enter and exit transitions."""

    def test_to_error(self):
        """Transition to error."""
        self.sm.handle_default('SYS_UNKNOWN_ERROR')
        self.assertEqual(self.main.actions, ['restart'])

    def test_init_localrescan(self):
        """Transition Init -> LocalRescan."""
        self.sm.state = StateManager.INIT
        self.sm.handle_default('SYS_INIT_DONE')
        self.assertEqual(self.main.actions, ['local_rescan'])

    def test_localrescan_ready_netok(self):
        """Transition LocalRescan -> Ready with network ok."""
        self.sm.state = StateManager.LOCAL_RESCAN
        self.sm.connection.state = ConnectionManager.WU_WN
        self.sm.handle_default('SYS_LOCAL_RESCAN_DONE')
        self.assertEqual(self.aq.actions, ['connect'])

    def test_localrescan_ready_netbad(self):
        """Transition LocalRescan -> Ready with network bad."""
        for net in (
                ConnectionManager.WU_NN, ConnectionManager.NU_WN,
                ConnectionManager.NU_NN):
            self.sm.connection.state = net
            self.sm.state = StateManager.LOCAL_RESCAN
            self.sm.handle_default('SYS_LOCAL_RESCAN_DONE')
            self.assertEqual(self.aq.actions, [])

    def test_waiting_ready_netok(self):
        """Transition LocalRescan -> Ready with network ok."""
        self.sm.state = StateManager.WAITING
        self.sm.connection.state = ConnectionManager.WU_WN
        self.sm.handle_default('SYS_CONNECTION_RETRY')
        self.assertEqual(self.aq.actions, ['connect'])

    def test_waiting_ready_netbad(self):
        """Transition LocalRescan -> Ready with network bad."""
        for net in (
                ConnectionManager.WU_NN, ConnectionManager.NU_WN,
                ConnectionManager.NU_NN):
            self.sm.connection.state = net
            self.sm.state = StateManager.WAITING
            self.sm.handle_default('SYS_CONNECTION_RETRY')
            self.assertEqual(self.aq.actions, [])

    def test_ready_internal_nunn(self):
        """Internal READY transition from NU_NN."""
        for evt in ('SYS_NET_CONNECTED', 'SYS_USER_CONNECT',
                    'SYS_NET_DISCONNECTED', 'SYS_USER_DISCONNECT',
                    'SYS_CONNECTION_LOST'):
            self.sm.state = StateManager.READY
            self.sm.connection.state = ConnectionManager.NU_NN
            self.sm.handle_default(evt)
        self.assertEqual(self.aq.actions, [])

    def test_ready_internal_nuwn(self):
        """Internal READY transition from NU_WN."""
        for evt in ('SYS_NET_CONNECTED' 'SYS_NET_DISCONNECTED',
                    'SYS_USER_DISCONNECT', 'SYS_CONNECTION_LOST'):
            self.sm.state = StateManager.READY
            self.sm.connection.state = ConnectionManager.NU_WN
            self.sm.handle_default(evt)
        self.assertEqual(self.aq.actions, [])

        self.sm.state = StateManager.READY
        self.sm.connection.state = ConnectionManager.NU_WN
        self.sm.handle_default('SYS_USER_CONNECT')
        self.assertEqual(self.aq.actions, ['connect'])

    def test_ready_internal_wunn(self):
        """Internal READY transition from WU_NN."""
        for evt in ('SYS_USER_CONNECT' 'SYS_NET_DISCONNECTED',
                    'SYS_USER_DISCONNECT', 'SYS_CONNECTION_LOST'):
            self.sm.state = StateManager.READY
            self.sm.connection.state = ConnectionManager.WU_NN
            self.sm.handle_default(evt)
        self.assertEqual(self.aq.actions, [])

        self.sm.state = StateManager.READY
        self.sm.connection.state = ConnectionManager.WU_NN
        self.sm.handle_default('SYS_NET_CONNECTED')
        self.assertEqual(self.aq.actions, ['connect'])

    def test_internal_valid_othernode(self):
        """Don't call connect if in other node."""
        self.sm.state = StateManager.LOCAL_RESCAN  # whatever
        self.sm.connection.state = ConnectionManager.NU_WN
        self.sm.handle_default('SYS_USER_CONNECT')
        self.assertEqual(self.aq.actions, [])

        self.sm.state = StateManager.STANDOFF  # whatever
        self.sm.connection.state = ConnectionManager.WU_NN
        self.sm.handle_default('SYS_NET_CONNECTED')
        self.assertEqual(self.aq.actions, [])

    def test_ready_internal_wuwn(self):
        """Internal READY transition from WU_WN."""
        for evt in ('SYS_NET_CONNECTED', 'SYS_USER_CONNECT',
                    'SYS_NET_DISCONNECTED', 'SYS_USER_DISCONNECT',
                    'SYS_CONNECTION_LOST'):
            self.sm.state = StateManager.READY
            self.sm.connection.state = ConnectionManager.WU_WN
            self.sm.handle_default(evt)
        self.assertEqual(self.aq.actions, [])

    def test_ready_checkversion(self):
        """Transition Ready -> CheckVersion."""
        self.sm.state = StateManager.READY
        self.sm.connection.state = ConnectionManager.WU_WN
        self.sm.handle_default('SYS_CONNECTION_MADE')
        self.assertEqual(self.main.actions, ['check_version'])

    def test_checkversion_setcapabilities(self):
        """Transition CheckVersion -> SetCapabilities."""
        self.sm.state = StateManager.CHECK_VERSION
        self.sm.handle_default('SYS_PROTOCOL_VERSION_OK')
        self.assertEqual(self.main.actions, ['set_capabilities'])

    def test_setcapabilities_authenticate(self):
        """Transition SetCapabilities -> Authenticate."""
        self.sm.state = StateManager.SET_CAPABILITIES
        self.sm.handle_default('SYS_SET_CAPABILITIES_OK')
        self.assertEqual(self.main.actions, ['authenticate'])

    def test_authenticate_serverrescan(self):
        """Transition Authenticate -> ServerRescan."""
        self.sm.state = StateManager.AUTHENTICATE
        self.sm.handle_default('SYS_AUTH_OK')
        self.assertEqual(self.main.actions, ['server_rescan'])

    def test_alot_standoff(self):
        """Lots of transitions to Standoff."""
        nodes = (StateManager.CHECK_VERSION, StateManager.SET_CAPABILITIES,
                 StateManager.AUTHENTICATE)
        events = ('SYS_NET_DISCONNECTED', 'SYS_USER_DISCONNECT',
                  'SYS_HANDSHAKE_TIMEOUT', 'SYS_SERVER_ERROR')
        cnt = 0
        for node in nodes:
            for event in events:
                cnt += 1
                self.sm.state = node
                self.sm.handle_default(event)
                self.assertEqual(self.aq.actions, ['disconnect']*cnt)

        self.aq.actions[:] = []
        cnt = 0
        for node in (StateManager.SERVER_RESCAN, StateManager.QUEUE_MANAGER):
            for event in ('SYS_NET_DISCONNECTED', 'SYS_USER_DISCONNECT'):
                cnt += 1
                self.sm.state = node
                self.sm.handle_default(event)
        # we just count the disconnects because there're some on_exit mixed
        # from QUEUE_MANAGER
        self.assertEqual(self.aq.actions.count('disconnect'), cnt)

    def test_server_rescan_to_standoff(self):
        """ServerRescan transitions to Standoff generates an AQ.disconnect."""
        # case of ServerRescan and SYS_SERVER_ERROR
        self.aq.actions[:] = []
        self.sm.state = StateManager.SERVER_RESCAN
        self.sm.handle_default('SYS_SERVER_ERROR')
        self.assertEqual(self.aq.actions, ['disconnect'])

    def test_exit_queuemanager(self):
        """Exit transitions from QueueManager."""
        events = ('SYS_NET_DISCONNECTED', 'SYS_USER_DISCONNECT',
                  'SYS_CONNECTION_LOST')
        for event in events:
            self.aq.queue.active = True
            self.sm.state = StateManager.QUEUE_MANAGER
            self.sm.handle_default(event)
            self.assertFalse(self.aq.queue.active)


class TestStateManagerPassToQueueManager(Base):
    """All queue events should go to QueueManager."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestStateManagerPassToQueueManager, self).setUp()

        # put a function in the middle to log calls
        self.called_events = []
        orig_on_event = self.sm.queues.on_event

        def fake_on_event(event):
            """Log the call and call original."""
            self.called_events.append(event)
            orig_on_event(event)

        self.sm.queues.on_event = fake_on_event

    def _test(self, event):
        """Generic test method."""
        cnt = 0
        for node in self.sm_nodes_ok:
            cnt += 1
            self.sm.state = node
            self.sm.handle_default(event)
            self.assertEqual(self.called_events, [event]*cnt)

    def test_meta_waiting(self):
        """SYS_QUEUE_WAITING should go to QueueMgr no matter where."""
        self._test('SYS_QUEUE_WAITING')

    def test_meta_done(self):
        """SYS_QUEUE_DONE should go to QueueMgr no matter where."""
        self._test('SYS_QUEUE_DONE')


class TestStateManagerAPI(Base):
    """Test StateManager API."""

    def test_states_have_data(self):
        """The StateManager states have some info."""
        sm = self.sm
        for node in self.sm_allnodes:
            sm.state = node
            self.assertTrue(isinstance(sm.state.name, basestring))
            self.assertTrue(isinstance(sm.state.description, basestring))
            self.assertTrue(isinstance(sm.state.is_error, bool))
            self.assertTrue(isinstance(sm.state.is_connected, bool))
            self.assertTrue(isinstance(sm.state.is_online, bool))

    def check_node(self, name, error, conn, online):
        self.assertEqual(self.sm.state.name, name)
        self.assertEqual(self.sm.state.is_error, error)
        self.assertEqual(self.sm.state.is_connected, conn)
        self.assertEqual(self.sm.state.is_online, online)

    def test_INIT(self):
        """INIT internals."""
        self.sm.state = StateManager.INIT
        self.check_node("INIT", error=False, conn=False, online=False)

    def test_LOCAL_RESCAN(self):
        """LOCAL_RESCAN internals."""
        self.sm.state = StateManager.LOCAL_RESCAN
        self.check_node("LOCAL_RESCAN", error=False, conn=False, online=False)

    def test_READY(self):
        """READY internals."""
        self.sm.state = StateManager.READY
        self.check_node("READY", error=False, conn=False, online=False)

    def test_WAITING(self):
        """WAITING internals."""
        self.sm.state = StateManager.WAITING
        self.check_node("WAITING", error=False, conn=False, online=False)

    def test_CHECK_VERSION(self):
        """CHECK_VERSION internals."""
        self.sm.state = StateManager.CHECK_VERSION
        self.check_node("CHECK_VERSION", error=False, conn=True, online=False)

    def test_BAD_VERSION(self):
        """BAD_VERSION internals."""
        self.sm.state = StateManager.BAD_VERSION
        self.check_node("BAD_VERSION", error=True, conn=False, online=False)

    def test_SET_CAPABILITIES(self):
        """SET_CAPABILITIES internals."""
        self.sm.state = StateManager.SET_CAPABILITIES
        self.check_node("SET_CAPABILITIES",
                        error=False, conn=True, online=False)

    def test_CAPABILITIES_MISMATCH(self):
        """CAPABILITIES_MISMATCH internals."""
        self.sm.state = StateManager.CAPABILITIES_MISMATCH
        self.check_node("CAPABILITIES_MISMATCH",
                        error=True, conn=False, online=False)

    def test_AUTHENTICATE(self):
        """AUTHENTICATE internals."""
        self.sm.state = StateManager.AUTHENTICATE
        self.check_node("AUTHENTICATE", error=False, conn=True, online=False)

    def test_AUTH_FAILED(self):
        """AUTH_FAILED internals."""
        self.sm.state = StateManager.AUTH_FAILED
        self.check_node("AUTH_FAILED", error=True, conn=False, online=False)

    def test_SERVER_RESCAN(self):
        """SERVER_RESCAN internals."""
        self.sm.state = StateManager.SERVER_RESCAN
        self.check_node("SERVER_RESCAN", error=False, conn=True, online=False)

    def test_QUEUE_MANAGER(self):
        """QUEUE_MANAGER internals."""
        self.sm.state = StateManager.QUEUE_MANAGER
        self.check_node("QUEUE_MANAGER", error=False, conn=True, online=True)

    def test_STANDOFF(self):
        """STANDOFF internals."""
        self.sm.state = StateManager.STANDOFF
        self.check_node("STANDOFF", error=False, conn=True, online=False)

    def test_SHUTDOWN(self):
        """SHUTDOWN internals."""
        self.sm.state = StateManager.SHUTDOWN
        self.check_node("SHUTDOWN", error=False, conn=False, online=False)
