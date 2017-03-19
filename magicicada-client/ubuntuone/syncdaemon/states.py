# Copyright 2010-2012 Canonical Ltd.
# Copyright 2017 Chicharreros (https://launchpad.net/~chicharreros)
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
"""States machinery for SyncDaemon."""

import logging

from twisted.internet import reactor

# the WAITING time will double itself until it gets into
# these seconds
MAX_WAITING = 120


class BadEventError(Exception):
    """One of the managers received a bad event."""


class ConnectionManager(object):
    """Class that knows how to play with network.

    This has four states, as you can see in the class attribs here.

    With/Not User means that User wants to be connected or not.

    With/Not Network means that Network Manager told us that we have network
    or not.
    """

    NU_NN = "Not User Not Network"
    NU_WN = "Not User With Network"
    WU_NN = "With User Not Network"
    WU_WN = "With User With Network"

    def __init__(self, state_manager, handshake_timeout):
        self.sm = state_manager
        self.eq = state_manager.main.event_q
        self.handshake_timeout = handshake_timeout
        self.waiting_timeout = .2
        self.state = self.NU_NN
        self.working = True

        self._handshake_nodes = (
            StateManager.CHECK_VERSION,
            StateManager.SET_CAPABILITIES,
            StateManager.AUTHENTICATE,
        )

        self.log = logging.getLogger("ubuntuone.SyncDaemon.ConnectionManager")
        self._hshake_timer = None
        self._waiting_timer = None
        self.log.debug("start")

    def on_event(self, event):
        """Called on an SM event."""
        if not self.working:
            return

        self._internal_transition(event)

        if self.sm.state.is_error:
            # no transition at all when in error
            return

        if event in ('SYS_USER_CONNECT', 'SYS_NET_CONNECTED'):
            return None  # no transition

        if event in ('SYS_USER_DISCONNECT', 'SYS_NET_DISCONNECTED'):
            if self.sm.state.is_connected:
                return StateManager.STANDOFF
            else:
                return None  # no transition

        if event == 'SYS_CONNECTION_LOST':
            if self.sm.state.is_connected:
                return StateManager.WAITING

        if event == 'SYS_HANDSHAKE_TIMEOUT':
            if self.sm.state in self._handshake_nodes:
                return StateManager.STANDOFF
            if self.sm.state == StateManager.SERVER_RESCAN:
                return None  # no transition

        raise BadEventError("%s out of place" % event)

    def _hshake_timeout(self):
        """Called when the hand shake time passed."""
        if self.working:
            self._hshake_timer = None
            self.log.debug("Handshake timeout!")
            self.eq.push('SYS_HANDSHAKE_TIMEOUT')

    def _waiting_timeout(self):
        """Called when the WAITING time passed."""
        if self.working:
            self._waiting_timer = None
            self.log.debug("Waiting time expired")
            self.eq.push('SYS_CONNECTION_RETRY')

    def on_enter(self, new_node):
        """Called when SM gets into a new node."""
        if not self.working:
            return

        if self._hshake_timer is not None:
            self._hshake_timer.cancel()
            self._hshake_timer = None
        if self._waiting_timer is not None:
            self._waiting_timer.cancel()
            self._waiting_timer = None

        if new_node == StateManager.WAITING:
            self.waiting_timeout *= 2
            if self.waiting_timeout > MAX_WAITING:
                self.waiting_timeout = MAX_WAITING
            self.log.debug("Setting up the 'waiting' timer on %d secs",
                           self.waiting_timeout)
            self._waiting_timer = reactor.callLater(self.waiting_timeout,
                                                    self._waiting_timeout)

        elif new_node in self._handshake_nodes:
            self.log.debug("Setting up the 'handshake' timer on %d secs",
                           self.handshake_timeout)
            self._hshake_timer = reactor.callLater(self.handshake_timeout,
                                                   self._hshake_timeout)

    def _internal_transition(self, event):
        """Execute the internal transition."""
        new_state = None

        if self.state == self.NU_NN:
            if event == 'SYS_NET_CONNECTED':
                new_state = self.NU_WN
            elif event == 'SYS_USER_CONNECT':
                new_state = self.WU_NN

        elif self.state == self.NU_WN:
            if event == 'SYS_NET_DISCONNECTED':
                new_state = self.NU_NN
            elif event == 'SYS_USER_CONNECT':
                new_state = self.WU_WN

        elif self.state == self.WU_WN:
            if event == 'SYS_NET_DISCONNECTED':
                new_state = self.WU_NN
            elif event == 'SYS_USER_DISCONNECT':
                new_state = self.NU_WN

        elif self.state == self.WU_NN:
            if event == 'SYS_NET_CONNECTED':
                new_state = self.WU_WN
            elif event == 'SYS_USER_DISCONNECT':
                new_state = self.NU_NN

        else:
            raise ValueError("Bad ConnectionManager internal state: %r",
                             self.state)

        # check if transitions
        if new_state is not None:
            self.log.debug("Internal transition %r -> %r",
                           self.state, new_state)
            self.state = new_state
            if new_state == self.WU_WN and self.sm.state == StateManager.READY:
                self.sm.aq.connect()

    def shutdown(self):
        """Clean all the timers."""
        self.working = False
        self.log.debug("shutdown")
        if self._hshake_timer is not None:
            self._hshake_timer.cancel()
        if self._waiting_timer is not None:
            self._waiting_timer.cancel()


class Node(object):
    """Node information."""
    def __init__(self, name, desc, error=False, conn=False, online=False):
        self.name = name
        self.description = desc
        self.is_error = error
        self.is_connected = conn
        self.is_online = online

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<Node %s (%s) error=%s connected=%s online=%s" % (
            self.name, self.description, self.is_error, self.is_connected,
            self.is_online)


class StateInfo(Node):
    """Object to pass state information."""
    def __init__(self, node, queue, conn):
        self.__dict__.update(node.__dict__)
        self.queue_state = queue.state
        self.connection_state = conn.state

    def __repr__(self):
        return (
            "%s (error=%s connected=%s online=%s)  Queue: %s  Connection: "
            "%s" % (self.name, self.is_error, self.is_connected,
                    self.is_online, self.queue_state, self.connection_state))

    __str__ = __repr__


class QueueManager(object):
    """A smaller finite state machine to handle queues."""

    IDLE = Node('IDLE', "nothing in the queues")
    WORKING = Node('WORKING', "working on the commands queue")

    def __init__(self):
        self.state = self.IDLE
        self.log = logging.getLogger("ubuntuone.SyncDaemon.QueueManager")
        self.log.debug("start")

    def _set_state(self, new_state):
        """Set the new state and log."""
        self.log.debug("Changing state  %s -> %s", self.state, new_state)
        self.state = new_state

    def on_event(self, event):
        """Handle transitions."""
        prv_state = self.state
        if self.state == self.IDLE:
            if event == 'SYS_QUEUE_WAITING':
                self._set_state(self.WORKING)
            else:
                self._bad_event(event)

        elif self.state == self.WORKING:
            if event == 'SYS_QUEUE_DONE':
                self._set_state(self.IDLE)
            else:
                self._bad_event(event)

        else:
            raise ValueError("Bad QueueManager internal state: %r", self.state)

        # inform if changed
        return self.state != prv_state

    def _bad_event(self, event):
        """Log the bad event."""
        m = "Bad Event received: Got %r while in %s"
        self.log.warning(m, event, self.state)


ACCEPTED_EVENTS = [
    'SYS_AUTH_ERROR',
    'SYS_AUTH_OK',
    'SYS_CONNECTION_FAILED',
    'SYS_CONNECTION_LOST',
    'SYS_CONNECTION_MADE',
    'SYS_CONNECTION_RETRY',
    'SYS_QUEUE_DONE',
    'SYS_QUEUE_WAITING',
    'SYS_HANDSHAKE_TIMEOUT',
    'SYS_INIT_DONE',
    'SYS_LOCAL_RESCAN_DONE',
    'SYS_NET_CONNECTED',
    'SYS_NET_DISCONNECTED',
    'SYS_PROTOCOL_VERSION_ERROR',
    'SYS_PROTOCOL_VERSION_OK',
    'SYS_QUIT',
    'SYS_ROOT_MISMATCH',
    'SYS_SERVER_RESCAN_DONE',
    'SYS_SERVER_ERROR',
    'SYS_SET_CAPABILITIES_ERROR',
    'SYS_SET_CAPABILITIES_OK',
    'SYS_UNKNOWN_ERROR',
    'SYS_USER_CONNECT',
    'SYS_USER_DISCONNECT',
]


class StateManager(object):
    """The Manager of the high level states."""

    INIT = Node('INIT', "just initialized")
    LOCAL_RESCAN = Node('LOCAL_RESCAN', "doing local rescan")
    READY = Node('READY', "ready to connect")
    WAITING = Node('WAITING', "waiting before try connecting again")

    CHECK_VERSION = Node('CHECK_VERSION', "checking protocol version",
                         conn=True)
    BAD_VERSION = Node('BAD_VERSION', "bad protocol version", error=True)

    SET_CAPABILITIES = Node('SET_CAPABILITIES', "checking capabilities",
                            conn=True)
    CAPABILITIES_MISMATCH = Node('CAPABILITIES_MISMATCH',
                                 "capabilities mismatch", error=True)

    AUTHENTICATE = Node('AUTHENTICATE', "doing auth dance", conn=True)
    AUTH_FAILED = Node('AUTH_FAILED', "auth failed", error=True)

    SERVER_RESCAN = Node('SERVER_RESCAN', "doing server rescan", conn=True)

    QUEUE_MANAGER = Node('QUEUE_MANAGER', "processing the commands pool",
                         conn=True, online=True)

    STANDOFF = Node('STANDOFF', "waiting for connection to end", conn=True)

    ROOT_MISMATCH = Node('ROOT_MISMATCH', "local and server roots are "
                         "different", error=True)
    UNKNOWN_ERROR = Node('UNKNOWN_ERROR', "something went wrong", error=True)

    SHUTDOWN = Node('SHUTDOWN', "shutting down the service")

    def __init__(self, main, handshake_timeout=None):
        self.main = main
        self.aq = main.action_q
        self.eq = main.event_q
        self.state = self.INIT
        self.queues = QueueManager()
        self.connection = ConnectionManager(self, handshake_timeout)
        self.eq.subscribe(self)
        self.log = logging.getLogger("ubuntuone.SyncDaemon.StateManager")
        self.log.debug("start")

        # define transitions!
        def _from_ready(conn_state):
            """Exiting from READY is special."""
            if conn_state == ConnectionManager.WU_WN:
                return self.CHECK_VERSION
            else:
                raise KeyError("Not a valid event while not connected!")

        self._transitions = {
            (self.INIT, 'SYS_INIT_DONE'): self.LOCAL_RESCAN,
            (self.LOCAL_RESCAN, 'SYS_LOCAL_RESCAN_DONE'): self.READY,
            (self.READY, 'SYS_CONNECTION_MADE'): _from_ready,
            (self.READY, 'SYS_CONNECTION_FAILED'): self.WAITING,
            (self.WAITING, 'SYS_CONNECTION_RETRY'): self.READY,
            (self.CHECK_VERSION,
             'SYS_PROTOCOL_VERSION_OK'): self.SET_CAPABILITIES,
            (self.CHECK_VERSION,
             'SYS_PROTOCOL_VERSION_ERROR'): self.BAD_VERSION,
            (self.CHECK_VERSION, 'SYS_SERVER_ERROR'): self.STANDOFF,
            (self.SET_CAPABILITIES,
             'SYS_SET_CAPABILITIES_OK'): self.AUTHENTICATE,
            (self.SET_CAPABILITIES,
             'SYS_SET_CAPABILITIES_ERROR'): self.CAPABILITIES_MISMATCH,
            (self.SET_CAPABILITIES, 'SYS_SERVER_ERROR'): self.STANDOFF,
            (self.AUTHENTICATE, 'SYS_AUTH_OK'): self.SERVER_RESCAN,
            (self.AUTHENTICATE, 'SYS_AUTH_ERROR'): self.AUTH_FAILED,
            (self.AUTHENTICATE, 'SYS_SERVER_ERROR'): self.STANDOFF,
            (self.SERVER_RESCAN, 'SYS_SERVER_RESCAN_DONE'): self.QUEUE_MANAGER,
            (self.SERVER_RESCAN, 'SYS_SERVER_ERROR'): self.STANDOFF,
        }

    def handle_default(self, event, **kwargs):
        """Receive all the events to make States tick."""
        if event not in ACCEPTED_EVENTS:
            return
        self.log.debug("received event %r", event)

        # quit
        if event == 'SYS_QUIT':
            self._transition(event, StateManager.SHUTDOWN)
            return

        # error management
        if event == 'SYS_UNKNOWN_ERROR':
            self._transition(event, StateManager.UNKNOWN_ERROR)
            return
        if event == 'SYS_ROOT_MISMATCH':
            self._transition(event, StateManager.ROOT_MISMATCH)
            return
        if self.state.is_error:
            return

        # queue events
        if event in ('SYS_QUEUE_WAITING', 'SYS_QUEUE_DONE'):
            self.log.debug("sending event to QueueManager")
            changed = self.queues.on_event(event)
            if changed:
                self._state_changed()
            return

        # User events
        if event in ('SYS_NET_CONNECTED', 'SYS_USER_CONNECT',
                     'SYS_NET_DISCONNECTED', 'SYS_USER_DISCONNECT',
                     'SYS_CONNECTION_LOST', 'SYS_HANDSHAKE_TIMEOUT'):
            self.log.debug("sending event to ConnectionManager")
            try:
                new_node = self.connection.on_event(event)
            except BadEventError:
                self._bad_event(event)
            else:
                self.log.debug("ConnectionManager returned %s", new_node)
                if new_node is None:
                    new_node = self.state
                self._transition(event, new_node)
            return

        # high level transitions
        try:
            new_node = self._transitions[self.state, event]
            if not isinstance(new_node, Node):
                new_node = new_node(self.connection.state)
        except KeyError:
            # not a valid event for that node
            self._bad_event(event)
            return
        self._transition(event, new_node)

    def _bad_event(self, event):
        """Log that we received a bad event."""
        m = "Bad Event received: Got %r while in %r (queues %s  connection %s)"
        self.log.warning(m, event, self.state.name,
                         self.queues.state.name, self.connection.state)

    def _transition(self, event, new_node):
        """Make the transition.

        If new node is the same as before, it just logs the event (this is
        actually used on purpose by the rest of the code to be log complete.)
        """
        if new_node == self.state:
            # no transition really
            return

        self.log.debug("Transition %s --[%s]--> %s (queues: %s; "
                       "connection: %s)", self.state, event, new_node,
                       self.queues.state.name, self.connection.state)

        # on exit actions
        if self.state == self.QUEUE_MANAGER:
            self.aq.queue.stop()

        # make the transition
        self.state = new_node

        # on enter actions
        if new_node == self.LOCAL_RESCAN:
            self.main.local_rescan()
        elif new_node == self.READY:
            if self.connection.state == ConnectionManager.WU_WN:
                self.aq.connect()
        elif new_node == self.CHECK_VERSION:
            self.main.check_version()
        elif new_node == self.SET_CAPABILITIES:
            self.main.set_capabilities()
        elif new_node == self.AUTHENTICATE:
            self.main.authenticate()
        elif new_node == self.SERVER_RESCAN:
            self.main.server_rescan()
        elif new_node == self.QUEUE_MANAGER:
            self.aq.queue.run()
        elif new_node == self.STANDOFF:
            self.main.action_q.disconnect()
        elif new_node == self.UNKNOWN_ERROR:
            self.main.restart()
        self.connection.on_enter(new_node)

        # inform the system
        self._state_changed()

    def _state_changed(self):
        """Push the event with all relevant info."""
        info = StateInfo(self.state, self.queues, self.connection)
        self.eq.push('SYS_STATE_CHANGED', state=info)

    def __str__(self):
        return "<State: %r  (queues %s  connection %r)>" % (
            self.state.name, self.queues.state.name, self.connection.state)

    def shutdown(self):
        """Finish all pending work."""
        self.connection.shutdown()
        self.eq.unsubscribe(self)
