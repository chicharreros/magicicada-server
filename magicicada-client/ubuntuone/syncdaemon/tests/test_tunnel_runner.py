# -*- coding: utf-8 -*-
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
"""Tests for the proxy tunnel runner."""

from twisted.internet import defer, error, reactor, task
from twisted.trial.unittest import TestCase

from ubuntuone.proxy.tests import FAKE_COOKIE
from ubuntuone.proxy import tunnel_client
from ubuntuone.syncdaemon import tunnel_runner

FAKE_HOST = "fs-1.two.ubuntu.com"
FAKE_PORT = 443


class TunnelRunnerConstructorTestCase(TestCase):
    """Test the tunnel runner constructor."""

    timeout = 3

    def raise_import_error(self, *args):
        """Raise an import error."""
        raise ImportError

    @defer.inlineCallbacks
    def test_proxy_support_not_installed(self):
        """The proxy support binary package is not installed."""
        self.patch(tunnel_runner.TunnelRunner, "start_process",
                   self.raise_import_error)
        tr = tunnel_runner.TunnelRunner(FAKE_HOST, FAKE_PORT)
        client = yield tr.get_client()
        self.assertEqual(client, reactor)

    @defer.inlineCallbacks
    def test_executable_not_found(self):
        """The executable is not found anywhere."""
        self.patch(tunnel_runner, "get_tunnel_bin_cmd",
                   lambda *args, **kwargs: ["this_does_not_exist"])
        tr = tunnel_runner.TunnelRunner(FAKE_HOST, FAKE_PORT)
        client = yield tr.get_client()
        self.assertEqual(client, reactor)


class FakeProcessTransport(object):
    """A fake ProcessTransport."""

    pid = 0

    def __init__(self):
        """Initialize this fake."""
        self._signals_sent = []

    def signalProcess(self, signalID):
        """Send a signal to the process."""
        self._signals_sent.append(signalID)


class TunnelRunnerTestCase(TestCase):
    """Tests for the TunnelRunner."""

    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(TunnelRunnerTestCase, self).setUp()
        self.spawned = []
        self.triggers = []
        self.fake_process_transport = FakeProcessTransport()

        def fake_spawn_process(*args, **kwargs):
            """A fake spawnProcess."""
            self.spawned.append((args, kwargs))
            return self.fake_process_transport

        self.patch(tunnel_client.reactor, "spawnProcess", fake_spawn_process)

        def fake_add_system_event_trigger(*args, **kwargs):
            """A fake addSystemEventTrigger."""
            self.triggers.append((args, kwargs))

        self.patch(tunnel_client.reactor, "addSystemEventTrigger",
                   fake_add_system_event_trigger)
        self.process_protocol = None
        self.process_protocol_class = tunnel_client.TunnelProcessProtocol
        self.patch(tunnel_client, "TunnelProcessProtocol",
                   self.storing_process_protocol_factory)
        self.tr = tunnel_runner.TunnelRunner("fs-1.one.ubuntu.com", 443)

    def storing_process_protocol_factory(self, *args, **kwargs):
        """Store the process protocol just created."""
        self.process_protocol = self.process_protocol_class(*args, **kwargs)
        return self.process_protocol

    def test_tunnel_process_is_started(self):
        """The tunnel process is started."""
        self.assertEqual(
            len(self.spawned), 1, "The tunnel process is started.")

    def test_system_event_finished(self):
        """An event is added to stop the process with the reactor."""
        expected = [(("before", "shutdown", self.tr.stop), {})]
        self.assertEqual(self.triggers, expected)

    def test_stop_process(self):
        """The process is stopped if still running."""
        self.tr.process_transport.pid = 1234
        self.tr.stop()
        self.assertEqual(self.fake_process_transport._signals_sent, ["KILL"])

    def test_not_stopped_if_already_finished(self):
        """Do not stop the tunnel process if it's already finished."""
        self.tr.process_transport.pid = None
        self.tr.stop()
        self.assertEqual(self.fake_process_transport._signals_sent, [])

    @defer.inlineCallbacks
    def test_tunnel_process_get_client_yielded_twice(self):
        """The get_client method can be yielded twice."""
        self.process_protocol.processExited(error.ProcessTerminated(1))
        client = yield self.tr.get_client()
        client = yield self.tr.get_client()
        self.assertNotEqual(client, None)

    @defer.inlineCallbacks
    def test_tunnel_process_exits_with_error(self):
        """The tunnel process exits with an error."""
        self.process_protocol.processExited(error.ProcessTerminated(1))
        client = yield self.tr.get_client()
        self.assertEqual(client, reactor)

    @defer.inlineCallbacks
    def test_tunnel_process_exits_gracefully(self):
        """The tunnel process exits gracefully."""
        self.process_protocol.processExited(error.ProcessDone(0))
        client = yield self.tr.get_client()
        self.assertEqual(client, reactor)

    @defer.inlineCallbacks
    def test_tunnel_process_prints_random_garbage_and_timeouts(self):
        """The tunnel process prints garbage and timeouts."""
        clock = task.Clock()
        self.patch(tunnel_client, "reactor", clock)
        self.process_protocol.connectionMade()
        self.process_protocol.outReceived("Random garbage")
        clock.advance(self.process_protocol.timeout)
        client = yield self.tr.get_client()
        self.assertEqual(client, clock)

    @defer.inlineCallbacks
    def test_tunnel_process_prints_port_number_and_cookie(self):
        """The tunnel process prints the port number."""
        received = "%s: %d\n%s: %s\n" % (
                                tunnel_client.TUNNEL_PORT_LABEL, FAKE_PORT,
                                tunnel_client.TUNNEL_COOKIE_LABEL, FAKE_COOKIE)
        self.process_protocol.outReceived(received)
        client = yield self.tr.get_client()
        self.assertEqual(client.tunnel_port, FAKE_PORT)
        self.assertEqual(client.cookie, FAKE_COOKIE)
