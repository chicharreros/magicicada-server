# -*- coding: utf-8 -*-
#
# Copyright 2011-2012 Canonical Ltd.
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Tests for the tcpactivation module."""

from __future__ import print_function

import twisted.internet
from twisted.internet import defer, protocol, task
from twisted.trial.unittest import TestCase

from ubuntuone.devtools.testcases.txsocketserver import (
    ServerTestCase,
    TidyTCPServer,
)

from ubuntuone.utils import tcpactivation
from ubuntuone.utils.tcpactivation import (
    ActivationClient,
    ActivationConfig,
    ActivationDetector,
    ActivationInstance,
    ActivationTimeoutError,
    AlreadyStartedError,
    NullProtocol,
    PortDetectFactory,
)

SAMPLE_SERVICE = "test_service_name"
SAMPLE_CMDLINE = ["python", __file__, "-server"]
SAMPLE_SERVER_DESCRIPTION = 'tcp:55555:interface=127.0.0.1'
SAMPLE_CLIENT_DESCRIPTION = 'tcp:host=127.0.0.1:port=55555'


class FakeServerProtocol(protocol.Protocol):
    """A test protocol."""

    def dataReceived(self, data):
        """Echo the data received."""
        self.transport.write(data)


class FakeServerFactory(protocol.ServerFactory):
    """A factory for the test server."""

    protocol = FakeServerProtocol


class FakeTransport(object):
    """A fake transport."""

    connectionLost = False

    def loseConnection(self):
        """Remember that the connection was dropped."""
        self.connectionLost = True


class FakeDescriptionFactory(object):
    """A fake description factory."""

    def __init__(self, server_description, client_description):
        """Create a new instace."""
        self.server = server_description
        self.client = client_description


class AsyncSleepTestCase(TestCase):
    """Tests for the async_sleep function."""

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(AsyncSleepTestCase, self).setUp()
        self.test_timeout = 5.0
        self.clock = task.Clock()
        self.patch(twisted.internet, "reactor", self.clock)
        self.d = tcpactivation.async_sleep(self.test_timeout)

    def test_async_sleep_not_fired_immediately(self):
        """The async_sleep deferred is not fired immediately."""
        self.assertFalse(self.d.called, "Must not be fired immediately.")

    def test_async_sleep_not_fired_in_a_bit(self):
        """The async_sleep deferred is not fired before the right time."""
        self.clock.advance(self.test_timeout / 2)
        self.assertFalse(self.d.called, "Must not be fired yet.")

    def test_async_sleep_fired_at_the_right_time(self):
        """The async_sleep deferred is fired at the right time."""
        self.clock.advance(self.test_timeout)
        self.assertTrue(self.d.called, "Must be fired by now.")


class NullProtocolTestCase(TestCase):
    """A test for the NullProtocol class."""

    def test_drops_connection(self):
        """The protocol drops the connection."""
        np = NullProtocol()
        np.transport = FakeTransport()
        np.connectionMade()
        self.assertTrue(np.transport.connectionLost,
                        "the connection must be dropped.")


class PortDetectFactoryTestCase(TestCase):
    """Tests for the PortDetectFactory."""

    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(PortDetectFactoryTestCase, self).setUp()
        self.factory = PortDetectFactory()

    @defer.inlineCallbacks
    def test_is_listening(self):
        """Test that the deferred returns True when something is listening."""
        addr = (tcpactivation.LOCALHOST, SAMPLE_CLIENT_DESCRIPTION)
        self.factory.buildProtocol(addr)
        is_listening = yield self.factory.is_listening()
        self.assertTrue(is_listening)

    @defer.inlineCallbacks
    def test_connection_lost(self):
        """Test that the deferred returns False when the connection is lost."""
        self.factory.clientConnectionLost(None, "test reason")
        is_listening = yield self.factory.is_listening()
        self.assertFalse(is_listening)

    @defer.inlineCallbacks
    def test_connection_failed(self):
        """Test that the deferred returns False when the connection fails."""
        self.factory.clientConnectionFailed(None, "test reason")
        is_listening = yield self.factory.is_listening()
        self.assertFalse(is_listening)

    @defer.inlineCallbacks
    def test_connection_failed_then_lost(self):
        """It's not an error if two events happen."""
        self.factory.clientConnectionFailed(None, "test reason")
        self.factory.clientConnectionLost(None, "test reason")
        is_listening = yield self.factory.is_listening()
        self.assertFalse(is_listening)

    @defer.inlineCallbacks
    def test_connection_works_then_lost(self):
        """It's not an error if two events happen."""
        addr = (tcpactivation.LOCALHOST, SAMPLE_CLIENT_DESCRIPTION)
        self.factory.buildProtocol(addr)
        d = self.factory.is_listening()
        self.factory.clientConnectionLost(None, "test reason")
        is_listening = yield d
        self.assertTrue(is_listening)


class ActivationConfigTestCase(TestCase):
    """Tests for the ActivationConfig class."""

    def test_initialization(self):
        """Test the constructor."""
        config = ActivationConfig(
            SAMPLE_SERVICE, SAMPLE_CMDLINE, SAMPLE_CLIENT_DESCRIPTION)
        self.assertEqual(config.service_name, SAMPLE_SERVICE)
        self.assertEqual(config.command_line, SAMPLE_CMDLINE)
        self.assertEqual(config.description, SAMPLE_CLIENT_DESCRIPTION)


class ActivationDetectorTestCase(TestCase):
    """Tests for the ActivationDetector class."""

    timeoue = 3

    client_description = 'tcp:host=127.0.0.1:port=55555'
    server_description = 'tcp:55555:interface=127.0.0.1'

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(ActivationDetectorTestCase, self).setUp()
        self.description_factory = FakeDescriptionFactory(
            self.server_description, self.client_description)
        self.config = ActivationConfig(SAMPLE_SERVICE, SAMPLE_CMDLINE,
                                       self.description_factory)

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyTCPServer()

    def test_initialization(self):
        """Test the constructor."""
        self.config = ActivationConfig(SAMPLE_SERVICE, SAMPLE_CMDLINE,
                                       self.description_factory)
        ai = ActivationDetector(self.config)
        self.assertEqual(ai.config, self.config)

    @defer.inlineCallbacks
    def test_is_not_already_running(self):
        """Test the is_already_running method returns False."""
        ad = ActivationDetector(self.config)
        result = yield ad.is_already_running()
        self.assertFalse(result, "It should not be already running.")

    @defer.inlineCallbacks
    def test_is_already_running(self):
        """The is_already_running method returns True if already started."""
        server = self.get_server()
        self.addCleanup(server.clean_up)

        class TestConnect(object):
            """A fake connection object."""

            @defer.inlineCallbacks
            def connect(my_self, factory):
                """A fake connection."""
                conn_fact = yield server.connect_client(PortDetectFactory)
                self.patch(factory, 'is_listening', conn_fact.is_listening)
                defer.returnValue(conn_fact)

        self.patch(
            tcpactivation, 'clientFromString', lambda *args: TestConnect())

        yield server.listen_server(protocol.ServerFactory)

        ad = ActivationDetector(self.config)
        result = yield ad.is_already_running()
        self.assertTrue(result, "It should be already running.")


class ActivationClientTestCase(TestCase):
    """Tests for the ActivationClient class."""

    timeout = 2

    server_description = 'tcp:55555:interface=127.0.0.1'
    client_description = 'tcp:host=127.0.0.1:port=55555'

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(ActivationClientTestCase, self).setUp()
        self.description_factory = FakeDescriptionFactory(
            self.server_description,
            self.client_description)
        self.config = ActivationConfig(SAMPLE_SERVICE, SAMPLE_CMDLINE,
                                       self.description_factory)

    def test_initialization(self):
        """Test the constructor."""
        ac = ActivationClient(self.config)
        self.assertEqual(ac.config, self.config)

    @defer.inlineCallbacks
    def test_do_get_active_description_running(self):
        """Test the _do_get_active_description method when is running."""
        ac = ActivationClient(self.config)
        self.patch(ac, "is_already_running", lambda: defer.succeed(True))
        result = yield ac._do_get_active_description()
        self.assertEqual(result, self.client_description)

    @defer.inlineCallbacks
    def test_do_get_active_description_not_running(self):
        """Test _do_get_active_description method when is not running."""
        server_spawned = []
        ac = ActivationClient(self.config)
        self.patch(
            ac, "_spawn_server", lambda *args: server_spawned.append(args))
        self.patch(ac, "is_already_running", lambda: defer.succeed(False))
        self.patch(ac, "_wait_server_active", lambda: defer.succeed(None))
        result = yield ac._do_get_active_description()
        self.assertEqual(result, self.client_description)
        self.assertEqual(len(server_spawned), 1)

    def test_get_active_description_waits_classwide(self):
        """Test the get_active_description method locks classwide."""
        d = defer.Deferred()
        ac1 = ActivationClient(self.config)
        ac2 = ActivationClient(self.config)
        self.patch(ac1, "_do_get_active_description", lambda: d)
        self.patch(ac2, "_do_get_active_description",
                   lambda: defer.succeed(None))
        ac1.get_active_client_description()
        d2 = ac2.get_active_client_description()
        self.assertFalse(d2.called, "The second must wait for the first.")
        d.callback(self.client_description)
        self.assertTrue(d2.called, "The second can fire after the first.")

    def test_wait_server_active(self):
        """Test the _wait_server_active method."""
        ac = ActivationClient(self.config)
        clock = task.Clock()
        self.patch(twisted.internet, "reactor", clock)
        self.patch(ac, "is_already_running", lambda: defer.succeed(False))

        d = ac._wait_server_active()

        self.assertFalse(d.called, "The deferred should not be fired yet.")
        clock.advance(tcpactivation.DELAY_BETWEEN_CHECKS)
        self.assertFalse(d.called, "The deferred should not be fired yet.")
        self.patch(ac, "is_already_running", lambda: defer.succeed(True))
        clock.advance(tcpactivation.DELAY_BETWEEN_CHECKS)
        self.assertTrue(d.called, "The deferred should be fired by now.")

    def test_wait_server_timeouts(self):
        """If the server takes too long to start then timeout."""
        ac = ActivationClient(self.config)
        clock = task.Clock()
        self.patch(twisted.internet, "reactor", clock)
        self.patch(ac, "is_already_running", lambda: defer.succeed(False))
        d = ac._wait_server_active()
        clock.pump([tcpactivation.DELAY_BETWEEN_CHECKS] *
                   tcpactivation.NUMBER_OF_CHECKS)
        return self.assertFailure(d, ActivationTimeoutError)

    def test_spawn_server(self):
        """Test the _spawn_server method."""
        popen_calls = []
        ac = ActivationClient(self.config)
        self.patch(tcpactivation.subprocess, "Popen",
                   lambda *args, **kwargs: popen_calls.append((args, kwargs)))
        ac._spawn_server()
        self.assertEqual(len(popen_calls), 1)


class ActivationInstanceTestCase(ServerTestCase):
    """Tests for the ActivationServer class."""

    timeout = 2

    server_description = 'tcp:55555:interface=127.0.0.1'
    client_description = 'tcp:host=127.0.0.1:port=55555'

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(ActivationInstanceTestCase, self).setUp()
        self.description_factory = FakeDescriptionFactory(
            self.server_description,
            self.client_description)
        self.config = ActivationConfig(SAMPLE_SERVICE, SAMPLE_CMDLINE,
                                       self.description_factory)

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyTCPServer()

    def test_initialization(self):
        """Test the constructor."""
        ai = ActivationInstance(self.config)
        self.assertEqual(ai.config, self.config)

    @defer.inlineCallbacks
    def test_get_sever_description(self):
        """Test the get_description method."""
        ai = ActivationInstance(self.config)
        self.patch(ai, 'is_already_running', lambda: False)

        description = yield ai.get_server_description()
        self.assertEqual(description, self.server_description)

    @defer.inlineCallbacks
    def test_get_description_fails_if_service_already_started(self):
        """The get_description method fails if service already started."""
        server = self.get_server()
        self.addCleanup(server.clean_up)

        class TestConnect(object):
            """A fake connection object."""

            @defer.inlineCallbacks
            def connect(my_self, factory):
                """A fake connection."""
                conn_fact = yield server.connect_client(PortDetectFactory)
                self.patch(factory, 'is_listening', conn_fact.is_listening)
                defer.returnValue(conn_fact)

        self.patch(
            tcpactivation, 'clientFromString', lambda *args: TestConnect())

        yield server.listen_server(protocol.ServerFactory)

        ai = ActivationInstance(self.config)
        yield self.assertFailure(ai.get_server_description(),
                                 AlreadyStartedError)


def server_test(config):
    """An IRL test of the server."""
    from twisted.internet import reactor

    def got_description(description):
        """The description was found."""
        print("got server description:", description)

        # start listening
        f = FakeServerFactory()
        reactor.listenTCP(description, f)

        # try to get the description again
        get_description()

    def already_started(failure):
        """This instance was already started."""
        print("already started!")
        reactor.callLater(3, reactor.stop)

    def get_description():
        """Try to get the description number."""
        get_description_d = ai.get_server_description()
        get_description_d.addCallback(got_description)
        get_description_d.addErrback(already_started)

    print("starting the server.")
    ai = ActivationInstance(config)
    get_description()
    reactor.run()


def client_test(config):
    """An IRL test of the client."""
    from twisted.internet import reactor
    print("starting the client.")
    ac = ActivationClient(config)
    d = ac.get_active_client_description()

    def got_description(description):
        """The description was found."""
        print("client got server description:", description)
        reactor.stop()

    d.addCallback(got_description)
    reactor.run()


def irl_test():
    """Do an IRL test of the client and the server."""
    import sys
    description_f = FakeDescriptionFactory(SAMPLE_SERVER_DESCRIPTION,
                                           SAMPLE_CLIENT_DESCRIPTION)
    config = ActivationConfig(SAMPLE_SERVICE, SAMPLE_CMDLINE, description_f)
    if "-server" in sys.argv[1:]:
        server_test(config)
    else:
        client_test(config)

if __name__ == "__main__":
    irl_test()
