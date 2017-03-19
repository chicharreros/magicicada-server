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
"""Tests for the proxy tunnel."""

from twisted.internet import defer, protocol, ssl
from twisted.trial.unittest import TestCase
from twisted.web import client

from ubuntuone.devtools.testcases.squid import SquidTestCase

from ubuntuone.proxy.tests import (
    FakeTransport,
    FAKE_COOKIE,
    MockWebServer,
    SAMPLE_CONTENT,
    SIMPLERESOURCE,
)
from ubuntuone.proxy import tunnel_client
from ubuntuone.proxy.tunnel_client import CRLF, TunnelClient
from ubuntuone.proxy.tunnel_server import TunnelServer


FAKE_HEADER = (
    "HTTP/1.0 200 Connected!" + CRLF +
    "Header1: value1" + CRLF +
    "Header2: value2" + CRLF +
    CRLF
)


class SavingProtocol(protocol.Protocol):
    """A protocol that saves all that it receives."""

    def __init__(self):
        """Initialize this protocol."""
        self.saved_data = None

    def connectionMade(self):
        """The connection was made, start saving."""
        self.saved_data = []

    def dataReceived(self, data):
        """Save the data received."""
        self.saved_data.append(data)

    @property
    def content(self):
        """All the content so far."""
        return "".join(self.saved_data)


class TunnelClientProtocolTestCase(TestCase):
    """Tests for the client side tunnel protocol."""

    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(TunnelClientProtocolTestCase, self).setUp()
        self.host, self.port = "9.9.9.9", 8765
        fake_addr = object()
        self.cookie = FAKE_COOKIE
        self.other_proto = SavingProtocol()
        other_factory = protocol.ClientFactory()
        other_factory.buildProtocol = lambda _addr: self.other_proto
        tunnel_client_factory = tunnel_client.TunnelClientFactory(
            self.host, self.port, other_factory, self.cookie)
        tunnel_client_proto = tunnel_client_factory.buildProtocol(fake_addr)
        tunnel_client_proto.transport = FakeTransport()
        tunnel_client_proto.connectionMade()
        self.tunnel_client_proto = tunnel_client_proto

    def test_sends_connect_request(self):
        """Sends the expected CONNECT request."""
        expected = tunnel_client.METHOD_LINE % (self.host, self.port)
        written = self.tunnel_client_proto.transport.getvalue()
        first_line = written.split(CRLF)[0]
        self.assertEqual(first_line + CRLF, expected)
        self.assertTrue(written.endswith(CRLF * 2),
                        "Ends with a double CRLF")

    def test_sends_cookie_header(self):
        """Sends the expected cookie header."""
        expected = "%s: %s" % (tunnel_client.TUNNEL_COOKIE_HEADER, self.cookie)
        written = self.tunnel_client_proto.transport.getvalue()
        headers = written.split(CRLF)[1:]
        self.assertIn(expected, headers)

    def test_handles_successful_connection(self):
        """A successful connection is handled."""
        self.tunnel_client_proto.dataReceived(FAKE_HEADER)
        self.assertEqual(self.tunnel_client_proto.status_code, "200")

    def test_protocol_is_switched(self):
        """The protocol is switched after the headers are received."""
        expected = (SAMPLE_CONTENT + CRLF) * 2
        self.tunnel_client_proto.dataReceived(FAKE_HEADER + SAMPLE_CONTENT)
        self.other_proto.dataReceived(CRLF + SAMPLE_CONTENT + CRLF)
        self.assertEqual(self.other_proto.content, expected)


class FakeOtherFactory(object):
    """A fake factory."""

    def __init__(self):
        """Initialize this fake."""
        self.started_called = None
        self.failed_called = None
        self.lost_called = None

    def startedConnecting(self, *args):
        """Store the call."""
        self.started_called = args

    def clientConnectionFailed(self, *args):
        """Store the call."""
        self.failed_called = args

    def clientConnectionLost(self, *args):
        """Store the call."""
        self.lost_called = args


class TunnelClientFactoryTestCase(TestCase):
    """Tests for the TunnelClientFactory."""

    def test_forwards_started(self):
        """The factory forwards the startedConnecting call."""
        fake_other_factory = FakeOtherFactory()
        tcf = tunnel_client.TunnelClientFactory(None, None, fake_other_factory,
                                                FAKE_COOKIE)
        fake_connector = object()
        tcf.startedConnecting(fake_connector)
        self.assertEqual(fake_other_factory.started_called, (fake_connector,))

    def test_forwards_failed(self):
        """The factory forwards the clientConnectionFailed call."""
        fake_reason = object()
        fake_other_factory = FakeOtherFactory()
        tcf = tunnel_client.TunnelClientFactory(None, None, fake_other_factory,
                                                FAKE_COOKIE)
        fake_connector = object()
        tcf.clientConnectionFailed(fake_connector, fake_reason)
        self.assertEqual(fake_other_factory.failed_called,
                         (fake_connector, fake_reason))

    def test_forwards_lost(self):
        """The factory forwards the clientConnectionLost call."""
        fake_reason = object()
        fake_other_factory = FakeOtherFactory()
        tcf = tunnel_client.TunnelClientFactory(None, None, fake_other_factory,
                                                FAKE_COOKIE)
        fake_connector = object()
        tcf.clientConnectionLost(fake_connector, fake_reason)
        self.assertEqual(fake_other_factory.lost_called,
                         (fake_connector, fake_reason))


class TunnelClientTestCase(SquidTestCase):
    """Test the client for the tunnel."""

    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(TunnelClientTestCase, self).setUp()
        self.ws = MockWebServer()
        self.addCleanup(self.ws.stop)
        self.dest_url = self.ws.get_iri().encode("utf-8") + SIMPLERESOURCE
        self.dest_ssl_url = (
            self.ws.get_ssl_iri().encode("utf-8") + SIMPLERESOURCE)
        self.cookie = FAKE_COOKIE
        self.tunnel_server = TunnelServer(self.cookie)
        self.addCleanup(self.tunnel_server.shutdown)

    @defer.inlineCallbacks
    def test_connects_right(self):
        """Uses the CONNECT method on the tunnel."""
        tunnel_client = TunnelClient("0.0.0.0", self.tunnel_server.port,
                                     self.cookie)
        factory = client.HTTPClientFactory(self.dest_url)
        scheme, host, port, path = client._parse(self.dest_url)
        tunnel_client.connectTCP(host, port, factory)
        result = yield factory.deferred
        self.assertEqual(result, SAMPLE_CONTENT)

    @defer.inlineCallbacks
    def test_starts_tls_connection(self):
        """TLS is started after connecting; control passed to the client."""
        tunnel_client = TunnelClient(
            "0.0.0.0", self.tunnel_server.port, self.cookie)
        factory = client.HTTPClientFactory(self.dest_ssl_url)
        scheme, host, port, path = client._parse(self.dest_ssl_url)
        context_factory = ssl.ClientContextFactory()
        tunnel_client.connectSSL(host, port, factory, context_factory)
        result = yield factory.deferred
        self.assertEqual(result, SAMPLE_CONTENT)
