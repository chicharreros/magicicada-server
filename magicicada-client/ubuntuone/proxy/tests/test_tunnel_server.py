# -*- coding: utf-8 -*-
#
# Copyright 2012-2013 Canonical Ltd.
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

from StringIO import StringIO
from urlparse import urlparse

from twisted.internet import defer, protocol, reactor
from twisted.trial.unittest import TestCase
from PyQt4.QtCore import QCoreApplication
from PyQt4.QtNetwork import QAuthenticator
from ubuntuone.devtools.testcases import skipIfOS
from ubuntuone.devtools.testcases.squid import SquidTestCase

from ubuntuone.proxy.tests import (
    FakeTransport,
    FAKE_COOKIE,
    MockWebServer,
    SAMPLE_CONTENT,
    SIMPLERESOURCE,
)
from ubuntuone.proxy import tunnel_server
from ubuntuone.proxy.tunnel_server import CRLF


FAKE_SESSION_TEMPLATE = (
    "CONNECT %s HTTP/1.0" + CRLF +
    "Header1: value1" + CRLF +
    "Header2: value2" + CRLF +
    tunnel_server.TUNNEL_COOKIE_HEADER + ": %s" + CRLF +
    CRLF +
    "GET %s HTTP/1.0" + CRLF + CRLF
)

FAKE_SETTINGS = {
    "http": {
        "host": "myhost",
        "port": 8888,
    }
}

FAKE_AUTH_SETTINGS = {
    "http": {
        "host": "myhost",
        "port": 8888,
        "username": "fake_user",
        "password": "fake_password",
    }
}

SAMPLE_HOST = "samplehost.com"
SAMPLE_PORT = 443

FAKE_CREDS = {
    "username": "rhea",
    "password": "caracolcaracola",
}


class DisconnectingProtocol(protocol.Protocol):
    """A protocol that just disconnects."""

    def connectionMade(self):
        """Upon connecting: just disconnect."""
        self.transport.loseConnection()


class DisconnectingClientFactory(protocol.ClientFactory):
    """A factory that fires a deferred on connection."""

    def __init__(self):
        """Initialize this instance."""
        self.connected = defer.Deferred()

    def buildProtocol(self, addr):
        """The connection was made."""
        proto = DisconnectingProtocol()
        if not self.connected.called:
            self.connected.callback(proto)
        return proto


class FakeProtocol(protocol.Protocol):
    """A protocol that forwards some data."""

    def __init__(self, factory, data):
        """Initialize this fake."""
        self.factory = factory
        self.data = data
        self.received_data = []

    def connectionMade(self):
        """Upon connection: send the stored data."""
        self.transport.write(self.data)

    def dataReceived(self, data):
        """Some data was received."""
        self.received_data.append(data)

    def connectionLost(self, reason):
        """The connection was lost, return the response."""
        response = "".join(self.received_data)
        if not self.factory.response.called:
            self.factory.response.callback(response)


class FakeClientFactory(protocol.ClientFactory):
    """A factory that forwards some data to the protocol."""

    def __init__(self, data):
        """Initialize this fake."""
        self.data = data
        self.response = defer.Deferred()

    def buildProtocol(self, addr):
        """The connection was made."""
        return FakeProtocol(self, self.data)


class TunnelIntegrationTestCase(SquidTestCase):
    """Basic tunnel integration tests."""

    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(TunnelIntegrationTestCase, self).setUp()
        self.ws = MockWebServer()
        self.addCleanup(self.ws.stop)
        self.dest_url = self.ws.get_iri().encode("utf-8") + SIMPLERESOURCE
        self.cookie = FAKE_COOKIE
        self.tunnel_server = tunnel_server.TunnelServer(self.cookie)
        self.addCleanup(self.tunnel_server.shutdown)

    def test_init(self):
        """The tunnel is started."""
        self.assertNotEqual(self.tunnel_server.port, 0)

    @defer.inlineCallbacks
    def test_accepts_connections(self):
        """The tunnel accepts incoming connections."""
        ncf = DisconnectingClientFactory()
        reactor.connectTCP("0.0.0.0", self.tunnel_server.port, ncf)
        yield ncf.connected

    @defer.inlineCallbacks
    def test_complete_connection(self):
        """Test from the tunnel server down."""
        url = urlparse(self.dest_url)
        fake_session = FAKE_SESSION_TEMPLATE % (
                                    url.netloc, self.cookie, url.path)
        client = FakeClientFactory(fake_session)
        reactor.connectTCP("0.0.0.0", self.tunnel_server.port, client)
        response = yield client.response
        self.assertIn(SAMPLE_CONTENT, response)


class FakeClient(object):
    """A fake destination client."""

    protocol = None
    connection_result = defer.succeed(True)
    credentials = None
    check_credentials = False
    proxy_domain = None

    def connect(self, hostport):
        """Establish a connection with the other end."""
        if (self.check_credentials and
                self.protocol.proxy_credentials != FAKE_CREDS):
            self.proxy_domain = "fake domain"
            return defer.fail(tunnel_server.ProxyAuthenticationError())
        return self.connection_result

    def write(self, data):
        """Write some data to the other end."""
        if data == 'GET /simpleresource HTTP/1.0\r\n\r\n':
            self.protocol.transport.write(SAMPLE_CONTENT)

    def stop(self):
        """Stop this fake client."""

    def close(self):
        """Reset this client."""


class ServerTunnelProtocolTestCase(SquidTestCase):
    """Tests for the ServerTunnelProtocol."""

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(ServerTunnelProtocolTestCase, self).setUp()
        self.ws = MockWebServer()
        self.addCleanup(self.ws.stop)
        self.dest_url = self.ws.get_iri().encode("utf-8") + SIMPLERESOURCE
        self.transport = FakeTransport()
        self.transport.cookie = FAKE_COOKIE
        self.fake_client = FakeClient()
        self.proto = tunnel_server.ServerTunnelProtocol(
                                                lambda _: self.fake_client)
        self.fake_client.protocol = self.proto
        self.proto.transport = self.transport
        self.cookie_line = "%s: %s" % (tunnel_server.TUNNEL_COOKIE_HEADER,
                                       FAKE_COOKIE)

    def test_broken_request(self):
        """Broken request."""
        self.proto.dataReceived("Broken request." + CRLF)
        self.assertTrue(self.transport.getvalue().startswith("HTTP/1.0 400 "),
                        "A broken request must fail.")

    def test_wrong_method(self):
        """Wrong method."""
        self.proto.dataReceived("GET http://slashdot.org HTTP/1.0" + CRLF)
        self.assertTrue(self.transport.getvalue().startswith("HTTP/1.0 405 "),
                        "Using a wrong method fails.")

    def test_invalid_http_version(self):
        """Invalid HTTP version."""
        self.proto.dataReceived("CONNECT 127.0.0.1:9999 HTTP/1.1" + CRLF)
        self.assertTrue(self.transport.getvalue().startswith("HTTP/1.0 505 "),
                        "Invalid http version is not allowed.")

    def test_connection_is_established(self):
        """The response code is sent."""
        expected = "HTTP/1.0 200 Proxy connection established" + CRLF
        self.proto.dataReceived("CONNECT 127.0.0.1:9999 HTTP/1.0" + CRLF +
                                self.cookie_line + CRLF * 2)
        self.assertTrue(self.transport.getvalue().startswith(expected),
                        "First line must be the response status")

    def test_connection_fails(self):
        """The connection to the other end fails, and it's handled."""
        error = tunnel_server.ConnectionError()
        self.patch(self.fake_client, "connection_result", defer.fail(error))
        expected = "HTTP/1.0 500 Connection error" + CRLF
        self.proto.dataReceived("CONNECT 127.0.0.1:9999 HTTP/1.0" + CRLF +
                                self.cookie_line + CRLF * 2)
        self.assertTrue(self.transport.getvalue().startswith(expected),
                        "The connection should fail at this point.")

    def test_headers_stored(self):
        """The request headers are stored."""
        expected = [
            ("Header1", "value1"),
            ("Header2", "value2"),
        ]
        self.proto.dataReceived("CONNECT 127.0.0.1:9999 HTTP/1.0" + CRLF +
                                "Header1: value1" + CRLF +
                                "Header2: value2" + CRLF + CRLF)
        self.assertEqual(self.proto.received_headers, expected)

    def test_cookie_header_present(self):
        """The cookie header must be present."""
        self.proto.received_headers = [
            (tunnel_server.TUNNEL_COOKIE_HEADER, FAKE_COOKIE),
        ]
        self.proto.verify_cookie()

    def test_cookie_header_absent(self):
        """The tunnel should refuse connections without the cookie."""
        self.proto.received_headers = []
        exception = self.assertRaises(tunnel_server.ConnectionError,
                                      self.proto.verify_cookie)
        self.assertEqual(exception.code, 418)

    def test_successful_connect(self):
        """A successful connect thru the tunnel."""
        url = urlparse(self.dest_url)
        data = FAKE_SESSION_TEMPLATE % (url.netloc, self.transport.cookie,
                                        url.path)
        self.proto.dataReceived(data)
        lines = self.transport.getvalue().split(CRLF)
        self.assertEqual(lines[-1], SAMPLE_CONTENT)

    def test_header_split(self):
        """Test a header with many colons."""
        self.proto.header_line("key: host:port")
        self.assertIn("key", dict(self.proto.received_headers))

    @defer.inlineCallbacks
    def test_keyring_credentials_are_retried(self):
        """Wrong credentials are retried with values from keyring."""
        self.fake_client.check_credentials = True
        self.patch(self.proto, "verify_cookie", lambda: None)
        self.patch(self.proto, "error_response",
                   lambda code, desc: self.fail(desc))
        self.proto.proxy_domain = "xxx"
        self.patch(tunnel_server.Keyring, "get_credentials",
                   lambda _, domain: defer.succeed(FAKE_CREDS))
        yield self.proto.headers_done()

    def test_creds_are_not_logged(self):
        """The proxy credentials are not logged."""
        log = []
        self.patch(tunnel_server.logger, "info",
                   lambda text, *args: log.append(text % args))
        proxy = tunnel_server.build_proxy(FAKE_AUTH_SETTINGS)
        authenticator = QAuthenticator()
        username = FAKE_AUTH_SETTINGS["http"]["username"]
        password = FAKE_AUTH_SETTINGS["http"]["password"]
        self.proto.proxy_credentials = {
            "username": username,
            "password": password,
        }
        self.proto.proxy_domain = proxy.hostName()

        self.proto.proxy_auth_required(proxy, authenticator)

        for line in log:
            self.assertNotIn(username, line)
            self.assertNotIn(password, line)


class FakeServerTunnelProtocol(object):
    """A fake ServerTunnelProtocol."""

    def __init__(self):
        """Initialize this fake tunnel."""
        self.response_received = defer.Deferred()
        self.proxy_credentials = None

    def response_data_received(self, data):
        """Fire the response deferred."""
        if not self.response_received.called:
            self.response_received.callback(data)

    def remote_disconnected(self):
        """The remote server disconnected."""

    def proxy_auth_required(self, proxy, authenticator):
        """Proxy credentials are needed."""
        if self.proxy_credentials:
            authenticator.setUser(self.proxy_credentials["username"])
            authenticator.setPassword(self.proxy_credentials["password"])


class BuildProxyTestCase(TestCase):
    """Tests for the build_proxy function."""

    def test_socks_is_preferred(self):
        """Socks overrides all protocols."""
        settings = {
            "http": {"host": "httphost", "port": 3128},
            "https": {"host": "httpshost", "port": 3129},
            "socks": {"host": "sockshost", "port": 1080},
        }
        proxy = tunnel_server.build_proxy(settings)
        self.assertEqual(proxy.type(), proxy.Socks5Proxy)
        self.assertEqual(proxy.hostName(), "sockshost")
        self.assertEqual(proxy.port(), 1080)

    def test_https_beats_http(self):
        """HTTPS wins over HTTP, since all of SD traffic is https."""
        settings = {
            "http": {"host": "httphost", "port": 3128},
            "https": {"host": "httpshost", "port": 3129},
        }
        proxy = tunnel_server.build_proxy(settings)
        self.assertEqual(proxy.type(), proxy.HttpProxy)
        self.assertEqual(proxy.hostName(), "httpshost")
        self.assertEqual(proxy.port(), 3129)

    def test_http_if_no_other_choice(self):
        """Finally, we use the host configured for HTTP."""
        settings = {
            "http": {"host": "httphost", "port": 3128},
        }
        proxy = tunnel_server.build_proxy(settings)
        self.assertEqual(proxy.type(), proxy.HttpProxy)
        self.assertEqual(proxy.hostName(), "httphost")
        self.assertEqual(proxy.port(), 3128)

    def test_use_noproxy_as_fallback(self):
        """If nothing useful, revert to no proxy."""
        settings = {}
        proxy = tunnel_server.build_proxy(settings)
        self.assertEqual(proxy.type(), proxy.DefaultProxy)


class RemoteSocketTestCase(SquidTestCase):
    """Tests for the client that connects to the other side."""

    timeout = 3

    def get_proxy_settings(self):
        return {}

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(RemoteSocketTestCase, self).setUp()
        self.ws = MockWebServer()
        self.addCleanup(self.ws.stop)
        self.dest_url = self.ws.get_iri().encode("utf-8") + SIMPLERESOURCE

        self.addCleanup(tunnel_server.QNetworkProxy.setApplicationProxy,
                        tunnel_server.QNetworkProxy.applicationProxy())
        settings = {"http": self.get_proxy_settings()}
        proxy = tunnel_server.build_proxy(settings)
        tunnel_server.QNetworkProxy.setApplicationProxy(proxy)

    def test_invalid_port(self):
        """A request with an invalid port fails with a 400."""
        protocol = tunnel_server.ServerTunnelProtocol(
                                                    tunnel_server.RemoteSocket)
        protocol.transport = FakeTransport()
        protocol.dataReceived("CONNECT 127.0.0.1:wrong_port HTTP/1.0" +
                              CRLF * 2)

        status_line = protocol.transport.getvalue()
        self.assertTrue(status_line.startswith("HTTP/1.0 400 "),
                        "The port must be an integer.")

    @defer.inlineCallbacks
    def test_connection_is_finished_when_stopping(self):
        """The client disconnects when requested."""
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        url = urlparse(self.dest_url)
        yield client.connect(url.netloc)
        yield client.stop()

    @defer.inlineCallbacks
    def test_stop_but_never_connected(self):
        """Stop but it was never connected."""
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        yield client.stop()

    @defer.inlineCallbacks
    def test_client_write(self):
        """Data written to the client is sent to the other side."""
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        self.addCleanup(client.stop)
        url = urlparse(self.dest_url)
        yield client.connect(url.netloc)
        client.write("GET /simpleresource HTTP/1.0" + CRLF * 2)
        yield self.ws.simple_resource.rendered

    @defer.inlineCallbacks
    def test_client_read(self):
        """Data received by the client is written into the transport."""
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        self.addCleanup(client.stop)
        url = urlparse(self.dest_url)
        yield client.connect(url.netloc)
        client.write("GET /simpleresource HTTP/1.0" + CRLF * 2)
        yield self.ws.simple_resource.rendered
        data = yield fake_protocol.response_received
        _headers, content = str(data).split(CRLF * 2, 1)
        self.assertEqual(content, SAMPLE_CONTENT)


class AnonProxyRemoteSocketTestCase(RemoteSocketTestCase):
    """Tests for the client going thru an anonymous proxy."""

    get_proxy_settings = RemoteSocketTestCase.get_nonauth_proxy_settings

    def parse_headers(self, raw_headers):
        """Parse the headers."""
        lines = raw_headers.split(CRLF)
        header_lines = lines[1:]
        headers_pairs = (l.split(":", 1) for l in header_lines)
        return dict((k.lower(), v.strip()) for k, v in headers_pairs)

    @defer.inlineCallbacks
    def test_verify_client_uses_proxy(self):
        """Verify that the client uses the proxy."""
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        self.addCleanup(client.stop)
        url = urlparse(self.dest_url)
        yield client.connect(url.netloc)
        client.write("GET /simpleresource HTTP/1.0" + CRLF * 2)
        yield self.ws.simple_resource.rendered
        data = yield fake_protocol.response_received
        raw_headers, _content = str(data).split(CRLF * 2, 1)
        self.parse_headers(raw_headers)


@skipIfOS('linux2', 'LP: #1111880 - ncsa_auth crashing for auth proxy tests.')
class AuthenticatedProxyRemoteSocketTestCase(AnonProxyRemoteSocketTestCase):
    """Tests for the client going thru an authenticated proxy."""

    get_proxy_settings = RemoteSocketTestCase.get_auth_proxy_settings

    @defer.inlineCallbacks
    def test_proxy_authentication_error(self):
        """The proxy credentials were wrong on purpose."""
        settings = {"http": self.get_proxy_settings()}
        settings["http"]["password"] = "wrong password!!!"
        proxy = tunnel_server.build_proxy(settings)
        tunnel_server.QNetworkProxy.setApplicationProxy(proxy)
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        self.addCleanup(client.stop)
        url = urlparse(self.dest_url)
        yield self.assertFailure(client.connect(url.netloc),
                                 tunnel_server.ProxyAuthenticationError)

    @defer.inlineCallbacks
    def test_proxy_nobody_listens(self):
        """The proxy settings point to a proxy that's unreachable."""
        settings = dict(http={
            "host": "127.0.0.1",
            "port": 83,  # unused port according to /etc/services
        })
        proxy = tunnel_server.build_proxy(settings)
        tunnel_server.QNetworkProxy.setApplicationProxy(proxy)
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        self.addCleanup(client.stop)
        url = urlparse(self.dest_url)
        yield self.assertFailure(client.connect(url.netloc),
                                 tunnel_server.ConnectionError)

    def test_use_credentials(self):
        """The credentials are used if present."""
        fake_protocol = FakeServerTunnelProtocol()
        client = tunnel_server.RemoteSocket(fake_protocol)
        proxy = tunnel_server.build_proxy(FAKE_SETTINGS)
        authenticator = QAuthenticator()

        client.proxyAuthenticationRequired.emit(proxy, authenticator)
        self.assertEqual(proxy.user(), "")
        self.assertEqual(proxy.password(), "")
        fake_protocol.proxy_credentials = FAKE_CREDS

        client.proxyAuthenticationRequired.emit(proxy, authenticator)
        self.assertEqual(authenticator.user(), FAKE_CREDS["username"])
        self.assertEqual(authenticator.password(), FAKE_CREDS["password"])


class FakeNetworkProxyFactoryClass(object):
    """A fake QNetworkProxyFactory."""
    last_query = None
    use_system = False

    def __init__(self, enabled):
        """Initialize this fake instance."""
        if enabled:
            self.proxy_type = tunnel_server.QNetworkProxy.HttpProxy
        else:
            self.proxy_type = tunnel_server.QNetworkProxy.NoProxy

    def type(self):
        """Return the proxy type configured."""
        return self.proxy_type

    @classmethod
    def setUseSystemConfiguration(cls, new_value):
        """Save the system configuration requested."""
        cls.use_system = new_value

    @classmethod
    def useSystemConfiguration(cls):
        """Is the system configured for proxies?"""
        return cls.use_system

    def systemProxyForQuery(self, query):
        """A list of proxies, but only type() will be called on the first."""
        return [self]


class CheckProxyEnabledTestCase(TestCase):
    """Tests for the check_proxy_enabled function."""

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(CheckProxyEnabledTestCase, self).setUp()
        self.app_proxy = []

    def _assert_proxy_state(self, platform, state, assertion):
        """Assert the proxy is in a given state."""
        self.patch(tunnel_server.QNetworkProxy, "setApplicationProxy",
                   lambda proxy: self.app_proxy.append(proxy))
        self.patch(tunnel_server.sys, "platform", platform)
        ret = tunnel_server.check_proxy_enabled(SAMPLE_HOST, str(SAMPLE_PORT))
        self.assertTrue(ret == state, assertion)

    def _assert_proxy_enabled(self, platform):
        """Assert that the proxy is enabled."""
        self._assert_proxy_state(platform, True, "Proxy is enabled.")

    def _assert_proxy_disabled(self, platform):
        """Assert that the proxy is disabled."""
        self._assert_proxy_state(platform, False, "Proxy is disabled.")

    def test_platform_linux_enabled(self):
        """Tests for the linux platform with proxies enabled."""
        self.patch(tunnel_server.gsettings, "get_proxy_settings",
                   lambda: FAKE_SETTINGS)
        self._assert_proxy_enabled("linux3")
        self.assertEqual(len(self.app_proxy), 1)

    def test_platform_linux_disabled(self):
        """Tests for the linux platform with proxies disabled."""
        self.patch(tunnel_server.gsettings, "get_proxy_settings", lambda: {})
        self._assert_proxy_disabled("linux3")
        self.assertEqual(len(self.app_proxy), 0)

    def test_platform_other_enabled(self):
        """Tests for any other platform with proxies enabled."""
        fake_netproxfact = FakeNetworkProxyFactoryClass(True)
        self.patch(tunnel_server, "QNetworkProxyFactory", fake_netproxfact)
        self._assert_proxy_enabled("windows 1.0")
        self.assertEqual(len(self.app_proxy), 0)
        self.assertTrue(fake_netproxfact.useSystemConfiguration())

    def test_platform_other_disabled(self):
        """Tests for any other platform with proxies disabled."""
        fake_netproxfact = FakeNetworkProxyFactoryClass(False)
        self.patch(tunnel_server, "QNetworkProxyFactory", fake_netproxfact)
        self._assert_proxy_disabled("windows 1.0")
        self.assertEqual(len(self.app_proxy), 0)
        self.assertTrue(fake_netproxfact.useSystemConfiguration())


class FakeQCoreApp(object):
    """A fake QCoreApplication."""

    fake_instance = None

    def __init__(self, argv):
        """Initialize this fake."""
        self.executed = False
        self.argv = argv
        FakeQCoreApp.fake_instance = self

    def exec_(self):
        """Fake the execution of this app."""
        self.executed = True

    @staticmethod
    def instance():
        """But return the real instance."""
        return QCoreApplication.instance()


class MainFunctionTestCase(TestCase):
    """Tests for the main function of the tunnel server."""

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize these testcases."""
        yield super(MainFunctionTestCase, self).setUp()
        self.called = []
        self.proxies_enabled = False

        def fake_is_proxy_enabled(*args):
            """Store the call, return false."""
            self.called.append(args)
            return self.proxies_enabled

        self.patch(tunnel_server, "check_proxy_enabled", fake_is_proxy_enabled)
        self.fake_stdout = StringIO()
        self.patch(tunnel_server.sys, "stdout", self.fake_stdout)
        self.patch(tunnel_server, "QCoreApplication", FakeQCoreApp)

    def test_checks_proxies(self):
        """Main checks that the proxies are enabled."""
        tunnel_server.main([])
        self.assertEqual(len(self.called), 1)

    def test_on_proxies_enabled_prints_port_and_cookie(self):
        """With proxies enabled print port to stdout and start the mainloop."""
        self.patch(tunnel_server.uuid, "uuid4", lambda: FAKE_COOKIE)
        self.proxies_enabled = True
        port = 443
        tunnel_server.main(["example.com", str(port)])
        stdout = self.fake_stdout.getvalue()

        self.assertIn(tunnel_server.TUNNEL_PORT_LABEL + ": ", stdout)
        cookie_line = tunnel_server.TUNNEL_COOKIE_LABEL + ": " + FAKE_COOKIE
        self.assertIn(cookie_line, stdout)

    def test_on_proxies_disabled_exit(self):
        """With proxies disabled, print a message and exit gracefully."""
        self.proxies_enabled = False
        tunnel_server.main(["example.com", "443"])
        self.assertIn("Proxy not enabled.", self.fake_stdout.getvalue())
        self.assertEqual(FakeQCoreApp.fake_instance, None)

    def test_qtdbus_installed_on_linux(self):
        """The QtDbus mainloop is installed."""
        self.patch(tunnel_server.sys, "platform", "linux123")
        installed = []
        self.patch(
            tunnel_server, "install_qt_dbus", lambda: installed.append(None))
        self.proxies_enabled = True
        tunnel_server.main(["example.com", "443"])
        self.assertEqual(len(installed), 1)

    def test_qtdbus_not_installed_on_windows(self):
        """The QtDbus mainloop is installed."""
        self.patch(tunnel_server.sys, "platform", "win98")
        installed = []
        self.patch(
            tunnel_server, "install_qt_dbus", lambda: installed.append(None))
        self.proxies_enabled = True
        tunnel_server.main(["example.com", "443"])
        self.assertEqual(len(installed), 0)

    def test_fix_turkish_locale_called(self):
        """The fix_turkish_locale function is called, always."""
        called = []
        self.patch(
            tunnel_server, "fix_turkish_locale",
            lambda *args, **kwargs: called.append((args, kwargs)))
        tunnel_server.main(["localhost", "443"])
        self.assertEqual(called, [((), {})])
