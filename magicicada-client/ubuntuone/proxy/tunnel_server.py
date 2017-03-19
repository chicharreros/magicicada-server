# -*- coding: utf-8 -*-
#
# Copyright 2012-2013 Canonical Ltd.
# Copyright 2015-2017 Chicharreros (https://launchpad.net/~chicharreros)
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
"""A tunnel through proxies.

The layers in a tunneled proxied connection:

↓ tunnelclient - initiates tcp to tunnelserver, request outward connection
↕ client protocol - started after the tunneclient gets connected
---process boundary---
↕ tunnelserver - creates a tunnel instance per incoming connection
↕ tunnel - hold a qtcpsocket to tunnelclient, and srvtunnelproto to the remote
↕ servertunnelprotocol - gets CONNECT from tunnelclient, creates a remotesocket
↕ remotesocket - connects to the destination server via a proxy
↕ proxy server - goes thru firewalls
↑ server - dialogues with the client protocol

"""

import sys
import uuid

from PyQt4.QtCore import QCoreApplication, QTimer
from PyQt4.QtNetwork import (
    QAbstractSocket,
    QHostAddress,
    QNetworkProxy,
    QNetworkProxyQuery,
    QNetworkProxyFactory,
    QTcpServer,
    QTcpSocket,
)
from twisted.internet import defer, interfaces
from zope.interface import implements

from ubuntuone.clientdefs import NAME
from ubuntuone.keyring import Keyring
from ubuntuone.utils import gsettings
from ubuntuone.proxy.common import (
    BaseTunnelProtocol,
    CRLF,
    TUNNEL_COOKIE_HEADER,
    TUNNEL_COOKIE_LABEL,
    TUNNEL_PORT_LABEL,
)
from ubuntuone.proxy.logger import logger
try:
    from ubuntuone.utils.locale import fix_turkish_locale
except ImportError:
    def fix_turkish_locale():
        return None


DEFAULT_CODE = 500
DEFAULT_DESCRIPTION = "Connection error"


class ConnectionError(Exception):
    """The client failed connecting to the destination."""

    def __init__(self, code=DEFAULT_CODE, description=DEFAULT_DESCRIPTION):
        self.code = code
        self.description = description


class ProxyAuthenticationError(ConnectionError):
    """Credentials mismatch going thru a proxy."""


def build_proxy(settings_groups):
    """Create a QNetworkProxy from these settings."""
    proxy_groups = [
        ("socks", QNetworkProxy.Socks5Proxy),
        ("https", QNetworkProxy.HttpProxy),
        ("http", QNetworkProxy.HttpProxy),
    ]
    for group, proxy_type in proxy_groups:
        if group not in settings_groups:
            continue
        settings = settings_groups[group]
        if "host" in settings and "port" in settings:
            return QNetworkProxy(proxy_type,
                                 hostName=settings.get("host", ""),
                                 port=settings.get("port", 0),
                                 user=settings.get("username", ""),
                                 password=settings.get("password", ""))
    logger.error("No proxy correctly configured.")
    return QNetworkProxy(QNetworkProxy.DefaultProxy)


class RemoteSocket(QTcpSocket):
    """A dumb connection through a proxy to a destination hostport."""

    def __init__(self, tunnel_protocol):
        """Initialize this object."""
        super(RemoteSocket, self).__init__()
        self.protocol = tunnel_protocol
        self.connected_d = defer.Deferred()
        self.connected.connect(self.handle_connected)
        self.proxyAuthenticationRequired.connect(self.handle_auth_required)
        self.buffered_data = []

    def handle_connected(self):
        """When connected, send all pending data."""
        self.disconnected.connect(self.handle_disconnected)
        self.connected_d.callback(None)
        for d in self.buffered_data:
            logger.debug("writing remote: %d bytes", len(d))
            super(RemoteSocket, self).write(d)
        self.buffered_data = []

    def handle_disconnected(self):
        """Do something with disconnections."""
        logger.debug("Remote socket disconnected")
        self.protocol.remote_disconnected()

    def write(self, data):
        """Write data to the remote end, buffering if not connected."""
        if self.state() == QAbstractSocket.ConnectedState:
            logger.debug("writing remote: %d bytes", len(data))
            super(RemoteSocket, self).write(data)
        else:
            self.buffered_data.append(data)

    def connect(self, hostport):
        """Try to establish the connection to the remote end."""
        host, port = hostport.split(":")

        try:
            port = int(port)
        except ValueError:
            raise ConnectionError(400, "Destination port must be an integer.")

        self.readyRead.connect(self.handle_ready_read)
        self.error.connect(self.handle_error)
        self.connectToHost(host, port)

        return self.connected_d

    def handle_auth_required(self, proxy, authenticator):
        """Handle the proxyAuthenticationRequired signal."""
        self.protocol.proxy_auth_required(proxy, authenticator)

    def handle_error(self, socket_error):
        """Some error happened while connecting."""
        error_description = "%s (%d)" % (self.errorString(), socket_error)
        logger.error("connection error: %s", error_description)
        if self.connected_d.called:
            return

        if socket_error == self.ProxyAuthenticationRequiredError:
            error = ProxyAuthenticationError(407, error_description)
        else:
            error = ConnectionError(500, error_description)

        self.connected_d.errback(error)

    def handle_ready_read(self):
        """Forward data from the remote end to the parent protocol."""
        data = self.readAll()
        self.protocol.response_data_received(data)

    @defer.inlineCallbacks
    def stop(self):
        """Finish and cleanup."""
        self.disconnectFromHost()
        while self.state() != self.UnconnectedState:
            d = defer.Deferred()
            QTimer.singleShot(100, lambda: d.callback(None))
            yield d


class ServerTunnelProtocol(BaseTunnelProtocol):
    """CONNECT sever protocol for tunnelling connections."""

    def __init__(self, client_class):
        """Initialize this protocol."""
        BaseTunnelProtocol.__init__(self)
        self.hostport = ""
        self.client = None
        self.client_class = client_class
        self.proxy_credentials = None
        self.proxy_domain = None

    def error_response(self, code, description):
        """Write a response with an error, and disconnect."""
        self.write_transport("HTTP/1.0 %d %s" % (code, description) + CRLF * 2)
        self.transport.loseConnection()
        if self.client:
            self.client.stop()
        self.clearLineBuffer()

    def write_transport(self, data):
        """Write a response in the transport."""
        self.transport.write(data)

    def proxy_auth_required(self, proxy, authenticator):
        """Proxy authentication is required."""
        logger.info("auth_required %r, %r",
                    proxy.hostName(), self.proxy_domain)
        if self.proxy_credentials and proxy.hostName() == self.proxy_domain:
            logger.info("Credentials added to authenticator.")
            authenticator.setUser(self.proxy_credentials["username"])
            authenticator.setPassword(self.proxy_credentials["password"])
        else:
            logger.info("Credentials needed, but none available.")
            self.proxy_domain = proxy.hostName()

    def handle_first_line(self, line):
        """Special handling for the first line received."""
        try:
            method, hostport, proto_version = line.split(" ", 2)
            if proto_version != "HTTP/1.0":
                self.error_response(505, "HTTP Version Not Supported")
                return
            if method != "CONNECT":
                self.error_response(405, "Only the CONNECT method is allowed")
                return
            self.hostport = hostport
        except ValueError:
            self.error_response(400, "Bad request")

    def verify_cookie(self):
        """Fail if the cookie is wrong or missing."""
        cookie_received = dict(self.received_headers).get(TUNNEL_COOKIE_HEADER)
        if cookie_received != self.transport.cookie:
            raise ConnectionError(418, "Please see RFC 2324")

    @defer.inlineCallbacks
    def headers_done(self):
        """An empty line was received, start connecting and switch mode."""
        try:
            self.verify_cookie()
            try:
                logger.info("Connecting once")
                self.client = self.client_class(self)
                yield self.client.connect(self.hostport)
            except ProxyAuthenticationError:
                if not self.proxy_domain:
                    logger.info("No proxy domain defined")
                    raise

                credentials = yield Keyring().get_credentials(
                    str(self.proxy_domain))
                if "username" in credentials:
                    self.proxy_credentials = credentials
                logger.info("Connecting again with keyring credentials")
                self.client = self.client_class(self)
                yield self.client.connect(self.hostport)
                logger.info("Connected with keyring credentials")

            response_headers = {
                "Server": "%s proxy tunnel" % NAME,
            }
            self.write_transport("HTTP/1.0 200 Proxy connection established" +
                                 CRLF + self.format_headers(response_headers) +
                                 CRLF)
        except ConnectionError as e:
            logger.exception("Connection error")
            self.error_response(e.code, e.description)
        except Exception:
            logger.exception("Unhandled problem while connecting")

    def rawDataReceived(self, data):
        """Tunnel all raw data straight to the other side."""
        self.client.write(data)

    def response_data_received(self, data):
        """Return data coming from the other side."""
        self.write_transport(data)


class Tunnel(object):
    """An instance of a running tunnel."""

    implements(interfaces.ITransport)

    def __init__(self, local_socket, cookie):
        """Initialize this Tunnel instance."""
        self.cookie = cookie
        self.disconnecting = False
        self.local_socket = local_socket
        self.protocol = ServerTunnelProtocol(RemoteSocket)
        self.protocol.transport = self
        local_socket.readyRead.connect(self.server_ready_read)
        local_socket.disconnected.connect(self.local_disconnected)

    def server_ready_read(self):
        """Data available on the local end. Move it forward."""
        data = bytes(self.local_socket.readAll())
        self.protocol.dataReceived(data)

    def write(self, data):
        """Data available on the remote end. Bring it back."""
        logger.debug("writing local: %d bytes", len(data))
        self.local_socket.write(data)

    def loseConnection(self):
        """The remote end disconnected."""
        logger.debug("disconnecting local end.")
        self.local_socket.close()

    def local_disconnected(self):
        """The local end disconnected."""
        logger.debug("The local socket got disconnected.")
        # TODO: handle this case in an upcoming branch


class TunnelServer(object):
    """A server for tunnel instances."""

    def __init__(self, cookie):
        """Initialize this tunnel instance."""
        self.tunnels = []
        self.cookie = cookie
        self.server = QTcpServer(QCoreApplication.instance())
        self.server.newConnection.connect(self.new_connection)
        self.server.listen(QHostAddress.LocalHost, 0)
        logger.info("Starting tunnel server at port %d", self.port)

    def new_connection(self):
        """On a new connection create a new tunnel instance."""
        logger.info("New connection made")
        local_socket = self.server.nextPendingConnection()
        tunnel = Tunnel(local_socket, self.cookie)
        self.tunnels.append(tunnel)

    def shutdown(self):
        """Terminate every connection."""
        # TODO: handle this gracefully in an upcoming branch

    @property
    def port(self):
        """The port where this server listens."""
        return self.server.serverPort()


def check_proxy_enabled(host, port):
    """Check if the proxy is enabled."""
    port = int(port)
    if sys.platform.startswith("linux"):
        settings = gsettings.get_proxy_settings()
        enabled = len(settings) > 0
        if enabled:
            proxy = build_proxy(settings)
            QNetworkProxy.setApplicationProxy(proxy)
        else:
            logger.info("Proxy is disabled.")
        return enabled
    else:
        QNetworkProxyFactory.setUseSystemConfiguration(True)
        query = QNetworkProxyQuery(host, port)
        proxies = QNetworkProxyFactory.systemProxyForQuery(query)
        return len(proxies) and proxies[0].type() != QNetworkProxy.NoProxy


def install_qt_dbus():
    """Import and install the qt+dbus integration."""
    from dbus.mainloop.qt import DBusQtMainLoop
    DBusQtMainLoop(set_as_default=True)


def main(argv):
    """The main function for the tunnel server."""
    fix_turkish_locale()
    if not check_proxy_enabled(*argv[1:]):
        sys.stdout.write("Proxy not enabled.")
        sys.stdout.flush()
    else:
        if sys.platform.startswith("linux"):
            install_qt_dbus()

        app = QCoreApplication(argv)
        cookie = str(uuid.uuid4())
        tunnel_server = TunnelServer(cookie)
        sys.stdout.write("%s: %d\n" % (TUNNEL_PORT_LABEL, tunnel_server.port) +
                         "%s: %s\n" % (TUNNEL_COOKIE_LABEL, cookie))
        sys.stdout.flush()
        app.exec_()
