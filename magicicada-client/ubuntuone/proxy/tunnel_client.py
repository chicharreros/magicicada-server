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
"""Client for the tunnel protocol."""

import logging

from twisted.internet import protocol, reactor

from ubuntuone.clientdefs import NAME
from ubuntuone.proxy.common import (
    BaseTunnelProtocol,
    CRLF,
    TUNNEL_COOKIE_LABEL,
    TUNNEL_COOKIE_HEADER,
    TUNNEL_PORT_LABEL,
)

METHOD_LINE = "CONNECT %s:%d HTTP/1.0" + CRLF
LOCALHOST = "127.0.0.1"

logger = logging.getLogger("ubuntuone.SyncDaemon.TunnelClient")


class TunnelClientProtocol(BaseTunnelProtocol):
    """Client protocol for the handshake part of the tunnel."""

    def connectionMade(self):
        """The connection to the tunnel was made so send request."""
        method_line = METHOD_LINE % (self.factory.tunnel_host,
                                     self.factory.tunnel_port)
        headers = {
            "User-Agent": "%s tunnel client" % NAME,
            TUNNEL_COOKIE_HEADER: self.factory.cookie,
        }
        self.transport.write(method_line +
                             self.format_headers(headers) +
                             CRLF)

    def handle_first_line(self, line):
        """The first line received is the status line."""
        try:
            proto_version, self.status_code, description = line.split(" ", 2)
        except ValueError:
            self.transport.loseConnection()

    def headers_done(self):
        """All the headers have arrived. Time to switch protocols."""
        remaining_data = self.clearLineBuffer()
        if self.status_code != "200":
            self.transport.loseConnection()
            return
        addr = self.transport.getPeer()
        other_protocol = self.factory.other_factory.buildProtocol(addr)
        self.transport.protocol = other_protocol
        other_protocol.transport = self.transport
        self.transport = None
        if self.factory.context_factory:
            other_protocol.transport.startTLS(self.factory.context_factory)
        other_protocol.connectionMade()
        if remaining_data:
            other_protocol.dataReceived(remaining_data)


class TunnelClientFactory(protocol.ClientFactory):
    """A factory for Tunnel Client Protocols."""

    protocol = TunnelClientProtocol

    def __init__(self, tunnel_host, tunnel_port, other_factory, cookie,
                 context_factory=None):
        """Initialize this factory."""
        self.tunnel_host = tunnel_host
        self.tunnel_port = tunnel_port
        self.other_factory = other_factory
        self.context_factory = context_factory
        self.cookie = cookie

    def startedConnecting(self, connector):
        """Forward this call to the other factory."""
        self.other_factory.startedConnecting(connector)

    def clientConnectionFailed(self, connector, reason):
        """Forward this call to the other factory."""
        self.other_factory.clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector, reason):
        """Forward this call to the other factory."""
        self.other_factory.clientConnectionLost(connector, reason)


class TunnelClient(object):
    """A client for the proxy tunnel."""

    def __init__(self, tunnel_host, tunnel_port, cookie):
        """Initialize this client."""
        self.tunnel_host = tunnel_host
        self.tunnel_port = tunnel_port
        self.cookie = cookie

    def connectTCP(self, host, port, factory, *args, **kwargs):
        """A connectTCP going thru the tunnel."""
        logger.info("Connecting (TCP) to %r:%r via tunnel at %r:%r",
                    host, port, self.tunnel_host, self.tunnel_port)
        tunnel_factory = TunnelClientFactory(host, port, factory, self.cookie)
        return reactor.connectTCP(self.tunnel_host, self.tunnel_port,
                                  tunnel_factory, *args, **kwargs)

    def connectSSL(self, host, port, factory,
                   contextFactory, *args, **kwargs):
        """A connectSSL going thru the tunnel."""
        logger.info("Connecting (SSL) to %r:%r via tunnel at %r:%r",
                    host, port, self.tunnel_host, self.tunnel_port)
        tunnel_factory = TunnelClientFactory(
            host, port, factory, self.cookie, contextFactory)
        return reactor.connectTCP(self.tunnel_host, self.tunnel_port,
                                  tunnel_factory, *args, **kwargs)


class TunnelProcessProtocol(protocol.ProcessProtocol):
    """The dialog thru stdout with the tunnel server."""

    timeout = 30

    def __init__(self, client_d):
        """Initialize this protocol."""
        self.client_d = client_d
        self.timer = None
        self.port = None
        self.cookie = None

    def connectionMade(self):
        """The process has started, start a timer."""
        logger.info("Tunnel process started.")
        self.timer = reactor.callLater(self.timeout, self.process_timeouted)

    def process_timeouted(self):
        """The process took too long to reply."""
        if not self.client_d.called:
            logger.info("Timeout while waiting for tunnel process.")
            self.client_d.callback(reactor)

    def finish_timeout(self):
        """Stop the timer from firing."""
        if self.timer and self.timer.active():
            logger.debug("canceling timer before connection timeout")
            self.timer.cancel()

    def processExited(self, status):
        """The tunnel process has exited with some error code."""
        self.finish_timeout()
        logger.info("Tunnel process exit status %r.", status)
        if not self.client_d.called:
            logger.debug("Tunnel process exited before TunnelClient created. "
                         "Falling back to reactor")
            self.client_d.callback(reactor)

    def outReceived(self, data):
        """Receive the port number."""
        if self.client_d.called:
            return

        for line in data.split("\n"):
            if line.startswith(TUNNEL_PORT_LABEL):
                _header, port = line.split(":", 1)
                self.port = int(port.strip())
            if line.startswith(TUNNEL_COOKIE_LABEL):
                _header, cookie = line.split(":", 1)
                self.cookie = cookie.strip()

        if self.port and self.cookie:
            logger.info("Tunnel process listening on port %r.", self.port)
            client = TunnelClient(LOCALHOST, self.port, self.cookie)
            self.client_d.callback(client)

    def errReceived(self, data):
        logger.debug("Got stderr from tunnel process: %r", data)
