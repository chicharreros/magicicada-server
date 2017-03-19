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
"""Common classes to the tunnel client and server."""

from twisted.protocols import basic

CRLF = "\r\n"
TUNNEL_PORT_LABEL = "Tunnel port"
TUNNEL_COOKIE_LABEL = "Tunnel cookie"
TUNNEL_COOKIE_HEADER = "Proxy-Tunnel-Cookie"


class BaseTunnelProtocol(basic.LineReceiver):
    """CONNECT base protocol for tunnelling connections."""

    delimiter = CRLF

    def __init__(self):
        """Initialize this protocol."""
        self._first_line = True
        self.received_headers = []

    def header_line(self, line):
        """Handle each header line received."""
        key, value = line.split(":", 1)
        value = value.strip()
        self.received_headers.append((key, value))

    def lineReceived(self, line):
        """Process a line in the header."""
        if self._first_line:
            self._first_line = False
            self.handle_first_line(line)
        else:
            if line:
                self.header_line(line)
            else:
                self.setRawMode()
                self.headers_done()

    def remote_disconnected(self):
        """The remote end closed the connection."""
        self.transport.loseConnection()

    def format_headers(self, headers):
        """Format some headers as a few response lines."""
        return "".join("%s: %s" % item + CRLF for item in headers.items())
