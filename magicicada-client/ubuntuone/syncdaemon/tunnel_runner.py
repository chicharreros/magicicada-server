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
"""Run the tunnel process and start a client, with a reactor as a fallback."""

import logging

from twisted.internet import defer, reactor

from ubuntuone.clientdefs import LIBEXECDIR
from ubuntuone.syncdaemon.utils import get_tunnel_bin_cmd

logger = logging.getLogger("ubuntuone.SyncDaemon.TunnelRunner")


class TunnelRunner(object):
    """Run a tunnel process."""

    def __init__(self, host, port):
        """Start this runner instance."""
        self.client_d = defer.Deferred()
        self.process_transport = None
        try:
            self.start_process(host, port)
        except ImportError:
            logger.info("Proxy support not installed.")
            self.client_d.callback(reactor)
        except Exception:
            logger.exception("Error while starting tunnel process:")
            self.client_d.callback(reactor)

    def start_process(self, host, port):
        """Start the tunnel process."""
        from ubuntuone.proxy.tunnel_client import TunnelProcessProtocol
        protocol = TunnelProcessProtocol(self.client_d)
        tunnel_cmd = get_tunnel_bin_cmd(extra_fallbacks=[LIBEXECDIR])

        args = tunnel_cmd + [host, str(port)]

        self.process_transport = reactor.spawnProcess(protocol, args[0],
                                                      env=None, args=args)
        reactor.addSystemEventTrigger("before", "shutdown", self.stop)

    def stop(self):
        """Stop the tunnel process if still running."""
        logger.info("Stopping process %r", self.process_transport.pid)
        if self.process_transport.pid is not None:
            self.process_transport.signalProcess("KILL")

    def get_client(self):
        """A deferred with the reactor or a tunnel client."""

        def client_selected(result, d):
            """The tunnel_client or the reactor were selected."""
            d.callback(result)
            # make sure the result is available for next callback
            return result

        d = defer.Deferred()
        self.client_d.addCallback(client_selected, d)
        return d
