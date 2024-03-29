# Copyright 2008-2015 Canonical
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/magicicada-server

"""Storage server stats helpers."""

import logging
import socket

from functools import update_wrapper

from twisted.application.internet import TCPServer, SSLServer
from twisted.internet import defer, reactor
from twisted.web import server, resource

from magicicada import metrics
from magicicada.monitoring import dump

logger = logging.getLogger(__name__)


def report_reactor_stats(prefix="reactor"):
    """Report statistics about a twisted reactor."""

    def report():
        return {
            prefix + ".readers": len(reactor.getReaders()),
            prefix + ".writers": len(reactor.getWriters()),
        }

    update_wrapper(report, report_reactor_stats)
    return report


class MeliaeResource(resource.Resource):
    """The Statistics Resource."""

    def render_GET(self, request):
        """Handle GET."""
        return dump.meliae_dump().encode('utf-8')


class GCResource(resource.Resource):
    """Working with the garbage collector."""

    def render_GET(self, request):
        """Handle GET."""
        return dump.gc_dump().encode('utf-8')


class StatsWorker(object):
    """Execute actions and log the results at the specified interval."""

    def __init__(self, service, interval, servername=None):
        self.service = service
        if servername is None:
            self.servername = socket.gethostname()
        else:
            self.servername = servername
        self.interval = interval
        self.next_loop = None
        self._get_reactor_stats = report_reactor_stats()
        self.metrics = metrics.get_meter("stats")

    def callLater(self, seconds, func, *args, **kwargs):
        """Wrap reactor.callLater to simplify testing."""
        reactor.callLater(seconds, func, *args, **kwargs)

    def log(self, msg, *args, **kwargs):
        """Wrap logger.info call to simplify testing."""
        logger.info(msg, *args, **kwargs)

    def start(self):
        """Start rolling."""
        if self.interval:
            self.next_loop = self.callLater(0, self.work)

    def stop(self):
        """Stop working, cancel delayed calls if active."""
        if self.next_loop is not None and self.next_loop.active():
            self.next_loop.cancel()

    def work(self):
        """Call the methods that do the real work."""
        self.runtime_info()
        self.next_loop = self.callLater(self.interval, self.work)

    def runtime_info(self):
        """Log runtime info.

        This includes: reactor readers/writers and buffers size.
        """
        reactor_report = self._get_reactor_stats()
        for key, value in reactor_report.items():
            self.metrics.gauge(key, value)

        self.log(
            "reactor readers: %(reactor.readers)s "
            "writers: %(reactor.writers)s",
            reactor_report,
        )


class _Status(resource.Resource):
    """The Status Resource."""

    def __init__(self, server, user_id):
        """Create the Resource."""
        resource.Resource.__init__(self)
        self.storage_server = server
        self.user_id = user_id

    @property
    def content(self):
        """A property to get the content manager."""
        return self.storage_server.factory.content

    def render_GET(self, request):
        """Handle GET."""
        d = self._check()

        def write_response(msg, status_code=200):
            request.setResponseCode(status_code)
            request.write(msg.encode('utf-8'))
            request.finish()

        def on_success(result):
            """Success callback"""
            write_response(result)

        def on_error(failure):
            """Error callback"""
            logger.error(
                "Error while getting status. %s", failure.getTraceback()
            )
            write_response(failure.getErrorMessage() + "\n", status_code=500)

        d.addCallbacks(on_success, on_error)
        return server.NOT_DONE_YET

    @defer.inlineCallbacks
    def _check(self):
        """The check for Alive/Dead.

        Get the user and it root object.
        """
        user = yield self.content.get_user_by_id(self.user_id, required=True)
        yield user.get_root()
        defer.returnValue('Status OK\n')


def create_status_service(
    storage, parent_service, port, user_id=0, ssl_context_factory=None
):
    """Create the status service."""
    root = resource.Resource()
    root.putChild(b'status', _Status(storage, user_id))
    root.putChild(b'+meliae', MeliaeResource())
    root.putChild(b'+gc-stats', GCResource())
    site = server.Site(root)
    if ssl_context_factory is None:
        service = TCPServer(port, site)
    else:
        service = SSLServer(port, site, ssl_context_factory)
    service.setServiceParent(parent_service)
    return service
