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
"""Tests for the Magicicada proxy support."""

from os import path
from StringIO import StringIO

from twisted.application import internet, service
from twisted.internet import defer, ssl
from twisted.web import http, resource, server

SAMPLE_CONTENT = "hello world!"
SIMPLERESOURCE = "simpleresource"
DUMMY_KEY_FILENAME = "dummy.key"
DUMMY_CERT_FILENAME = "dummy.cert"
FAKE_COOKIE = "fa:ke:co:ok:ie"


class SaveHTTPChannel(http.HTTPChannel):
    """A save protocol to be used in tests."""

    protocolInstance = None

    def connectionMade(self):
        """Keep track of the given protocol."""
        SaveHTTPChannel.protocolInstance = self
        http.HTTPChannel.connectionMade(self)


class SaveSite(server.Site):
    """A site that let us know when it's closed."""

    protocol = SaveHTTPChannel

    def __init__(self, *args, **kwargs):
        """Create a new instance."""
        server.Site.__init__(self, *args, **kwargs)
        self.timeOut = None


class BaseMockWebServer(object):
    """A mock webserver for testing"""

    def __init__(self):
        """Start up this instance."""
        self.root = self.get_root_resource()
        self.site = SaveSite(self.root)
        application = service.Application('web')
        self.service_collection = service.IServiceCollection(application)
        self.tcpserver = internet.TCPServer(0, self.site)
        self.tcpserver.setServiceParent(self.service_collection)
        self.sslserver = internet.SSLServer(0, self.site, self.get_context())
        self.sslserver.setServiceParent(self.service_collection)
        self.service_collection.startService()

    def get_dummy_path(self, filename):
        """Path pointing at the dummy certificate files."""
        base_path = path.dirname(__file__)
        return path.join(base_path, "ssl", filename)

    def get_context(self):
        """Return an ssl context."""
        key_path = self.get_dummy_path(DUMMY_KEY_FILENAME)
        cert_path = self.get_dummy_path(DUMMY_CERT_FILENAME)
        return ssl.DefaultOpenSSLContextFactory(key_path, cert_path)

    def get_root_resource(self):
        """Get the root resource with all the children."""
        raise NotImplementedError

    def get_iri(self):
        """Build the iri for this mock server."""
        port_num = self.tcpserver._port.getHost().port
        return u"http://0.0.0.0:%d/" % port_num

    def get_ssl_iri(self):
        """Build the iri for the ssl mock server."""
        port_num = self.sslserver._port.getHost().port
        return u"https://0.0.0.0:%d/" % port_num

    def stop(self):
        """Shut it down."""
        if self.site.protocol.protocolInstance:
            self.site.protocol.protocolInstance.timeoutConnection()
        return self.service_collection.stopService()


class SimpleResource(resource.Resource):
    """A simple web resource."""

    def __init__(self):
        """Initialize this mock resource."""
        resource.Resource.__init__(self)
        self.rendered = defer.Deferred()

    def render_GET(self, request):
        """Make a bit of html out of the resource's content."""
        if not self.rendered.called:
            self.rendered.callback(None)
        return SAMPLE_CONTENT


class MockWebServer(BaseMockWebServer):
    """A mock webserver."""

    def __init__(self):
        """Initialize this mock server."""
        self.simple_resource = SimpleResource()
        super(MockWebServer, self).__init__()

    def get_root_resource(self):
        """Get the root resource with all the children."""
        root = resource.Resource()
        root.putChild(SIMPLERESOURCE, self.simple_resource)
        return root


class FakeTransport(StringIO):
    """A fake transport that stores everything written to it."""

    connected = True
    disconnecting = False
    cookie = None

    def loseConnection(self):
        """Mark the connection as lost."""
        self.connected = False
        self.disconnecting = True

    def getPeer(self):
        """Return the peer IAddress."""
        return None
