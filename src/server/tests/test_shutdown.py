# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Test server shutdown."""

import os

from twisted.trial.unittest import TestCase as TwistedTestCase
from twisted.internet import reactor, defer, error

from txstatsd.metrics.countermetric import CounterMetric
from txstatsd.metrics.metermetric import MeterMetric

from backends.filesync.services import make_storage_user
from backends.testing.testcase import BaseTestCase
from ubuntuone.storage.server.auth import DummyAuthProvider
from ubuntuone.storage.server.testing.testcase import StorageServerService
from ubuntuone.storageprotocol import request
from ubuntuone.storageprotocol.content_hash import content_hash_factory
from ubuntuone.storageprotocol.client import (
    StorageClientFactory, StorageClient)


class TestClient(StorageClient):
    """A simple client for tests."""

    def connectionMade(self):
        """Setup and call callback."""
        StorageClient.connectionMade(self)
        self.factory.connected(self)


class TestClientFactory(StorageClientFactory):
    """A test oriented protocol factory."""
    protocol = TestClient


class TestShutdown(TwistedTestCase, BaseTestCase):
    """Test the basic stuff."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup for testing."""
        # make sure we start with clean state
        yield super(TestShutdown, self).setUp()
        # since storageusers are not automatically created, we need to create
        self.usr0 = make_storage_user(u"dummy", 2 ** 20)

    @defer.inlineCallbacks
    def create_service(self):
        # create a server
        service = StorageServerService(
            0, auth_provider_class=DummyAuthProvider, heartbeat_interval=0)
        yield service.startService()
        self.addCleanup(service.stopService)

        defer.returnValue(service)

    @defer.inlineCallbacks
    def connect_client(self, service):
        # create a user, connect a client
        d = defer.Deferred()
        f = TestClientFactory()
        f.connected = d.callback
        reactor.connectTCP("localhost", service.port, f)
        client = yield d
        # auth, get root, create a file
        service.factory.auth_provider._allowed["open sesame"] = self.usr0.id
        yield client.dummy_authenticate("open sesame")

        # see that the server has not protocols alive
        self.addCleanup(service.factory.wait_for_shutdown)

        defer.returnValue(client)

    @defer.inlineCallbacks
    def test_shutdown_upload(self):
        """Stop and restart the server."""
        service = yield self.create_service()
        client = yield self.connect_client(service)
        root = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root, "hola")

        # try to upload something that will fail when sending data
        empty_hash = content_hash_factory().content_hash()
        # lose the connection if something wrong
        try:
            yield client.put_content(request.ROOT, mkfile_req.new_id,
                                     empty_hash, "fake_hash", 1234, 1000, None)
        except:
            client.transport.loseConnection()

        ujobs = self.usr0.get_uploadjobs(node_id=mkfile_req.new_id)
        self.assertEqual(ujobs, [])

    @defer.inlineCallbacks
    def test_shutdown_metrics(self):
        """Stop and restart the server."""
        service = yield self.create_service()

        # ensure we employ the correct metric name.
        name = service.metrics.fully_qualify_name('server_start')
        self.assertIsInstance(
            service.metrics._metrics[name], MeterMetric)
        name = service.metrics.fully_qualify_name('services_active')
        self.assertIsInstance(
            service.metrics._metrics[name], CounterMetric)
        self.assertEqual(service.metrics._metrics[name].count(), 1)

    @defer.inlineCallbacks
    def test_requests_leak(self):
        """Test that the server waits for pending requests."""
        service = yield self.create_service()
        client = yield self.connect_client(service)

        root_id = yield client.get_root()
        # create a bunch of files
        mk_deferreds = []

        def handle_conn_done(f):
            """Ignore ConnectionDone errors."""
            if not f.check(error.ConnectionDone):
                return f

        for i in range(10):
            mk = client.make_file(request.ROOT, root_id, "hola_%s" % i)
            mk.addErrback(handle_conn_done)
            mk_deferreds.append(mk)
        try:
            reactor.callLater(0.1, client.transport.loseConnection)
            yield defer.DeferredList(mk_deferreds)
        finally:
            if not os.environ.get('MAGICICADA_DEBUG'):
                self.assertTrue(service.factory.protocols[0].requests)
