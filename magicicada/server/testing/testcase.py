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

"""The Storage network server testcase.

Base classes to do all the testing.
"""

import logging
import os
import time
import zlib
from functools import wraps
from io import BytesIO

from magicicadaprotocol import client as protocol_client, request, protocol_pb2
from magicicadaprotocol.client import StorageClientFactory, StorageClient
from magicicadaprotocol.content_hash import (
    content_hash_factory,
    crc32,
    magic_hash_factory,
)
from OpenSSL import crypto
from twisted.internet import reactor, defer, ssl
from twisted.internet.protocol import connectionDone
from twisted.python.failure import Failure
from twisted.trial.unittest import TestCase as TwistedTestCase
from twisted.web.error import Error
from twisted.web.client import getPage

from magicicada import settings
from magicicada.filesync import services
from magicicada.server.auth import DummyAuthProvider
from magicicada.server.content import DBUploadJob, UploadJob
from magicicada.server.server import PREFERRED_CAP, StorageServerService
from magicicada.testing.testcase import BaseTestCase

logger = logging.getLogger(__name__)
server_key = settings.CRT_KEY
server_crt = settings.CRT
server_crt_chain = settings.CRT_CHAIN
EMPTY_HASH = content_hash_factory().content_hash()
NO_CONTENT_HASH = ""


def get_hash(data):
    """Return the hash for the data."""
    hash_object = content_hash_factory()
    hash_object.update(data)
    return hash_object.content_hash()


def get_magic_hash(data):
    """Return the magic hash for the data."""
    magic_hash_object = magic_hash_factory()
    magic_hash_object.update(data)
    return magic_hash_object.content_hash()._magic_hash


def get_put_content_params(
    data=None, deflated_data=None, share=request.ROOT, **overrides
):
    """Return the test data for put_content."""
    if data is None:
        data = os.urandom(1000)  # not terribly compressible
    assert isinstance(data, bytes), 'data should be bytes, got %s' % type(data)

    if deflated_data is None:
        deflated_data = zlib.compress(data)
    assert isinstance(
        deflated_data, bytes
    ), 'deflated_data should be bytes, got %s' % type(deflated_data)

    params = overrides.copy()
    params.setdefault('share', share)
    params.setdefault('previous_hash', NO_CONTENT_HASH)
    params.setdefault('new_hash', get_hash(data))
    params.setdefault('crc32', crc32(data))
    params.setdefault('size', len(data))
    params.setdefault('deflated_size', len(deflated_data))
    params.setdefault('fd', BytesIO(deflated_data))
    return params


class FakeTimestampChecker(object):
    """Fake timestamp checker."""

    def get_faithful_time(self):
        """In the present we trust."""
        return int(time.time())


# need to patch this timestamp checker so it doesn't go to the real server
protocol_client.tx_timestamp_checker = FakeTimestampChecker()


class State(object):
    """An empty class to store state."""


class BaseProtocolTestCase(TwistedTestCase):
    """Reusable part of ProtocolTestCase."""

    heartbeat_interval = 0
    timeout = 120
    maxDiff = None

    @property
    def port(self):
        """The TCP port where the server listens."""
        return self.service.port

    @defer.inlineCallbacks
    def setUp(self):
        """Setup for testing."""
        # make sure we start with clean state
        yield super(BaseProtocolTestCase, self).setUp()
        logger.info("starting test %s", self.id())
        self.ssl_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, server_crt
        )
        if server_crt_chain:
            self.ssl_cert_chain = crypto.load_certificate(
                crypto.FILETYPE_PEM, server_crt_chain
            )
        else:
            self.ssl_cert_chain = None
        self.ssl_key = crypto.load_privatekey(crypto.FILETYPE_PEM, server_key)

        self._state = State()
        self.service = StorageServerService(
            0,
            auth_provider_class=self.auth_provider_class,
            status_port=0,
            heartbeat_interval=self.heartbeat_interval,
        )
        yield self.service.startService()

    @defer.inlineCallbacks
    def tearDown(self):
        """Tear down after testing."""
        yield self.service.stopService()
        yield super(BaseProtocolTestCase, self).tearDown()
        logger.info("finished test %s", self.id())

    def make_user(self, username=None, **kwargs):
        if username is None:
            username = self.factory.get_unique_string()
        return services.make_storage_user(username=username, **kwargs)

    @defer.inlineCallbacks
    def make_upload_job(self, size, user, content_user):
        """Create an UploadJob object.

        @param size: the size of the upload
        @param user: the storage user
        @param content_user: the User owning the file content
        @return: a tuple (deflated_data, hash_value, upload_job)

        """
        data = os.urandom(int(size))
        deflated_data = zlib.compress(data)
        hash_value = get_hash(data)
        magic_hash_value = get_magic_hash(data)
        crc32_value = crc32(data)
        deflated_size = len(deflated_data)
        root, _ = yield content_user.get_root()
        r = yield self.service.factory.content.rpc_dal.call(
            'make_file_with_content',
            user_id=content_user.id,
            volume_id=user.root_volume_id,
            parent_id=root,
            name="A new file",
            node_hash=EMPTY_HASH,
            crc32=0,
            size=0,
            deflated_size=0,
            storage_key=None,
        )
        node_id = r['node_id']
        node = yield content_user.get_node(user.root_volume_id, node_id, None)
        args = (
            content_user,
            user.root_volume_id,
            node_id,
            node.content_hash,
            hash_value,
            crc32_value,
            size,
        )
        upload = yield DBUploadJob.make(*args)
        upload_job = UploadJob(
            content_user,
            node,
            node.content_hash,
            hash_value,
            crc32_value,
            size,
            deflated_size,
            None,
            False,
            magic_hash_value,
            upload,
        )
        defer.returnValue((deflated_data, hash_value, upload_job))


class ClientTestHelper(object):
    """helper for StorageClient used in tests."""

    def on_notification(self, share, node, hash):
        """Handle new notifications."""
        self.factory.pending_notifications -= 1
        if self.factory.pending_notifications < 0:
            self.test_fail(Exception("too many notifications"))
        else:
            if (
                self.factory.test_success
                and self.factory.pending_notifications == 0
            ):
                self._test_done("finished after notifications")

    def _test_done(self, result):
        """Real test done."""
        self.factory.cancel_timeout()
        self.transport.loseConnection()
        self.factory.test_deferred.callback(result)

    def kill(self):
        """Destroy this client without ending the test."""
        self.factory.cancel_timeout()
        self.transport.loseConnection()

    def test_done(self, result=None):
        """Finish test with success. Wait for pending notifications."""
        if (
            self.factory.pending_notifications == 0
            and not self.factory.test_failed
        ):
            self._test_done(result)
        self.factory.test_success = True

    def test_fail(self, result):
        """End test with error."""
        if not self.factory.test_failed:
            self.factory.test_failed = True
            if (
                self.factory.timeout.active()
                and not self.factory.timeout.cancelled
            ):
                self.factory.timeout.cancel()
            self.transport.loseConnection()
            if not self.factory.test_deferred.called:
                self.factory.test_deferred.errback(result)

    def check_doesnotexist(self, result):
        """Check for error."""
        error = result.check(request.StorageRequestError)
        if error is not None and result.getErrorMessage() == 'DOES_NOT_EXIST':
            self.test_done("ok")
        else:
            self.test_fail(result)

    # protocol API
    def connectionMade(self):
        """Setup and call callback."""
        self.connectionLostHandler = lambda _: None
        if self.factory.pending_notifications > 0:
            self.set_node_state_callback(self.on_notification)
        self.factory.callback(self)

    def connectionLost(self, reason=connectionDone):
        """Handle connection lost."""
        self.connectionLostHandler(reason)


class SimpleClient(StorageClient, ClientTestHelper):
    """Simple client that calls a callback on connection."""

    def __init__(self, *args, **kwargs):
        """create the instance"""
        StorageClient.__init__(self, *args, **kwargs)
        self.messages = []

    def connectionMade(self):
        """Handle connection made"""
        StorageClient.connectionMade(self)
        ClientTestHelper.connectionMade(self)

    def connectionLost(self, reason=connectionDone):
        """Handle connection lost."""
        ClientTestHelper.connectionLost(self, reason=reason)

    def processMessage(self, message):
        self.messages.append(message)
        StorageClient.processMessage(self, message)


class SimpleFactory(StorageClientFactory):
    """A test oriented protocol factory."""

    protocol = SimpleClient


class FactoryHelper(object):
    """A StorageClientFactory with helper methods for testing clients."""

    def __init__(
        self,
        cb_func,
        factory=SimpleFactory(),
        timeout=None,
        wait_notifications=0,
        caps=None,
        **kwargs
    ):
        """create the instance"""
        self.factory = factory
        self.cb_func = cb_func
        self.cb_kwargs = kwargs
        self.caps = caps
        if timeout is None:
            timeout = 120
        self.test_success = False
        self.test_failed = False
        self.pending_notifications = wait_notifications
        self.test_deferred = defer.Deferred()
        self.protocols = []
        self.timeout = reactor.callLater(timeout, self.error_shutdown)

    def cancel_timeout(self):
        """Cancel the timeout delayed call."""
        if self.timeout.active():
            self.timeout.cancel()

    @defer.inlineCallbacks
    def callback(self, client):
        """The callback to be executed when connected."""
        if self.caps is not None:
            request = yield client.set_caps(self.caps)
            assert request.accepted

        result = yield self.cb_func(client, **self.cb_kwargs)
        defer.returnValue(result)

    def buildProtocol(self, addr):
        """Create a protocol and keep a list of them."""
        p = self.factory.buildProtocol(addr)
        # replace the factory with self
        p.factory = self
        self.factory.client = p
        self.protocols.append(p)
        return p

    def error_shutdown(self):
        """Callback on timeout."""
        for p in self.protocols:
            p.transport.loseConnection()
        if self.test_success and self.pending_notifications > 0:
            self.test_deferred.errback(
                Exception("timeout waiting for notifications")
            )
        else:
            self.test_deferred.errback(Exception("timeout"))

    def __getattr__(self, name):
        """forward call to the factory"""
        return getattr(self.factory, name)


class TestWithDatabase(BaseTestCase, BaseProtocolTestCase):
    """Setup the storage server on a random port.

    Keeps the port number on self.port so children classes can just write
    client code.

    """

    auth_provider_class = DummyAuthProvider
    factory_class = SimpleFactory
    STORAGE_CHUNK_SIZE = 1024 * 64

    def _save_state(self, key, value):
        """Store values to be accessed by deferred functions."""
        setattr(self._state, key, value)
        return value

    def callback_test(
        self,
        func,
        wait_notifications=0,
        timeout=None,
        caps=PREFERRED_CAP,
        add_default_callbacks=False,
        use_ssl=False,
        **kwargs
    ):
        """Create a client and call callback on connection."""
        if add_default_callbacks:

            @wraps(func)
            def wrapped(client, **kwargs):
                """Wrapper which wires up test_done/test_fail."""
                d = func(client, **kwargs)
                d.addCallbacks(client.test_done, client.test_fail)
                return d

        else:
            wrapped = func
        f = FactoryHelper(
            wrapped,
            factory=self.buildFactory(),
            wait_notifications=wait_notifications,
            timeout=timeout,
            caps=caps,
            **kwargs
        )
        # there are 3 ways to connect to a server.
        # tcp and ssl will work in the tests
        if use_ssl:
            reactor.connectSSL(
                "localhost", self.ssl_port, f, ssl.ClientContextFactory()
            )
        else:
            reactor.connectTCP("localhost", self.port, f)

        # https connect requires a working proxy and a server on
        # the default port running (we are not setting this up for
        # automated testing yet)
        # proxy_tunnel.connectHTTPS('localhost', 3128, "localhost", 20101, f,
        #     user="test", passwd="test")
        return f.test_deferred

    def assertFails(self, d, failure_name):
        """
        Fail unless a failure called failure_name (from
        protocol_pb2.Error) is thrown. If a different type of failure
        is thrown, it will not be caught, and the test case will be
        deemed to have suffered an error, exactly as for an unexpected
        failure.
        """
        if getattr(protocol_pb2.Error, failure_name, None) is None:
            raise ValueError("Unknown failure %r" % failure_name)

        def callback(*a):
            """Things worked. This is bad."""
            message = "expected %s failure, but nothing failed" % failure_name
            return Failure(AssertionError(message))

        def errback(failure):
            """Things broke. Lets see if this is good.""" ""
            if not failure.check(request.StorageProtocolError):
                return failure
            message = getattr(failure.value, 'error_message', None)
            if message is None:
                message = failure.value.message
            failure_type = message.error.type
            expected_type = getattr(protocol_pb2.Error, failure_name)
            if failure_type != expected_type:
                return failure

        d.addCallbacks(callback, errback)
        return d

    def buildFactory(self, *args, **kwargs):
        """build self.factory with the specified args and kwargs"""
        return self.factory_class(*args, **kwargs)

    @defer.inlineCallbacks
    def get_url(self, url):
        logger.debug('Getting URL at: %s', url)
        try:
            result = yield getPage(url.encode('utf-8'))
        except Error as e:
            result = {
                'status': int(e.status),
                'message': e.message.decode('utf-8'),
                'response': e.response.decode('utf-8'),
            }
        else:
            result = {'status': 200, 'response': result.decode('utf-8')}
        defer.returnValue(result)

    @defer.inlineCallbacks
    def setUp(self):
        """Setup."""
        yield super(TestWithDatabase, self).setUp()

        users = (
            ('usr0', 'open sesame'),
            ('usr1', 'friend'),
            ('usr2', 'pass2'),
            ('usr3', 'usr3'),
        )
        for username, password in users:
            user = self.make_user(username=username, password=password)
            setattr(self, username, user)
            # set the password in the object just as a test simplifier
            user.password = password
            dummy_tokens = getattr(self.auth_provider_class, '_allowed', None)
            if dummy_tokens:
                dummy_tokens[password] = user.id

        # tune the config for this tests
        self.patch(settings, 'STORAGE_CHUNK_SIZE', self.STORAGE_CHUNK_SIZE)

    def save_req(self, req, name):
        """Save a request for later use."""
        setattr(self._state, name, req)
        return req

    @defer.inlineCallbacks
    def get_client_helper(
        self,
        wait_notifications=0,
        timeout=None,
        caps=PREFERRED_CAP,
        use_ssl=False,
        auth_token=None,
        name='a-client',
        **kwargs
    ):
        """Simplify the testing code by getting a client for the user."""
        connect_d = defer.Deferred()
        factory = FactoryHelper(
            connect_d.callback,
            factory=self.buildFactory(),
            wait_notifications=wait_notifications,
            timeout=timeout,
            caps=caps,
            **kwargs
        )

        def wait_test_deferred():
            logger.info(
                'TestWithDatabase.get_client_helper: client %r waiting for '
                'deferred %r (already called? %s)',
                name,
                factory.test_deferred,
                factory.test_deferred.called,
            )
            return factory.test_deferred

        self.addCleanup(wait_test_deferred)

        # there are 3 ways to connect to a server.
        # tcp and ssl will work in the tests
        if use_ssl:
            connector = reactor.connectSSL(
                "localhost", self.ssl_port, factory, ssl.ClientContextFactory()
            )
        else:
            connector = reactor.connectTCP("localhost", self.port, factory)
        # https connect requires a working proxy and a server on
        # the default port running (we are not setting this up for
        # automated testing yet)
        # connector = proxy_tunnel.connectHTTPS(
        #     'localhost', 3128, "localhost", 20101, factory,
        #     user="test", passwd="test")
        self.addCleanup(connector.disconnect)

        client = yield connect_d
        self.addCleanup(client.test_done)
        self.addCleanup(client.kill)
        self.addCleanup(client.transport.loseConnection)

        if isinstance(auth_token, dict):
            yield client.simple_authenticate(**auth_token)
        elif isinstance(auth_token, str):
            yield client.dummy_authenticate(auth_token)
        else:
            logger.warning(
                'TestWithDatabase.get_client_helper, no authentication done '
                '(auth_token: %r)',
                auth_token,
            )

        defer.returnValue(client)


class BufferedConsumer(object):
    """Consumer that stores the content in a internal buffer."""

    def __init__(self, bytes_producer):
        """Create a BufferedConsumer."""
        self.producer = bytes_producer
        self.producer.consumer = self
        self.buffer = BytesIO()

    def resumeProducing(self):
        """IPushProducer interface."""
        if self.producer:
            self.producer.resumeProducing()

    def stopProducing(self):
        """IPushProducer interface."""
        if self.producer:
            self.producer.stopProducing()

    def pauseProducing(self):
        """IPushProducer interface."""
        if self.producer:
            self.producer.pauseProducing()

    def write(self, content):
        """Part of IConsumer."""
        self.buffer.write(content)
