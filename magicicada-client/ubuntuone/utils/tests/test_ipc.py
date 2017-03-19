# -*- coding: utf-8 -*-
#
# Copyright 2011-2012 Canonical Ltd.
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Perspective Broker IPC test cases."""

import logging

from collections import namedtuple

from twisted.internet import defer
from twisted.spread.pb import (
    DeadReferenceError,
    NoSuchMethod,
)
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipIfOS
from ubuntuone.devtools.testcases.txsocketserver import (
    TidyUnixServer,
    TCPPbServerTestCase,
)

from ubuntuone.tests import TestCase
from ubuntuone.utils import ipc


TEST_SERVICE = 'foo-service'
TEST_CMDLINE = 'foo.bin'
TEST_SERVER_DESCRIPTION = 'tcp:40404:interface=127.0.0.1'
TEST_CLIENT_DESCRIPTION = 'tcp:host=127.0.0.1:port=40404'


class RandomException(Exception):
    """A random exception."""


class FakeActivationClient(object):
    """A fake ActivationClient."""

    def __init__(self, config):
        """Initialize this fake instance."""
        self.config = config

    def get_active_client_description(self):
        """Return the description where the pb server is running."""
        return defer.succeed(self.config.description.client)


class FakeActivationInstance(object):
    """A fake ActivationInstance."""

    def __init__(self, config):
        """Initialize the fake instance."""
        self.config = config

    def get_server_description(self):
        """Return the description where the pb server is running."""
        return defer.succeed(self.config.description.server)


class FakeDescriptionFactory(object):
    """A fake description factory."""

    def __init__(self, server_description, client_description):
        """Create a new instace."""
        self.server = server_description
        self.client = client_description


class FakeReactor(object):
    """A fake reactor."""

    def __init__(self):
        """Initialize this faker."""
        self.connection_class = namedtuple("Connection",
                                           "host port factory backlog")
        self.connections = []

    def connectTCP(self, host, port, factory, timeout=None, bindAddress=None):
        """Store the connected factory."""
        connection = self.connection_class(host, port, factory, None)
        self.connections.append(connection)

    def listenTCP(self, port, factory, interface=None, backlog=None):
        """Store the listenning factory."""
        connection = self.connection_class(interface, port, factory, backlog)
        self.connections.append(connection)


class FakeTCP4ClientEndpoint(object):
    """A fake tcp4 client."""

    def __init__(self, protocol):
        """Create a new instance."""
        self.protocol = protocol

    def connect(self, *args, **kwargs):
        """Return the client."""
        return defer.succeed(self.protocol)


class FakeRemoteClient(object):
    """A fake RemoteClient."""

    missing_signal = "missing"
    failing_signal = "failing"
    dead_remote = False
    random_exception = RandomException()

    def __init__(self, dead_remote=False):
        self.called = False
        self.dead_remote = dead_remote

    def callRemote(self, signal_name, *a, **kw):
        """Fake a call to a given remote method."""
        if self.dead_remote:
            raise DeadReferenceError("Calling Stale Broker")

        if signal_name == self.missing_signal:
            return defer.fail(NoSuchMethod())
        if signal_name == self.failing_signal:
            return defer.fail(self.random_exception)

        self.called = (a, kw)
        return defer.succeed(None)


class DummyRemoteService(ipc.RemoteService):
    """Represent a dummy IPC object."""

    remote_calls = ['foo', 'bar']
    next_result = None

    def foo(self):
        """Dummy foo."""
        self.Success(self.next_result)

    def bar(self, error):
        """Dummy bar."""
        self.NotSuccess(error)

    @ipc.signal
    def Success(self, param):
        """Fire a signal to notify a success."""

    @ipc.signal
    def NotSuccess(self, error):
        """Fire a signal to notify a not-success."""

    @ipc.signal
    def NoArgs(self):
        """Get no args passed."""

    @ipc.signal
    def JustArgs(self, *args):
        """Just get args."""

    @ipc.signal
    def JustKwargs(self, **kwargs):
        """Just get kwargs."""

    @ipc.signal
    def BothArgsAndKwargs(self, *args, **kwargs):
        """Both args and kwargs."""


class DummyService(ipc.BaseService):
    """Represent a dummy root service."""

    services = {'dummy': DummyRemoteService}
    name = 'Dummy Service'
    description = TEST_CLIENT_DESCRIPTION
    cmdline = 'yadda yo'


class DummyRemoteClient(ipc.RemoteClient):
    """Represent a dummy remote client."""

    call_remote_functions = DummyRemoteService.remote_calls
    signal_handlers = ['Success', 'NotSuccess']


class DummyClient(ipc.BaseClient):
    """Represent a dummy base client."""

    clients = {'dummy': DummyRemoteClient}
    service_name = DummyService.name
    service_port = TEST_SERVER_DESCRIPTION
    service_cmdline = DummyService.cmdline


class DummyDescription(object):
    """Return the descriptions accordingly."""

    def __init__(self, client, server):
        """Create a new instance."""
        self.client = client
        self.server = server


class BaseIPCTestCase(TCPPbServerTestCase, TestCase):
    """Set the ipc to a random port for this instance."""

    timeout = 5

    client_class = None  # the BaseClient instance
    service_class = None  # the BaseService instance

    remote_client_name = None  # the name of the remote client in the client
    remote_service_name = None  # the name of the remote service in the service

    method_mapping = []
    signal_mapping = []

    @defer.inlineCallbacks
    def setUp(self):
        yield super(BaseIPCTestCase, self).setUp()

        self.service = None
        self.client = None

        if self.service_class is not None:

            self.service = self.service_class()
            self.client = self.client_class()

            # patch server connection and client connection to ensure that
            # we have clean connections

            @defer.inlineCallbacks
            def server_listen(server_factory, service_name, activation_cmd,
                              description, reactor=None):
                """Connect to the local running service."""
                yield self.listen_server(self.service)
                defer.returnValue(self.listener)

            self.patch(ipc, 'server_listen', server_listen)

            @defer.inlineCallbacks
            def client_connect(client_factory, service_name,
                               activation_cmdline, description, reactor=None):
                """Connect the local running client."""
                yield self.connect_client()
                self.client.factory = self.client_factory
                defer.returnValue(self.connector)

            self.patch(ipc, 'client_connect', client_connect)

            yield self.service.start()
            yield self.client.connect()

    @property
    def remote_service(self):
        """Get the service named 'service_name'."""
        return getattr(self.service, self.remote_service_name)

    @property
    def remote_client(self):
        """Get the client named 'remote_client_name'."""
        return getattr(self.client, self.remote_client_name)

    @defer.inlineCallbacks
    def assert_method_called(self, service, method, result, *args, **kwargs):
        """Check that calling 'method(*args, **kwargs)' should query 'service'.

        The returned result from calling 'method(*args, **kwargs)' should be
        equal to the given parameter 'result'. If 'result' is a deferred, its
        result attribute will be used as expected result (ergo the deferred
        should be already called).

        """
        client = self.remote_client

        # hack to handle service methods returning a deferred with result
        if isinstance(result, defer.Deferred):
            real_result = result.result
        else:
            real_result = result

        self.patch(service, method, lambda *a, **kw: result)
        actual = yield client.call_method(method, *args, **kwargs)
        self.assertEqual(real_result, actual)
        self.assertEqual(service.called, {method: [(args, kwargs)]})

    def assert_remote_method(self, method_name, *args, **kwargs):
        """Assert that 'method_name' is a remote method.

        The parameters args and kwargs will be passed as such to the method
        itself, to exercise it.

        """
        self.assertIn(method_name, self.remote_service.remote_calls)
        method = getattr(self.remote_service, method_name)
        method(*args, **kwargs)

    def assert_remote_signal(self, signal_name, *args, **kwargs):
        """Assert that 'signal' is a remote signal.

        The parameters args and kwargs will be passed as such to the signal
        itself, to exercise it.

        """
        self.patch(self.remote_service, 'emit_signal', self._set_called)
        signal = getattr(self.remote_service, signal_name)
        signal(*args, **kwargs)

        expected = (signal_name,) + args
        self.assertEqual(self._called, (expected, kwargs))

    def test_remote_methods(self):
        """Check every method defined in self.method_mapping.

        Assert that every method is a remote method and that it has the
        expected signature.

        """
        for method, args, kwargs in self.method_mapping:
            self.assert_remote_method(method, *args, **kwargs)

    def test_remote_signals(self):
        """Check every signal defined in self.signal_mapping.

        Assert that every signal is a remote signal and that it has the
        expected signature.

        """
        for signal_name, args, kwargs in self.signal_mapping:
            self.assert_remote_signal(signal_name, *args, **kwargs)


class TCPListenConnectTestCase(BaseIPCTestCase):
    """Test suite for the server_listen and client_connect methods."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TCPListenConnectTestCase, self).setUp()
        self.fake_reactor = FakeReactor()

    @defer.inlineCallbacks
    def test_server_listen(self):
        """Test the server_listen function."""
        self.patch(ipc, "ActivationInstance", FakeActivationInstance)

        description_factory = FakeDescriptionFactory(TEST_SERVER_DESCRIPTION,
                                                     TEST_CLIENT_DESCRIPTION)

        fake_factory = object()
        yield ipc.server_listen(fake_factory, TEST_SERVICE,
                                TEST_CMDLINE, description_factory,
                                reactor=self.fake_reactor)

        self.assertEqual(len(self.fake_reactor.connections), 1)
        conn = self.fake_reactor.connections[0]
        self.assertEqual(conn.factory, fake_factory)
        self.assertEqual(conn.host, ipc.LOCALHOST)

    @defer.inlineCallbacks
    def test_client_connect(self):
        """Test the client_connect function."""
        called = []
        self.patch(ipc, "ActivationClient", FakeActivationClient)

        protocol = 'protocol'
        client = FakeTCP4ClientEndpoint(protocol)

        def client_from_string(reactor, description):
            """Create a client from the given string."""
            called.append(('clientFromString', reactor, description))
            return client

        self.patch(ipc.endpoints, 'clientFromString', client_from_string)

        description_factory = FakeDescriptionFactory(TEST_SERVER_DESCRIPTION,
                                                     TEST_CLIENT_DESCRIPTION)

        fake_factory = object()
        returned_protocol = yield ipc.client_connect(
            fake_factory, TEST_SERVICE, TEST_CMDLINE, description_factory,
            reactor=self.fake_reactor)
        expected = (
            'clientFromString', self.fake_reactor, description_factory.client)
        self.assertIn(expected, called)
        self.assertEqual(protocol, returned_protocol)


@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DomainListenConnectTestCase(TCPListenConnectTestCase):
    """Test suite for the server_listen and client_connect methods."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class TCPDummyClientTestCase(BaseIPCTestCase):
    """Test the status client class."""

    client_class = DummyClient
    service_class = DummyService

    remote_client_name = remote_service_name = 'dummy'

    method_mapping = [
        ('foo', (), {}),
        ('bar', (object(),), {}),
    ]
    signal_mapping = [
        ('Success', ('test',), {}),
        ('NotSuccess', ('yadda',), {}),
        ('NoArgs', (), {}),
        ('JustArgs', (object(), 'foo'), {}),
        ('JustKwargs', (), {'foo': 'bar'}),
        ('BothArgsAndKwargs', ('zaraza', 8), {'foo': -42}),
    ]

    @defer.inlineCallbacks
    def test_deprecated_siganl_is_also_sent(self):
        """Old-style, deprecated signals handler are also called."""
        d1 = defer.Deferred()
        d2 = defer.Deferred()

        self.remote_service.next_result = 'yadda'

        # old, deprecated way
        self.remote_client.connect_to_signal('Success', d1.callback)
        self.remote_client.on_success_cb = d2.callback

        self.remote_client.foo()

        result = yield defer.gatherResults([d1, d2])

        self.assertEqual(result, ['yadda', 'yadda'])

    @defer.inlineCallbacks
    def test_register_to_signals(self):
        """Test the register_to_signals method."""
        yield self.remote_client.register_to_signals()
        self.addCleanup(self.remote_client.unregister_to_signals)

        for signal in self.remote_client.signal_handlers:
            self.assertIn(signal, self.service.dummy.clients_per_signal)

    @defer.inlineCallbacks
    def test_unregister_to_signals(self):
        """Test the register_to_signals method."""
        yield self.remote_client.register_to_signals()
        yield self.remote_client.unregister_to_signals()

        for signal in self.remote_client.signal_handlers:
            actual = len(self.remote_service.clients_per_signal[signal])
            self.assertEqual(0, actual)


@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DomainDummyClientTestCase(TCPDummyClientTestCase):
    """Test the status client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class RemoteMetaTestCase(TestCase):
    """Tests for the RemoteMeta metaclass."""

    def test_remote_calls_renamed(self):
        """The remote_calls are renamed."""
        test_token = object()

        class TestClass(ipc.meta_base(ipc.RemoteMeta)):
            """A class for testing."""

            remote_calls = ['test_method']

            def test_method(self):
                """Fake call."""
                return test_token

        tc = TestClass()
        self.assertEqual(tc.test_method(), test_token)
        self.assertEqual(tc.remote_test_method(), test_token)


class SignalBroadcasterTestCase(TestCase):
    """Test the signal broadcaster code."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(SignalBroadcasterTestCase, self).setUp()
        self.client = FakeRemoteClient()
        self.sb = ipc.SignalBroadcaster()

        self.memento = MementoHandler()
        ipc.logger.addHandler(self.memento)
        ipc.logger.setLevel(logging.DEBUG)
        self.addCleanup(ipc.logger.removeHandler, self.memento)

    def test_remote_register_to_signals(self):
        """Assert that the client was added."""
        signals = ["demo_signal1", "demo_signal2"]
        self.sb.remote_register_to_signals(self.client, signals)
        for signal in signals:
            clients = self.sb.clients_per_signal[signal]
            self.assertTrue(self.client in clients)

    def test_emit_signal(self):
        """Assert that the client method was called."""
        first = 1
        second = 2
        word = 'word'
        signal_name = 'on_test'

        self.client.callRemote(signal_name, first, second, word=word)

        signals = [signal_name]
        self.sb.remote_register_to_signals(self.client, signals)
        self.sb.emit_signal(signal_name, first, second, foo=word)

        self.assertEqual(self.client.called, ((first, second), dict(foo=word)))

    def test_emit_signal_dead_reference(self):
        """Test dead reference while emitting a signal."""
        sample_signal = "sample_signal"
        fake_remote_client = FakeRemoteClient(dead_remote=True)

        self.sb.remote_register_to_signals(fake_remote_client, [sample_signal])
        self.assertIn(fake_remote_client,
                      self.sb.clients_per_signal[sample_signal])

        self.sb.emit_signal(sample_signal)
        self.assertNotIn(fake_remote_client,
                         self.sb.clients_per_signal[sample_signal])

    def test_emit_signal_some_dead_some_not(self):
        """Test a clean reference after a dead one."""
        sample_signal = "sample_signal"
        fake_dead_remote = FakeRemoteClient(dead_remote=True)
        fake_alive_remote = FakeRemoteClient()

        self.sb.remote_register_to_signals(fake_dead_remote, [sample_signal])
        self.sb.remote_register_to_signals(fake_alive_remote, [sample_signal])
        self.sb.emit_signal(sample_signal)

        self.assertTrue(fake_alive_remote.called, "The alive must be called.")

    def test_emit_signal_ignore_missing_handlers(self):
        """A missing signal handler should just log a debug line."""
        fake_remote_client = FakeRemoteClient()

        signal = fake_remote_client.missing_signal
        signals = [signal]
        self.sb.remote_register_to_signals(fake_remote_client, signals)
        sb_clients = self.sb.clients_per_signal[signal]
        self.assertIn(fake_remote_client, sb_clients)
        self.sb.emit_signal(signal)

        expected = ipc.SignalBroadcaster.MSG_NO_SIGNAL_HANDLER % (
            signal,
            fake_remote_client,
        )
        self.assertTrue(self.memento.check_debug(*expected))

    def test_emit_signal_log_other_errors(self):
        """Other errors should be logged as warnings."""
        fake_remote_client = FakeRemoteClient()

        signal = fake_remote_client.failing_signal
        signals = [signal]
        self.sb.remote_register_to_signals(fake_remote_client, signals)
        sb_clients = self.sb.clients_per_signal[signal]
        self.assertIn(fake_remote_client, sb_clients)
        self.sb.emit_signal(signal)

        expected = ipc.SignalBroadcaster.MSG_COULD_NOT_EMIT_SIGNAL % (
            signal,
            fake_remote_client,
            fake_remote_client.random_exception,
        )
        self.assertTrue(self.memento.check_warning(*expected))


class FakeRootObject(object):
    """A fake root object."""

    def __init__(self, called, remote_obj):
        """Create a new instance."""
        self.called = called
        self.remote_obj = remote_obj

    def callRemote(self, method_name):
        """A fake call remove method."""
        self.called.append(method_name)
        return defer.succeed(self.remote_obj)


class FakeWorkingRemoteClient(object):
    """A fake remote client."""

    def __init__(self, called):
        """Create a new instance."""
        self.remote = None
        self.called = called

    def register_to_signals(self):
        """Register to signals."""
        self.called.append('register_to_signals')
        return defer.succeed(True)


class ReconnectTestCase(TestCase):
    """Test the reconnection when service is dead."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set the different tests."""
        yield super(ReconnectTestCase, self).setUp()
        self.called = []
        self.remote_obj = 'remote'
        self.root_obj = FakeRootObject(self.called, self.remote_obj)

        def fake_get_root_object():
            """Fake getting the root object."""
            self.called.append('getRootObject')
            return defer.succeed(self.root_obj)

        def fake_client_connect(factory, service_name, cmd, description):
            """Fake the client connect."""
            self.called.append('client_connect')
            self.patch(factory, 'getRootObject', fake_get_root_object)
            return defer.succeed(True)

        self.patch(ipc, 'client_connect', fake_client_connect)

    @defer.inlineCallbacks
    def test_reconnect_method(self):
        """Test the execcution of the reconnect method."""
        clients = dict(first=FakeWorkingRemoteClient(self.called),
                       second=FakeWorkingRemoteClient(self.called))

        base_client = ipc.BaseClient()
        base_client.clients = clients
        for name, client in clients.items():
            setattr(base_client, name, client)

        yield base_client.reconnect()
        # assert that we did call the correct methods
        self.assertIn('client_connect', self.called)
        self.assertIn('getRootObject', self.called)

        for name in clients:
            self.assertIn('get_%s' % name, self.called)

        self.assertEqual(
            len(clients), self.called.count('register_to_signals'))
