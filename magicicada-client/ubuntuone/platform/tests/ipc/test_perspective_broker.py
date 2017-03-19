# -*- coding: utf-8 -*-
#
# Copyright 2011-2012 Canonical Ltd.
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
"""IPC tests on perspective broker."""
import itertools
import os

from mocker import MockerTestCase, ANY

from dirspec import basedir
from twisted.internet import defer
from twisted.spread.pb import (
    DeadReferenceError,
    NoSuchMethod,
    RemoteReference,
)
from twisted.trial.unittest import TestCase

from contrib.testing.testcase import (
    FakedService,
    FakeMainTestCase,
)
try:
    from ubuntuone.devtools.testcases import skipIf, skipIfOS
except ImportError:
    from ubuntuone.devtools.testcase import skipIf, skipIfOS
from ubuntuone.platform.ipc import perspective_broker as ipc
from ubuntuone.platform.ipc.perspective_broker import (
    Config,
    Events,
    Folders,
    FileSystem,
    PublicFiles,
    RemoteMeta,
    Shares,
    SignalBroadcaster,
    Status,
    SyncDaemon,
)
from ubuntuone.platform.ipc import ipc_client
from ubuntuone.platform.ipc.ipc_client import (
    signal,
    ConfigClient,
    EventsClient,
    FoldersClient,
    FileSystemClient,
    PublicFilesClient,
    RemoteClient,
    StatusClient,
    SyncDaemonClient,
    SharesClient,
)
from ubuntuone.syncdaemon import interaction_interfaces
try:
    from ubuntuone.networkstate.networkstates import ONLINE
except ImportError:
    from ubuntuone.networkstate import ONLINE


class NoTestCase(object):
    """Dummy class to be used when txsocketserver is not available."""

try:
    from ubuntuone.devtools.testcases.txsocketserver import (
        TidyUnixServer,
        TCPPbServerTestCase,
    )
except ImportError:
    TidyUnixServer = None
    TCPPbServerTestCase = NoTestCase

TEST_PORT = 40404
TEST_DOMAIN_SOCKET = os.path.join(basedir.xdg_cache_home, 'ubuntuone', 'ipc')


class RandomException(Exception):
    """A random exception."""


class FakeActivationClient(object):
    """A fake ActivationClient."""

    def __init__(self, config):
        """Initialize this fake instance."""
        self.config = config

    def get_active_client_description(self):
        """Return the port where the pb server is running."""
        return defer.succeed(self.config.description.client)


class FakeDecoratedObject(object):
    """An object that has decorators."""

    def __init__(self):
        """Create a new instance."""
        super(FakeDecoratedObject, self).__init__()

    @signal
    def on_no_args(self):
        """Get no args passwed."""

    @signal
    def on_just_args(self, *args):
        """Just get args."""

    @signal
    def on_just_kwargs(self, **kwargs):
        """Just get kwargs."""

    @signal
    def on_both_args(self, *args, **kwargs):
        """Both args."""


class SignalTestCase(MockerTestCase):
    """Test the signal decorator."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(SignalTestCase, self).setUp()
        self.fake_object = FakeDecoratedObject()
        self.cb = self.mocker.mock()

    def test_no_args(self):
        """Test when the cb should have no args."""
        self.fake_object.on_no_args_cb = self.cb
        self.cb()
        self.mocker.replay()
        self.fake_object.on_no_args()

    def test_just_args(self):
        """Test when the cb just has *args"""
        first = 'first'
        second = 'second'
        self.fake_object.on_just_args_cb = self.cb
        self.cb(first, second)
        self.mocker.replay()
        self.fake_object.on_just_args(first, second)

    def test_just_kwargs(self):
        """Test when the cb just has kwargs."""
        first = 'first'
        second = 'second'
        self.fake_object.on_just_kwargs_cb = self.cb
        self.cb(first=first, second=second)
        self.mocker.replay()
        self.fake_object.on_just_kwargs(first=first, second=second)

    def test_just_kwargs_empty(self):
        """Test when the cb just has kwargs."""
        self.fake_object.on_just_kwargs_cb = self.cb
        self.cb()
        self.mocker.replay()
        self.fake_object.on_just_kwargs()

    def test_both_args(self):
        """Test with args and kwargs."""
        first = 'first'
        second = 'second'
        self.fake_object.on_both_args_cb = self.cb
        self.cb(first, second, first=first, second=second)
        self.mocker.replay()
        self.fake_object.on_both_args(first, second, first=first,
                                      second=second)

    def test_both_args_no_kwargs(self):
        """Test with args and kwargs."""
        first = 'first'
        second = 'second'
        self.fake_object.on_both_args_cb = self.cb
        self.cb(first, second)
        self.mocker.replay()
        self.fake_object.on_both_args(first, second)

    def test_both_args_no_args(self):
        """Test with args and kwargs."""
        first = 'first'
        second = 'second'
        self.fake_object.on_both_args_cb = self.cb
        self.cb(first=first, second=second)
        self.mocker.replay()
        self.fake_object.on_both_args(first=first, second=second)


class PerspectiveBrokerTestCase(TestCase):
    """Base test case for the IPC used on Windows."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(PerspectiveBrokerTestCase, self).setUp()
        self.config = Config(None)
        self.status = Status(None)
        self.events = Events(None)
        self.sync = SyncDaemon(None)
        self.shares = Shares(None)
        self.folders = Folders(None)
        self.public_files = PublicFiles(None)
        self.fs = FileSystem(None)


class TestSignalBroadcaster(MockerTestCase):
    """Test the signal broadcaster code."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestSignalBroadcaster, self).setUp()
        self.client = self.mocker.mock()
        self.broad_caster = SignalBroadcaster()

    def test_remote_register_to_signals(self):
        """Assert that the client was added."""
        self.mocker.replay()
        signals = ["demo_signal1", "demo_signal2"]
        self.broad_caster.remote_register_to_signals(self.client, signals)
        for sig in signals:
            clients = self.broad_caster.clients_per_signal[sig]
            self.assertTrue(self.client in clients)

    def test_emit_signal(self):
        """Assert that the client method was called."""
        first = 1
        second = 2
        word = 'word'
        signal_name = 'on_test'
        deferred = self.mocker.mock()
        self.client.callRemote(signal_name, first, second, word=word)
        self.mocker.result(deferred)
        deferred.addErrback(ANY, ANY, ANY)
        deferred.addErrback(ANY, ANY, ANY)
        self.mocker.replay()
        signals = [signal_name]
        self.broad_caster.remote_register_to_signals(self.client, signals)
        self.broad_caster.emit_signal(signal_name, first, second, word=word)

    def test_emit_signal_dead_reference(self):
        """Test dead reference while emitting a signal."""
        sample_signal = "sample_signal"
        fake_remote_client = self.mocker.mock()
        fake_remote_client.callRemote(sample_signal)
        self.mocker.throw(DeadReferenceError())
        self.mocker.replay()

        sb = SignalBroadcaster()
        sb.remote_register_to_signals(fake_remote_client, [sample_signal])
        self.assertIn(fake_remote_client, sb.clients_per_signal[sample_signal])
        sb.emit_signal(sample_signal)
        self.assertNotIn(fake_remote_client,
                         sb.clients_per_signal[sample_signal])

    def test_emit_signal_some_dead_some_not(self):
        """Test a clean reference after a dead one."""
        sample_signal = "sample_signal"
        fake_dead_remote = self.mocker.mock()
        fake_alive_remote = self.mocker.mock()

        fake_dead_remote.callRemote(sample_signal)
        self.mocker.throw(DeadReferenceError())
        fake_alive_remote.callRemote(sample_signal)
        self.mocker.result(defer.succeed(None))
        self.mocker.replay()

        sb = SignalBroadcaster()
        sb.remote_register_to_signals(fake_dead_remote, [sample_signal])
        sb.remote_register_to_signals(fake_alive_remote, [sample_signal])
        sb.emit_signal(sample_signal)


class FakeRemoteClient(object):
    """A fake RemoteClient."""

    missing_signal = "missing"
    failing_signal = "failing"
    random_exception = RandomException()

    def callRemote(self, signal_name):
        """Fake a call to a given remote method."""
        if signal_name == self.missing_signal:
            return defer.fail(NoSuchMethod())
        if signal_name == self.failing_signal:
            return defer.fail(self.random_exception)
        raise ValueError("not a valid fake signal name")


class SignalBroadcasterFailuresTestCase(TestCase):
    """Test some signal broadcaster failures."""

    def test_emit_signal_ignore_missing_handlers(self):
        """A missing signal handler should just log a debug line."""
        debugs = []
        self.patch(ipc.logger, "debug", lambda *args: debugs.append(args))

        fake_remote_client = FakeRemoteClient()

        sb = SignalBroadcaster()
        signals = [fake_remote_client.missing_signal]
        sb.remote_register_to_signals(fake_remote_client, signals)
        sb_clients = sb.clients_per_signal[fake_remote_client.missing_signal]
        self.assertIn(fake_remote_client, sb_clients)
        sb.emit_signal(fake_remote_client.missing_signal)

        expected = (
            SignalBroadcaster.MSG_NO_SIGNAL_HANDLER,
            fake_remote_client.missing_signal,
            fake_remote_client,
        )
        self.assertIn(expected, debugs)

    def test_emit_signal_log_other_errors(self):
        """Other errors should be logged as warnings."""
        warnings = []
        self.patch(ipc.logger, "warning", lambda *args: warnings.append(args))

        fake_remote_client = FakeRemoteClient()

        sb = SignalBroadcaster()
        signals = [fake_remote_client.failing_signal]
        sb.remote_register_to_signals(fake_remote_client, signals)
        sb_clients = sb.clients_per_signal[fake_remote_client.failing_signal]
        self.assertIn(fake_remote_client, sb_clients)
        sb.emit_signal(fake_remote_client.failing_signal)

        expected = (
            SignalBroadcaster.MSG_COULD_NOT_EMIT_SIGNAL,
            fake_remote_client.failing_signal,
            fake_remote_client,
            fake_remote_client.random_exception,
        )
        self.assertIn(expected, warnings)


class FakeRemoteObject(object):
    """A test helper."""

    def __init__(self):
        """Initialize this test helper."""
        self.called = []

    def callRemote(self, *args):
        """A remote call to this object."""
        self.called.append(args)


class FakeNetworkManagerState(object):
    """Fake NetworkState."""

    def __init__(self, result_cb=None):
        """Just save callback."""
        self.cb = result_cb

    def find_online_state(self):
        """Always say ONLINE."""
        self.cb(ONLINE)


class RemoteClientTestCase(TestCase):
    """Tests for the RemoteClient class."""

    def test_register_to_signals(self):
        """Test the register_to_signals method."""
        fake_remote_object = FakeRemoteObject()
        client = RemoteClient(fake_remote_object)
        client.signal_handlers = ["on_abc"]
        client.register_to_signals()
        expected = [
            ("register_to_signals", client, client.signal_handlers)
        ]
        self.assertEqual(fake_remote_object.called, expected)


@skipIf(TCPPbServerTestCase is NoTestCase,
        'Testcases from txsocketserver not availble.')
class IPCTestCase(FakeMainTestCase, TCPPbServerTestCase):
    """Set the ipc to a random port for this instance."""

    timeout = 5
    service_class = FakedService
    client_name = None
    client_class = None
    signal_mapping = []

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        self.patch(ipc, 'ActivationClient', FakeActivationClient)
        # patch the interaction interfaces to not choose the system one but
        # always the perspective broker one
        self.patch(interaction_interfaces, 'ExternalInterface',
                   ipc.IPCInterface)

        yield super(IPCTestCase, self).setUp()

        class FakeDescriptionFactory(object):
            """Factory used that returns settings for the test."""

            def __init__(my_self):
                """Create a new instance."""
                my_self.server = self.server_runner.get_server_endpoint()
                my_self.client = self.server_runner.get_client_endpoint()

        # patch the description facotry to return the settings used by the
        # test
        self.patch(ipc, 'DescriptionFactory', FakeDescriptionFactory)

        self.bus = None  # parity with linux code

        # patch the networkmanagerstate to avoid spawning unnecessary
        # threads when we instantiate the syncdaemonservice:
        self.patch(interaction_interfaces, 'NetworkManagerState',
                   FakeNetworkManagerState)

        self.service = self.service_class(main=self.main, send_events=True)
        self.service.auth_credentials = ('foo', 'bar')

        # patch the way the ipc interface is started so that we use the clean
        # method provided by the test case

        @defer.inlineCallbacks
        def server_listen(*args):
            """Start listening using the interface."""
            yield self.listen_server(self.service.interface)
            self.service.interface.listener = self.listener
            defer.returnValue(self.listener)

        self.patch(ipc, 'ipc_server_listen', server_listen)
        self.connector = yield self.service.start()
        self.service.connect()

        self.interface = self.service.interface

        if self.client_name is not None:
            client = getattr(self.interface, self.client_name)
            setattr(self, self.client_name, client)

    @defer.inlineCallbacks
    def get_client(self):
        """Get the client."""
        # request the remote object and create a client
        yield self.connect_client()
        root = yield self.client_factory.getRootObject()
        if self.client_name is not None:
            remote = yield root.callRemote('get_%s' % self.client_name)
            client = self.client_class(remote)
            yield client.register_to_signals()
            # addCleanup support having deferreds as cleanup calls
            self.addCleanup(client.unregister_to_signals)

            def helper(method, *a, **kw):
                return getattr(result, method)(*a, **kw)

            client.call_method = helper
            result = client
        else:
            result = root
        defer.returnValue(result)

    @defer.inlineCallbacks
    def assert_method_called(self, service, method, result, *args, **kwargs):
        """Check that calling 'method(*args, **kwargs)' should query 'service'.

        The returned result from calling 'method(*args, **kwargs)' should be
        equal to the given parameter 'result'. If 'result' is a deferred, its
        result attribute will be used as expected result (ergo the deferred
        should be already called).

        """
        client = yield self.get_client()

        # hack to handle service methods returning a deferred with result
        if isinstance(result, defer.Deferred):
            real_result = result.result
        else:
            real_result = result

        self.patch(service, method, lambda *a, **kw: result)
        actual = yield client.call_method(method, *args, **kwargs)
        self.assertEqual(real_result, actual)
        self.assertEqual(service._called, {method: [(args, kwargs)]})

    def assert_remote_method(self, method, in_signature='', out_signature='',
                             async_callbacks=None):
        """Assert that 'method' is a remote method.

        'in_signature' and 'out_signature' are ignored for now.

        """
        client = getattr(self, self.client_name)
        self.assertIn(method, client.remote_calls)

    def assert_remote_signal(self, signal_name, *args):
        """Assert that 'signal' is a remote signal.

        The parameters args will be passed as such to the signal itself, to
        exercise it.

        """
        client = getattr(self, self.client_name)
        self.patch(client, 'emit_signal', self._set_called)
        signal = getattr(client, signal_name)
        signal(*args)

        expected = (client.signal_mapping[signal_name],) + args
        self.assertEqual(self._called, (expected, {}))

    def test_remote_signals(self):
        """Check every signal defined in self.signal_mapping.

        Assert that every signal is a remote signal and that it has the
        expected signature.

        """

        for signal_name, args in self.signal_mapping:
            self.assert_remote_signal(signal_name, *args)

    def test_remote_signal_calling(self):
        """Call client functions directly, test for TypeErrors."""
        if self.client_name is None:
            return

        def fake_remote_cb(*args, **kwargs):
            return (args, kwargs)

        client = getattr(self, self.client_name)
        remote_client = self.client_class(FakeRemoteObject())
        for signal_name, args in self.signal_mapping:

            remote_client_func_name = client.signal_mapping[signal_name]
            remote_cb_name = "%s_cb" % remote_client_func_name
            setattr(remote_client, remote_cb_name, fake_remote_cb)
            self.addCleanup(delattr, remote_client, remote_cb_name)

            remote_client_func = getattr(remote_client,
                                         remote_client_func_name)

            result = remote_client_func(*args)

            # add empty kwargs because signal wrapper will add them:
            expected = (args, {})
            self.assertEqual(expected, result)


class StatusTestCase(IPCTestCase):
    """Test the status client class."""

    client_class = StatusClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSStatusTestCase(StatusTestCase):
    """Test the status client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class EventsTestCase(IPCTestCase):
    """Test the events client class."""

    client_class = EventsClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSEventsTestCase(EventsTestCase):
    """Test the events client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class SyncDaemonTestCase(IPCTestCase):
    """Test the syncdaemon client class."""

    client_class = SyncDaemonClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSSyncDaemonTestCase(SyncDaemonTestCase):
    """Test the syncdaemon client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class FileSystemTestCase(IPCTestCase):
    """Test the file system client class."""

    client_class = FileSystemClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSFileSystemTestCase(FileSystemTestCase):
    """Test the file system client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class SharesTestCase(IPCTestCase):
    """Test the shares client class."""

    client_class = SharesClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSSharesTestCase(SharesTestCase):
    """Test the shares client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class ConfigTestCase(IPCTestCase):
    """Test the status client class."""

    client_class = ConfigClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSConfigTestCase(ConfigTestCase):
    """Test the status client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class FoldersTestCase(IPCTestCase):
    """Test the status client class."""

    client_class = FoldersClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSFoldersTestCase(FoldersTestCase):
    """Test the status client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class PublicFilesTestCase(IPCTestCase):
    """Test the status client class."""

    client_class = PublicFilesClient


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSPublicFilesTestCase(PublicFilesTestCase):
    """Test the status client class."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class RemoteMetaTestCase(TestCase):
    """Tests for the RemoteMeta metaclass."""

    def test_remote_calls_renamed(self):
        """The remote_calls are renamed."""
        test_token = object()

        class TestClass(object):
            """A class for testing."""

            __metaclass__ = RemoteMeta

            remote_calls = ['test_method']

            def test_method(self):
                """Fake call."""
                return test_token

        tc = TestClass()
        self.assertEqual(tc.test_method(), test_token)
        self.assertEqual(tc.remote_test_method(), test_token)

    def test_signal_handlers_renamed(self):
        """The signal_handlers are renamed."""
        test_token = object()

        class TestClass(object):
            """A class for testing."""

            __metaclass__ = RemoteMeta

            signal_handlers = ['test_signal_handler']

            def test_signal_handler(self):
                """Fake call."""
                return test_token

        tc = TestClass()
        self.assertEqual(tc.test_signal_handler(), test_token)
        self.assertEqual(tc.remote_test_signal_handler(), test_token)


class IPCInterfaceTestCase(IPCTestCase):
    """Ensure that the IPCInterface works as expected."""

    @defer.inlineCallbacks
    def test_get_status(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_status')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_events(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_events')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_sync_daemon(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_sync_daemon')
        self.assertNotEqual(
            remote, None, 'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_file_system(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_file_system')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_shares(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_shares')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_config(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_config')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_folders(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_folders')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)

    @defer.inlineCallbacks
    def test_get_public_files(self):
        """Ensure that a reference object is returned."""
        client = yield self.get_client()
        remote = yield client.callRemote('get_public_files')
        self.assertNotEqual(remote, None,
                            'Remote object should not be None')
        self.assertIsInstance(remote, RemoteReference)


@skipIf(TidyUnixServer is None, 'Testcases from txsocketserver not availble.')
@skipIfOS('win32', 'Unix domain sockets not supported on windows.')
class DUSInterfaceTestCase(IPCInterfaceTestCase):
    """Ensure that the IPCInterface works as expected."""

    def get_server(self):
        """Return the server to be used to run the tests."""
        return TidyUnixServer()


class IPCPortTestCase(TestCase):
    """Tests for the ipc port setup."""

    def patch_ipc_activation(self, new_value):
        method_name = 'get_server_description'
        if getattr(ipc.ActivationInstance, method_name, None) is None:
            method_name = 'get_port'
        self.patch(ipc.ActivationInstance, method_name, new_value)

    @defer.inlineCallbacks
    def test_is_already_running_no(self):
        """Test the is_already_running function."""
        self.patch_ipc_activation(lambda _: defer.succeed(TEST_PORT))
        is_running = yield ipc.is_already_running()
        self.assertFalse(is_running, "Should not be running.")

    @defer.inlineCallbacks
    def test_is_already_running_yes(self):
        """Test the is_already_running function."""
        self.patch_ipc_activation(
            lambda _: defer.fail(ipc.AlreadyStartedError()))
        is_running = yield ipc.is_already_running()
        self.assertTrue(is_running, "Should be running by now.")


class MultipleConnectionsTestCase(TestCase):
    """Test the execution of the client with multiple connections."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set the different tests."""
        yield super(MultipleConnectionsTestCase, self).setUp()
        self.client_connect_d = defer.Deferred()  # called when we connected
        self.client_root_obj_d = defer.Deferred()  # called when we got root
        self.remote_obj_d = defer.Deferred()  # called when we got the remotes
        self.register_to_signals_d = defer.Deferred()  # called with signals
        self.called = []
        self.num_clients = 4

        @defer.inlineCallbacks
        def fake_get_root_object():
            """Fake getting a root objects."""
            yield self.client_root_obj_d
            self.called.append('getRootObject')
            defer.returnValue(True)

        @defer.inlineCallbacks
        def fake_ipc_client_connect(factory):
            """Fake ipc_client_connect."""
            yield self.client_connect_d
            self.called.append('ipc_client_connect')

            # lets patch the factory getRootObjects function
            self.patch(factory, 'getRootObject', fake_get_root_object)
            defer.returnValue(True)

        self.patch(ipc_client, 'ipc_client_connect', fake_ipc_client_connect)

        @defer.inlineCallbacks
        def fake_request_remote_objects(my_self, root):
            """Fake request_remote_objects."""
            yield self.remote_obj_d
            self.called.append('_request_remote_objects')
            defer.returnValue(True)

        self.patch(
            ipc_client.UbuntuOneClient, '_request_remote_objects',
            fake_request_remote_objects)

        @defer.inlineCallbacks
        def fake_register_to_signals(my_self):
            """Fake registering to signals."""
            yield self.register_to_signals_d
            self.called.append('register_to_signals')
            defer.returnValue(True)

        self.patch(
            ipc_client.UbuntuOneClient, 'register_to_signals',
            fake_register_to_signals)

    def grouper(self, n, iterable, fillvalue=None):
        "grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx"
        args = [iter(iterable)] * n
        return itertools.izip_longest(*args, fillvalue=fillvalue)

    @defer.inlineCallbacks
    def test_multiple_connections(self):
        """Test that we only perform connect once but all other are correct."""
        deferreds = [self.client_connect_d, self.client_root_obj_d,
                     self.remote_obj_d, self.register_to_signals_d]

        # the order in which the calls are expected
        expected_calls = (
            'ipc_client_connect', 'getRootObject',
            '_request_remote_objects', 'register_to_signals')

        clients = []
        while len(clients) < self.num_clients:
            clients.append(ipc_client.UbuntuOneClient())

        connected_d = []

        for num_steps in range(len(deferreds)):
            # tell the first client to connect
            connected_d.append(clients[0].connect())

            # perform the number of connection steps so far
            for index, step_d in enumerate(deferreds):
                if index > num_steps:
                    break
                step_d.callback(True)

            # call connect to all the other clients
            for client in clients[1:]:
                connected_d.append(client.connect())

            # perform the rest of steps
            for step_d in deferreds[num_steps + 1:]:
                step_d.callback(True)

            yield defer.gatherResults(connected_d)

            # reset all the deferreds for the next round of testing
            methods = enumerate(
                ('client_connect_d', 'client_root_obj_d', 'remote_obj_d',
                 'register_to_signals_d'))
            for i, d_name in methods:
                new_d = defer.Deferred()
                setattr(self, d_name, new_d)
                deferreds[i] = new_d

            # assert that all connect calls have been done in the correct
            # order
            for calls in self.grouper(4, self.called, None):
                self.assertEqual(expected_calls, calls)
