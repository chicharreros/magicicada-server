# -*- coding: utf-8 -*-
#
# Copyright 2009-2012 Canonical Ltd.
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
"""Tests for the DBUS interface."""

import logging

import dbus

from twisted.internet import defer
try:
    from ubuntuone.devtools.testcases.dbus import DBusTestCase
except ImportError:
    from ubuntuone.devtools.testcase import DBusTestCase

from contrib.testing.testcase import (
    FakeMainTestCase,
    FakedService,
    FakedObject,
)
from ubuntuone.platform.ipc import linux as dbus_interface
from ubuntuone.platform.ipc.linux import (
    DBusExposedObject,
    DBUS_IFACE_STATUS_NAME,
    DBUS_IFACE_EVENTS_NAME,
    DBUS_IFACE_FS_NAME,
    DBUS_IFACE_SYNC_NAME,
    DBUS_IFACE_SHARES_NAME,
    DBUS_IFACE_CONFIG_NAME,
    DBUS_IFACE_FOLDERS_NAME,
    DBUS_IFACE_PUBLIC_FILES_NAME,
    DBUS_IFACE_LAUNCHER_NAME,
)
from ubuntuone.platform.tools.linux import DBusClient


class FakeNetworkManager(DBusExposedObject):
    """ A fake NetworkManager that only emits StatusChanged signal. """

    State = 3
    path = '/org/freedesktop/NetworkManager'

    def __init__(self, bus):
        """ Creates the instance. """
        self.bus = bus
        self.bus.request_name('org.freedesktop.NetworkManager',
                              flags=dbus.bus.NAME_FLAG_REPLACE_EXISTING |
                              dbus.bus.NAME_FLAG_DO_NOT_QUEUE |
                              dbus.bus.NAME_FLAG_ALLOW_REPLACEMENT)
        self.busName = dbus.service.BusName('org.freedesktop.NetworkManager',
                                            bus=self.bus)
        DBusExposedObject.__init__(self, bus_name=self.busName,
                                   service=None)

    def shutdown(self):
        """ Shutdown the fake NetworkManager """
        self.busName.get_bus().release_name(self.busName.get_name())
        self.remove_from_connection()

    @dbus.service.signal('org.freedesktop.NetworkManager', signature='i')
    def StateChanged(self, state):
        """ Fire DBus signal StatusChanged. """

    def emit_connected(self):
        """ Emits the signal StateCganged(3). """
        self.StateChanged(70)

    def emit_disconnected(self):
        """ Emits the signal StateCganged(4). """
        self.StateChanged(20)

    @dbus.service.method(dbus.PROPERTIES_IFACE,
                         in_signature='ss', out_signature='v',
                         async_callbacks=('reply_handler', 'error_handler'))
    def Get(self, interface, propname, reply_handler=None, error_handler=None):
        """Fake dbus's Get method to get at the State property."""
        try:
            reply_handler(getattr(self, propname, None))
        except Exception, e:
            error_handler(e)

    @dbus.service.method('org.freedesktop.NetworkManager')
    def state(self):
        """Fake the state."""
        return 70


class IPCTestCase(FakeMainTestCase, DBusTestCase):
    """Test the IPC handling"""

    timeout = 5
    service_class = FakedService
    path = None
    iface = None
    client_name = None  # parity with other platform's tests
    # a list of tuples (name, signature) to be used in test_remote_signals
    signal_mapping = []

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(IPCTestCase, self).setUp()
        self.log = logging.getLogger("ubuntuone.SyncDaemon.TEST")
        self.log.info("starting test %s.%s", self.__class__.__name__,
                      self._testMethodName)
        self.nm = FakeNetworkManager(self.bus)

        self.service = self.service_class(main=self.main, send_events=True)
        self.addCleanup(self.service.shutdown)
        self.service.auth_credentials = ('foo', 'bar')
        yield self.service.connect()

        self.interface = self.service.interface
        self.addCleanup(self.interface.bus.flush)

        if self.client_name is not None:  # parity with other platform's tests
            client = getattr(self.interface, self.client_name)
            setattr(self, self.client_name, client)

    def get_client(self, path=None, iface=None):
        """Return a DBusClient pointing to 'path' on 'iface'."""
        if path is None:
            path = self.path
        if iface is None:
            iface = self.iface
        return DBusClient(self.bus, path, iface)

    @defer.inlineCallbacks
    def assert_method_called(self, service, method, result, *args, **kwargs):
        """Calling 'method(*args, **kwargs)' should query 'service'.

        The returned result from calling 'method(*args, **kwargs)' should be
        equal to the given parameter 'result'. If 'result' is a deferred, its
        result attribute will be used as expected result (ergo the deferred
        should be already called).

        """
        client = self.get_client()

        # hack to handle service methods returning a deferred with result
        if isinstance(result, defer.Deferred):
            real_result = result.result
        else:
            real_result = result

        self.patch(service, method, lambda *a, **kw: result)
        actual = yield client.call_method(method, *args, **kwargs)
        self.assertEqual(real_result, actual)
        self.assertEqual(service._called, {method: [(args, kwargs)]})

    def assert_remote_method(self, method_name,
                             in_signature='', out_signature='',
                             async_callbacks=None):
        """Assert that 'method_name' is a remote method.

        'in_signature' and 'out_signature' should match with the method's
        signature.

        """
        client = getattr(self, self.client_name)
        method = getattr(client, method_name)
        self.assertTrue(method._dbus_is_method)
        self.assertEqual(method._dbus_interface, self.iface)
        self.assertEqual(method._dbus_in_signature, in_signature)
        self.assertEqual(method._dbus_out_signature, out_signature)
        self.assertEqual(method._dbus_async_callbacks, async_callbacks)

    def assert_remote_signal(self, signal_name, *args):
        """Assert that 'signal' is a remote signal.

        The parameters args will be passed as such to the signal itself, to
        exercise it.

        """
        client = getattr(self, self.client_name)
        signal = getattr(client, signal_name)

        self.assertTrue(signal._dbus_is_signal)
        self.assertEqual(signal._dbus_interface, self.iface)
        signal(*args)

    def test_remote_signals(self):
        """Check every signal defined in self.signal_mapping.

        Assert that every signal is a remote signal and that it has the
        expected signature.

        """
        for signal_name, args in self.signal_mapping:
            self.assert_remote_signal(signal_name, *args)


DBusTwistedTestCase = IPCTestCase  # API compatibility


class StatusTestCase(IPCTestCase):
    """Tests for the Status exposed object."""

    path = '/status'
    iface = DBUS_IFACE_STATUS_NAME


class EventsTestCase(IPCTestCase):
    """Tests for the Events exposed object."""

    path = '/events'
    iface = DBUS_IFACE_EVENTS_NAME


class SyncDaemonTestCase(IPCTestCase):
    """Tests for the SyncDaemon exposed object."""

    path = '/'
    iface = DBUS_IFACE_SYNC_NAME


class FileSystemTestCase(IPCTestCase):
    """Tests for the FileSystem exposed object."""

    path = '/filesystem'
    iface = DBUS_IFACE_FS_NAME


class SharesTestCase(IPCTestCase):
    """Tests for the Shares exposed object."""

    path = '/shares'
    iface = DBUS_IFACE_SHARES_NAME


class ConfigTestCase(IPCTestCase):
    """Tests for the Config exposed object."""

    path = '/config'
    iface = DBUS_IFACE_CONFIG_NAME
    name = 'files_sync'


class FoldersTestCase(IPCTestCase):
    """Tests for the Folder exposed object."""

    path = '/folders'
    iface = DBUS_IFACE_FOLDERS_NAME


class PublicFilesTestCase(IPCTestCase):
    """Tests for the FileSystem exposed object."""

    path = '/publicfiles'
    iface = DBUS_IFACE_PUBLIC_FILES_NAME


class LauncherTests(IPCTestCase):
    """Tests for the Launcher exposed object."""

    client_name = 'launcher'
    path = '/launcher'
    iface = DBUS_IFACE_LAUNCHER_NAME

    @defer.inlineCallbacks
    def test_unset_urgency(self):
        """Test unset_urgency."""
        service = FakedObject()

        def launcher_factory():
            return service

        self.patch(dbus_interface.launcher, 'Launcher', launcher_factory)
        client = self.get_client()
        yield client.call_method('unset_urgency')
        self.assertEqual(service._called, {'set_urgent': [((False,), {})]})
        self.assert_remote_method(
            'unset_urgency', in_signature=None, out_signature=None)


class TestDBusRestart(DBusTwistedTestCase):
    """Test main's restart method (and its interaction with dbus)."""

    def test_restart(self):
        """Start things up, then fire a restart, check it tries to restart."""
        d = defer.Deferred()

        def _handler(*a):
            """Async helper."""
            d.callback(True)
        # shutdown will fail when trying to restart because of our
        # half-backed dbus. That's OK, we don't actually want it
        # restarted :)
        self.main.external.shutdown = d.callback
        try:
            self.main.restart()
        except SystemExit:
            pass
        return d
    test_restart.skip = "leaves dbus stuff around, need to cleanup"
