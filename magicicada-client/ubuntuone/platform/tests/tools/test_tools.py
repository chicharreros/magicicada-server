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
"""Tests for some tools for talking to the syncdaemon."""

import sys
import operator

from twisted.internet import defer
from twisted.spread import pb
from twisted.trial.unittest import TestCase

from ubuntuone.platform.tools import perspective_broker


# ugly trick to stop pylint for complaining about
# WindowsError on Linux
if sys.platform != 'win32':
    WindowsError = None


class TestSyncDaemonTool(TestCase):
    """Various utility methods to test/play with the SyncDaemon."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestSyncDaemonTool, self).setUp()
        self.patch(
            perspective_broker.UbuntuOneClient, "connect",
            lambda _: defer.Deferred())
        self.sdtool = perspective_broker.SyncDaemonToolProxy()
        self.calls = {}

    def test_call_after_connection(self):
        """Test the _call_after_connection method."""
        collected_calls = []
        test_method = self.sdtool._call_after_connection(
            lambda *args: collected_calls.append(args))
        test_method(123)
        self.assertEqual(len(collected_calls), 0)
        self.sdtool.connected.callback("got connected!")
        self.assertEqual(len(collected_calls), 1)

    def test_call_after_connection_connect(self):
        """Test execute connect in _call_after_connection method."""
        self.patch(self.sdtool.client, "is_connected", lambda: False)
        self.patch(
            self.sdtool.client, "connect",
            lambda *a, **kw: operator.setitem(self.calls, "connect", (a, kw)))
        collected_calls = []
        test_method = self.sdtool._call_after_connection(
            lambda *args: collected_calls.append(args))
        test_method(123)
        self.assertIn("connect", self.calls)
        self.assertEqual(self.calls["connect"], ((), {}))

    def test_call_after_connection_not_connect(self):
        """Test execute connect in _call_after_connection method."""
        self.patch(self.sdtool.client, "is_connected", lambda: True)
        self.patch(
            self.sdtool.client, "connect",
            lambda *a, **kw: operator.setitem(self.calls, "connect", (a, kw)))
        collected_calls = []
        test_method = self.sdtool._call_after_connection(
            lambda *args: collected_calls.append(args))
        test_method(123)
        self.assertNotIn("connect", self.calls)

    def test_should_wrap(self):
        """Only some attributes should be wrapped."""
        test_function = "sample_function"
        assert test_function not in self.sdtool._DONT_VERIFY_CONNECTED
        self.assertTrue(self.sdtool._should_wrap(test_function))

    def test_should_not_wrap_listed_attributes(self):
        """Attributes listed in DONT_VERIFY_CONNECTED should not be wrapped."""
        for attribute_name in self.sdtool._DONT_VERIFY_CONNECTED:
            self.assertFalse(self.sdtool._should_wrap(attribute_name))

    def test_should_not_wrap_underscore_attributes(self):
        """Attributes starting with underscore should not be wrapped."""
        dunder_function = "__sample_attribute__"
        assert dunder_function not in self.sdtool._DONT_VERIFY_CONNECTED
        self.assertFalse(self.sdtool._should_wrap(dunder_function))

        under_function = "_sampleattribute"
        assert under_function not in self.sdtool._DONT_VERIFY_CONNECTED
        self.assertFalse(self.sdtool._should_wrap(under_function))

    def test_getattributes_wraps_methods(self):
        """The common methods are wrapped with connect."""
        for attr_name in dir(self.sdtool):
            if self.sdtool._should_wrap(attr_name):
                attr = getattr(self.sdtool, attr_name)
                func_name = getattr(attr, "__name__", None)
                self.assertEqual(func_name, "call_after_connection_inner")

    def test_getattributes_does_not_wrap_special(self):
        """The special methods and attributes are not wrapped."""
        for attr_name in dir(self.sdtool):
            if not self.sdtool._should_wrap(attr_name):
                attr = getattr(self.sdtool, attr_name)
                func_name = getattr(attr, "__name__", None)
                self.assertNotEqual(func_name, "call_after_connection_inner")


class FakeRemoteObject(object):
    """Fake a remote object."""

    def __init__(self):
        """Create a new instance."""
        self.number_calls = 0
        self.called = []

    def method_call(self, *args, **kwargs):
        """Fake a remote method call."""
        if self.number_calls == 0:
            self.number_calls += 1
            raise pb.DeadReferenceError()
        else:
            self.called.append((args, kwargs))
            return defer.succeed(self.number_calls)


class PerspectiveBrokerReconnect(TestCase):
    """Test when the ipc is reconnected."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set the tests."""
        yield super(PerspectiveBrokerReconnect, self).setUp()
        self.sdtool = perspective_broker.SyncDaemonToolProxy()
        self.sdtool.client.fake_remote = FakeRemoteObject()
        self.connected_signals = []
        self.reconnected = False

        def connect_signal(my_self, *args, **kwargs):
            """Fake connect_signal call."""
            self.connected_signals.append(('connect_signal', args, kwargs))

        self.patch(
            perspective_broker.SyncDaemonToolProxy, 'connect_signal',
            connect_signal)

        def fake_reconnect(_):
            """Fake the reconnection of the client."""
            self.reconnected = True

        self.patch(
            perspective_broker.UbuntuOneClient, 'reconnect', fake_reconnect)
        self.patch(
            perspective_broker.UbuntuOneClient, 'connect',
            lambda _: defer.succeed(True))

    @defer.inlineCallbacks
    def test_reconnect_no_signals(self):
        """Test reconnection with no signals."""
        yield self.sdtool.call_method('fake_remote', 'method_call')
        self.assertTrue(self.reconnected)
        self.assertEqual(0, len(self.connected_signals))

    @defer.inlineCallbacks
    def test_reconnect_signals(self):
        """Test reconnection with signals."""
        self.sdtool.connected_signals = dict(create_signal=[lambda: None],
                                             delete_signal=[lambda: None])
        yield self.sdtool.call_method('fake_remote', 'method_call')
        self.assertTrue(self.reconnected)
        self.assertEqual(2, len(self.connected_signals))


class FakeU1Objects(object):
    """Fake PublicFiles for UbuntuOneClient."""

    def on_public_files_list_cb(self):
        """Do nothing."""

    def on_share_changed_cb(self):
        """Do nothing."""


class FakeUbuntuOneClient(object):
    """Fake UbuntuOneClient."""

    def __init__(self):
        self.public_files = FakeU1Objects()
        self.shares = FakeU1Objects()
        self.connected = True

    def is_connected(self):
        """Fake is_connected."""
        return self.connected

    def connect(self):
        """Fake connect."""
        self.connected = True
        yield self.connected

    def disconnect(self):
        """Fake disconnect."""
        self.connected = False


class PerspectiveBrokerConnectSignal(TestCase):
    """Test when the ipc is reconnected."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set the tests."""
        yield super(PerspectiveBrokerConnectSignal, self).setUp()
        self.patch(perspective_broker, 'UbuntuOneClient', FakeUbuntuOneClient)
        self.sdtool = perspective_broker.SyncDaemonToolProxy()
        self.addCleanup(self.sdtool.shutdown)

    def test_connect_several_handlers_to_same_signal(self):
        """Connect more than one handler to the same signal name."""
        data = []

        signal_name = "PublicFilesList"
        self.sdtool.connect_signal(signal_name, lambda *a: data.append(a))
        self.sdtool.connect_signal(signal_name, lambda *a: data.append(a))

        self.assertEqual(len(self.sdtool.connected_signals[signal_name]), 2)
        self.sdtool.client.public_files.on_public_files_list_cb()
        expected = [(), ()]
        self.assertEqual(data, expected)

    def test_connect_avoid_repeated_connection(self):
        """Ensure that we don't have the same handler called twice."""
        data = []

        signal_name = "PublicFilesList"

        def func(*a):
            return data.append(a)

        self.sdtool.connect_signal(signal_name, func)
        self.sdtool.connect_signal(signal_name, func)

        self.assertEqual(len(self.sdtool.connected_signals[signal_name]), 1)
        self.sdtool.client.public_files.on_public_files_list_cb()
        expected = [()]
        self.assertEqual(data, expected)

    def test_proper_connections(self):
        """Check that the proper handlers are called."""
        data = []
        data2 = []

        signal_name = "PublicFilesList"
        signal_name2 = "ShareChanges"
        self.sdtool.connect_signal(signal_name, lambda *a: data.append(a))
        self.sdtool.connect_signal(signal_name2, lambda *a: data2.append(a))

        self.assertEqual(len(self.sdtool.connected_signals[signal_name]), 1)
        self.assertEqual(len(self.sdtool.connected_signals[signal_name2]), 1)
        self.sdtool.client.public_files.on_public_files_list_cb()
        expected = [()]
        self.assertEqual(data, expected)
        self.assertEqual(data2, [])
        data = []
        self.sdtool.client.shares.on_share_changed_cb()
        self.assertEqual(data, [])
        self.assertEqual(data2, expected)
