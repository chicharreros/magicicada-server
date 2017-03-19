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

"""Tests for the network manager."""

from ctypes import windll
from mocker import MockerTestCase
from twisted.internet.defer import inlineCallbacks

from ubuntuone.networkstate import NetworkFailException
from ubuntuone.networkstate.windows import (
    is_machine_connected,
    NetworkManager,
    NetworkManagerState,
    ONLINE,
    OFFLINE)
from ubuntuone.tests import TestCase


class TestNetworkManager(MockerTestCase):
    """Test he Network Manager."""

    def setUp(self):
        super(TestNetworkManager, self).setUp()
        self.connection_info = self.mocker.mock()
        self.connection_no_info = self.mocker.mock()
        self.disconnected = self.mocker.mock()
        self.manager = NetworkManager(self.connection_no_info,
                                      self.connection_info, self.disconnected)

    def test_connection_made(self):
        """Ensure db is called."""
        self.connection_info()
        self.mocker.replay()
        self.manager.ConnectionMade()

    def test_connection_made_no_cb(self):
        """Ensure db is called."""
        self.manager.connected_cb_info = None
        self.mocker.replay()
        self.manager.ConnectionMade()

    def test_connection_made_no_info(self):
        """Ensure db is called."""
        self.connection_no_info()
        self.mocker.replay()
        self.manager.ConnectionMadeNoQOCInfo()

    def test_connection_made_no_info_no_cb(self):
        """Ensure db is called."""
        self.manager.connected_cb = None
        self.mocker.replay()
        self.manager.ConnectionMadeNoQOCInfo()

    def test_disconnection(self):
        """Ensure db is called."""
        self.disconnected()
        self.mocker.replay()
        self.manager.ConnectionLost()

    def test_disconnection_no_cb(self):
        """Ensure db is called."""
        self.manager.disconnected_cb = None
        self.mocker.replay()
        self.manager.ConnectionLost()


class TestNetworkManagerState(MockerTestCase):
    """Test the Network Manager State."""

    def setUp(self):
        super(TestNetworkManagerState, self).setUp()
        self.network_manager = self.mocker.mock()
        self.is_connected = self.mocker.replace(
            'ubuntuone.networkstate.windows.is_machine_connected')
        self.thread = self.mocker.mock()
        self.cb = self.mocker.mock()
        self.state = NetworkManagerState(self.cb)

    def test_connection_made(self):
        """Test that the cb is actually called."""
        self.cb(ONLINE)
        self.mocker.replay()
        self.state.connection_made()

    def test_connection_lost(self):
        """Test that the cb is actually called."""
        self.cb(OFFLINE)
        self.mocker.replay()
        self.state.connection_lost()

    def test_find_online_state_not_connected(self):
        """Test that we do find the online state correctly."""
        self.is_connected()
        self.mocker.result(False)
        self.cb(OFFLINE)
        self.mocker.result(self.thread)
        self.thread.daemon = True
        self.thread.start()
        self.mocker.replay()
        self.state.find_online_state(listener=self.network_manager,
                                     listener_thread=self.thread)

    def test_find_online_state_connected(self):
        """Test that we do find the online state correctly."""
        self.is_connected()
        self.mocker.result(ONLINE)
        self.cb(ONLINE)
        self.mocker.result(self.thread)
        self.thread.daemon = True
        self.thread.start()
        self.mocker.replay()
        self.state.find_online_state(listener=self.network_manager,
                                     listener_thread=self.thread)


class FakeWininet(object):
    """Fake wininet for windll."""

    connection_state = -1

    def InternetGetConnectedState(self, *args, **kwargs):
        """Fake InternetGetConnectedState function from wininet."""
        return self.connection_state


class FakeWininetException(object):
    """Fake wininet for windll."""

    connection_state = -1

    def InternetGetConnectedState(self, *args, **kwargs):
        """Fake InternetGetConnectedState function from wininet."""
        raise Exception()


class TestConnection(TestCase):
    """Test the state of the connection."""

    @inlineCallbacks
    def setUp(self):
        """Setup the mocker dbus object tree."""
        yield super(TestConnection, self).setUp()
        self.patch(windll, "wininet", FakeWininet())

    @inlineCallbacks
    def test_is_machine_connected_connected(self):
        """Fake the NetworkManagerState."""
        self.patch(FakeWininet, "connection_state", 1)
        result = yield is_machine_connected()
        self.assertTrue(result)

    @inlineCallbacks
    def test_is_machine_connected_disconnected(self):
        """Fake the NetworkManagerState."""
        self.patch(FakeWininet, "connection_state", 0)
        result = yield is_machine_connected()
        self.assertFalse(result)

    @inlineCallbacks
    def test_is_machine_connected_error(self):
        """Fake the NetworkManagerState."""
        self.patch(windll, "wininet", FakeWininetException())
        yield self.assertFailure(is_machine_connected(), NetworkFailException)
