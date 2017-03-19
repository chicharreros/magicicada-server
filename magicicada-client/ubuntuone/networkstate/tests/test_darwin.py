# -*- coding: utf-8 -*-
#
# Copyright 2010-2012 Canonical Ltd.
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

"""Tests for the network state detection code."""

from twisted.internet.defer import inlineCallbacks

from ubuntuone.networkstate import (
    darwin,
    NetworkFailException,
)
from ubuntuone.networkstate.darwin import (
    NetworkManagerState,
    flags_say_reachable,
    is_machine_connected,
)
from ubuntuone.networkstate.networkstates import (
    ONLINE, OFFLINE, UNKNOWN,
)
from ubuntuone.tests import TestCase


REACHABLE_FLAG = 1 << 1
CONNECTION_REQUIRED_FLAG = 1 << 2


class TestSCNRFailingInDirect(TestCase):

    """Test that we handle a problem getting status in a direct call
    to check_connected_state (used by is_machine_connected) by
    raising an exception.
    """

    def test_cant_create_target(self):
        """SCNRCreateWithName returning None should cause an exception."""
        self.patch(darwin, "SCNRCreateWithName",
                   lambda _1, _2: None)
        self.assertRaises(NetworkFailException,
                          darwin.check_connected_state)

    def test_cant_get_flags(self):
        """SCNRGetFlags returning False should cause an exception."""
        self.patch(darwin, "SCNRGetFlags",
                   lambda _1, _2: False)
        self.assertRaises(NetworkFailException,
                          darwin.check_connected_state)


class TestFailingSCNRInCallbacks(TestCase):

    """Test that we handle a problem getting status in the separate
    listening thread by updating the status to UNKNOWN.
    """

    def expect_unknown(self, state):
        """A convenience callback that fails unless it sees UNKNOWN."""
        self.assertEqual(state, UNKNOWN)

    def test_exc_in_find_online_state(self):
        """Expect UNKNOWN from find_online_state in case of exception."""
        def fake_check_connected_state():
            "fake a broken check_connected_state"
            raise NetworkFailException()

        self.patch(darwin, "check_connected_state",
                   fake_check_connected_state)
        NetworkManagerState(self.expect_unknown)

    def test_cant_create_target(self):
        """SCNRCreateWithName returning None -> callback gets UNKNOWN."""
        self.patch(darwin, "SCNRCreateWithName", lambda _1, _2: None)
        nms = NetworkManagerState(self.expect_unknown)
        nms._listen_on_separate_thread()

    def test_cant_set_callback(self):
        """SCNRSetCallback returning false -> callback gets UNKNOWN."""
        self.patch(darwin, "SCNRSetCallback", lambda _1, _2, _3: False)
        nms = NetworkManagerState(self.expect_unknown)
        nms._listen_on_separate_thread()

    def test_cant_schedule_with_runloop(self):
        """SCNRScheduleWithRunLoop returning false -> callback gets UNKNOWN."""
        self.patch(darwin, "SCNRScheduleWithRunLoop",
                   lambda _1, _2, _3: False)
        nms = NetworkManagerState(self.expect_unknown)
        nms._listen_on_separate_thread()


class TestReadingFlags(TestCase):
    """Test interpretation of flags returned from SCNR API"""

    def test_flag_reachable(self):
        """Reachable by itself is OK."""
        flag = REACHABLE_FLAG
        self.assertTrue(flags_say_reachable(flag))

    def test_flag_reachable_and_flag_connection_required(self):
        """Reachable and connection-required is NOT OK"""
        flag = REACHABLE_FLAG | CONNECTION_REQUIRED_FLAG
        self.assertFalse(flags_say_reachable(flag))

    def test_other_flagvals(self):
        """All other flag configurations are false for our purposes.

        They either indicate an iOS device, which we won't run this
        code on, or that the server we're testing for is on this
        machine or wired directly to it. These cases won't happen.
        """
        for flag in range(0, 17) + [1 << 16, 1 << 17, 1 << 18]:
            # only test cases without the reachable bit set:
            flag = flag & ~ 2
            self.assertEqual(False, flags_say_reachable(flag))


class TestNMSListeningForNWStateChanges(TestCase):
    """
    Test that the NetworkManagerState class calls the callback with
    ONLINE/OFFLINE when the state changes appropriately
    """

    @inlineCallbacks
    def setUp(self):
        """Setup array to hold state changes."""
        yield super(TestNMSListeningForNWStateChanges, self).setUp()
        self.network_changes = []

    def _listen_network_changes(self, state):
        """Fake callback function, records state changes."""
        self.network_changes.append(state)

    def test_network_state_change(self):
        """Test the changes in the network connection."""
        nms = NetworkManagerState(self._listen_network_changes)
        nms._state_changed(2)
        nms._state_changed(0)  # 0 or anything other than 2
        nms._state_changed(2)

        self.assertEqual(self.network_changes, [ONLINE, OFFLINE, ONLINE])


class TestIsMachineConnectedFunc(TestCase):
    """Simple test of is_machine_connected."""

    @inlineCallbacks
    def test_not_connected_returns_false(self):
        """test that False comes back False"""
        self.patch(darwin, "check_connected_state",
                   lambda: False)
        con = yield is_machine_connected()
        self.assertEqual(con, False)

    @inlineCallbacks
    def test_connected_returns_true(self):
        """check that True comes back True"""
        self.patch(darwin, "check_connected_state",
                   lambda: True)
        con = yield is_machine_connected()
        self.assertEqual(con, True)
