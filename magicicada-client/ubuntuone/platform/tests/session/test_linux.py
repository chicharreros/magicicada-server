# tests.platform.linux.test_session
#
# Author: Alejandro J. Cura <alecu@canonical.com>
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
"""Tests for the session inhibition DBus client."""

import dbus
import operator

from dbus.mainloop.glib import DBusGMainLoop
from twisted.internet.defer import inlineCallbacks
try:
    from ubuntuone.devtools.testcases.dbus import DBusTestCase
except ImportError:
    from ubuntuone.devtools.testcase import DBusTestCase
from ubuntuone.platform import session

INHIBIT_ALL = (session.INHIBIT_LOGGING_OUT |
               session.INHIBIT_USER_SWITCHING |
               session.INHIBIT_SUSPENDING_COMPUTER |
               session.INHIBIT_SESSION_IDLE)


class FakeGnomeSessionManagerInhibitor(dbus.service.Object):
    """A fake Gnome Session Manager (but only the inhibitor bits)."""

    cookie_counter = 0
    inhibitions = {}

    @dbus.service.method(dbus_interface=session.SESSION_MANAGER_IFACE,
                         in_signature="susu", out_signature="u")
    def Inhibit(self, app_id, toplevel_xid, reason, flags):
        """Inhibit a set of flags."""
        self.cookie_counter += 1
        self.inhibitions[self.cookie_counter] = (flags, reason)
        return self.cookie_counter

    @dbus.service.method(dbus_interface=session.SESSION_MANAGER_IFACE,
                         in_signature="u")
    def Uninhibit(self, inhibit_cookie):
        """Cancel a previous call to Inhibit() identified by the cookie."""
        if inhibit_cookie in self.inhibitions:
            del(self.inhibitions[inhibit_cookie])

    @dbus.service.method(dbus_interface=session.SESSION_MANAGER_IFACE,
                         in_signature="u", out_signature="b")
    def IsInhibited(self, flags):
        """Determine if ops specified by flags are currently inhibited."""
        all_inhibitions = (v[0] for v in self.inhibitions.values())
        inhibited = reduce(operator.or_, all_inhibitions, 0)
        return bool(flags & inhibited)


class SessionDBusClientTestCase(DBusTestCase):
    """Test the DBus session manager client"""

    timeout = 5

    @inlineCallbacks
    def setUp(self):
        """Initialize this test case."""
        yield super(SessionDBusClientTestCase, self).setUp()
        DBusGMainLoop(set_as_default=True)

    def test_fake_inhibitor(self):
        """Test the FakeGnomeSessionManagerInhibitor."""
        inhibitor = FakeGnomeSessionManagerInhibitor()
        self.assertFalse(inhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT))
        self.assertFalse(inhibitor.IsInhibited(session.INHIBIT_USER_SWITCHING))
        i1 = inhibitor.Inhibit("u1", 0, "test", session.INHIBIT_LOGGING_OUT)
        self.assertTrue(inhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT))
        self.assertFalse(inhibitor.IsInhibited(session.INHIBIT_USER_SWITCHING))
        i2 = inhibitor.Inhibit("u2", 0, "for testing", INHIBIT_ALL)
        self.assertTrue(inhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT))
        self.assertTrue(inhibitor.IsInhibited(session.INHIBIT_USER_SWITCHING))
        inhibitor.Uninhibit(i1)
        self.assertTrue(inhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT))
        self.assertTrue(inhibitor.IsInhibited(session.INHIBIT_USER_SWITCHING))
        inhibitor.Uninhibit(i2)
        self.assertFalse(inhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT))
        self.assertFalse(inhibitor.IsInhibited(session.INHIBIT_USER_SWITCHING))

    def register_fakeserver(self, bus_name, object_path, object_class,
                            **kwargs):
        """The fake service is registered on the DBus."""
        flags = (dbus.bus.NAME_FLAG_REPLACE_EXISTING |
                 dbus.bus.NAME_FLAG_DO_NOT_QUEUE |
                 dbus.bus.NAME_FLAG_ALLOW_REPLACEMENT)
        name = self.bus.request_name(bus_name, flags=flags)
        self.assertNotEqual(name, dbus.bus.REQUEST_NAME_REPLY_EXISTS)
        fake = object_class(object_path=object_path, conn=self.bus, **kwargs)
        self.addCleanup(fake.remove_from_connection)
        self.addCleanup(self.bus.release_name, bus_name)

        return fake

    @inlineCallbacks
    def test_inhibit_call(self):
        """Test the inhibit call."""
        fakeinhibitor = self.register_fakeserver(
            session.SESSION_MANAGER_BUSNAME, session.SESSION_MANAGER_PATH,
            FakeGnomeSessionManagerInhibitor)
        inhibit_result = yield session.inhibit_logout_suspend("fake reason")
        self.assertNotEqual(None, inhibit_result)
        result = fakeinhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT)
        self.assertTrue(result)
        result = fakeinhibitor.IsInhibited(session.INHIBIT_SUSPENDING_COMPUTER)
        self.assertTrue(result)

    @inlineCallbacks
    def test_uninhibit_call(self):
        """Test the uninhibit call."""
        fakeinhibitor = self.register_fakeserver(
                                             session.SESSION_MANAGER_BUSNAME,
                                             session.SESSION_MANAGER_PATH,
                                             FakeGnomeSessionManagerInhibitor)
        i = yield session.inhibit_logout_suspend("fake reason")
        yield i.cancel()
        result = fakeinhibitor.IsInhibited(session.INHIBIT_LOGGING_OUT)
        self.assertFalse(result)
        result = fakeinhibitor.IsInhibited(session.INHIBIT_SUSPENDING_COMPUTER)
        self.assertFalse(result)
