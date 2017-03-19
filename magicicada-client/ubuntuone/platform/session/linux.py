# -*- coding: utf-8 *-*
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
"""Inhibit session logout when busy thru the Gnome Session DBus service."""

import dbus

from twisted.internet import defer

from ubuntuone.clientdefs import NAME

SESSION_MANAGER_BUSNAME = "org.gnome.SessionManager"
SESSION_MANAGER_IFACE = "org.gnome.SessionManager"
SESSION_MANAGER_PATH = "/org/gnome/SessionManager"
TOPLEVEL_XID = 0


class Inhibitor(object):
    """An object representing an inhibition, that can be cancelled."""

    def __init__(self):
        """Initialize this instance."""
        self.cookie = None
        bus = dbus.SessionBus()
        obj = bus.get_object(bus_name=SESSION_MANAGER_BUSNAME,
                             object_path=SESSION_MANAGER_PATH,
                             follow_name_owner_changes=True)
        self.proxy = dbus.Interface(object=obj,
                                    dbus_interface=SESSION_MANAGER_IFACE)

    def inhibit(self, flags, reason):
        """Inhibit some events with a given reason."""
        d = defer.Deferred()

        def inhibit_handler(cookie):
            """Got the cookie for this inhibition."""
            self.cookie = cookie
            d.callback(self)

        self.proxy.Inhibit(NAME, TOPLEVEL_XID, reason, flags,
                           reply_handler=inhibit_handler,
                           error_handler=d.errback)
        return d

    def cancel(self):
        """Cancel the inhibition for the current cookie."""
        d = defer.Deferred()
        self.proxy.Uninhibit(self.cookie,
                             reply_handler=lambda: d.callback(self),
                             error_handler=d.errback)
        return d
