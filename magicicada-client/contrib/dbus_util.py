#
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
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
"""Utilities for finding and running a dbus session bus for testing."""

import os
import signal
import subprocess

from distutils.spawn import find_executable

SRCDIR = os.environ.get('SRCDIR', os.getcwd())

class DBusLaunchError(Exception):
    """Error while launching dbus-daemon"""
    pass

class NotFoundError(Exception):
    """Not found error"""
    pass


class DBusRunner(object):

    def __init__(self):
        self.dbus_address = None
        self.dbus_pid = None
        self.running = False

    def startDBus(self):
        """Start our own session bus daemon for testing."""
        dbus = find_executable("dbus-daemon")
        if not dbus:
            raise NotFoundError("dbus-daemon was not found.")

        config_file = os.path.join(os.path.abspath(SRCDIR),
                                   "contrib", "testing",
                                   "dbus-session.conf")
        dbus_args = ["--fork",
                     "--config-file=" + config_file,
                     "--print-address=1",
                     "--print-pid=2"]
        p = subprocess.Popen([dbus] + dbus_args,
                             bufsize=4096, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        self.dbus_address = "".join(p.stdout.readlines()).strip()
        self.dbus_pid = int("".join(p.stderr.readlines()).strip())

        if self.dbus_address != "":
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = self.dbus_address
        else:
            os.kill(self.dbus_pid, signal.SIGKILL)
            raise DBusLaunchError("There was a problem launching dbus-daemon.")
        self.running = True

    def stopDBus(self):
        """Stop our DBus session bus daemon."""
        del os.environ["DBUS_SESSION_BUS_ADDRESS"]
        os.kill(self.dbus_pid, signal.SIGKILL)
        self.running = False

