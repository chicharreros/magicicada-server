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
"""Inhibit session logout when busy."""

import sys


INHIBIT_LOGGING_OUT = 1
INHIBIT_USER_SWITCHING = 2
INHIBIT_SUSPENDING_COMPUTER = 4
INHIBIT_SESSION_IDLE = 8
INHIBIT_LOGOUT_SUSPEND = INHIBIT_LOGGING_OUT | INHIBIT_SUSPENDING_COMPUTER


if sys.platform == "win32":
    from ubuntuone.platform.session import windows
    source = windows
elif sys.platform == "darwin":
    from ubuntuone.platform.session import darwin
    source = darwin
else:
    from ubuntuone.platform.session import linux
    source = linux
    SESSION_MANAGER_BUSNAME = source.SESSION_MANAGER_BUSNAME
    SESSION_MANAGER_IFACE = source.SESSION_MANAGER_IFACE
    SESSION_MANAGER_PATH = source.SESSION_MANAGER_PATH
    TOPLEVEL_XID = source.TOPLEVEL_XID


Inhibitor = source.Inhibitor


def inhibit_logout_suspend(reason):
    """Inhibit the suspend and logout. The result can be cancelled."""
    return Inhibitor().inhibit(INHIBIT_LOGOUT_SUSPEND, reason)
