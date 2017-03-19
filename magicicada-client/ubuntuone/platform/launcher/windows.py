# ubuntuone.platform.launcher.windows
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
"""Use libunity to show a progressbar and emblems on the launcher icon."""

CONTROLPANEL_DOTDESKTOP = "ubuntuone-control-panel-gtk.desktop"


class Launcher(object):
    """The launcher icon."""

    def __init__(self):
        """Initialize this instance."""

    def show_progressbar(self):
        """The progressbar is shown."""

    def hide_progressbar(self):
        """The progressbar is hidden."""

    def set_progress(self, value):
        """The progressbar value is changed."""

    def set_urgent(self, value=True):
        """Set the launcher to urgent."""


# linux needs a dummy launcher in case Unity is not running, of course this
# makes no bloody sense on windows, lets adapt to it and discuss about it
# later
DummyLauncher = Launcher
