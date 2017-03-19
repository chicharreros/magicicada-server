# tests.platform.linux.test_launcher
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
"""Tests for the liblauncher interface."""

from twisted.internet import defer
from twisted.trial.unittest import TestCase

from ubuntuone.platform import launcher


class FakeLauncherEntryProps(object):
    """A fake Unity.LauncherEntry.props"""

    progress = 0.0
    progress_visible = False
    count = 0
    count_visible = False
    urgent = False


class FakeLauncherEntry(object):
    """A fake Unity.LauncherEntry"""

    @staticmethod
    def get_for_desktop_id(dotdesktop):
        """Find the LauncherEntry for a given dotdesktop."""
        return FakeLauncherEntry()

    def __init__(self):
        """Initialize this fake instance."""
        self.props = FakeLauncherEntryProps()

    def set_property(self, launcher_property, value):
        """Set the property on the fake launcher object."""
        setattr(self.props, launcher_property, value)


class LauncherTestCase(TestCase):
    """Test the Launcher interface."""

    from ubuntuone.platform.launcher.linux import use_libunity
    skip = None if use_libunity else "libunity not installed."

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this test instance."""
        yield super(LauncherTestCase, self).setUp()
        import ubuntuone.platform.launcher.linux
        self.patch(ubuntuone.platform.launcher.linux.Unity,
                   "LauncherEntry", FakeLauncherEntry)
        self.launcher = launcher.Launcher()

    def test_progress_starts_hidden(self):
        """The progressbar starts hidden."""
        self.assertFalse(self.launcher.entry.props.progress_visible,
                         "The progressbar starts hidden.")

    def test_progress_shown(self):
        """The progressbar is shown."""
        self.launcher.show_progressbar()
        self.assertTrue(self.launcher.entry.props.progress_visible,
                        "The progressbar is shown.")

    def test_progress_hidden_after_shown(self):
        """The progressbar is hidden after being shown."""
        self.launcher.show_progressbar()
        self.launcher.hide_progressbar()
        self.assertFalse(self.launcher.entry.props.progress_visible,
                         "The progressbar is hidden.")

    def test_progress_is_updated(self):
        """The progress value is updated."""
        value = 0.5
        self.launcher.set_progress(value)
        self.assertEqual(value, self.launcher.entry.props.progress)

    def test_urgency_set(self):
        """The urgency of the launcher is set."""
        self.launcher.set_urgent()
        self.assertTrue(
            self.launcher.entry.props.urgent,
            "The launcher should be set to urgent.")
        self.launcher.set_urgent(False)
        self.assertFalse(
            self.launcher.entry.props.urgent,
            "The launcher should not be set to urgent.")

    def test_set_count(self):
        """The count property is set on the launcher."""
        value = 200
        self.launcher.set_count(value)
        self.assertEqual(value, self.launcher.entry.props.count)

    def test_set_count_visible(self):
        """The count_visible property is set to True on the launcher."""
        self.launcher.show_count()
        self.assertTrue(self.launcher.entry.props.count_visible)

    def test_hide_count(self):
        """The count_visible property is set to False on the launcher."""
        self.launcher.hide_count()
        self.assertFalse(self.launcher.entry.props.count_visible)
