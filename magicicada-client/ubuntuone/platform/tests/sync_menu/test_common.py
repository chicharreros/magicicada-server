# -*- coding: utf-8 *-*
#
# Copyright 2012 Canonical Ltd.
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
"""Test the common dummy Sync Menu implementation for win32/darwin."""

from collections import Callable

from twisted.trial.unittest import TestCase

from ubuntuone.platform.sync_menu import common


class SyncMenuDummyTestCase(TestCase):
    """Test the SyncMenu."""

    def test_dummy_support(self):
        """Can we create a Dummy with the same #args as the real obj."""
        dummy = common.UbuntuOneSyncMenu(1, 2)
        self.assertIsInstance(dummy, common.UbuntuOneSyncMenu)

    def test_dummy_has_update_transfers(self):
        """Check that the dummy has the proper methods required by the API."""
        dummy = common.UbuntuOneSyncMenu(1, 2)
        self.assertIsInstance(dummy.update_transfers, Callable)

    def test_dummy_has_sync_status_changed(self):
        """Check that the dummy has the proper methods required by the API."""
        dummy = common.UbuntuOneSyncMenu(1, 2)
        self.assertIsInstance(dummy.sync_status_changed, Callable)
