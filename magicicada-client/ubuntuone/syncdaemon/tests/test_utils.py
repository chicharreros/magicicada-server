# -*- coding: utf-8 -*-
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
"""Test utility functions."""

import sys

from twisted.trial.unittest import TestCase

import ubuntuone.syncdaemon.utils


class UtilsTestCase(TestCase):
    """Test utils."""

    def test_get_sd_bin_cmd_src_nonlinux(self):
        """Test that we use the buildout python running from source."""
        self.patch(sys, 'platform', 'darwin')
        self.patch(ubuntuone.syncdaemon.utils, 'get_program_path',
                   lambda _, *args, **kwargs: 'test-path')
        args = ubuntuone.syncdaemon.utils.get_sd_bin_cmd()
        self.assertEqual(len(args), 2)
        self.assertEqual(args[0], 'python')

    def test_get_sd_bin_cmd_src_linux(self):
        """Test that we DO NOT use the buildout python running from source."""
        self.patch(sys, 'platform', 'linux2')
        self.patch(ubuntuone.syncdaemon.utils, 'get_program_path',
                   lambda _, *args, **kwargs: 'test-path')
        args = ubuntuone.syncdaemon.utils.get_sd_bin_cmd()
        self.assertEqual(len(args), 1)
        self.assertEqual(args[0], 'test-path')

    def test_get_sd_bin_cmd_installed_nonlinux(self):
        """Test that we DO NOT use the buildout python when installed."""
        sys.frozen = True
        self.addCleanup(delattr, sys, 'frozen')
        self.patch(sys, 'platform', 'darwin')
        self.patch(ubuntuone.syncdaemon.utils, 'get_program_path',
                   lambda _, *args, **kwargs: 'test-path')
        args = ubuntuone.syncdaemon.utils.get_sd_bin_cmd()
        self.assertEqual(len(args), 1)
        self.assertEqual(args[0], 'test-path')

    def test_get_sd_bin_cmd_installed_linux(self):
        """Test that we DO NOT use the buildout python when installed."""
        sys.frozen = True
        self.addCleanup(delattr, sys, 'frozen')
        self.patch(sys, 'platform', 'linux2')
        self.patch(ubuntuone.syncdaemon.utils, 'get_program_path',
                   lambda _, *args, **kwargs: 'test-path')
        args = ubuntuone.syncdaemon.utils.get_sd_bin_cmd()
        self.assertEqual(len(args), 1)
        self.assertEqual(args[0], 'test-path')
