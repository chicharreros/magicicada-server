# -*- encoding: utf-8 -*-
# tests.platform.os_helper - darwin platform tests
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
"""Darwin specific tests for the platform module."""

import logging
import os

from twisted.internet import defer
from ubuntuone.devtools.handlers import MementoHandler

from ubuntuone.platform import (
    move_to_trash,
    open_file,
    stat_path,
)
from ubuntuone.platform.os_helper import darwin
from ubuntuone.platform.tests.os_helper import test_os_helper

DARWIN_TEST_FILE_NAME = u'naïve_test_file'


class OSWrapperTests(test_os_helper.OSWrapperTests):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Set up."""
        yield super(OSWrapperTests, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name,
            valid_file_path_builder=None)
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)
        self.patch(darwin.shutil, "move", self._fake_move)

    def _fake_move(*args):
        """Fake shutil move."""
        raise Exception("Fail fake move")

    def test_stat_symlink(self):
        """Test that it doesn't follow symlinks.

        We compare the inode only (enough to see if it's returning info
        from the link or the linked), as we can not compare the full stat
        because the st_mode will be different.
        """
        link = os.path.join(self.basedir, 'foo')
        os.symlink(self.testfile, link)
        self.assertNotEqual(os.stat(link).st_ino, stat_path(link).st_ino)
        self.assertEqual(os.lstat(link).st_ino, stat_path(link).st_ino)

    def test_movetotrash_file_bad(self):
        """Something bad happen when moving to trash, removed anyway."""
        path = os.path.join(self.basedir, 'foo')
        open_file(path, 'w').close()
        move_to_trash(path)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(self.handler.check_warning("Problems moving to trash!",
                                                   "Removing anyway", "foo"))

    def test_movetotrash_file_not_exists(self):
        """Something bad happen when moving to trash, removed anyway."""
        path = os.path.join(self.basedir, 'foo2')
        self.assertFalse(os.path.exists(path))
        self.assertRaises(OSError, move_to_trash, path)

    def test_movetotrash_dir_bad(self):
        """Something bad happen when moving to trash, removed anyway."""
        path = os.path.join(self.basedir, 'foo')
        os.mkdir(path)
        open_file(os.path.join(path, 'file inside directory'), 'w').close()
        move_to_trash(path)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(self.handler.check_warning("Problems moving to trash!",
                                                   "Removing anyway", "foo"))


class TestIllegalPaths(OSWrapperTests):
    """Test all the operations using illegal paths."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Set up for the tests."""
        test_file_name = DARWIN_TEST_FILE_NAME
        yield super(TestIllegalPaths, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name)

    def test_listdir(self, expected_result=None):
        """Return a list of the files in a dir."""
        _, valid_path_name = os.path.split(self.valid_path)
        expected_result = [valid_path_name.encode('utf-8')]
        super(TestIllegalPaths, self).test_listdir(expected_result)

    def _assert_read_link(self, target):
        """Assert if the target path of the link is correct."""
        destination = os.path.join(self.basedir, target)
        darwin.make_link(self.testfile, destination)

        target = darwin.read_link(destination)
        self.assertEqual(self.testfile.encode('utf-8'), target)

    def test_make_link(self):
        """The link is properly made."""
        destination = os.path.join(self.basedir, 'destination')
        darwin.make_link(self.testfile, destination)

        self.assertTrue(darwin.is_link(destination))
        self.assertEqual(self.testfile.encode('utf-8'),
                         darwin.read_link(destination))


class TestIllegalPathsWalk(test_os_helper.WalkTests):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None, valid_file_name_builder=None):
        """Setup for the tests."""
        test_file_name = DARWIN_TEST_FILE_NAME
        yield super(TestIllegalPathsWalk, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name)

    def test_top_down(self, topdown=True, expected=None):
        """Walk the tree top-down."""
        result = os.walk(self.basedir, topdown)
        expected = self._build_dict_from_walk(
            result, path_transformer=darwin.get_syncdaemon_valid_path,
            name_transformer=darwin.get_syncdaemon_valid_path)
        super(TestIllegalPathsWalk, self).test_top_down(topdown=topdown,
                                                        expected=expected)
