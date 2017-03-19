# Copyright 2010-2013 Canonical Ltd.
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
"""Linux specific tests for the platform module."""

import logging
import os

try:
    from gi.repository import Gio as gio
    GIO_NOT_SUPPORTED = gio.IOErrorEnum.NOT_SUPPORTED
except ImportError:
    import gio
    GIO_NOT_SUPPORTED = gio.ERROR_NOT_SUPPORTED

from twisted.internet import defer
from ubuntuone.devtools.handlers import MementoHandler

from ubuntuone.platform.tests.os_helper import test_os_helper
from ubuntuone.platform import (
    move_to_trash,
    open_file,
    stat_path,
)


class FakeGIOFile(object):
    """Fake File for gio."""

    _bad_trash_call = None

    def __init__(self, path):
        pass

    @classmethod
    def new_for_path(klass, path):
        """Fake new_for_path for GI."""
        return klass(path)

    def trash(self, *args):
        """Fake trash call."""
        return self._bad_trash_call


class OSWrapperTests(test_os_helper.OSWrapperTests):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(OSWrapperTests, self).setUp()
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)

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
        FakeGIOFile._bad_trash_call = False   # error
        self.patch(gio, "File", FakeGIOFile)
        path = os.path.join(self.basedir, 'foo')
        open_file(path, 'w').close()
        move_to_trash(path)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(self.handler.check_warning("Problems moving to trash!",
                                                   "Removing anyway", "foo"))

    def test_movetotrash_dir_bad(self):
        """Something bad happen when moving to trash, removed anyway."""
        FakeGIOFile._bad_trash_call = False   # error
        self.patch(gio, "File", FakeGIOFile)
        path = os.path.join(self.basedir, 'foo')
        os.mkdir(path)
        open_file(os.path.join(path, 'file inside directory'), 'w').close()
        move_to_trash(path)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(self.handler.check_warning("Problems moving to trash!",
                                                   "Removing anyway", "foo"))

    def test_movetotrash_file_systemnotcapable(self):
        """The system is not capable of moving into trash."""
        FakeGIOFile._bad_trash_call = GIO_NOT_SUPPORTED
        self.patch(gio, "File", FakeGIOFile)
        path = os.path.join(self.basedir, 'foo')
        open_file(path, 'w').close()
        move_to_trash(path)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(self.handler.check_warning("Problems moving to trash!",
                                                   "Removing anyway", "foo",
                                                   "ERROR_NOT_SUPPORTED"))

    def test_movetotrash_dir_systemnotcapable(self):
        """The system is not capable of moving into trash."""
        FakeGIOFile._bad_trash_call = GIO_NOT_SUPPORTED
        self.patch(gio, "File", FakeGIOFile)
        path = os.path.join(self.basedir, 'foo')
        os.mkdir(path)
        open_file(os.path.join(path, 'file inside directory'), 'w').close()
        move_to_trash(path)
        self.assertFalse(os.path.exists(path))
        self.assertTrue(self.handler.check_warning("Problems moving to trash!",
                                                   "Removing anyway", "foo",
                                                   "ERROR_NOT_SUPPORTED"))
