# -*- encoding: utf-8 -*-
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
"""Specific tests for the os_helper on Windows."""

import errno
import os
import shutil
import sys

from twisted.internet import defer
from twisted.trial.unittest import TestCase

from contrib.testing.testcase import BaseTwistedTestCase

from ntsecuritycon import (
    FILE_ALL_ACCESS,
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
)
from win32file import (
    FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_SYSTEM,
    GetFileAttributesW,
    SetFileAttributesW
)

from ubuntuone.platform.os_helper import windows as os_helper
from ubuntuone.platform.os_helper.windows import (
    _set_file_attributes,
    _unicode_to_bytes,
    EVERYONE_SID,
    LONG_PATH_PREFIX,
    USER_SID,
    access,
    assert_windows_path,
    can_write,
    get_syncdaemon_valid_path,
    get_user_sid,
    get_windows_valid_path,
    normpath,
    set_dir_readwrite,
    set_file_readwrite,
    set_no_rights,
    WINDOWS_ILLEGAL_CHARS_MAP,
)
from ubuntuone.platform.tests.os_helper.test_os_helper import (
    OSWrapperTests,
    WalkTests,
)


# ugly trick to stop pylint for complaining about
# WindowsError on Linux
if sys.platform != 'win32':
    WindowsError = Exception


def _build_invalid_windows_bytes_name():
    invalid_unicodes = u''.join(WINDOWS_ILLEGAL_CHARS_MAP)
    invalid_filename = 'test_file' + invalid_unicodes.encode('utf8')
    return invalid_filename


class TestIllegalPaths(OSWrapperTests):
    """Test all the operations using illegal paths."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Setup for the tests."""
        test_file_name = _build_invalid_windows_bytes_name()
        yield super(TestIllegalPaths, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name,
            valid_file_path_builder=get_windows_valid_path)

    def test_rename_file(self, target=None):
        """Rename a file."""
        target = os.path.join(self.basedir, 'target?!><:')
        super(TestIllegalPaths, self).test_rename_file(target)

    def test_rename_dir(self, source=None, target=None):
        """Rename a dir."""
        source = os.path.join(self.basedir, 'source?!><:')
        os.mkdir(get_windows_valid_path(source))
        target = os.path.join(self.basedir, 'target?!><:')
        super(TestIllegalPaths, self).test_rename_dir(source, target)

    def test_listdir(self, expected_result=None):
        """Return a list of the files in a dir."""
        _, valid_path_name = os.path.split(self.valid_path)
        expected_result = [_unicode_to_bytes(valid_path_name)]
        super(TestIllegalPaths, self).test_listdir(expected_result)

    def test_make_link(self):
        """The link is properly made."""
        # XXX: make_link will not work when passing literal paths or
        # invalid characters. We need to do something about that.
        self.testfile = os.path.join(self.basedir, 'test me')
        super(TestIllegalPaths, self).test_make_link()


class TestSpecialOSCalls(BaseTwistedTestCase):
    """Test those calls that have extra logic."""

    def test_normpath_with_longprefix(self):
        """Ensure that the normpath is correct when it uses the long prefix."""
        paths = [os.path.join('A', 'B?'),
                 os.path.join('A', 'B?') + os.path.sep,
                 os.path.join('A:C', '.', 'B?'),
                 os.path.join('A', 'foo', '..', 'B?')]
        for current_path in paths:
            valid_path = get_windows_valid_path(current_path)
            normalized_path = os.path.normpath(valid_path)
            self.assertEqual(get_syncdaemon_valid_path(normalized_path),
                             normpath(current_path))
            self.assertFalse(LONG_PATH_PREFIX in current_path)


class FakeSecurityInfo(object):

    user_sid = 'user_sid'

    def GetSecurityDescriptorOwner(self):
        return self.user_sid


class TestAccess(BaseTwistedTestCase):
    """Test specific windows implementation access details."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup for the tests."""
        yield super(TestAccess, self).setUp()

        self.basedir = self.mktemp('test_root')
        self.addCleanup(set_dir_readwrite, self.basedir)

        self.testfile = os.path.join(self.basedir, "test_file")
        self.valid_path = get_windows_valid_path(self.testfile)
        open(self.testfile, 'w').close()
        self.addCleanup(set_file_readwrite, self.testfile)

    def test_access_no_rights(self):
        """Test when the sid is not present."""
        # remove all the rights from the test file so that
        # we cannot read or write
        set_no_rights(self.testfile)
        self.assertFalse(access(self.testfile))

    def test_access_read_write_user(self):
        """Test when the user sid has rw rights."""
        # set the file to be read and write just by the user
        groups = [(USER_SID, FILE_GENERIC_READ | FILE_GENERIC_WRITE)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_read_write_everyone(self):
        """Test when the everyone sid has rw rights."""
        groups = [(EVERYONE_SID, FILE_GENERIC_READ | FILE_GENERIC_WRITE)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_write_user_everyone_read(self):
        """Test when the user sid has w rights."""
        groups = [
            (USER_SID, FILE_GENERIC_WRITE),
            (EVERYONE_SID, FILE_GENERIC_READ),
        ]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_write_everyone_user_read(self):
        """Test when the everyone sid has w rights"""
        groups = [
            (USER_SID, FILE_GENERIC_READ),
            (EVERYONE_SID, FILE_GENERIC_WRITE),
        ]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_write_user_everyone(self):
        """Test when everyone and user have w rights."""
        groups = [
            (USER_SID, FILE_GENERIC_WRITE),
            (EVERYONE_SID, FILE_GENERIC_WRITE),
        ]
        _set_file_attributes(self.valid_path, groups)
        self.assertFalse(access(self.testfile))

    def test_access_read_user(self):
        """Test when the sid has r rights."""
        groups = [(USER_SID, FILE_GENERIC_READ)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_read_everyone(self):
        """Test when everyone has r rights."""
        groups = [(EVERYONE_SID, FILE_GENERIC_READ)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_read_user_everyone(self):
        """Test when user and everyone have r rights."""
        groups = [
            (USER_SID, FILE_GENERIC_READ),
            (EVERYONE_SID, FILE_GENERIC_READ),
        ]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_full_user(self):
        """Test when the sid has full control."""
        groups = [(USER_SID, FILE_ALL_ACCESS)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_access_full_everyone(self):
        """test when everyone has full control."""
        groups = [(EVERYONE_SID, FILE_ALL_ACCESS)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(access(self.testfile))

    def test_canwrite_no_rights(self):
        """Test when the sid is not present."""
        # remove all the rights from the test file so that
        # we cannot read or write
        set_no_rights(self.testfile)
        self.assertFalse(can_write(self.testfile))

    def test_can_write_read_write_user(self):
        """Test when the user sid has rw rights."""
        # set the file to be read and write just by the user
        groups = [(USER_SID, FILE_GENERIC_READ | FILE_GENERIC_WRITE)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(can_write(self.testfile))

    def test_can_write_read_write_everyone(self):
        """Test when the everyone sid has rw rights."""
        groups = [(EVERYONE_SID, FILE_GENERIC_READ | FILE_GENERIC_WRITE)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(can_write(self.testfile))

    def test_can_write_write_user_everyone_read(self):
        """Test when the user sid has w rights."""
        groups = [
            (USER_SID, FILE_GENERIC_WRITE),
            (EVERYONE_SID, FILE_GENERIC_READ),
        ]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(can_write(self.testfile))

    def test_can_write_write_everyone_user_read(self):
        """Test when the everyone sid has w rights"""
        groups = [
            (USER_SID, FILE_GENERIC_READ),
            (EVERYONE_SID, FILE_GENERIC_WRITE),
        ]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(can_write(self.testfile))

    def test_can_write_full_user(self):
        """Test when the sid has full control."""
        groups = [(USER_SID, FILE_ALL_ACCESS)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(can_write(self.testfile))

    def test_can_write_full_everyone(self):
        """test when everyone has full control."""
        groups = [(EVERYONE_SID, FILE_ALL_ACCESS)]
        _set_file_attributes(self.valid_path, groups)
        self.assertTrue(can_write(self.testfile))

    def fake_security_info(self, *args):
        return FakeSecurityInfo()

    def test_get_user_sid(self):
        self.patch(os_helper, "GetSecurityInfo", self.fake_security_info)
        user_sid = get_user_sid()
        self.assertEqual(user_sid, FakeSecurityInfo.user_sid)

    def test_set_file_attributes_missing_path(self):
        """Set file attr for a missing file."""
        groups = [(EVERYONE_SID, FILE_ALL_ACCESS)]
        # file does not exist.
        self.patch(os_helper.os.path, 'exists', lambda f: False)
        exc = self.assertRaises(WindowsError, _set_file_attributes,
                                self.valid_path, groups)
        self.assertEqual(errno.ENOENT, exc.errno,
                         'Errno should be file not found.')


class DecoratorsTestCase(TestCase):
    """Test case for all the validators and transformers."""

    def assert_error_raised(self, path, method_name=None):
        if method_name is None:
            self.assertRaises(AssertionError, assert_windows_path, path)
        else:
            exc = self.assertRaises(
                AssertionError, assert_windows_path, path, method_name)
            self.assertTrue(method_name in exc.message)

    def test_assert_windows_path_slash(self):
        """A path with a / is invalid."""
        path = LONG_PATH_PREFIX + u'/a/b/'
        self.assert_error_raised(path)

    def test_assert_windows_method_name_path_slash(self):
        """A path with a / is invalid."""
        path = LONG_PATH_PREFIX + u'/a/b/'
        method_name = 'method_name'
        self.assert_error_raised(path, method_name)

    def test_assert_windows_path_non_unicode(self):
        """A non-unicode path is invalid."""
        path = (LONG_PATH_PREFIX + u'C:\\Yadda').encode('utf8')
        self.assert_error_raised(path)

    def test_assert_windows_method_name_path_non_unicode(self):
        """A non-unicode path is invalid."""
        path = (LONG_PATH_PREFIX + u'C:\\Yadda').encode('utf8')
        method_name = 'method_name'
        self.assert_error_raised(path, method_name)

    def test_assert_windows_path_non_literal(self):
        """A non-literal path is invalid."""
        path = u'C:\\Yadda'
        self.assert_error_raised(path)

    def test_assert_windows_method_name_path_non_literal(self):
        """A non-literal path is invalid."""
        path = u'C:\\Yadda'
        method_name = 'method_name'
        self.assert_error_raised(path, method_name)

    def test_assert_windows_path_non_absolute(self):
        """A non-absolute path is invalid."""
        path = u'./yadda'
        self.assert_error_raised(path)

    def test_assert_windows_method_name_path_non_absolute(self):
        """A non-absolute path is invalid."""
        path = u'./yadda'
        method_name = 'method_name'
        self.assert_error_raised(path, method_name)

    def test_assert_windows_path_with_illegal_chars(self):
        """A path with illegal chars is invalid."""
        path = u'./yadda' + u''.join(WINDOWS_ILLEGAL_CHARS_MAP)
        self.assert_error_raised(path)

    def test_assert_windows_method_name_path_with_illegal_chars(self):
        """A path with illegal chars is invalid."""
        path = u'./yadda' + u''.join(WINDOWS_ILLEGAL_CHARS_MAP)
        method_name = 'method_name'
        self.assert_error_raised(path, method_name)


class TestIllegalPathsWalk(WalkTests):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None, valid_file_name_builder=None):
        """Setup for the tests."""
        test_file_name = _build_invalid_windows_bytes_name()
        yield super(TestIllegalPathsWalk, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name,
            valid_file_path_builder=get_windows_valid_path)

    def test_top_down(self, topdown=True, expected=None):
        """Walk the tree top-down."""
        valid_base_dir = get_windows_valid_path(self.basedir)
        result = os.walk(valid_base_dir, topdown)
        expected = self._build_dict_from_walk(
            result, path_transformer=get_syncdaemon_valid_path,
            name_transformer=_unicode_to_bytes)
        super(TestIllegalPathsWalk, self).test_top_down(topdown=topdown,
                                                        expected=expected)


class TestSystemPaths(TestCase):
    """Tests related with the system paths."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set tests."""
        yield super(TestSystemPaths, self).setUp()
        self.system_paths = ['My Music', 'My Pictures']
        self.dirs = ['One', 'Two', 'Tree']
        self.files = ['File', 'Second File', 'Last file']
        self.temp = self.mktemp()
        self._make_test_files()
        self.addCleanup(shutil.rmtree, self.temp)

    def _make_test_files(self):
        """Create the temp test files."""

        # lets make the files for the tests
        for d in self.dirs:
            os.makedirs(os.path.join(self.temp, d))

        for s in self.system_paths:
            path = os.path.join(self.temp, s)
            os.makedirs(path)
            self._set_as_system_path(path)

        for f in self.files:
            path = os.path.join(self.temp, f)
            with open(path, 'w') as fd:
                fd.write('Im a test, blame TestSystemPaths!')

    def _set_as_system_path(self, path):
        """Set a path to have the system attr."""
        attrs = GetFileAttributesW(path)
        attrs = attrs | FILE_ATTRIBUTE_SYSTEM
        SetFileAttributesW(path, attrs)

    def test_os_listdir(self):
        """Test the list dir."""
        expected_result = self.dirs + self.files
        self.assertEqual(
            sorted(expected_result), sorted(os_helper.listdir(self.temp)))

    def test_os_walk(self):
        """Test the walk."""
        expected_dirs = ['One', 'Two', 'Tree']
        expected_files = ['File', 'Second File', 'Last file']
        result_dirs = []
        result_files = []
        for dirpath, dirs, files in os_helper.walk(self.temp):
            result_dirs.extend(dirs)
            result_files.extend(files)
        self.assertEqual(sorted(expected_dirs), sorted(result_dirs))
        self.assertEqual(sorted(expected_files), sorted(result_files))

    def test_native_is_system_path_true(self):
        """Test the function that returns if is a sytem folder."""

        def fake_get_attrs(path):
            """Fake the GetFileAttributes method."""
            return FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM

        self.patch(os_helper, 'GetFileAttributesW', fake_get_attrs)
        self.assertTrue(os_helper.native_is_system_path(self.temp))

    def test_native_is_system_path_false(self):
        """Test the function that returns if is a sytem folder."""

        def fake_get_attrs(path):
            """Fake the GetFileAttributes method."""
            return FILE_ATTRIBUTE_NORMAL

        self.patch(os_helper, 'GetFileAttributesW', fake_get_attrs)
        self.assertFalse(os_helper.native_is_system_path(self.temp))


class TestIsRoot(TestCase):
    """Tests for the is_root function."""

    def test_is_root(self):
        """Test that os_helper.is_root always returns False"""
        expected = False
        actual = os_helper.is_root()
        self.assertEqual(expected, actual)
