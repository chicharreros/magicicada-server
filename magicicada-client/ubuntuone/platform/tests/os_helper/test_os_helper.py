# -*- encoding: utf-8 -*-
#
# Copyright 2010-2012 Canonical Ltd.
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
"""Test for the  os operations in the platform module."""

import errno
import os
import shutil

from collections import defaultdict

from twisted.internet import defer

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    skip_if_win32_and_uses_readonly,
)
from ubuntuone.platform import (
    access,
    allow_writes,
    can_write,
    expand_user,
    is_link,
    listdir,
    make_dir,
    make_link,
    move_to_trash,
    open_file,
    path_exists,
    read_link,
    recursive_move,
    remove_dir,
    remove_file,
    remove_tree,
    rename,
    set_dir_readonly,
    set_dir_readwrite,
    set_no_rights,
    set_file_readonly,
    set_file_readwrite,
    stat_path,
    walk,
)


class BaseTestCase(BaseTwistedTestCase):
    """Base test case that builds test dirs and files."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Setup for the tests."""
        yield super(BaseTestCase, self).setUp()

        if test_dir_name is None:
            test_dir_name = 'test_root'
        self.basedir = self.mktemp(test_dir_name)

        if test_file_name is None:
            test_file_name = 'test_file'
        self.testfile = os.path.join(self.basedir, test_file_name)

        if valid_file_path_builder is None:

            def valid_file_path_builder(x):
                return x  # skip

        self.valid_file_path_builder = valid_file_path_builder
        self.valid_path = self.valid_file_path_builder(self.testfile)


class OSWrapperTests(BaseTestCase):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Setup for the tests."""
        yield super(OSWrapperTests, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name,
            valid_file_path_builder=valid_file_path_builder)
        # make sure the file exists
        open_file(self.testfile, 'w').close()

    @skip_if_win32_and_uses_readonly
    def test_set_dir_readonly(self):
        """Test for set_dir_readonly."""
        set_dir_readonly(self.basedir)
        self.addCleanup(set_dir_readwrite, self.basedir)

        self.assertRaises(OSError, make_dir, os.path.join(self.basedir, 'foo'))

    def test_set_dir_readwrite(self):
        """Test for set_dir_readwrite."""
        set_dir_readonly(self.basedir)
        # do not queue up any cleanup function since we're restoring perms in
        # the next call

        set_dir_readwrite(self.basedir)
        foo_dir = os.path.join(self.basedir, 'foo')
        os.mkdir(foo_dir)
        self.assertTrue(path_exists(foo_dir))

    def test_allow_writes(self):
        """Test for allow_writes."""
        set_dir_readonly(self.basedir)
        with allow_writes(self.basedir):
            foo_dir = os.path.join(self.basedir, 'foo')
            os.mkdir(foo_dir)
            self.assertTrue(path_exists(foo_dir))

    def test_set_file_readonly(self):
        """Test for set_file_readonly."""
        set_file_readonly(self.testfile)
        self.addCleanup(set_dir_readwrite, self.testfile)
        self.assertRaises(IOError, open_file, self.testfile, 'w')

    def test_set_file_readwrite(self):
        """Test for set_file_readwrite."""
        set_file_readonly(self.testfile)
        self.addCleanup(set_dir_readwrite, self.testfile)

        set_file_readwrite(self.testfile)
        open_file(self.testfile, 'w')
        self.assertTrue(can_write(self.testfile))

    def test_path_file_exist_yes(self):
        """Test that the file exists."""
        self.assertTrue(path_exists(self.testfile))

    def test_path_file_exist_no(self):
        """Test that the file doesn't exist."""
        remove_file(self.testfile)
        self.assertFalse(path_exists(self.testfile))

    def test_path_dir_exist_yes(self):
        """Test that the dir exists."""
        self.assertTrue(path_exists(self.basedir))

    def test_path_dir_exist_no(self):
        """Test that the dir doesn't exist."""
        self.assertFalse(path_exists(os.path.join(self.basedir, 'nodir')))

    def test_remove_file(self):
        """Test the remove file."""
        remove_file(self.testfile)
        self.assertFalse(path_exists(self.testfile))

    def test_remove_dir(self):
        """Test the remove dir."""
        testdir = os.path.join(self.basedir, 'foodir')
        os.mkdir(testdir)
        assert path_exists(testdir)
        remove_dir(testdir)
        self.assertFalse(path_exists(testdir))

    def test_make_dir_one(self):
        """Test the make dir with one dir."""
        testdir = os.path.join(self.basedir, 'foodir')
        assert not path_exists(testdir)
        make_dir(testdir)
        self.assertTrue(path_exists(testdir))

    def test_make_dir_already_there(self):
        """Test the make dir with one dir that exists."""
        self.assertRaises(OSError, make_dir, self.basedir)

    def test_make_dir_recursive_no(self):
        """Test the make dir with some dirs, not recursive explicit."""
        testdir = os.path.join(self.basedir, 'foo', 'bar')
        assert not path_exists(testdir)
        self.assertRaises(OSError, make_dir, testdir)

    def test_make_dir_recursive_yes(self):
        """Test the make dir with some dirs, recursive."""
        testdir = os.path.join(self.basedir, 'foo', 'bar')
        assert not path_exists(testdir)
        make_dir(testdir, recursive=True)
        self.assertTrue(path_exists(testdir))

    def test_open_file_not_there(self):
        """Open a file that does not exist."""
        self.assertRaises(IOError, open_file, os.path.join(self.basedir, 'no'))

    def test_open_file_gets_a_fileobject(self):
        """Open a file, and get a file object."""
        f = open_file(self.testfile)
        self.assertTrue(isinstance(f, file))

    def test_open_file_read(self):
        """Open a file, and read."""
        with open_file(self.testfile, 'w') as fh:
            fh.write("foo")
        f = open_file(self.testfile, 'r')
        self.assertTrue(f.read(), "foo")

    def test_open_file_write(self):
        """Open a file, and write."""
        fh = open_file(self.testfile, 'w')
        fh.write("foo")
        fh.close()

        f = open_file(self.testfile)
        self.assertTrue(f.read(), "foo")

    def test_rename_not_there(self):
        """Rename something that does not exist."""
        exc = self.assertRaises(
            OSError, rename, os.path.join(self.basedir, 'no'), 'foo')
        self.assertEqual(exc.errno, errno.ENOENT)

    def test_rename_file(self, target=None):
        """Rename a file."""
        if target is None:
            target = os.path.join(self.basedir, 'target')

        assert path_exists(self.testfile)
        rename(self.testfile, target)

        self.assertFalse(
            path_exists(self.testfile),
            'Path %r should not exist after rename.' % self.testfile)
        self.assertTrue(
            path_exists(target),
            'Path %r should exist after rename.' % target)

    def test_rename_dir(self, source=None, target=None):
        """Rename a dir."""
        if source is None:
            source = os.path.join(self.basedir, 'source')
            os.mkdir(source)
        if target is None:
            target = os.path.join(self.basedir, 'target')

        rename(source, target)

        self.assertFalse(
            path_exists(source),
            'Path %r should not exist after rename.' % source)
        self.assertTrue(
            path_exists(target),
            'Path %r should exist after rename.' % target)

    def test_listdir(self, expected_result=None):
        """Return a list of the files in a dir."""
        if expected_result is None:
            _, valid_path_name = os.path.split(self.testfile)
            expected_result = [valid_path_name]

        for extra in ('foo', 'bar'):
            open_file(os.path.join(self.basedir, extra), 'w').close()
            expected_result.append(extra)

        l = listdir(self.basedir)
        self.assertEqual(sorted(l), sorted(expected_result))
        for path in l:
            self.assertIsInstance(path, type(self.basedir))

    def test_access_rw(self):
        """Test access on a file with full permission."""
        self.assertTrue(access(self.testfile))

    def test_access_ro(self):
        """Test access on a file with read only permission."""
        set_file_readonly(self.testfile)
        self.addCleanup(set_file_readwrite, self.testfile)
        self.assertTrue(access(self.testfile))

    def test_access_nothing(self):
        """Test access on a file with no permission at all."""
        set_no_rights(self.testfile)
        self.addCleanup(set_file_readwrite, self.testfile)
        self.assertFalse(access(self.testfile))

    def test_stat_normal(self):
        """Test on a normal file."""
        self.assertEqual(os.stat(self.valid_path),
                         stat_path(self.testfile))

    def test_stat_no_path(self):
        """Test that it raises proper error when no file is there."""
        try:
            return stat_path(os.path.join(self.basedir, 'nofile'))
        except OSError, e:
            self.assertEqual(e.errno, errno.ENOENT)

    def test_path_exists_file_yes(self):
        """The file is there."""
        self.assertTrue(path_exists(self.testfile))

    def test_path_exists_file_no(self):
        """The file is not there."""
        remove_file(self.testfile)
        self.assertFalse(path_exists(self.testfile))

    def test_path_exists_dir_yes(self):
        """The dir is there."""
        self.assertTrue(path_exists(self.basedir))

    def test_path_exists_dir_no(self):
        """The dir is not there."""
        self.assertFalse(path_exists(os.path.join(self.basedir, 'subdir')))

    def test_path_exist_for_link_without_lnk_extension(self):
        """Test if the path of a link exist without the lnk extension."""
        destination = os.path.join(self.basedir, 'destination')
        make_link(self.testfile, destination)
        self.assertTrue(path_exists(destination))

    def test_make_link(self):
        """The link is properly made."""
        destination = os.path.join(self.basedir, 'destination')
        make_link(self.testfile, destination)

        self.assertTrue(is_link(destination))
        self.assertEqual(os.path.normcase(self.testfile),
                         os.path.normcase(read_link(destination)))

    def _assert_read_link(self, target):
        """Assert if the target path of the link is correct."""
        destination = os.path.join(self.basedir, target)
        make_link(self.testfile, destination)

        target = read_link(destination)
        self.assertEqual(self.testfile, target)

    def test_links_target_without_lnk_extension(self):
        """Create a link to self.testfile and then retrieve the link target."""
        # In windows the .lnk extension should be added automatically
        # if the extension is not added by make_link, read_link will fail
        # because Windows is not going to recognize the file as a link
        target = 'target'
        self._assert_read_link(target)

    def test_links_target_with_lnk_extension(self):
        """Create a link to self.testfile and then retrieve the link target."""
        target = 'target.lnk'
        self._assert_read_link(target)

    def test_movetotrash_file_ok(self):
        """Move a file to trash ok.

        Just check it was removed because can't monkeypatch the trash.
        to see that that was actually called.
        """
        move_to_trash(self.testfile)
        self.assertFalse(path_exists(self.testfile))

    def test_movetotrash_dir_ok(self):
        """Move a dir to trash ok.

        Just check it was removed because can't monkeypatch the trash
        to see that that was actually called.
        """
        path = os.path.join(self.basedir, 'foo')
        make_dir(path)
        move_to_trash(path)
        self.assertFalse(path_exists(path))

    def test_movetotrash_notthere(self):
        """Try to move to trash something that is not there."""
        path = os.path.join(self.basedir, 'notthere')
        e = self.assertRaises(OSError, move_to_trash, path)
        self.assertEqual(e.errno, errno.ENOENT)

    def test_expand_user_not_start_with_tilde(self):
        """Test the expand_user function with an ordinary path."""
        path = 'userpath'
        result = expand_user(path)
        self.assertEqual(path, result)

    def test_expand_user_start_with_tilde_no_backslash(self):
        """Test the expand_user function with tilde an ordinary path."""
        path = '~userpath'
        result = expand_user(path)
        self.assertEqual(path, result)

    def test_expand_user_double_backslash(self):
        """Test the expand_user function with double backslash."""
        path = '~~userpath'
        result = expand_user(path)
        self.assertEqual(path, result)

    def test_expand_user_start_with_tilde(self):
        """Test the expand_user function with a path like: ~/userpath."""
        path = os.path.join('~', 'userpath')
        result = expand_user(path)
        expected = os.path.join(self.home_dir, 'userpath')
        self.assertEqual(expected, result)

    def test_expand_user_tilde_and_backslash(self):
        """Test the expand_user function with tilde and backslash."""
        tilde = '~' + os.path.sep
        result = expand_user(tilde)
        expected = self.home_dir + os.path.sep
        self.assertEqual(expected, result)

    def test_expand_user_only_tilde(self):
        """Test the expand_user function returns with only tilde input."""
        tilde = '~'
        result = expand_user(tilde)
        self.assertEqual(self.home_dir, result)
        self.assertFalse(result.endswith(os.path.sep))

    def test_expand_user_fails_if_not_bytes(self):
        """Test the expand_user function input assertions."""
        path = u'userpath'
        self.assertRaises(AssertionError, expand_user, path)

    def test_expand_user_fails_if_not_utf8_encoded(self):
        """Test the expand_user function input encoding."""
        path = u'usérpath'.encode('latin-1')
        self.assertRaises(AssertionError, expand_user, path)


class RecursiveMoveTests(BaseTestCase):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Setup for the tests."""
        yield super(RecursiveMoveTests, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name,
            valid_file_path_builder=valid_file_path_builder)

        # make sure the file exists
        open_file(self.testfile, 'w').close()
        self._create_recursive_move_dirs()
        self.addCleanup(self._clean_recursive_move_dirs)

    def _create_recursive_move_dirs(self):
        """Create the dirs used for the recursive move tests."""
        filename = "foo"
        self.src_dir = os.path.join(self.basedir, 'src')
        make_dir(self.src_dir, recursive=True)
        self.dst_dir = os.path.join(self.basedir, 'dst')
        make_dir(self.dst_dir, recursive=True)
        self.src_file = os.path.join(self.src_dir, filename)
        self.dst_file = os.path.join(self.dst_dir, filename)
        # lets assume we can create a dir in a diff fs
        # add some fake data
        with open_file(self.src_file, "wb") as f:
            f.write("spam")

    def _clean_recursive_move_dirs(self):
        """Clean the created files."""
        for d in (self.src_dir, self.dst_dir):
            self.rmtree(d)

    def _check_move_file(self, src, dst, real_dst):
        """Check that a file was indeed moved."""
        with open_file(src, "rb") as f:
            contents = f.read()
        recursive_move(src, dst)
        with open_file(real_dst, "rb") as f:
            self.assertEqual(contents, f.read())
        self.assertFalse(path_exists(src))

    def _check_move_dir(self, src, dst, real_dst):
        """Check that a dir was indeed moved."""
        contents = sorted(listdir(src))
        recursive_move(src, dst)
        self.assertEqual(contents, sorted(listdir(real_dst)))
        self.assertFalse(path_exists(src))

    def test_move_file(self):
        """Test moving a file to another location on the same filesystem."""
        self._check_move_file(self.src_file, self.dst_file, self.dst_file)

    def test_move_file_to_dir(self):
        """Test moving a file inside an existing dir on the same filesystem."""
        self._check_move_file(self.src_file, self.dst_dir, self.dst_file)

    def test_move_dir_to_dir(self):
        """Test moving a dir inside an existing dir on the same filesystem."""
        self._check_move_dir(self.src_dir, self.dst_dir,
                             os.path.join(self.dst_dir,
                                          os.path.basename(self.src_dir)))

    def test_dont_move_dir_in_itself(self):
        """Test moving a dir inside itself raises an Error."""
        dst = os.path.join(self.src_dir, "bar")
        self.assertRaises(shutil.Error, recursive_move, self.src_dir, dst)


class WalkTests(BaseTestCase):
    """Tests for os wrapper functions."""

    @defer.inlineCallbacks
    def setUp(self, test_dir_name=None, test_file_name=None,
              valid_file_path_builder=None):
        """Setup for the tests."""
        yield super(WalkTests, self).setUp(
            test_dir_name=test_dir_name, test_file_name=test_file_name,
            valid_file_path_builder=valid_file_path_builder)

        self._create_paths()
        self.addCleanup(remove_tree, self.basedir)

    def _create_paths(self):
        """Create the paths for the tests.

        The following structure will be created:

            self.basedir/
            |-> self.testfile
            |-> dir0/
                |-> file0
                |-> link
            |-> dir1/
                |-> file1
                |-> dir11/
            |-> dir2/
                |-> file2
            |-> dir3/

        """
        open_file(self.testfile, 'w').close()

        for i in xrange(3):
            dir_name = 'dir%i' % i
            dir_path = os.path.join(self.basedir, dir_name)
            make_dir(dir_path, recursive=True)

            file_name = 'file%i' % i
            file_path = os.path.join(dir_path, file_name)
            open_file(file_path, "w").close()

        make_link(os.path.devnull,
                  os.path.join(self.basedir, 'dir0', 'link'))
        make_dir(os.path.join(self.basedir, 'dir1', 'dir11'))
        make_dir(os.path.join(self.basedir, 'dir3'), recursive=True)

    def _build_dict_from_walk(self, walk_generator,
                              path_transformer=lambda x: x,
                              name_transformer=lambda x: x):
        """Build a dict from the result of a os.walk call."""
        result = defaultdict(dict)
        for dirpath, dirnames, filenames in walk_generator:
            dirpath = path_transformer(dirpath)
            result[dirpath]['dirnames'] = \
                sorted(map(name_transformer, dirnames))
            result[dirpath]['filenames'] = \
                sorted(map(name_transformer, filenames))

        return result

    def test_len_result(self):
        """Lenght of result is correct."""
        result = list(walk(self.basedir))
        self.assertEqual(len(result), len(list(os.walk(self.basedir))))

    def test_is_a_generator(self):
        """Walk the tree top-down."""
        result = walk(self.basedir)

        for _ in xrange(len(list(os.walk(self.basedir)))):
            dirpath, dirnames, filenames = result.next()

        self.assertRaises(StopIteration, result.next)

    def test_top_down(self, topdown=True, expected=None):
        """Walk the tree top-down."""
        if expected is None:
            result = os.walk(self.basedir, topdown)
            expected = self._build_dict_from_walk(result)
        actual = self._build_dict_from_walk(walk(self.basedir, topdown))

        self.assertEqual(sorted(actual.keys()), sorted(expected.keys()))
        for dirpath, values in expected.iteritems():
            self.assertEqual(values['dirnames'], actual[dirpath]['dirnames'])
            self.assertEqual(values['filenames'], actual[dirpath]['filenames'])

    def test_bottom_up(self):
        """Walk the tree bottom-up."""
        self.test_top_down(topdown=False)
