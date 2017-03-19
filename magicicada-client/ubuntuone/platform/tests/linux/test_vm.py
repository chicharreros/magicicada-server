# tests.platform.linux - linux platform tests
#
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
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
"""Linux specific tests for the platform module."""

import os
import uuid

from twisted.internet import defer

from contrib.testing.testcase import FakeMain
from ubuntuone.storageprotocol import request
from ubuntuone.syncdaemon.tests.test_vm import (
    MetadataTestCase,
    BaseVolumeManagerTests,
)
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    ACCESS_LEVEL_RW,
    get_udf_path,
    LegacyShareFileShelf, _Share, Share, Shared, Root, UDF, _UDF,
    MetadataUpgrader, VMFileShelf,
)


class VolumesTests(BaseVolumeManagerTests):
    """Test UDF/Volumes bits of the VolumeManager."""

    def test_get_udf_path(self):
        """Test for get_udf_path."""
        suggested_path = u"suggested_path"
        udf_path = get_udf_path(u"~/" + suggested_path)
        self.assertEqual(
            os.path.join(self.home_dir, suggested_path.encode('utf-8')),
            udf_path)


class MetadataOldLayoutTests(MetadataTestCase):
    """Tests for 'old' layouts and metadata upgrade"""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(MetadataOldLayoutTests, self).setUp()
        self.root_dir = os.path.join(self.u1_dir, 'My Files')
        self.shares_dir = os.path.join(self.u1_dir, 'Shared With Me')
        self.new_root_dir = self.u1_dir
        self.new_shares_dir = self.mktemp('shares_dir')

    def _build_layout_version_0(self):
        """Build the dir structure to mimic md v.0/None."""
        self.share_md_dir = os.path.join(self.tmpdir, 'data_dir', 'vm')
        os.makedirs(self.share_md_dir)
        os.makedirs(self.root_dir)
        os.makedirs(self.shares_dir)

    def _build_layout_version_1(self):
        """Build the dir structure to mimic md v.1"""
        self.share_md_dir = os.path.join(self.vm_data_dir, 'shares')
        self.shared_md_dir = os.path.join(self.vm_data_dir, 'shared')
        os.makedirs(self.share_md_dir)
        os.makedirs(self.shared_md_dir)
        os.makedirs(self.root_dir)
        os.makedirs(self.shares_dir)

    def _set_permissions(self):
        """Set the RO perms in the root and the shares directory."""
        os.chmod(self.shares_dir, 0500)
        os.chmod(self.u1_dir, 0500)

    def test_upgrade_0(self):
        """Test the upgrade from the first shelf layout version."""
        self._build_layout_version_0()
        old_shelf = LegacyShareFileShelf(self.share_md_dir)
        # add the root_uuid key
        root_share = _Share(path=self.root_dir)
        root_share.access_level = ACCESS_LEVEL_RW
        old_shelf[request.ROOT] = root_share
        for idx in range(1, 10):
            sid = str(uuid.uuid4())
            old_shelf[sid] = _Share(
                path=os.path.join(self.shares_dir, str(idx)), share_id=sid)
        # ShareFileShelf.keys returns a generator
        old_keys = [key for key in old_shelf.keys()]
        self.assertEqual(10, len(old_keys))
        if self.md_version_None:
            self.set_md_version('')
        # set the ro permissions
        self._set_permissions()
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)
        new_keys = [new_key for new_key in self.main.vm.shares.keys()]
        self.assertEqual(10, len(new_keys))
        for new_key in new_keys:
            self.assertIn(new_key, old_keys)
        # check the old data is still there (in the backup)
        bkp_dir = os.path.join(os.path.dirname(self.vm_data_dir),
                               '5.bkp', '0.bkp')
        backup_shelf = LegacyShareFileShelf(bkp_dir)
        backup_keys = [key for key in backup_shelf.keys()]
        for old_key in old_keys:
            self.assertIn(old_key, backup_keys)
        for new_key in new_keys:
            self.assertIn(new_key, backup_keys)
        self.check_version()

    def test_upgrade_1(self):
        """ Test the upgrade from v.1"""
        self._build_layout_version_1()
        # write the .version file with v.1
        self.set_md_version('1')

        share_file = os.path.join(self.share_md_dir,
                                  '0/6/6/0664f050-9254-45c5-9f31-3482858709e4')
        os.makedirs(os.path.dirname(share_file))
        # this is the str of a version 2 pickle
        share_value = (
            "\x80\x02ccanonical.ubuntuone.storage.syncdaemon."
            "volume_manager\nShare\nq\x01)\x81q\x02}q\x03(U\x04nameq"
            "\x04U\tfakeshareq\x05U\x0eother_usernameq\x06U\x08fakeu"
            "serq\x07U\x07subtreeq\x08U$beb0c48c-6755-4fbd-938f-3d20"
            "fa7b102bq\tU\x12other_visible_nameq\nU\tfake userq\x0bU"
            "\x0caccess_levelq\x0cU\x04Viewq\rU\x04pathq\x0eU=/home/"
            "auser/Magicicada/Shared With Me/fakeshare from fakeuser"
            "q\x0fU\x08acceptedq\x10\x88U\x02idq\x11U$0664f050-9254-"
            "45c5-9f31-3482858709e4q\x12ub.")
        with open(share_file, 'w') as fd:
            fd.write(share_value)

        # try to load the shelf
        old_shelf = LegacyShareFileShelf(self.share_md_dir)
        share = old_shelf['0664f050-9254-45c5-9f31-3482858709e4']
        self.assertTrue(share is not None)
        if self.md_version_None:
            self.set_md_version('')

        self._set_permissions()
        # now use the real VolumeManager
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)
        new_keys = [new_key for new_key in self.main.vm.shares.keys()]
        self.assertEqual(2, len(new_keys))  # the fake share plus root
        for key in [request.ROOT, share.id]:
            self.assertIn(key, new_keys)
        self.check_version()

    def test_upgrade_2(self):
        """Test the upgrade from v.2."""
        self._build_layout_version_1()
        self.set_md_version('2')
        open(self.root_dir + '/foo.conflict', 'w').close()
        open(self.root_dir + '/foo.conflict.23', 'w').close()
        open(self.shares_dir + '/bar.partial', 'w').close()
        os.mkdir(self.shares_dir + '/baz/')
        open(self.shares_dir + '/baz/baz.conflict', 'w').close()
        os.chmod(self.shares_dir + '/baz/', 0500)
        if self.md_version_None:
            self.set_md_version('')
        self._set_permissions()
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)
        self.assertTrue(os.path.exists(self.new_root_dir + '/foo.u1conflict'))
        self.assertTrue(
            os.path.exists(self.new_root_dir + '/foo.u1conflict.23'))
        self.assertTrue(
            os.path.exists(self.new_shares_dir + '/.u1partial.bar'))
        self.assertTrue(
            os.path.exists(self.new_shares_dir + '/baz/baz.u1conflict'))
        self.check_version()

    def test_upgrade_2_more(self):
        """Test the upgrade from v.2 some more."""
        self._build_layout_version_1()
        self.set_md_version('2')

        expected = []

        for dirname, new_dirname in [(self.root_dir, self.new_root_dir),
                                     (self.shares_dir, self.new_shares_dir)]:
            # a plain .conflict...
            # ...on a file
            open(dirname + '/1a.conflict', 'w').close()
            expected.append(new_dirname + '/1a.u1conflict')
            # ...on an empty directory
            os.mkdir(dirname + '/1b.conflict')
            expected.append(new_dirname + '/1b.u1conflict')
            # ...on a directory with content
            os.mkdir(dirname + '/1c.conflict')
            os.mkdir(dirname + '/1c.conflict/1c')
            expected.append(new_dirname + '/1c.u1conflict/1c')
            # ...in a readonly directory
            os.mkdir(dirname + '/1d')
            os.mkdir(dirname + '/1d/1d.conflict')
            os.chmod(dirname + '/1d', 0500)
            expected.append(new_dirname + '/1d/1d.u1conflict')
            # ...in a directory that is also a .conflict
            os.mkdir(dirname + '/1e.conflict')
            os.mkdir(dirname + '/1e.conflict/1e.conflict')
            expected.append(new_dirname + '/1e.u1conflict/1e.u1conflict')

            # a numbered .conflict...
            # ...on a file
            open(dirname + '/2a.conflict.2', 'w').close()
            expected.append(new_dirname + '/2a.u1conflict.2')
            # ...on an empty directory
            os.mkdir(dirname + '/2b.conflict.3')
            expected.append(new_dirname + '/2b.u1conflict.3')
            # ...on a directory with content
            os.mkdir(dirname + '/2c.conflict.4')
            os.mkdir(dirname + '/2c.conflict.4/2c')
            expected.append(new_dirname + '/2c.u1conflict.4/2c')
            # ...in a readonly directory
            os.mkdir(dirname + '/2d')
            os.mkdir(dirname + '/2d/2d.conflict.5')
            os.chmod(dirname + '/2d', 0500)
            expected.append(new_dirname + '/2d/2d.u1conflict.5')
            # ...in a directory that is also a .conflict
            os.mkdir(dirname + '/2e.conflict')
            os.mkdir(dirname + '/2e.conflict/2e.conflict.6')
            expected.append(new_dirname + '/2e.u1conflict/2e.u1conflict.6')

            # a plain .conflict of which there already exists a .u1conflict...
            # ...on a file
            open(dirname + '/3a.conflict', 'w').close()
            open(dirname + '/3a.u1conflict', 'w').close()
            expected.append(new_dirname + '/3a.u1conflict')
            expected.append(new_dirname + '/3a.u1conflict.1')
            # ...on an empty directory
            os.mkdir(dirname + '/3b.conflict')
            os.mkdir(dirname + '/3b.u1conflict')
            expected.append(new_dirname + '/3b.u1conflict')
            expected.append(new_dirname + '/3b.u1conflict.1')
            # ...on a directory with content
            os.mkdir(dirname + '/3c.conflict')
            os.mkdir(dirname + '/3c.conflict/3c')
            os.mkdir(dirname + '/3c.u1conflict')
            os.mkdir(dirname + '/3c.u1conflict/3c2')
            expected.append(new_dirname + '/3c.u1conflict.1/3c')
            expected.append(new_dirname + '/3c.u1conflict/3c2')
            # ...in a readonly directory
            os.mkdir(dirname + '/3d')
            os.mkdir(dirname + '/3d/3d.conflict')
            os.mkdir(dirname + '/3d/3d.u1conflict')
            os.mkdir(dirname + '/3d/3d.u1conflict/3d')
            os.chmod(dirname + '/3d', 0500)
            expected.append(new_dirname + '/3d/3d.u1conflict/3d')
            expected.append(new_dirname + '/3d/3d.u1conflict.1')
            # ...in a directory that is also a .conflict
            os.mkdir(dirname + '/3e.conflict')
            os.mkdir(dirname + '/3e.conflict/3e.conflict')
            os.mkdir(dirname + '/3e.conflict/3e.u1conflict')
            os.mkdir(dirname + '/3e.conflict/3e.u1conflict/3e')
            expected.append(new_dirname + '/3e.u1conflict/3e.u1conflict/3e')
            expected.append(new_dirname + '/3e.u1conflict/3e.u1conflict.1')

            # a numbered .conflict of which there already exists a .u1conflict
            # ...on a file
            open(dirname + '/4a.conflict.1', 'w').close()
            open(dirname + '/4a.u1conflict.1', 'w').close()
            expected.append(new_dirname + '/4a.u1conflict.1')
            expected.append(new_dirname + '/4a.u1conflict.2')
            # ...on an empty directory
            os.mkdir(dirname + '/4b.conflict.2')
            os.mkdir(dirname + '/4b.u1conflict.2')
            expected.append(new_dirname + '/4b.u1conflict.2')
            expected.append(new_dirname + '/4b.u1conflict.3')
            # ...on a directory with content
            os.mkdir(dirname + '/4c.conflict.3')
            os.mkdir(dirname + '/4c.conflict.3/4c')
            os.mkdir(dirname + '/4c.u1conflict.3')
            expected.append(new_dirname + '/4c.u1conflict.4/4c')
            expected.append(new_dirname + '/4c.u1conflict.3')
            # ...in a readonly directory
            os.mkdir(dirname + '/4d')
            os.mkdir(dirname + '/4d/4d.conflict.4')
            os.mkdir(dirname + '/4d/4d.u1conflict.4')
            os.chmod(dirname + '/4d', 0500)
            expected.append(new_dirname + '/4d/4d.u1conflict.4')
            expected.append(new_dirname + '/4d/4d.u1conflict.5')
            # ...in a directory that is also a .conflict
            os.mkdir(dirname + '/4e.conflict')
            os.mkdir(dirname + '/4e.conflict/4e.conflict.5')
            os.mkdir(dirname + '/4e.conflict/4e.u1conflict.5')
            expected.append(new_dirname + '/4e.u1conflict/4e.u1conflict.5')
            expected.append(new_dirname + '/4e.u1conflict/4e.u1conflict.6')

            # a plain .partial...
            # ...of a file
            open(dirname + '/5a.partial', 'w').close()
            expected.append(new_dirname + '/.u1partial.5a')
            # ...of a directory
            os.mkdir(dirname + '/5b')
            open(dirname + '/5b/.partial', 'w').close()
            expected.append(new_dirname + '/5b/.u1partial')
            # ...of a readonly directory
            os.mkdir(dirname + '/5c')
            open(dirname + '/5c/.partial', 'w').close()
            os.chmod(dirname + '/5c', 0500)
            expected.append(new_dirname + '/5c/.u1partial')

            # a plain .partial of which there already exists a .u1partial...
            # ...of a file
            open(dirname + '/6a.partial', 'w').close()
            open(dirname + '/.u1partial.6a', 'w').close()
            expected.append(new_dirname + '/.u1partial.6a')
            expected.append(new_dirname + '/.u1partial.6a.1')
            # ...of a directory
            os.mkdir(dirname + '/6b')
            open(dirname + '/6b/.partial', 'w').close()
            open(dirname + '/6b/.u1partial', 'w').close()
            expected.append(new_dirname + '/6b/.u1partial')
            expected.append(new_dirname + '/6b/.u1partial.1')
            # ...of a readonly directory
            os.mkdir(dirname + '/6c')
            open(dirname + '/6c/.partial', 'w').close()
            open(dirname + '/6c/.u1partial', 'w').close()
            os.chmod(dirname + '/6c', 0500)
            expected.append(new_dirname + '/6c/.u1partial')
            expected.append(new_dirname + '/6c/.u1partial.1')

        self._set_permissions()
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)

        for path in expected:
            self.assertTrue(os.path.exists(path), 'missing ' + path)
        self.check_version()

    def test_missing_version_file_with_version_non_0(self):
        """Test the upgrade from the first shelf layout version
        while the metadata sould be in v3 or greater format.

        """
        self._build_layout_version_1()
        maybe_old_shelf = LegacyShareFileShelf(self.share_md_dir)
        # add the root_uuid key
        root_share = _Share(path=self.root_dir)
        root_share.access_level = ACCESS_LEVEL_RW
        maybe_old_shelf[request.ROOT] = root_share
        for idx in range(1, 10):
            share_id = str(uuid.uuid4())
            maybe_old_shelf[share_id] = _Share(
                share_id=share_id, path=os.path.join(self.shares_dir, str(idx))
            )
        # ShareFileShelf.keys returns a generator
        maybe_old_keys = [key for key in maybe_old_shelf.keys()]
        self.assertEqual(10, len(maybe_old_keys))
        if self.md_version_None:
            self.set_md_version('')
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)
        new_keys = [new_key for new_key in self.main.vm.shares.keys()]
        self.assertEqual(10, len(new_keys))
        for new_key in new_keys:
            self.assertIn(new_key, maybe_old_keys)
        # as we didn't actually upgrade the shelf, just the .version file
        # check the empty 0.bkp
        # check the old data is still there (in the backup)
        backup_shelf = LegacyShareFileShelf(os.path.join(self.vm_data_dir,
                                                         '0.bkp'))
        backup_keys = [key for key in backup_shelf.keys()]
        self.assertEqual(0, len(backup_keys))
        self.check_version()

    def test_upgrade_3(self):
        """Test upgrade from version 3."""
        self._build_layout_version_1()
        self.set_md_version('3')
        # create a dir in the root
        os.makedirs(os.path.join(self.root_dir, 'test_dir'))
        # create a file in the root
        open(os.path.join(self.root_dir, 'test_file'), 'w').close()
        # create a file in the new root
        open(os.path.join(self.new_root_dir, 'test_file'), 'w').close()
        share_path = os.path.join(self.shares_dir, 'Bla from Foo')
        os.makedirs(share_path)
        os.makedirs(os.path.join(share_path, 'test_dir'))
        open(os.path.join(share_path, 'test_file'), 'w').close()
        # fix permissions
        self._set_permissions()
        if self.md_version_None:
            self.set_md_version('')
        # migrate the data
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)
        self.assertFalse(os.path.exists(self.root_dir))
        self.assertTrue(os.path.exists(self.shares_dir))
        self.assertTrue(os.path.islink(self.shares_dir), self.shares_dir)
        self.assertEqual(self.shares_dir, self.main.shares_dir_link)
        self.assertTrue(os.path.exists(os.path.join(self.new_root_dir,
                                                    'test_dir')))
        self.assertTrue(os.path.exists(os.path.join(self.new_root_dir,
                                                    'test_file')))
        self.assertTrue(os.path.exists(os.path.join(self.new_root_dir,
                                                    'test_file.u1conflict')))
        self.assertTrue(os.path.exists(share_path))
        self.assertTrue(os.path.exists(os.path.join(share_path, 'test_dir')))
        self.assertTrue(os.path.exists(os.path.join(share_path, 'test_file')))
        self.check_version()

    def test_upgrade_3_with_symlink_in_myfiles(self):
        """Test upgrade from version 3 with symlink in 'My Files'."""
        self._build_layout_version_1()
        self.set_md_version('3')
        # build the old layout
        os.makedirs(os.path.join(self.root_dir, 'test_dir'))
        open(os.path.join(self.root_dir, 'test_file'), 'w').close()
        # create a file in the root
        open(os.path.join(self.new_root_dir, 'test_file'), 'w').close()
        share_path = os.path.join(self.shares_dir, 'Bla from Foo')
        os.makedirs(share_path)
        os.makedirs(os.path.join(share_path, 'test_dir'))
        open(os.path.join(share_path, 'test_file'), 'w').close()
        # create the Shared with Me symlink in My Files
        os.symlink(self.shares_dir, os.path.join(self.root_dir,
                                                 "Shared With Me"))
        # fix permissions
        self._set_permissions()
        if self.md_version_None:
            self.set_md_version('')
        # migrate the data
        self.main = FakeMain(self.new_root_dir, self.new_shares_dir,
                             self.data_dir, self.partials_dir)
        self.assertFalse(os.path.exists(self.root_dir))
        self.assertTrue(os.path.exists(self.shares_dir))
        self.assertTrue(os.path.islink(self.shares_dir))
        self.assertEqual(self.shares_dir, self.main.shares_dir_link)
        self.assertTrue(os.path.exists(os.path.join(self.new_root_dir,
                                                    'test_dir')))
        self.assertTrue(os.path.exists(os.path.join(self.new_root_dir,
                                                    'test_file')))
        self.assertTrue(os.path.exists(os.path.join(self.new_root_dir,
                                                    'test_file.u1conflict')))
        self.assertTrue(os.path.exists(share_path))
        self.assertTrue(os.path.exists(os.path.join(share_path, 'test_dir')))
        self.assertTrue(os.path.exists(os.path.join(share_path, 'test_file')))
        self.assertEqual(
            self.main.shares_dir, os.readlink(self.main.shares_dir_link))
        self.check_version()


class MetadataNewLayoutTests(MetadataTestCase):
    """Test for 'new' layout and metadata upgrade."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(MetadataNewLayoutTests, self).setUp()
        # We need to define home_dir here to add 'home' to the path
        # and avoid crashes between existing paths.
        self.home_dir = os.path.join(self.tmpdir, 'home', 'ubuntuonehacker')
        self.share_md_dir = os.path.join(self.vm_data_dir, 'shares')
        self.shared_md_dir = os.path.join(self.vm_data_dir, 'shared')
        self.u1_dir = os.path.join(
            self.home_dir, os.path.split(self.u1_dir)[1])
        self.root_dir = self.u1_dir
        self.shares_dir = os.path.join(self.tmpdir, 'shares')
        self.shares_dir_link = os.path.join(self.u1_dir, 'Shared With Me')

    def _build_layout_version_4(self):
        """Build the directory structure to mimic md v.4/5."""
        os.makedirs(self.share_md_dir)
        os.makedirs(self.shared_md_dir)
        os.makedirs(self.root_dir)
        os.makedirs(self.shares_dir)
        os.symlink(self.shares_dir, self.shares_dir_link)

    def _fix_permissions(self):
        """Fix shares dir permissions, making it read-only."""
        os.chmod(self.shares_dir, 0500)

    def test_upgrade_None_to_last(self):
        """Upgrade from version 'None' (possibly a clean start)."""
        old_root = os.path.join(self.root_dir, 'My Files')
        old_shares = os.path.join(self.root_dir, 'Shared With Me')
        # start and check that everything is ok
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.assertFalse(os.path.exists(old_root))
        self.assertTrue(os.path.exists(self.root_dir))
        self.assertTrue(os.path.exists(old_shares))
        self.assertTrue(os.path.islink(old_shares))
        self.assertEqual(old_shares, self.main.shares_dir_link)
        self.check_version()

    def test_upgrade_None_to_last_phantom_share_path(self):
        """Upgrade from version 'None' (possibly a clean start) with a root
        with missing path.

        """
        old_root = os.path.join(self.root_dir, 'My Files')
        old_shares = os.path.join(self.root_dir, 'Shared With Me')
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.main.shutdown()
        self.rmtree(self.vm_data_dir)
        os.makedirs(self.vm_data_dir)
        self.set_md_version('')
        shares = LegacyShareFileShelf(self.share_md_dir)
        root_share = _Share(path=self.root_dir)
        root_share.access_level = ACCESS_LEVEL_RW
        # set None to the share path
        root_share.path = None
        shares[request.ROOT] = root_share

        if self.md_version_None:
            self.set_md_version('')
        # check that it's all OK
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.assertFalse(os.path.exists(old_root))
        self.assertTrue(os.path.exists(self.root_dir))
        self.assertTrue(os.path.exists(self.shares_dir))
        self.assertTrue(os.path.islink(old_shares))
        self.assertEqual(old_shares, self.main.shares_dir_link)
        self.check_version()

    def test_upgrade_4(self):
        """Test migration from 4 to 5 (broken symlink in the root)."""
        self._build_layout_version_4()
        self.set_md_version('4')
        # break the symlink
        if os.path.exists(self.shares_dir_link):
            os.unlink(self.shares_dir_link)
        os.symlink(self.shares_dir_link, self.shares_dir_link)

        if self.md_version_None:
            self.set_md_version('')
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.assertEqual(
            self.main.shares_dir, os.readlink(self.main.shares_dir_link))
        self.check_version()

    def test_upgrade_5(self):
        """Test the migration from version 5."""
        # build a fake version 5 state
        self._build_layout_version_4()
        self.set_md_version('5')
        # create some old shares and shared metadata
        legacy_shares = LegacyShareFileShelf(self.share_md_dir)
        root_share = _Share(path=self.root_dir, share_id=request.ROOT,
                            access_level=ACCESS_LEVEL_RW)
        legacy_shares[request.ROOT] = root_share
        for idx, name in enumerate(['share'] * 10):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.shares_dir, share_name),
                           share_id=sid, name=share_name,
                           node_id=str(uuid.uuid4()),
                           other_username='username' + str(idx),
                           other_visible_name='visible name ' + str(idx))
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shares[sid] = share

        # create shared shares
        legacy_shared = LegacyShareFileShelf(self.shared_md_dir)
        for idx, name in enumerate(['dir'] * 5):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.root_dir, share_name),
                           share_id=sid, node_id=str(uuid.uuid4()),
                           name=share_name, other_username='hola',
                           other_visible_name='hola')
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shared[sid] = share

        # keep a copy of the current shares and shared metadata to check
        # the upgrade went ok
        legacy_shares = dict(legacy_shares.items())
        legacy_shared = dict(legacy_shared.items())

        if self.md_version_None:
            self.set_md_version('')
        # upgrade it!
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        vm = self.main.vm

        def compare_share(share, old_share):
            """Compare two shares, new and old"""
            self.assertEqual(share.volume_id, old_share.id)
            self.assertEqual(share.path, old_share.path)
            self.assertEqual(share.node_id, old_share.subtree)
            if not isinstance(share, Root):
                self.assertEqual(share.name, old_share.name)
                self.assertEqual(
                    share.other_username, old_share.other_username)
                self.assertEqual(
                    share.other_visible_name, old_share.other_visible_name)
                self.assertEqual(share.access_level, old_share.access_level)

        for sid in vm.shares:
            old_share = legacy_shares[sid]
            share = vm.shares[sid]
            self.assertTrue(
                isinstance(share, Share) or isinstance(share, Root))
            compare_share(share, old_share)

        for sid in vm.shared:
            old_share = legacy_shared[sid]
            share = vm.shared[sid]
            self.assertTrue(isinstance(share, Shared))
            compare_share(share, old_share)

    def test_upgrade_5_with_udfs(self):
        """Test the migration from version 5 with old UDFs."""
        # build a fake version 5 state
        self._build_layout_version_4()
        self.set_md_version('5')
        self.udfs_md_dir = os.path.join(self.vm_data_dir, 'udfs')
        # create some old shares and shared metadata
        legacy_shares = LegacyShareFileShelf(self.share_md_dir)
        root_share = _Share(path=self.root_dir, share_id=request.ROOT,
                            access_level=ACCESS_LEVEL_RW)
        legacy_shares[request.ROOT] = root_share
        for idx, name in enumerate(['share'] * 10):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.shares_dir, share_name),
                           share_id=sid, name=share_name,
                           node_id=str(uuid.uuid4()),
                           other_username='username' + str(idx),
                           other_visible_name='visible name ' + str(idx))
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shares[sid] = share

        # create shared shares
        legacy_shared = LegacyShareFileShelf(self.shared_md_dir)
        for idx, name in enumerate(['dir'] * 5):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.root_dir, share_name),
                           share_id=sid, node_id=str(uuid.uuid4()),
                           name=share_name, other_username='hola',
                           other_visible_name='hola')
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shared[sid] = share

        # create some udfs
        legacy_udfs = LegacyShareFileShelf(self.udfs_md_dir)
        for idx, name in enumerate(['dir'] * 5):
            udf_id = str(uuid.uuid4())
            udf_name = name + '_' + str(idx)
            udf = _UDF(
                udf_id, str(uuid.uuid4()), u'~/' + udf_name.decode('utf-8'),
                os.path.join(self.home_dir, udf_name))
            if idx % 2:
                udf.subscribed = True
            else:
                udf.subscribed = False
            legacy_udfs[sid] = udf

        # keep a copy of the current shares and shared metadata to check
        # the upgrade went ok
        legacy_shares = dict(legacy_shares.items())
        legacy_shared = dict(legacy_shared.items())
        legacy_udfs = dict(legacy_udfs.items())

        if self.md_version_None:
            self.set_md_version('')
        # upgrade it!
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        vm = self.main.vm

        def compare_share(share, old_share):
            """Compare two shares, new and old"""
            self.assertEqual(share.volume_id, old_share.id)
            self.assertEqual(share.path, old_share.path)
            self.assertEqual(share.node_id, old_share.subtree)
            if not isinstance(share, Root):
                self.assertEqual(share.name, old_share.name)
                self.assertEqual(
                    share.other_username, old_share.other_username)
                self.assertEqual(
                    share.other_visible_name, old_share.other_visible_name)
                self.assertEqual(share.access_level, old_share.access_level)

        for sid in vm.shares:
            old_share = legacy_shares[sid]
            share = vm.shares[sid]
            self.assertTrue(
                isinstance(share, Share) or isinstance(share, Root))
            compare_share(share, old_share)

        for sid in vm.shared:
            old_share = legacy_shared[sid]
            share = vm.shared[sid]
            self.assertTrue(isinstance(share, Shared))
            compare_share(share, old_share)

        for udf_id in vm.udfs:
            old_udf = legacy_udfs[udf_id]
            udf = vm.udfs[udf_id]
            self.assertTrue(isinstance(udf, UDF))
            self.assertEqual(udf.volume_id, old_udf.id)
            self.assertEqual(udf.path, old_udf.path)
            self.assertEqual(udf.node_id, old_udf.node_id)
            self.assertEqual(udf.suggested_path, old_udf.suggested_path)
            self.assertEqual(
                type(udf.suggested_path), type(old_udf.suggested_path))
            self.assertEqual(udf.subscribed, old_udf.subscribed)

    def test_upgrade_5_partial_upgrade(self):
        """Test migration from version 5 with upgrade to 6 unfinished."""
        # build a fake version 5 state
        self._build_layout_version_4()
        self.set_md_version('5')
        self.udfs_md_dir = os.path.join(self.vm_data_dir, 'udfs')
        # create some old shares and shared metadata
        legacy_shares = LegacyShareFileShelf(self.share_md_dir)
        root_share = _Share(path=self.root_dir, share_id=request.ROOT,
                            access_level=ACCESS_LEVEL_RW, node_id=str(
                                uuid.uuid4()))
        legacy_shares[request.ROOT] = root_share
        for idx, name in enumerate(['share'] * 3):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.shares_dir, share_name),
                           share_id=sid, name=share_name,
                           node_id=str(uuid.uuid4()),
                           other_username='username' + str(idx),
                           other_visible_name='visible name ' + str(idx))
            if idx == 0:
                share.access_level = ACCESS_LEVEL_RW
                legacy_shares[sid] = share
            elif idx == 1:
                share.access_level = ACCESS_LEVEL_RO
                legacy_shares[sid] = share
            else:
                # add a 'new' Share dict to the shelf
                share.access_level = ACCESS_LEVEL_RW
                share = Share(
                    path=share.path, volume_id=share.id, name=share.name,
                    access_level=share.access_level,
                    other_username=share.other_username,
                    other_visible_name=share.other_visible_name,
                    node_id=share.subtree)
                legacy_shares[sid] = share.__dict__

        # create shared shares
        legacy_shared = LegacyShareFileShelf(self.shared_md_dir)
        for idx, name in enumerate(['dir'] * 3):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.root_dir, share_name),
                           share_id=sid, node_id=str(uuid.uuid4()),
                           name=share_name, other_username='hola',
                           other_visible_name='hola')
            if idx == 0:
                share.access_level = ACCESS_LEVEL_RW
                legacy_shares[sid] = share
            elif idx == 1:
                share.access_level = ACCESS_LEVEL_RO
                legacy_shares[sid] = share
            else:
                # add a 'new' Shared dict to the shelf
                share.access_level = ACCESS_LEVEL_RW
                share = Shared(path=share.path,
                               volume_id=share.id, name=share.name,
                               access_level=share.access_level,
                               other_username=share.other_username,
                               other_visible_name=share.other_visible_name,
                               node_id=share.subtree)
                legacy_shares[sid] = share.__dict__

        # keep a copy of the current shares and shared metadata to check
        # the upgrade went ok
        legacy_shares = dict(legacy_shares.items())
        legacy_shared = dict(legacy_shared.items())

        if self.md_version_None:
            self.set_md_version('')
        # upgrade it!
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        vm = self.main.vm

        def compare_share(share, old_share):
            """Compare two shares, new and old"""
            old_id = getattr(old_share, 'id', None)
            if old_id is None:
                old_id = old_share['volume_id']
            self.assertEqual(share.volume_id, old_id)
            self.assertEqual(
                share.path,
                getattr(old_share, 'path', None) or old_share['path'])
            self.assertEqual(
                share.node_id,
                getattr(old_share, 'subtree', None) or old_share['node_id'])
            if not isinstance(share, Root):
                self.assertEqual(
                    share.name,
                    getattr(old_share, 'name', None) or old_share['name'])
                username = (getattr(old_share, 'other_username', None) or
                            old_share['other_username'])
                self.assertEqual(share.other_username, username)
                name = (getattr(old_share, 'other_visible_name', None) or
                        old_share['other_visible_name'])
                self.assertEqual(share.other_visible_name, name)
                level = (getattr(old_share, 'access_level', None) or
                         old_share['access_level'])
                self.assertEqual(share.access_level, level)

        for sid in vm.shares:
            old_share = legacy_shares[sid]
            share = vm.shares[sid]
            self.assertTrue(
                isinstance(share, Share) or isinstance(share, Root))
            compare_share(share, old_share)

        for sid in vm.shared:
            old_share = legacy_shared[sid]
            share = vm.shared[sid]
            self.assertTrue(isinstance(share, Shared))
            compare_share(share, old_share)

    def test_upgrade_5_critical_error(self):
        """Test the migration from version 5 with a critical error."""
        # build a fake version 5 state
        self._build_layout_version_4()
        self.set_md_version('5')
        # create some old shares and shared metadata
        legacy_shares = LegacyShareFileShelf(self.share_md_dir)
        root_share = _Share(path=self.root_dir, share_id=request.ROOT,
                            access_level=ACCESS_LEVEL_RW)
        legacy_shares[request.ROOT] = root_share
        for idx, name in enumerate(['share'] * 10):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.shares_dir, share_name),
                           share_id=sid, name=share_name,
                           node_id=str(uuid.uuid4()),
                           other_username='username' + str(idx),
                           other_visible_name='visible name ' + str(idx))
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shares[sid] = share
        # create shared shares
        legacy_shared = LegacyShareFileShelf(self.shared_md_dir)
        for idx, name in enumerate(['dir'] * 5):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = _Share(path=os.path.join(self.root_dir, share_name),
                           share_id=sid, node_id=str(uuid.uuid4()),
                           name=share_name, other_username='hola',
                           other_visible_name='hola')
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shared[sid] = share

        # keep a copy of the current shares and shared metadata to check
        # the upgrade went ok
        legacy_shares = dict(legacy_shares.items())
        legacy_shared = dict(legacy_shared.items())

        if self.md_version_None:
            self.set_md_version('')
        # upgrade it!
        old_upgrade_share_to_volume = MetadataUpgrader._upgrade_share_to_volume

        def upgrade_share_to_volume(share, shared=False):
            raise ValueError('FAIL!')
        MetadataUpgrader._upgrade_share_to_volume = upgrade_share_to_volume
        try:
            self.assertRaises(ValueError, FakeMain, self.root_dir,
                              self.shares_dir, self.data_dir,
                              self.partials_dir)
        finally:
            MetadataUpgrader._upgrade_share_to_volume = \
                    old_upgrade_share_to_volume

        shares = LegacyShareFileShelf(self.share_md_dir)
        self.assertEqual(len(list(shares.keys())), len(legacy_shares.keys()))
        for sid, share in shares.iteritems():
            old_share = legacy_shares[sid]
            self.assertTrue(isinstance(share, _Share))
            self.assertTrue(isinstance(old_share, _Share))
        shared = LegacyShareFileShelf(self.shared_md_dir)
        self.assertEqual(len(list(shared.keys())), len(legacy_shared.keys()))
        for sid, share in shared.iteritems():
            old_share = legacy_shared[sid]
            self.assertTrue(isinstance(share, _Share))
            self.assertTrue(isinstance(old_share, _Share))

    def test_broken_symlink_latest_metadata(self):
        """Test vm startup with latest metadata and a broken symlink."""
        self._build_layout_version_4()
        os.unlink(self.shares_dir_link)
        # create a broken link
        os.symlink('foo', self.shares_dir_link)
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.check_version()

    def test_upgrade_6(self):
        """Test the migration from version 6."""
        # build a fake version 5 state
        self._build_layout_version_4()
        self.set_md_version('6')
        self.udfs_md_dir = os.path.join(self.vm_data_dir, 'udfs')
        # create some old shares and shared metadata
        legacy_shares = VMFileShelf(self.share_md_dir)
        root = Root(path=self.root_dir)
        legacy_shares[request.ROOT] = root
        for idx, name in enumerate(['share'] * 10):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = Share(
                path=os.path.join(self.shares_dir, share_name),
                volume_id=sid, name=share_name, node_id=str(uuid.uuid4()),
                other_username='username' + str(idx),
                other_visible_name='visible name ' + str(idx))
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shares[sid] = share

        # create shared shares
        legacy_shared = VMFileShelf(self.shared_md_dir)
        for idx, name in enumerate(['dir'] * 5):
            sid = str(uuid.uuid4())
            share_name = name + '_' + str(idx)
            share = Shared(path=os.path.join(self.root_dir, share_name),
                           volume_id=sid, node_id=str(uuid.uuid4()),
                           name=share_name, other_username='hola',
                           other_visible_name='hola')
            if idx % 2:
                share.access_level = ACCESS_LEVEL_RW
            else:
                share.access_level = ACCESS_LEVEL_RO
            legacy_shared[sid] = share

        # create some udfs
        legacy_udfs = VMFileShelf(self.udfs_md_dir)
        for idx, name in enumerate(['dir'] * 5):
            udf_id = str(uuid.uuid4())
            udf_name = name + '_' + str(idx)
            udf = UDF(
                udf_id, str(uuid.uuid4()), u'~/' + udf_name.decode('utf-8'),
                os.path.join(self.home_dir, udf_name))
            if idx % 2:
                udf.subscribed = True
            else:
                udf.subscribed = False
            legacy_udfs[sid] = udf

        # keep a copy of the current shares and shared metadata to check
        # the upgrade went ok
        legacy_shares = dict(legacy_shares.items())
        legacy_shared = dict(legacy_shared.items())
        legacy_udfs = dict(legacy_udfs.items())

        if self.md_version_None:
            self.set_md_version('')
        # upgrade it!
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        vm = self.main.vm

        for sid in vm.shares:
            old_share = legacy_shares[sid]
            share = vm.shares[sid]
            self.assertTrue(
                isinstance(share, Share) or isinstance(share, Root))
            self.assertEqual(share.__dict__, old_share.__dict__)

        for sid in vm.shared:
            old_share = legacy_shared[sid]
            share = vm.shared[sid]
            self.assertTrue(isinstance(share, Shared))
            self.assertEqual(share.__dict__, old_share.__dict__)

        for udf_id in vm.udfs:
            old_udf = legacy_udfs[udf_id]
            udf = vm.udfs[udf_id]
            self.assertTrue(isinstance(udf, UDF))
            self.assertEqual(udf.__dict__, old_udf.__dict__)


class BrokenOldMDVersionUpgradeTests(MetadataOldLayoutTests):
    """MetadataOldLayoutTests with broken .version file."""
    md_version_None = True


class BrokenNewMDVersionUpgradeTests(MetadataNewLayoutTests):
    """MetadataNewLayoutTests with broken .version file."""
    md_version_None = True
