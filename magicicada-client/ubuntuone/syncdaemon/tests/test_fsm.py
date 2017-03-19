# -*- coding: utf-8 -*-
#
# Copyright 2009-2012 Canonical Ltd.
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
"""Tests for the File System Manager."""

from __future__ import with_statement

import errno
import os
import time

from mocker import MockerTestCase, ANY
from twisted.internet import defer

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    FakeVolumeManager,
    FakeMain,
    FakeMonitor,
    Listener,
    skip_if_win32_and_uses_metadata_older_than_5,
    skip_if_win32_and_uses_readonly,
)

from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.platform import (
    listdir,
    make_dir,
    make_link,
    open_file,
    path_exists,
    remove_dir,
    remove_file,
    set_dir_readonly,
    set_dir_readwrite,
    stat_path,
)
from ubuntuone.syncdaemon.filesystem_manager import (
    DirectoryNotRemovable,
    EnableShareWrite,
    FileSystemManager,
    InconsistencyError,
    METADATA_VERSION,
    TrashFileShelf,
    TrashTritcaskShelf,
    TRASH_ROW_TYPE,
)
from ubuntuone.syncdaemon import filesystem_manager, config, logger
from ubuntuone.syncdaemon.file_shelf import FileShelf
from ubuntuone.syncdaemon.tritcask import Tritcask
from ubuntuone.syncdaemon.event_queue import EventQueue
from ubuntuone.syncdaemon.interfaces import IMarker
from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    ACCESS_LEVEL_RW,
    allow_writes,
    Share,
)

BROKEN_PICKLE = '\axb80\x02}q\x01(U\x01aU\x04testq\x02U\x01bU\x06brokenq\x03u.'


@defer.inlineCallbacks
def _create_share(share_id, share_name, fsm, shares_dir,
                  access_level=ACCESS_LEVEL_RW):
    """Create a share."""
    assert isinstance(share_name, unicode)
    share_path = os.path.join(shares_dir, share_name.encode('utf-8'))
    make_dir(share_path, recursive=True)
    share = Share(path=share_path, volume_id=share_id,
                  access_level=access_level)
    yield fsm.vm.add_share(share)
    defer.returnValue(share)


class FSMTestCase(BaseTwistedTestCase):
    """Base test case for FSM."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(FSMTestCase, self).setUp()
        self.shares_dir = self.mktemp('shares')
        self.root_dir = self.mktemp('root')
        self.fsmdir = self.mktemp("fsmdir")
        self.partials_dir = self.mktemp("partials")
        self.tritcask_path = self.mktemp("tritcask")

        self.db = Tritcask(self.tritcask_path)
        self.addCleanup(self.db.shutdown)
        self.fsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                     FakeVolumeManager(self.root_dir), self.db)
        self.eq = EventQueue(self.fsm, monitor_class=FakeMonitor)
        self.addCleanup(self.eq.shutdown)
        self.fsm.register_eq(self.eq)
        self.share = yield self.create_share('share', u'share_name')
        self.share_path = self.share.path
        config.get_user_config().set_use_trash(True)

        # add a in-memory logger handler
        self.handler = MementoHandler()
        self.handler.setLevel(0)
        logger.root_logger.addHandler(self.handler)
        self.addCleanup(logger.root_logger.removeHandler, self.handler)

    @defer.inlineCallbacks
    def create_share(self, share_id, share_name, fsm=None, shares_dir=None,
                     access_level=ACCESS_LEVEL_RW):
        """Create a share."""
        assert isinstance(share_name, unicode)
        if fsm is None:
            fsm = self.fsm
        if shares_dir is None:
            shares_dir = self.shares_dir
        share = yield _create_share(share_id, share_name, fsm, shares_dir,
                                    access_level)
        defer.returnValue(share)

    def create_node(self, name, is_dir=False, share=None):
        """Create a node."""
        if share is None:
            share = self.share
        path = os.path.join(share.path, name)
        mdid = self.fsm.create(path, share.volume_id, is_dir=is_dir)
        self.fsm.set_node_id(path, "uuid1")
        mdobj = self.fsm.get_by_mdid(mdid)
        return mdobj


class StartupTests(BaseTwistedTestCase):
    """Test the basic startup behaviour."""

    def test_basic_startup(self):
        """Test the init interface."""
        # only one arg
        self.assertRaises(TypeError, FileSystemManager)
        self.assertRaises(TypeError, FileSystemManager, 1, 2)

        # that creates the dir
        fsmdir = self.mktemp("a_fsmdir")
        partials_dir = self.mktemp("a_partials_dir")
        db = Tritcask(fsmdir)
        self.addCleanup(db.shutdown)
        FileSystemManager(fsmdir, partials_dir,
                          FakeVolumeManager(fsmdir), db)
        self.assertTrue(path_exists(fsmdir))

    @defer.inlineCallbacks
    def test_complex_startup(self):
        """Test startup after having data."""
        # open an empty one
        fsmdir = self.mktemp("fsmdir")
        partials_dir = self.mktemp("a_partials_dir")

        db = Tritcask(fsmdir)
        self.addCleanup(db.shutdown)
        fsm = FileSystemManager(fsmdir, partials_dir,
                                FakeVolumeManager(fsmdir), db)
        share = yield _create_share('share', u'share_name',
                                    fsm=fsm, shares_dir=fsmdir)
        self.assertEqual(fsm._idx_path, {})
        self.assertEqual(fsm._idx_node_id, {})

        # write some data, one with node_id
        path1 = os.path.join(share.path, 'path1')
        fsm.create(path1, "share")
        created_mdid1 = fsm._idx_path[path1]
        self.assertEqual(fsm._idx_path, {path1: created_mdid1})
        fsm.set_node_id(path1, "uuid1")
        self.assertEqual(fsm._idx_node_id, {("share", "uuid1"): created_mdid1})

        # ...and one without
        path2 = os.path.join(share.path, 'path2')
        fsm.create(path2, "share")
        created_mdid2 = fsm._idx_path[path2]
        self.assertEqual(fsm._idx_path,
                         {path1: created_mdid1, path2: created_mdid2})

        # open a second one to see if everything is ok
        fsm = FileSystemManager(fsmdir, partials_dir, fsm.vm, db)
        self.assertEqual(fsm._idx_path,
                         {path1: created_mdid1, path2: created_mdid2})
        self.assertEqual(fsm._idx_node_id, {("share", "uuid1"): created_mdid1})
        self.assertTrue(fsm.get_by_mdid(created_mdid1))
        self.assertTrue(fsm.get_by_mdid(created_mdid2))


class CreationTests(FSMTestCase):
    """Test the creation behaviour."""

    def test_simple(self):
        """Test simple creation."""
        # create, but not twice
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share")
        self.assertRaises(ValueError, self.fsm.create, path, "share")
        self.assertRaises(ValueError, self.fsm.create, path, "other")
        mdobj = self.fsm.get_by_path(path)
        self.assertEqual(mdobj.path, "path")
        self.assertEqual(mdobj.share_id, "share")
        self.assertEqual(mdobj.generation, None)
        self.assertEqual(mdobj.crc32, None)
        self.assertEqual(mdobj.size, None)
        when = mdobj.info.created
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # set uuid using valid path, but not twice
        self.fsm.set_node_id(path, "uuid")
        self.assertRaises(ValueError, self.fsm.set_node_id, path, "whatever")
        mdobj = self.fsm.get_by_path(path)
        when = mdobj.info.node_id_assigned
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

    def test_with_node_id(self):
        """Test creation with node_id"""
        # create, but not twice
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share", node_id='a_node_id')
        self.assertRaises(ValueError, self.fsm.create, path, "share")
        self.assertRaises(ValueError, self.fsm.create, path, "other")
        mdobj = self.fsm.get_by_path(path)
        self.assertEqual(mdobj.path, "path")
        self.assertEqual(mdobj.share_id, "share")
        self.assertEqual(mdobj.node_id, "a_node_id")
        self.assertEqual(mdobj.generation, None)
        self.assertEqual(mdobj.crc32, None)
        self.assertEqual(mdobj.size, None)
        when = mdobj.info.created
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # set uuid using valid path, but not twice
        self.assertRaises(ValueError, self.fsm.set_node_id, path, "whatever")
        mdobj = self.fsm.get_by_path(path)
        when = mdobj.info.node_id_assigned
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

    def test_invalid_args(self):
        """Test using invalid args in set_node_id."""
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share")

        # set uuid using an invalid path
        self.assertRaises(KeyError, self.fsm.set_node_id, "no-path", "whatevr")

        # set uuid using an invalid node_id
        self.assertRaises(ValueError, self.fsm.set_node_id, path, None)

    def test_twice_sameid_ok(self):
        """Test that uuid can be set twice, if the uuid is same."""
        # using the first FSM
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        self.fsm.set_node_id(path, "uuid")

        # opening another FSM
        fsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                self.fsm.vm, self.db)
        fsm.set_node_id(path, "uuid")

    def test_twice_different_bad(self):
        """Test that assignments must be done once, even in different FSMs."""
        # using the first FSM
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        self.assertRaises(ValueError, self.fsm.set_node_id, path, "other_uuid")

        # opening another FSM
        fsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                self.fsm.vm, self.db)
        self.assertRaises(ValueError, fsm.create, path, "share")
        self.assertRaises(ValueError, fsm.set_node_id, path, "other_uuid")

    def test_fresh_metadata(self):
        """Initing with nothing in the metadata, it should leave it right."""
        with open_file(os.path.join(self.fsmdir, "metadata_version")) as f:
            md_version = f.read()
        self.assertEqual(md_version, METADATA_VERSION)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_None(self):
        """Test old metadata situation, in None."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        open_file(path, "w").close()
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        # create a path with the old layout
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid1")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, 'share1_name')
        make_link(self.shares_dir, old_shares_path)

        # put the old path in the mdobj
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md

        # break the node on purpose
        real_mdobj = self.fsm.fs[mdid]
        del real_mdobj["stat"]
        del real_mdobj["generation"]
        real_mdobj["path"] = unicode(real_mdobj["path"])
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # delete the version that should have left the previous fsm
        version_file = os.path.join(self.fsmdir, "metadata_version")
        remove_file(version_file)

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.stat, stat_path(path))
        self.assertEqual(newmdobj.generation, None)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertTrue(other_share.path in newfsm._idx_path)
        self.assertFalse(old_path in self.fsm._idx_path)
        self.assertFalse(old_path in newfsm._idx_path)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_1(self):
        """Test old metadata situation, in v1."""
        # create some stuff
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        mdid1 = self.fsm.create(path1, "share")
        self.fsm.set_node_id(path1, "uuid1")
        mdid2 = self.fsm.create(path2, "share")
        self.fsm.set_node_id(path2, "uuid2")

        # create a path with the old layout
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid1")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, 'share1_name')
        make_link(self.shares_dir, old_shares_path)

        # put the old path in the mdobj
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md

        # break the node on purpose, with unicode valid and not
        real_mdobj = self.fsm.fs[mdid1]
        real_mdobj["path"] = unicode(real_mdobj["path"])
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        del real_mdobj["generation"]
        self.fsm.fs[mdid1] = real_mdobj
        real_mdobj = self.fsm.fs[mdid2]
        real_mdobj["path"] = "asdas\x00\xff\xffasd"
        self.fsm.fs[mdid2] = real_mdobj

        # put the old version in file
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("1")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path1)
        self.assertEqual(newmdobj.mdid, mdid1)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertEqual(newmdobj.generation, None)
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertEqual(2, len(newfsm._idx_node_id))
        self.assertTrue(other_share.path in newfsm._idx_path)
        self.assertFalse(old_path in newfsm._idx_path)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_2(self):
        """Test old metadata situation, in v2."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        # create a path with the old layout
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid1")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, 'share1_name')
        make_link(self.shares_dir, old_shares_path)

        # put the old path in the mdobj
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md

        # break the node on purpose, with hashes in None
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        del real_mdobj["generation"]
        self.fsm.fs[mdid] = real_mdobj

        # put the old version in file
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("2")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertEqual(newmdobj.generation, None)
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertEqual(2, len(newfsm._idx_node_id))
        self.assertTrue(other_share.path in newfsm._idx_path)
        self.assertFalse(old_path in newfsm._idx_path)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_3(self):
        """Test old metadata situation, in v3."""
        # create a path with the old layout and metadata
        # the root
        root_mdid = self.fsm.create(self.root_dir, "")
        self.fsm.set_node_id(self.root_dir, "uuid")
        # a share
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid1")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, 'share1_name')
        make_link(self.shares_dir, old_shares_path)
        old_root_path = os.path.join(os.path.dirname(self.root_dir),
                                     'Magicicada', 'My Files')

        # simulate old data in the mdobjs
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md
        root_md = self.fsm.fs[root_mdid]
        root_md['path'] = old_root_path
        del root_md["generation"]
        self.fsm.fs[root_mdid] = root_md

        # put the old version in file
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("3")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(other_share.path)
        self.assertEqual(newmdobj.mdid, share_md['mdid'])
        self.assertNotEqual(newmdobj.path, share_md['path'])

        root_dir = os.path.dirname(old_root_path)
        rootmdobj = newfsm.get_by_path(root_dir)
        self.assertEqual(rootmdobj.mdid, root_md['mdid'])
        self.assertEqual(rootmdobj.path, root_dir)
        self.assertEqual(rootmdobj.generation, None)
        self.assertEqual(2, len(newfsm._idx_node_id))
        self.assertTrue(other_share.path in newfsm._idx_path)
        self.assertFalse(old_path in newfsm._idx_path)
        self.assertTrue(root_dir in newfsm._idx_path)
        self.assertFalse(old_root_path in newfsm._idx_path)

    def test_old_metadata_4(self):
        """Test old metadata situation, in v4."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        path_1 = os.path.join(self.share.path, 'path_1')
        mdid_1 = self.fsm.create(path_1, "share")
        self.fsm.set_node_id(path_1, "uuid_1")

        # break the node on purpose, without generation
        real_mdobj = self.fsm.fs[mdid]
        del real_mdobj["generation"]
        self.fsm.fs[mdid] = real_mdobj
        real_mdobj = self.fsm.fs[mdid_1]
        del real_mdobj["generation"]
        self.fsm.fs[mdid_1] = real_mdobj

        # add a node to the trash
        self.fsm.delete_to_trash(mdid_1, "parent")
        # and to the move limbo
        self.fsm.add_to_move_limbo("share", "uuid_1", "old_parent",
                                   "new_parent", "new_name", "pfrom", "pto")

        # put the old version in file
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("4")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v
        # create a old-style trash
        old_trash = TrashFileShelf(self.fsm._trash_dir)
        for k, v in self.fsm.trash.iteritems():
            old_trash[k] = v
        # create a old-style move_limbo
        old_mvlimbo = TrashFileShelf(self.fsm._movelimbo_dir)
        for k, v in self.fsm.move_limbo.iteritems():
            old_mvlimbo[k] = v

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.generation, None)
        # check that the trash is the same:
        self.assertEqual(
            self.fsm.trash,
            {("share", "uuid_1"): (mdid_1, "parent", path_1, False)})
        self.assertEqual(list(self.fsm.get_iter_trash()),
                         [("share", "uuid_1", "parent", path_1, False)])
        # check the move limbo
        expected = [(("share", "uuid_1"),
                    ("old_parent", "new_parent", "new_name", "pfrom", "pto"))]
        self.assertEqual(expected, self.fsm.move_limbo.items())
        r = [("share", "uuid_1", "old_parent", "new_parent",
              "new_name", "pfrom", "pto")]
        self.assertEqual(list(self.fsm.get_iter_move_limbo()), r)

    def test_old_metadata_5(self):
        """Test old metadata situation, in v5."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        path_1 = os.path.join(self.share.path, 'path_1')
        mdid_1 = self.fsm.create(path_1, "share")
        self.fsm.set_node_id(path_1, "uuid_1")

        # add a node to the trash
        self.fsm.delete_to_trash(mdid_1, "parent")
        # and to the move limbo
        self.fsm.add_to_move_limbo("share", "uuid_1", "old_parent",
                                   "new_parent", "new_name", "pfrom", "pto")

        # put the old version in file
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("4")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v
        # create a old-style trash
        old_trash = TrashFileShelf(self.fsm._trash_dir)
        for k, v in self.fsm.trash.iteritems():
            old_trash[k] = v
        # create a old-style move_limbo
        old_mvlimbo = TrashFileShelf(self.fsm._movelimbo_dir)
        for k, v in self.fsm.move_limbo.iteritems():
            old_mvlimbo[k] = v

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.share_id, 'share')
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.generation, None)
        # check that the trash is the same:
        self.assertEqual(
            self.fsm.trash,
            {("share", "uuid_1"): (mdid_1, "parent", path_1, False)})
        self.assertEqual(list(self.fsm.get_iter_trash()),
                         [("share", "uuid_1", "parent", path_1, False)])
        # check the move limbo
        expected = [(("share", "uuid_1"),
                    ("old_parent", "new_parent", "new_name", "pfrom", "pto"))]
        self.assertEqual(expected, self.fsm.move_limbo.items())
        r = [("share", "uuid_1", "old_parent", "new_parent",
              "new_name", "pfrom", "pto")]
        self.assertEqual(list(self.fsm.get_iter_move_limbo()), r)

    @skip_if_win32_and_uses_metadata_older_than_5
    def test_old_metadata_None_broken_pickle_without_backup(self):
        """Test old metadata situation, in None with broken metadata values."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        for p in [path, path1, path2]:
            open_file(p, "w").close()
        mdid = self.fsm.create(path, "share", node_id='uuid')
        mdid1 = self.fsm.create(path1, "share", node_id='uuid1')
        mdid2 = self.fsm.create(path2, "share", node_id='uuid2')

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # break the node on purpose
        with open_file(old_fs.key_file(mdid1), 'w') as f:
            f.write(BROKEN_PICKLE)
            os.fsync(f.fileno())

        # break the node by creating a 0 byte pickle
        with open_file(old_fs.key_file(mdid2), 'w') as f:
            os.fsync(f.fileno())

        # delete the version that should have left the previous fsm
        version_file = os.path.join(self.fsmdir, "metadata_version")
        remove_file(version_file)

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        self.assertTrue(newfsm.get_by_mdid(mdid) is not None)
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid1)
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid2)

    @skip_if_win32_and_uses_metadata_older_than_5
    def test_old_metadata_1_broken_pickle_without_backup(self):
        """Test old metadata situation, in v1 with broken metadata values."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        mdid = self.fsm.create(path, "share", node_id='uuid')
        mdid1 = self.fsm.create(path1, "share", node_id='uuid1')
        mdid2 = self.fsm.create(path2, "share", node_id='uuid2')

        # break the node on purpose
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["path"] = unicode(real_mdobj["path"])
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # break the second node on purpose but with an invalid pickle
        with open_file(old_fs.key_file(mdid1), 'w') as f:
            f.write(BROKEN_PICKLE)
            os.fsync(f.fileno())
        # break the third node by creating a 0 byte pickle
        with open_file(old_fs.key_file(mdid2), 'w') as f:
            os.fsync(f.fileno())

        # put the version file in 1
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("1")

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid1)
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid2)
        self.assertEqual(1, len(newfsm._idx_node_id))

    @skip_if_win32_and_uses_metadata_older_than_5
    def test_old_metadata_2_broken_pickle_without_backup(self):
        """Test old metadata situation, in v2 with broken metadata values."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        for p in [path, path1, path2]:
            open_file(p, "w").close()
        mdid = self.fsm.create(path, "share", node_id='uuid')
        mdid1 = self.fsm.create(path1, "share", node_id='uuid1')
        mdid2 = self.fsm.create(path2, "share", node_id='uuid2')

        # break the node on purpose, with hashes in None
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # put the version file in 1
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("2")
        # break the second node on purpose but with an invalid pickle
        with open_file(old_fs.key_file(mdid1), 'w') as f:
            f.write(BROKEN_PICKLE)
            os.fsync(f.fileno())
        # break the third node by creating a 0 byte pickle
        with open_file(old_fs.key_file(mdid2), 'w') as f:
            os.fsync(f.fileno())

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid1)
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid2)
        self.assertEqual(1, len(newfsm._idx_node_id))

    @skip_if_win32_and_uses_metadata_older_than_5
    def test_old_metadata_None_broken_pickle_with_backup(self):
        """Test old metadata situation, in None with broken metadata values."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        for p in [path, path1, path2]:
            open_file(p, "w").close()
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        mdid1 = self.fsm.create(path1, "share")
        self.fsm.set_node_id(path1, "uuid1")
        mdid2 = self.fsm.create(path2, "share")
        self.fsm.set_node_id(path2, "uuid2")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v
        # fake version 2 with a backup
        mdobj = old_fs[mdid1]
        mdobj['node_id'] = None
        old_fs[mdid1] = mdobj
        old_fs[mdid1] = mdobj
        mdobj = old_fs[mdid2]
        mdobj['node_id'] = None
        old_fs[mdid2] = mdobj
        old_fs[mdid2] = mdobj
        # break the node on purpose
        with open_file(old_fs.key_file(mdid1), 'w') as f:
            f.write(BROKEN_PICKLE)
            os.fsync(f.fileno())

        # break the node by creating a 0 byte pickle
        with open_file(old_fs.key_file(mdid2), 'w') as f:
            os.fsync(f.fileno())

        # delete the version that should have left the previous fsm
        version_file = os.path.join(self.fsmdir, "metadata_version")
        remove_file(version_file)

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        self.assertTrue(newfsm.get_by_mdid(mdid) is not None)
        self.assertEqual(1, len(newfsm._idx_node_id))
        self.assertEqual(3, len(newfsm._idx_path))
        # check that the broken mdid's load the old metadata
        self.assertEqual(None, newfsm.get_by_mdid(mdid1).node_id)
        self.assertEqual(None, newfsm.get_by_mdid(mdid2).node_id)

    @skip_if_win32_and_uses_metadata_older_than_5
    def test_old_metadata_1_broken_pickle_with_backup(self):
        """Test old metadata situation, in v1 with broken metadata values."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        mdid1 = self.fsm.create(path1, "share")
        self.fsm.set_node_id(path1, "uuid1")
        mdid2 = self.fsm.create(path2, "share")
        self.fsm.set_node_id(path2, "uuid2")

        # break the node on purpose
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["path"] = unicode(real_mdobj["path"])
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v
        # fake version 2 with a backup
        mdobj = old_fs[mdid1]
        mdobj['node_id'] = None
        old_fs[mdid1] = mdobj
        old_fs[mdid1] = mdobj
        mdobj = old_fs[mdid2]
        mdobj['node_id'] = None
        old_fs[mdid2] = mdobj
        old_fs[mdid2] = mdobj
        # break the second node on purpose but with an invalid pickle
        with open_file(old_fs.key_file(mdid1), 'w') as f:
            f.write(BROKEN_PICKLE)
            os.fsync(f.fileno())
        # break the third node by creating a 0 byte pickle
        with open_file(old_fs.key_file(mdid2), 'w') as f:
            os.fsync(f.fileno())

        # put the version file in 1
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("1")

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertEqual(1, len(newfsm._idx_node_id))
        self.assertEqual(3, len(newfsm._idx_path))
        # check that the broken mdid's load the old metadata
        self.assertEqual(None, newfsm.get_by_mdid(mdid1).node_id)
        self.assertEqual(None, newfsm.get_by_mdid(mdid2).node_id)

    @skip_if_win32_and_uses_metadata_older_than_5
    def test_old_metadata_2_broken_pickle_with_backup(self):
        """Test old metadata situation, in v2 with broken metadata values."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        for p in [path, path1, path2]:
            open_file(p, "w").close()
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        mdid1 = self.fsm.create(path1, "share")
        self.fsm.set_node_id(path1, "uuid1")
        mdid2 = self.fsm.create(path2, "share")
        self.fsm.set_node_id(path2, "uuid2")

        # break the node on purpose, with hashes in None
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # put the version file in 1
        version_file = os.path.join(self.fsmdir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("2")

        # create a old-style fs with the data
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # fake version 2 with a backup
        mdobj = old_fs[mdid1]
        mdobj['node_id'] = None
        old_fs[mdid1] = mdobj
        old_fs[mdid1] = mdobj
        mdobj = old_fs[mdid2]
        mdobj['node_id'] = None
        old_fs[mdid2] = mdobj
        old_fs[mdid2] = mdobj

        # break the second node on purpose but with an invalid pickle
        with open_file(old_fs.key_file(mdid1), 'w') as f:
            f.write(BROKEN_PICKLE)
            os.fsync(f.fileno())
        # break the third node by creating a 0 byte pickle
        with open_file(old_fs.key_file(mdid2), 'w') as f:
            os.fsync(f.fileno())

        # start up again, and check
        db = Tritcask(self.tritcask_path+'.new')
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertEqual(1, len(newfsm._idx_node_id))
        self.assertEqual(3, len(newfsm._idx_path))
        # check that the broken mdid's load the old metadata
        self.assertEqual(None, newfsm.get_by_mdid(mdid1).node_id)
        self.assertEqual(None, newfsm.get_by_mdid(mdid2).node_id)

    def test_current_metadata_phantom_node_older(self):
        """Test current metadata with a phantom node."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        # keep the mdobj around
        mdobj = self.fsm.fs[mdid]
        # delete it from metadata and add it again to fake a phantom node.
        self.fsm.delete_metadata(path)
        self.fsm.fs[mdid] = mdobj

        # create a new node with the same path
        mdid_1 = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid_1")

        # shutdown old self.db so files are closed
        self.db.shutdown()

        # start up again, and check
        self.db = Tritcask(self.tritcask_path)
        self.addCleanup(self.db.shutdown)

        # patch this tritcask instance to return the keys ordered by tstamp
        # (reversed), in order to make this test deterministic.
        def rsorted_keys():
            """Custom keys function to sort in reverse order by tstamp."""
            return [k for k, _ in sorted(self.db._keydir.items(),
                    key=lambda v: v[1].tstamp, reverse=True)]

        self.patch(self.db, 'keys', rsorted_keys)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, self.db)
        newmdobj = newfsm.get_by_path(path)
        # check that the mdobj is the new one.
        self.assertEqual(newmdobj.mdid, mdid_1)
        self.assertNotEqual(newmdobj.mdid, mdid)
        self.assertEqual(1, len(self.db.keys()))
        self.handler.check_warning("Path already in the index: %s" % (path))
        self.handler.check_debug("Replacing and deleting node %s witth newer "
                                 "node: %s" % (mdid, mdid_1))

    def test_current_metadata_phantom_node_newer(self):
        """Test current metadata with a phantom node."""
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        # keep the mdobj around
        mdobj = self.fsm.fs[mdid]
        # delete it from metadata and add it again to fake a phantom node.
        self.fsm.delete_metadata(path)
        self.fsm.fs[mdid] = mdobj
        # verterok: hack to ensure time moves forward
        time.sleep(.1)

        # create a new node with the same path
        mdid_1 = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid_1")

        # shutdown old self.db so files are closed
        self.db.shutdown()

        # start up again, and check
        self.db = Tritcask(self.tritcask_path)
        self.addCleanup(self.db.shutdown)

        # patch this tritcask instance to return the keys ordered by tstamp
        # (reversed), in order to make this test deterministic.
        def sorted_keys():
            """Custom keys function to sort ordered by tstamp."""
            return [k for k, _ in sorted(self.db._keydir.items(),
                    key=lambda v: v[1].tstamp, reverse=False)]

        self.patch(self.db, 'keys', sorted_keys)
        newfsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                   self.fsm.vm, self.db)
        newmdobj = newfsm.get_by_path(path)

        # check that the mdobj is the new one.
        self.assertEqual(newmdobj.mdid, mdid_1)
        self.assertNotEqual(newmdobj.mdid, mdid)
        self.assertEqual(1, len(self.db.keys()))
        self.handler.check_warning("Path already in the index: %s" % (path))
        self.handler.check_debug("The node: %s is newer than: %s, "
                                 "leaving it alone and deleting the old one.",
                                 mdid, mdid_1)


class GetSetTests(FSMTestCase):
    """Test the get/set interface."""

    def test_bad_data(self):
        """No such info is allowed as path."""
        self.assertRaises(ValueError, self.fsm.create, "", "share")
        self.assertRaises(ValueError, self.fsm.create, " ", "share")

    def test_basic(self):
        """Test basic retrieval."""
        # write some data
        path1 = os.path.join(self.share_path, "path1")
        newmdid = self.fsm.create(path1, "share")
        mdid1 = self.fsm._idx_path[path1]
        self.fsm.set_node_id(path1, "uuid1")
        self.assertEqual(newmdid, mdid1)

        mdobj = self.fsm.get_by_mdid(mdid1)
        self.assertEqual(mdobj.node_id, "uuid1")
        self.assertEqual(mdobj.path, "path1")
        self.assertEqual(mdobj.share_id, "share")
        self.assertEqual(mdobj.local_hash, "")
        self.assertEqual(mdobj.server_hash, "")
        self.assertEqual(mdobj.info.is_partial, False)
        self.assertEqual(mdobj.is_dir, False)
        self.assertEqual(mdobj.mdid, mdid1)
        self.assertEqual(self.fsm.get_by_node_id("share", "uuid1"), mdobj)
        self.assertEqual(self.fsm.get_by_path(path1), mdobj)

        # write more data
        path2 = os.path.join(self.share_path, "path2")
        newmdid = self.fsm.create(path2, "share", is_dir=True)
        mdid2 = self.fsm._idx_path[path2]
        self.fsm.set_node_id(path2, "uuid2")
        self.assertEqual(newmdid, mdid2)

        # check that is not mixed
        mdobj = self.fsm.get_by_mdid(mdid1)
        self.assertEqual(mdobj.node_id, "uuid1")
        self.assertEqual(mdobj.path, "path1")
        self.assertEqual(mdobj.share_id, "share")
        self.assertEqual(mdobj.mdid, mdid1)
        self.assertEqual(mdobj.is_dir, False)
        self.assertEqual(self.fsm.get_by_node_id("share", "uuid1"), mdobj)
        self.assertEqual(self.fsm.get_by_path(path1), mdobj)
        mdobj = self.fsm.get_by_mdid(mdid2)
        self.assertEqual(mdobj.node_id, "uuid2")
        self.assertEqual(mdobj.path, "path2")
        self.assertEqual(mdobj.share_id, "share")
        self.assertEqual(mdobj.mdid, mdid2)
        self.assertEqual(mdobj.is_dir, True)
        self.assertEqual(self.fsm.get_by_node_id("share", "uuid2"), mdobj)
        self.assertEqual(self.fsm.get_by_path(path2), mdobj)

    def test_iteration(self):
        """Test basic retrieval."""
        # create a few objects
        mdids = []
        path_names = "path1 path2 path3".split()
        paths = []
        for path in path_names:
            path = os.path.join(self.share.path, path)
            paths.append(path)
            mdid = self.fsm.create(path, "share")
            mdids.append(mdid)
        mdids.sort()

        # get them
        retrieved_mdids = []
        retrieved_paths = []
        for mdobj in self.fsm.get_mdobjs_by_share_id("share"):
            retrieved_mdids.append(mdobj.mdid)
            retrieved_paths.append(mdobj.path)
        retrieved_mdids.sort()
        retrieved_paths.sort()

        # check them
        self.assertEqual(mdids, retrieved_mdids)
        self.assertEqual(path_names, retrieved_paths)

    def test_getacopy(self):
        """Test that we receive only a copy."""
        # write some data
        path = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        self.fsm.set_by_mdid(mdid, newarg="foo")

        # test getting a copy with mdid
        d = self.fsm.get_by_mdid(mdid)
        # XXX http://bugs.launchpad.net/bugs/400331
        d.newarg = "bar"
        d = self.fsm.get_by_mdid(mdid)
        self.assertEqual(d.newarg, "foo")

        # test getting a copy with uuid
        d = self.fsm.get_by_node_id("share", "uuid")
        d.newarg = "bar"
        d = self.fsm.get_by_node_id("share", "uuid")
        self.assertEqual(d.newarg, "foo")

        # test getting a copy with path
        d = self.fsm.get_by_path(path)
        d.newarg = "bar"
        d = self.fsm.get_by_path(path)
        self.assertEqual(d.newarg, "foo")

    def test_get_raises(self):
        """Test that we get an exception if the object is not there."""
        # write some data
        path = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # with mdid, ok and bad
        self.fsm.get_by_mdid(mdid)
        self.assertRaises(KeyError, self.fsm.get_by_mdid, "no-such-key")

        # with uuid, ok and bad
        self.fsm.get_by_node_id("share", "uuid")
        self.assertRaises(KeyError, self.fsm.get_by_node_id,
                          "share", "no-such-key")
        self.assertRaises(ValueError, self.fsm.get_by_node_id,
                          "share", None)

        # with path, ok and bad
        self.fsm.get_by_path(path)
        self.assertRaises(KeyError, self.fsm.get_by_path, "no-such-key")

    def test_setters_simple(self):
        """Test that setters work."""
        # create some data
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # test using mdid
        self.fsm.set_by_mdid(mdid, foo="foo1")
        self.fsm.set_by_mdid(mdid, bar="bar1", baz="baz1")
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.foo, "foo1")
        self.assertEqual(mdobj.bar, "bar1")
        self.assertEqual(mdobj.baz, "baz1")

        # test using uuid
        self.assertRaises(ValueError, self.fsm.set_by_node_id, None, "sh", j=3)
        self.fsm.set_by_node_id("uuid", "share", foo="foo2")
        self.fsm.set_by_node_id("uuid", "share", bar="bar2", baz="baz2")
        mdobj = self.fsm.get_by_node_id("share", "uuid")
        self.assertEqual(mdobj.foo, "foo2")
        self.assertEqual(mdobj.bar, "bar2")
        self.assertEqual(mdobj.baz, "baz2")

        # test using path
        self.fsm.set_by_path(path, foo="foo3")
        self.fsm.set_by_path(path, bar="bar3", baz="baz3")
        mdobj = self.fsm.get_by_path(path)
        self.assertEqual(mdobj.foo, "foo3")
        self.assertEqual(mdobj.bar, "bar3")
        self.assertEqual(mdobj.baz, "baz3")

    def test_setters_mixed(self):
        """Test the setters using different combinations."""
        # create some data
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # set with mdid, get with uuid and path
        self.fsm.set_by_mdid(mdid, foo="foo1")
        self.assertEqual(self.fsm.get_by_node_id("share", "uuid").foo, "foo1")
        self.assertEqual(self.fsm.get_by_path(path).foo, "foo1")

        # set with uuid, get with mdid and path
        self.fsm.set_by_node_id("uuid", "share", foo="foo2")
        self.assertEqual(self.fsm.get_by_mdid(mdid).foo, "foo2")
        self.assertEqual(self.fsm.get_by_path(path).foo, "foo2")

        # set with path, get with uuid and mdid
        self.fsm.set_by_path(path, foo="foo3")
        self.assertEqual(self.fsm.get_by_node_id("share", "uuid").foo, "foo3")
        self.assertEqual(self.fsm.get_by_mdid(mdid).foo, "foo3")

    def test_setters_raises(self):
        """Test that setters raise ok."""
        # create some data
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # test with bad values
        self.assertRaises(KeyError, self.fsm.get_by_node_id, "share", "bad")
        self.assertRaises(KeyError, self.fsm.get_by_mdid, "bad-value")
        self.assertRaises(KeyError, self.fsm.get_by_path, "bad-value")

    def test_setting_forbidden_values(self):
        """Test trying to set forbidden values."""
        # create some data
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # test with forbidden uuid
        self.assertRaises(ValueError, self.fsm.set_by_mdid, mdid, node_id="-")
        self.assertRaises(ValueError, self.fsm.set_by_path, path, node_id="")

        # test with forbidden path
        self.assertRaises(ValueError, self.fsm.set_by_node_id, "uuid", "share",
                          path="-")
        self.assertRaises(ValueError, self.fsm.set_by_mdid, mdid, path="-")

        # test with forbidden info
        self.assertRaises(ValueError, self.fsm.set_by_node_id, "uuid", "share",
                          info="-")
        self.assertRaises(ValueError, self.fsm.set_by_mdid, mdid, info="-")
        self.assertRaises(ValueError, self.fsm.set_by_path, path, info="-")

        # test with forbidden share
        self.assertRaises(ValueError, self.fsm.set_by_mdid, mdid, share_id="-")
        self.assertRaises(ValueError, self.fsm.set_by_path, path, share_id="-")

        # test with forbidden mdid
        self.assertRaises(ValueError, self.fsm.set_by_node_id, "uuid", "share",
                          mdid="-")
        self.assertRaises(ValueError, self.fsm.set_by_path, path, mdid="-")

        # test with forbidden is_dir
        self.assertRaises(ValueError, self.fsm.set_by_mdid, mdid, is_dir="-")
        self.assertRaises(ValueError, self.fsm.set_by_path, path, is_dir="-")
        self.assertRaises(ValueError,
                          self.fsm.set_by_node_id, "uuid", "share", is_dir="-")

    def test_setting_forbidden_mixed(self):
        """Test that when trying with forbidden, nothing happens at all."""
        # create some data
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # test with mixed stuff
        self.assertRaises(TypeError, self.fsm.set_by_node_id, info="n", foo="")
        self.assertRaises(TypeError, self.fsm.set_by_mdid, path="nop", bar="?")
        self.assertRaises(TypeError, self.fsm.set_by_path, node_id="n", baz="")

        # see that it still is unchanged
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.path, "path")
        self.assertEqual(mdobj.node_id, "uuid")

    def test_get_root(self):
        """ Test that the root of a share is stored properly. """
        # write some data
        self.fsm.create(self.share_path, "share")
        self.fsm.set_node_id(self.share_path, "uuid")

        # with path, ok and bad
        self.fsm.get_by_path(self.share_path)
        self.assertRaises(KeyError, self.fsm.get_by_path, "no-such-key")

        # check the path stored in the mdobj
        mdobj = self.fsm.get_by_node_id("share", "uuid")
        self.assertEqual(self.share_path, mdobj.path)

    @defer.inlineCallbacks
    def test_get_all_by_share(self):
        """ Test that it returns all the mdids in a share. """
        # create the shares
        share1 = yield self.create_share('share_id1', u'share_name1',
                                         access_level=ACCESS_LEVEL_RO)
        share2 = yield self.create_share('share_id2', u'share_name2',
                                         access_level=ACCESS_LEVEL_RO)
        self.fsm.create(share1.path, "share_id1", is_dir=True)
        self.fsm.set_node_id(share1.path, "uuid1")
        self.fsm.create(share2.path, "share_id2", is_dir=True)
        self.fsm.set_node_id(share2.path, "uuid2")

        # create some nodes in share 1
        path3 = os.path.join(share1.path, "a")
        mdid3 = self.fsm.create(path3, "share_id1", is_dir=True)
        self.fsm.set_node_id(path3, "uuid3")
        path4 = os.path.join(share1.path, "a", "b")
        mdid4 = self.fsm.create(path4, "share_id1")
        self.fsm.set_node_id(path4, "uuid4")
        path5 = os.path.join(share1.path, "c")
        mdid5 = self.fsm.create(path5, "share_id1")
        self.fsm.set_node_id(path5, "uuid5")
        path9 = os.path.join(share1.path, "aaa")
        mdid9 = self.fsm.create(path9, "share_id1")
        self.fsm.set_node_id(path9, "uuid9")

        # create some nodes in share 2
        path6 = os.path.join(share2.path, "a")
        mdid6 = self.fsm.create(path6, "share_id2", is_dir=True)
        self.fsm.set_node_id(path6, "uuid6")
        path7 = os.path.join(share2.path, "c")
        mdid7 = self.fsm.create(path7, "share_id2")
        self.fsm.set_node_id(path7, "uuid7")

        # tricky: node without node_id yet
        path8 = os.path.join(share2.path, "d")
        mdid8 = self.fsm.create(path8, "share_id2")

        # get them
        all_data = set()
        for mdobj in self.fsm.get_mdobjs_by_share_id("share_id1"):
            all_data.add(mdobj.mdid)
        self.assertTrue(mdid3 in all_data)
        self.assertTrue(mdid4 in all_data)
        self.assertTrue(mdid5 in all_data)
        self.assertTrue(mdid9 in all_data)
        self.assertTrue(mdid6 not in all_data)
        self.assertTrue(mdid7 not in all_data)
        self.assertTrue(mdid8 not in all_data)

        all_data = set()
        for mdobj in self.fsm.get_mdobjs_by_share_id("share_id2"):
            all_data.add(mdobj.mdid)
        self.assertTrue(mdid3 not in all_data)
        self.assertTrue(mdid4 not in all_data)
        self.assertTrue(mdid5 not in all_data)
        self.assertTrue(mdid9 not in all_data)
        self.assertTrue(mdid6 in all_data)
        self.assertTrue(mdid7 in all_data)
        self.assertTrue(mdid8 in all_data)

        all_data = set()
        patha = os.path.join(share1.path, 'a')
        for mdobj in self.fsm.get_mdobjs_by_share_id("share_id1", patha):
            all_data.add(mdobj.mdid)
        self.assertTrue(mdid3 in all_data)
        self.assertTrue(mdid4 in all_data)
        self.assertTrue(mdid5 not in all_data)
        self.assertTrue(mdid6 not in all_data)
        self.assertTrue(mdid7 not in all_data)
        self.assertTrue(mdid8 not in all_data)
        self.assertTrue(mdid9 not in all_data)

    @defer.inlineCallbacks
    def test_get_all_by_share_mixed(self):
        """Test that it returns all the mdids in a share with mixed nodes."""
        # create the shares
        share = yield self.create_share('share_id', u'sharetest',
                                        access_level=ACCESS_LEVEL_RO)
        self.fsm.create(share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(share.path, "uuid")

        # create one real node...
        path1 = os.path.join(share.path, "a")
        mdid1 = self.fsm.create(path1, "share_id", is_dir=True)
        self.fsm.set_node_id(path1, "uuid1")

        # ...and two without node_id's
        path2 = os.path.join(share.path, "b")
        mdid2 = self.fsm.create(path2, "share_id")
        path3 = os.path.join(share.path, "c")
        mdid3 = self.fsm.create(path3, "share_id")

        # get them
        all_data = set()
        for mdobj in self.fsm.get_mdobjs_by_share_id("share_id"):
            all_data.add(mdobj.mdid)
        self.assertTrue(mdid1 in all_data)
        self.assertTrue(mdid2 in all_data)
        self.assertTrue(mdid3 in all_data)

    def test_internal_set_node_id(self):
        """Test _set_node_id"""
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        mdobj = self.fsm.fs[mdid]
        # yes, it's a unit test, I access protected members.
        self.fsm._set_node_id(mdobj, "uuid", path)

        self.assertEqual('uuid', mdobj['node_id'])
        self.fsm.set_node_id(path, "uuid")
        new_mdobj = self.fsm.get_by_node_id('share', 'uuid')
        for k, v in mdobj.items():
            if k == 'info':
                for k1, v1 in v.items():
                    self.assertEqual(int(v1), int(getattr(new_mdobj.info, k1)))
            else:
                self.assertEqual(v, getattr(new_mdobj, k))

        # test using bad uuid
        mdobj = self.fsm.fs[mdid]
        self.assertEqual('uuid', mdobj['node_id'])
        self.assertRaises(ValueError,
                          self.fsm._set_node_id, mdobj, 'bad-uuid', path)


class GetMDObjectsInDirTests(FSMTestCase):
    """Test the get_mdobjs_in_dir method."""

    def create_some_contents(self, share):
        a = 'a'
        ab = os.path.join(a, 'b')
        ab1 = os.path.join(a, 'b1')
        ab2 = os.path.join(a, 'b2')
        ac = os.path.join(a, 'c')
        acd = os.path.join(ac, 'd')

        dirs = [a, ab, ab1, ab2, ac, acd]
        for d in dirs:
            self.create_node(d, is_dir=True, share=share)

        x = os.path.join(a, 'x.txt')
        y = os.path.join(ab, 'y.txt')
        z = os.path.join(ac, 'z.txt')

        files = [x, y, z]
        for f in files:
            self.create_node(f, is_dir=False, share=share)

        self.contents[share] = sorted(dirs + files)

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(GetMDObjectsInDirTests, self).setUp()
        self.contents = {}
        self.create_some_contents(self.share)

    def test_basic(self):
        """Test basic retrieval."""
        expected = ['a']
        actual = sorted([d.path for d in
                         self.fsm.get_mdobjs_in_dir(self.share.path)])
        self.assertEqual(expected, actual)

    def test_no_tree(self):
        """Test just receiving the dir and not the tree."""
        expected = [os.path.join('a', 'b'),
                    os.path.join('a', 'b1'),
                    os.path.join('a', 'b2'),
                    os.path.join('a', 'c'),
                    os.path.join('a', 'x.txt')]
        actual = sorted(
            d.path for d in
            self.fsm.get_mdobjs_in_dir(os.path.join(self.share.path, 'a'))
        )
        self.assertEqual(expected, actual)

    def test_similar_paths(self):
        """Test having similar paths (a/b, a/b1, a/b2)."""
        expected = [os.path.join('a', 'b', 'y.txt')]
        actual = sorted([d.path for d in self.fsm.get_mdobjs_in_dir(
                                    os.path.join(self.share.path, 'a', 'b'))])
        self.assertEqual(expected, actual)

    @defer.inlineCallbacks
    def test_with_two_shares(self):
        """Test having 2 shares."""
        second_share = yield self.create_share('second_share', u'the_second')
        self.create_some_contents(second_share)

        expected = ['a']
        actual = sorted([d.path for d in
                         self.fsm.get_mdobjs_in_dir(second_share.path)])
        self.assertEqual(expected, actual)

    @defer.inlineCallbacks
    def test_both_shares(self):
        """Test having 2 shares and asking for mdobjs in shares_dir."""
        second_share = yield self.create_share('second_share', u'the_second')
        self.create_some_contents(second_share)

        expected = []
        actual = sorted([d.path for d in
                         self.fsm.get_mdobjs_in_dir(self.shares_dir)])
        self.assertEqual(expected, actual)


class StatTests(FSMTestCase):
    """Test all the behaviour regarding the stats."""

    def test_create_nofile(self):
        """Test creation when there's no file."""
        mdobj = self.create_node("foo")
        self.assertEqual(mdobj.stat, None)

    def test_create_file(self):
        """Test creation when there's a file."""
        # file
        path = os.path.join(self.share.path, "thisfile")
        open_file(path, "w").close()
        mdobj = self.create_node("thisfile")
        self.assertEqual(mdobj.stat, stat_path(path))

        # dir
        path = os.path.join(self.share.path, "thisdir")
        make_dir(path)
        mdobj = self.create_node("thisdir")
        self.assertEqual(mdobj.stat, stat_path(path))

    def test_commit_partial(self):
        """Test that it's updated in the commit."""
        path = os.path.join(self.share.path, "thisfile")
        open_file(path, "w").close()
        mdobj = self.create_node("thisfile")
        mdid = mdobj.mdid
        oldstat = stat_path(path)
        self.assertEqual(mdobj.stat, oldstat)

        # create a partial
        self.fsm.create_partial(mdobj.node_id, mdobj.share_id)
        fh = self.fsm.get_partial_for_writing(mdobj.node_id, mdobj.share_id)
        fh.write("foobar")
        fh.close()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.stat, oldstat)

        # commit the partial
        self.fsm.commit_partial(mdobj.node_id, mdobj.share_id, "localhash")
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.stat, stat_path(path))

    def test_commit_partial_pushes_event(self):
        """Test that the right event is pushed after the commit."""
        listener = Listener()
        self.eq.subscribe(listener)

        path = os.path.join(self.share.path, "thisfile")
        open_file(path, "w").close()
        mdobj = self.create_node("thisfile")
        mdid = mdobj.mdid
        oldstat = stat_path(path)
        self.assertEqual(mdobj.stat, oldstat)

        # create a partial
        self.fsm.create_partial(mdobj.node_id, mdobj.share_id)
        fh = self.fsm.get_partial_for_writing(mdobj.node_id, mdobj.share_id)
        fh.write("foobar")
        fh.close()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.stat, oldstat)

        # commit the partial
        self.fsm.commit_partial(mdobj.node_id, mdobj.share_id, "localhash")
        mdobj = self.fsm.get_by_mdid(mdid)

        kwargs = dict(share_id=mdobj.share_id, node_id=mdobj.node_id)
        self.assertTrue(("FSM_PARTIAL_COMMITED", kwargs) in listener.events)

    def test_move(self):
        """Test that move refreshes stat."""
        path1 = os.path.join(self.share.path, "thisfile1")
        path2 = os.path.join(self.share.path, "thisfile2")
        open_file(path1, "w").close()
        mdobj = self.create_node(path1)
        self.assertEqual(mdobj.stat, stat_path(path1))

        # move
        self.fsm.move_file("share", path1, path2)

        # check
        mdobj = self.fsm.get_by_path(path2)
        self.assertEqual(mdobj.stat, stat_path(path2))

    def test_move_overwriting(self):
        """Test that move refreshes stat when overwrites other file."""
        self.fsm.create(self.share_path, self.share.id, is_dir=True)
        path1 = os.path.join(self.share.path, "thisfile1")
        path2 = os.path.join(self.share.path, "thisfile2")
        open_file(path1, "w").close()
        open_file(path2, "w").close()
        mdobj1 = self.create_node(path1)
        mdobj2 = self.create_node(path2)
        self.assertEqual(mdobj1.stat, stat_path(path1))
        self.assertEqual(mdobj2.stat, stat_path(path2))

        # move
        self.fsm.move_file("share", path1, path2)

        # check
        self.assertRaises(KeyError, self.fsm.get_by_path, path1)
        mdobj2 = self.fsm.get_by_path(path2)
        self.assertEqual(mdobj2.stat, stat_path(path2))

    def test_set_stat_by_mdid(self):
        """Test that update_stat works."""
        path = os.path.join(self.share.path, "thisfile")
        open_file(path, "w").close()
        mdobj = self.create_node("thisfile")
        mdid = mdobj.mdid
        oldstat = stat_path(path)
        self.assertEqual(mdobj.stat, oldstat)

        # touch the file, it's not automagically updated
        open_file(path, "w").close()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.stat, oldstat)

        # it's updated when asked, even if it's an old stat
        self.fsm.set_by_mdid(mdid, stat=oldstat)
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.stat, oldstat)


class PartialTests(FSMTestCase):
    """Test all the .partial nitty gritty."""

    def test_create_file(self):
        """Test create .partial for a file."""
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(testfile))
        self.fsm.set_node_id(testfile, "uuid")

        # create partial ok
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)
        self.assertTrue(path_exists(partial_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        when = mdobj.info.last_partial_created
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid uuid
        self.assertRaises(KeyError, self.fsm.create_partial, "foo", "share")
        self.assertRaises(ValueError, self.fsm.create_partial, None, "share")

        # already has a partial!
        self.assertRaises(ValueError, self.fsm.create_partial, "uuid", "share")

    def test_commit_file(self):
        """Test commit the .partial for a file, after a successful download."""
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(testfile))
        self.fsm.set_node_id(testfile, "uuid")

        # create partial
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)
        with open_file(partial_path, "w") as fh:
            fh.write("test info!")

        # commit partial, and check that the file is moved, and metadata is ok
        self.fsm.commit_partial("uuid", "share", local_hash=9876)
        self.assertFalse(path_exists(partial_path))

        with open_file(testfile) as fh:
            in_file = fh.read()

        self.assertEqual(in_file, "test info!")
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertFalse(mdobj.info.is_partial)
        self.assertEqual(mdobj.local_hash, 9876)
        when = mdobj.info.last_downloaded
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid uuid
        self.assertRaises(
            KeyError, self.fsm.commit_partial, "foo", "share", 123)
        self.assertRaises(
            ValueError, self.fsm.commit_partial, None, "share", 123)
        # it has no partial!
        self.assertRaises(
            ValueError, self.fsm.commit_partial, "uuid", "share", 1)

    def test_remove_file(self):
        """Test removing the .partial for a file, because a bad download."""
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(testfile))
        self.fsm.set_node_id(testfile, "uuid")

        # create partial
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)
        with open_file(partial_path, "w") as fh:
            fh.write("test info!")
        with open_file(testfile, "w") as fh:
            fh.write("previous stuff!")

        # remove partial, and check that the file is gone, and metadata is ok
        self.fsm.remove_partial("uuid", "share")
        self.assertFalse(path_exists(partial_path))

        with open_file(testfile) as fh:
            in_file = fh.read()

        self.assertEqual(in_file, "previous stuff!")
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertFalse(mdobj.info.is_partial)
        when = mdobj.info.last_partial_removed
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid uuid
        self.assertRaises(KeyError, self.fsm.remove_partial, "foo", "share")
        self.assertRaises(ValueError, self.fsm.remove_partial, None, "share")

        # it has no partial!
        self.fsm.remove_partial("uuid", "share")

    def test_create_dir_previous(self):
        """Test create .partial for a dir when the dir existed."""
        testdir = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid")
        make_dir(testdir)

        # create partial ok
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)
        partial_path = os.path.join(
            self.fsm.partials_dir, mdid + ".u1partial." +
            os.path.basename(testdir))
        self.assertTrue(path_exists(partial_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        when = mdobj.info.last_partial_created
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid uuid
        self.assertRaises(KeyError, self.fsm.create_partial, "foo", "share")

        # already has a partial!
        self.assertRaises(ValueError, self.fsm.create_partial, "uuid", "share")

    def test_create_dir_notprevious(self):
        """Test create .partial for a dir when the dir didn't exist."""
        testdir = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid")

        # create partial ok
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)
        self.assertTrue(path_exists(testdir))
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(testdir))
        self.assertTrue(path_exists(partial_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        when = mdobj.info.last_partial_created
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid uuid
        self.assertRaises(KeyError, self.fsm.create_partial, "foo", "share")

        # already has a partial!
        self.assertRaises(ValueError, self.fsm.create_partial, "uuid", "share")

    def test_commit_dir(self):
        """Test commit the .partial for a dir, after a successful download."""
        testdir = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid")

        # create partial
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)

        # commit is forbidden for directories
        self.assertRaises(
            ValueError, self.fsm.commit_partial, "uuid", "share",
            local_hash=9876)

    def test_remove_dir(self):
        """Test removing the .partial for a dir, because a bad download."""
        testdir = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid")

        # create partial
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)

        # remove partial, and check that the file is gone, and metadata is ok
        self.fsm.remove_partial("uuid", "share")
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(testdir))
        self.assertFalse(path_exists(partial_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertFalse(mdobj.info.is_partial)
        when = mdobj.info.last_partial_removed
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid uuid
        self.assertRaises(KeyError, self.fsm.remove_partial, "foo", "share")

        # it has no partial!
        self.fsm.remove_partial("uuid", "share")

    @defer.inlineCallbacks
    def test_ro_share(self):
        """Test creating a partial of a RO share.

        It should leave the partials dir permissions intact.
        """
        share = yield self.create_share('ro_share', u'ro_share_name',
                                        access_level=ACCESS_LEVEL_RO)
        testdir = os.path.join(share.path, "path")
        mdid = self.fsm.create(testdir, share.volume_id, is_dir=False)
        self.fsm.set_node_id(testdir, "uuid")
        # create partial
        self.fsm.create_partial("uuid", share.volume_id)
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)
        # commit the partial
        self.fsm.commit_partial('uuid', share.volume_id, '')
        # create a new partial, this time for a rw share
        testdir = os.path.join(self.share.path, "path")
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid1")
        self.fsm.create_partial("uuid1", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)

    def test_disk_problem(self):
        """On any disk problem, the node should be left in partial state."""
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")

        # ugly problem not handled
        remove_dir(self.partials_dir)
        try:
            self.fsm.create_partial("uuid", "share")
        except IOError, e:
            if e.errno == errno.ENOENT:
                # expected
                pass
        else:
            raise

        # the node should still be in partial internally
        # for LR to handle it ok
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertTrue(mdobj.info.is_partial)

    def test_filename_too_long(self):
        """Handle the filename being too long."""
        # find a almost too long file
        repeat = 300
        while True:
            testfile = os.path.join(self.share_path, "x"*repeat)
            try:
                fh = open_file(testfile, 'w')
            except IOError, e:
                # linux will give you "too long", windows will say "invalid"
                if e.errno in (errno.ENAMETOOLONG, errno.EINVAL):
                    repeat -= 10
            else:
                fh.close()
                remove_file(testfile)
                break
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")

        # create partial ok, even knowing that "full partial path" won't fit
        self.fsm.create_partial("uuid", "share")
        self.assertTrue(self.fsm.get_by_mdid(mdid).info.is_partial)

        # check the path
        partial_path = self.fsm._get_partial_path(self.fsm.fs[mdid])
        self.assertTrue(path_exists(partial_path))

    def test_get_partial_path_notrim(self):
        """Create the partial path."""
        testfile = os.path.join(self.share_path, "foo")
        mdid = self.fsm.create(testfile, "share")
        partial_path = self.fsm._get_partial_path(self.fsm.fs[mdid])
        partial_name = os.path.basename(partial_path)
        self.assertEqual(partial_name, mdid + ".u1partial.foo")

    def test_get_partial_path_trim1(self):
        """Create the partial path trimmed some chars."""
        longname = "longnamethatistoolong"
        testfile = os.path.join(self.share_path, longname)
        mdid = self.fsm.create(testfile, "share")
        partial_path = self.fsm._get_partial_path(self.fsm.fs[mdid], trim=1)
        partial_name = os.path.basename(partial_path)
        self.assertEqual(partial_name, mdid + ".u1partial." + longname[:-10])

    def test_get_partial_path_trim2(self):
        """Create the partial path trimmed more chars."""
        longname = "longnamethatistoolong"
        testfile = os.path.join(self.share_path, longname)
        mdid = self.fsm.create(testfile, "share")
        partial_path = self.fsm._get_partial_path(self.fsm.fs[mdid], trim=2)
        partial_name = os.path.basename(partial_path)
        self.assertEqual(partial_name, mdid + ".u1partial." + longname[:-20])

    def test_get_partial_path_dontcache_when_notrim(self):
        """Normal behaviour, no partial path cached."""
        testfile = os.path.join(self.share_path, "longnamethatistoolong")
        mdid = self.fsm.create(testfile, "share")
        self.fsm._get_partial_path(self.fsm.fs[mdid])

        # check
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertFalse(hasattr(mdobj.info, 'partial_path'))

    def test_get_partial_path_caches_when_trim(self):
        """If trimming is necessary, it will cache the name."""
        testfile = os.path.join(self.share_path, "longnamethatistoolong")
        mdid = self.fsm.create(testfile, "share")
        mdobj = self.fsm.fs[mdid]
        partial_path = self.fsm._get_partial_path(mdobj, trim=1)

        # check
        self.assertEqual(mdobj['info']['partial_path'], partial_path)

    def test_get_partial_path_cached_normal(self):
        """Return the cached partial path if there."""
        testfile = os.path.join(self.share_path, "foo")
        mdid = self.fsm.create(testfile, "share")

        # fake the cache
        mdobj = self.fsm.fs[mdid]
        mdobj['info']['partial_path'] = "bar"

        # check
        partial_path = self.fsm._get_partial_path(mdobj)
        partial_name = os.path.basename(partial_path)
        self.assertEqual(partial_name, "bar")

    def test_get_partial_path_cached_trimming(self):
        """Do not return the cached partial path if there when trimming."""
        testfile = os.path.join(self.share_path, "foobarlongone")
        mdid = self.fsm.create(testfile, "share")

        # fake the cache
        mdobj = self.fsm.fs[mdid]
        mdobj['info']['partial_path'] = "bar"

        # check
        partial_path = self.fsm._get_partial_path(mdobj, trim=1)
        partial_name = os.path.basename(partial_path)
        self.assertEqual(partial_name, mdid + ".u1partial.foo")


class FileHandlingTests(FSMTestCase):
    """Test the file handling services."""

    def assert_no_metadata(self, mdid, path, share_id, node_id):
        """The node has no metadata registered."""
        self.assertRaises(KeyError, self.fsm.get_by_mdid, mdid)
        self.assertRaises(KeyError, self.fsm.get_by_path, path)
        self.assertRaises(KeyError, self.fsm.get_by_node_id, share_id, node_id)

    def test_move_to_conflict(self):
        """Test that the conflict stuff works."""
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")
        with open_file(testfile, "w") as fh:
            fh.write("test!")

        # move first time
        self.fsm.move_to_conflict(mdid)
        self.assertFalse(path_exists(testfile))
        with open_file(testfile + self.fsm.CONFLICT_SUFFIX) as fh:
            in_file = fh.read()
        self.assertEqual(in_file, "test!")
        mdobj = self.fsm.get_by_mdid(mdid)
        when = mdobj.info.last_conflicted
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # move second time, start the .N serie
        with open_file(testfile, "w") as fh:
            fh.write("test 1!")
        self.fsm.move_to_conflict(mdid)
        self.assertFalse(path_exists(testfile))
        with open_file(testfile + ".u1conflict.1") as fh:
            in_file = fh.read()
        self.assertEqual(in_file, "test 1!")

        # create a few more, test a higher one
        open_file(testfile + ".u1conflict.2", "w").close()
        open_file(testfile + ".u1conflict.3", "w").close()
        open_file(testfile + ".u1conflict.4", "w").close()
        open_file(testfile + ".u1conflict.5", "w").close()
        with open_file(testfile, "w") as fh:
            fh.write("test 6!")
        self.fsm.move_to_conflict(mdid)
        self.assertFalse(path_exists(testfile))
        with open_file(testfile + ".u1conflict.6") as fh:
            in_file = fh.read()
        self.assertEqual(in_file, "test 6!")

        # invalid uuid
        self.assertRaises(KeyError, self.fsm.move_to_conflict, "no-such-mdid")

    def test_conflict_file_pushes_event(self):
        """A conflict with a file pushes FSM_FILE_CONFLICT."""
        listener = Listener()
        self.eq.subscribe(listener)

        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")
        with open_file(testfile, "w") as fh:
            fh.write("test!")

        self.fsm.move_to_conflict(mdid)

        new_name = testfile + self.fsm.CONFLICT_SUFFIX
        kwargs = dict(old_name=testfile, new_name=new_name)

        self.assertTrue(("FSM_FILE_CONFLICT", kwargs) in listener.events)

    def test_conflict_dir_pushes_event(self):
        """A conflict with a dir pushes FSM_DIR_CONFLICT."""
        listener = Listener()
        self.eq.subscribe(listener)

        testdir = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid")
        make_dir(testdir)

        self.fsm.move_to_conflict(mdid)

        new_name = testdir + self.fsm.CONFLICT_SUFFIX
        kwargs = dict(old_name=testdir, new_name=new_name)

        self.assertTrue(("FSM_DIR_CONFLICT", kwargs) in listener.events)

    def test_upload_finished(self):
        """Test upload finished."""
        path = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")

        # finish the upload!
        self.fsm.upload_finished(mdid, server_hash=1234567890)
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.server_hash, 1234567890)
        when = mdobj.info.last_uploaded
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # invalid mdid
        self.assertRaises(KeyError, self.fsm.upload_finished,
                          "no-such-mdid", 123)

        # bad arguments
        self.assertRaises(TypeError, self.fsm.upload_finished, mdid)

    def test_move_file_withfile(self):
        """Test that a file is moved from one point to the other."""
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")
        with open_file(testfile, "w") as fh:
            fh.write("test!")

        # move the file
        to_path = os.path.join(self.share_path, "path2")
        self.fsm.move_file("share", testfile, to_path)
        self.assertFalse(path_exists(testfile))
        with open_file(to_path) as fh:
            in_file = fh.read()
        self.assertEqual(in_file, "test!")
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.info.last_moved_from, testfile)
        when = mdobj.info.last_moved_time
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # move again, to a directory
        from_path = to_path
        make_dir(os.path.join(self.share_path, "testdir"))
        to_path = os.path.join(self.share_path, "testdir", "path3")
        self.fsm.move_file("share", from_path, to_path)
        self.assertFalse(path_exists(from_path))
        with open_file(to_path) as fh:
            in_file = fh.read()
        self.assertEqual(in_file, "test!")

        # invalid path
        self.assertRaises(
            KeyError, self.fsm.move_file, "share", "no-path", "dest")

        # other share
        self.assertRaises(
            KeyError, self.fsm.move_file, "othershare", testfile, to_path)

        # invalid args
        self.assertRaises(TypeError, self.fsm.move_file, "one-path")

    def test_move_file_overwrite(self):
        """Test that a file is moved over other one."""
        self.fsm.create(self.share_path, self.share.id,
                        self.share.node_id, is_dir=True)
        testfile1 = os.path.join(self.share_path, "path1")
        mdid1 = self.fsm.create(testfile1, "share")
        self.fsm.set_node_id(testfile1, "uuid1")
        with open_file(testfile1, "w") as fh:
            fh.write("test 1")

        testfile2 = os.path.join(self.share_path, "path2")
        mdid2 = self.fsm.create(testfile2, "share")
        self.fsm.set_node_id(testfile2, "uuid2")
        with open_file(testfile2, "w") as fh:
            fh.write("test 2")

        # move the file
        self.fsm.move_file("share", testfile1, testfile2)
        self.assertFalse(path_exists(testfile1))
        with open_file(testfile2) as fh:
            in_file = fh.read()
        self.assertEqual(in_file, "test 1")
        mdobj = self.fsm.get_by_mdid(mdid1)
        self.assertEqual(mdobj.path, "path2")
        mdobj = self.fsm.get_by_path(testfile2)
        self.assertEqual(mdobj.mdid, mdid1)

        # check that the info for the overwritten one is gone to trash
        self.assert_no_metadata(mdid2, testfile1, "share", "uuid2")
        self.assertEqual(self.fsm.trash[(self.share.id, "uuid2")],
                         (mdid2, self.share.node_id, testfile2, False))

    def test_move_file_withdir(self):
        """Test that a dir is moved from one point to the other."""
        from_path = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(from_path, "share", is_dir=True)
        self.fsm.set_node_id(from_path, "uuid")

        # move the file
        make_dir(from_path)
        to_path = os.path.join(self.share_path, "path2")
        self.fsm.move_file("share", from_path, to_path)
        self.assertFalse(path_exists(from_path))
        self.assertTrue(path_exists(to_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.info.last_moved_from, from_path)
        when = mdobj.info.last_moved_time
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # move again, to a directory
        from_path = to_path
        make_dir(os.path.join(self.share_path, "testdir"))
        to_path = os.path.join(self.share_path, "testdir", "path3")
        self.fsm.move_file("share", from_path, to_path)
        self.assertFalse(path_exists(from_path))
        self.assertTrue(path_exists(to_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.info.last_moved_from, from_path)
        when = mdobj.info.last_moved_time
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

    def test_move_file_withfulldir(self):
        """Test that a dir is moved from even having a file inside."""
        # the containing dir
        from_path = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(from_path, "share", is_dir=True)
        self.fsm.set_node_id(from_path, "uuid")
        make_dir(from_path)

        # the file outside, with a similar name just to confuse
        otherfile = os.path.join(self.share_path, "pa")
        self.fsm.create(otherfile, "share", is_dir=False)
        self.fsm.set_node_id(otherfile, "otheruuid")
        open_file(otherfile, "w").close()

        # the file inside
        filepath = os.path.join(from_path, "file.txt")
        fileid = self.fsm.create(filepath, "share", is_dir=False)
        self.fsm.set_node_id(filepath, "fileuuid")
        open_file(filepath, "w").close()

        # move the dir
        to_path = os.path.join(self.share_path, "path2")
        self.fsm.move_file("share", from_path, to_path)
        self.assertFalse(path_exists(from_path))
        self.assertTrue(path_exists(to_path))
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.info.last_moved_from, from_path)
        when = mdobj.info.last_moved_time
        now = time.time()
        self.assertTrue(now-3 <= when <= now)  # 3 seconds test range

        # check that file inside is ok
        newfilepath = os.path.join(to_path, "file.txt")
        self.assertFalse(path_exists(filepath))
        self.assertTrue(path_exists(newfilepath))
        mdobj = self.fsm.get_by_path(newfilepath)
        self.assertEqual(mdobj.mdid, fileid)
        self.assertEqual(mdobj.path, os.path.join('path2', 'file.txt'))

        # check the outer file
        self.assertTrue(path_exists(otherfile))
        mdobj = self.fsm.get_by_path(otherfile)
        self.assertEqual(mdobj.path, "pa")

    def _delete_file(self):
        """Helper to test that a file is deleted."""
        testfile = os.path.join(self.share_path, "path")
        open_file(testfile, "w").close()
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")

        # delete the file
        self.fsm.delete_file(testfile)
        self.assertFalse(path_exists(testfile))
        self.assert_no_metadata(mdid, testfile, "share", "uuid")

    def test_delete_file_directly(self):
        """Really delete the file."""
        config.get_user_config().set_use_trash(False)

        # check it was sent to trash, not just deleted
        called = []
        orig_call = filesystem_manager.remove_file
        self.patch(filesystem_manager, 'remove_file',
                   lambda path: called.append(True) or orig_call(path))

        self._delete_file()
        self.assertTrue(called)

    def test_delete_file_trash(self):
        """Move the file to trash."""
        config.get_user_config().set_use_trash(True)

        # check it was sent to trash, not just deleted
        called = []
        orig_call = filesystem_manager.move_to_trash
        self.patch(filesystem_manager, 'move_to_trash',
                   lambda path: called.append(True) or orig_call(path))

        self._delete_file()
        self.assertTrue(called)

    def _delete_dir(self):
        """Helper to test that an empty dir is deleted."""
        testdir = os.path.join(self.share.path, "path")
        make_dir(testdir)
        mdid = self.fsm.create(testdir, "share", is_dir=True)
        self.fsm.set_node_id(testdir, "uuid")

        # try to delete the dir, but has files on it
        open_file(os.path.join(testdir, "foo"), "w").close()
        self.assertEqual(self.fsm.get_by_mdid(mdid).path, "path")
        self.assertEqual(self.fsm.get_by_path(testdir).path, "path")
        self.assertEqual(self.fsm.get_by_node_id("share", "uuid").path, "path")
        remove_file(os.path.join(testdir, "foo"))

        # really delete the dir
        self.fsm.delete_file(testdir)

        self.assertFalse(path_exists(testdir))
        self.assert_no_metadata(mdid, testdir, "share", "uuid")

    def test_delete_dir_directly(self):
        """Really delete the dir."""
        config.get_user_config().set_use_trash(False)

        # check it was sent to trash, not just deleted
        called = []
        orig_call = filesystem_manager.remove_dir
        self.patch(filesystem_manager, 'remove_dir',
                   lambda path: called.append(True) or orig_call(path))

        self._delete_dir()
        self.assertTrue(called)

    def test_delete_dir_trash(self):
        """Move the dir to trash."""
        config.get_user_config().set_use_trash(True)

        # check it was sent to trash, not just deleted
        called = []
        orig_call = filesystem_manager.move_to_trash
        self.patch(filesystem_manager, 'move_to_trash',
                   lambda path: called.append(True) or orig_call(path))

        self._delete_dir()
        self.assertTrue(called)

    def _delete_dir_when_non_empty_and_no_modifications(self):
        """Helper to test that a dir is deleted, non empty but ok to clean."""
        local_dir = os.path.join(self.root_dir, "foo")
        make_dir(local_dir)
        mdid = self.fsm.create(local_dir, "", is_dir=True)
        self.fsm.set_node_id(local_dir, "uuid")

        local_file = os.path.join(local_dir, "bar.txt")
        open_file(local_file, 'w').close()  # touch bar.txt so it exists
        mdid_file = self.fsm.create(local_file, "")
        self.fsm.set_node_id(local_file, "uuid_file")

        assert len(listdir(local_dir)) > 0  # local_dir is not empty
        assert not self.fsm.local_changed(path=local_dir)

        self.fsm.delete_file(local_dir)

        self.assertFalse(path_exists(local_file))
        self.assert_no_metadata(mdid_file, local_file, "", "uuid_file")

        self.assertFalse(path_exists(local_dir))
        self.assert_no_metadata(mdid, local_dir, "", "uuid")

    def test_delete_nonempty_cleanable_dir_directly(self):
        """Really delete the non empty but cleanable dir."""
        config.get_user_config().set_use_trash(False)

        # check it was sent to trash, not just deleted
        called = []
        orig_call = filesystem_manager.remove_tree
        self.patch(filesystem_manager, 'remove_tree',
                   lambda path: called.append(True) or orig_call(path))

        self._delete_dir_when_non_empty_and_no_modifications()
        self.assertTrue(called)

    def test_delete_nonempty_cleanable_dir_trash(self):
        """Move the non empty but cleanable dir to trash."""
        config.get_user_config().set_use_trash(True)

        # check it was sent to trash, not just deleted
        called = []
        orig_call = filesystem_manager.move_to_trash
        self.patch(filesystem_manager, 'move_to_trash',
                   lambda path: called.append(True) or orig_call(path))

        self._delete_dir_when_non_empty_and_no_modifications()
        self.assertTrue(called)

    def test_delete_dir_when_non_empty_and_modifications_prior_delete(self):
        """Test that a dir is deleted, when is not empty and modified."""
        local_dir = os.path.join(self.root_dir, "foo")
        make_dir(local_dir)
        self.fsm.create(local_dir, "", is_dir=True)
        self.fsm.set_node_id(local_dir, "uuid")

        local_file = os.path.join(local_dir, "bar.txt")
        open_file(local_file, 'w').close()  # touch bar.txt so it exists
        mdid_file = self.fsm.create(local_file, "")
        self.fsm.set_node_id(local_file, "uuid_file")
        self.fsm.set_by_mdid(mdid_file, local_hash=98765)

        assert len(listdir(local_dir)) > 0  # local_dir is not empty
        assert self.fsm.changed(path=local_file) == self.fsm.CHANGED_LOCAL
        self.assertRaises(DirectoryNotRemovable,
                          self.fsm.delete_file, local_dir)

    def test_delete_dir_when_non_empty_and_prior_conflict_on_file(self):
        """Test that a dir is not deleted, when there is a conflicted file."""
        # local directory
        local_dir = os.path.join(self.root_dir, "foo")
        make_dir(local_dir)
        self.fsm.create(local_dir, "", is_dir=True)
        self.fsm.set_node_id(local_dir, "uuid")

        local_file = os.path.join(local_dir,
                                  "bar.txt" + self.fsm.CONFLICT_SUFFIX)
        open_file(local_file, 'w').close()  # touch bar.txt.u1conflict

        assert local_file not in self.fsm._idx_path
        self.assertRaises(DirectoryNotRemovable,
                          self.fsm.delete_file, local_dir)

        infos = [record.message for record in self.handler.records
                 if record.levelname == 'INFO']
        self.assertTrue(len(infos) == 1)
        self.assertTrue(repr(local_file) in infos[0])

    def test_delete_dir_when_non_empty_and_prior_conflict_on_subdir(self):
        """Test that a dir is not deleted, when there is a conflicted dir."""
        # local directory
        local_dir = os.path.join(self.root_dir, "foo")
        make_dir(local_dir)
        self.fsm.create(local_dir, "", is_dir=True)
        self.fsm.set_node_id(local_dir, "uuid")

        local_subdir = os.path.join(local_dir,
                                    "subdir_bar" + self.fsm.CONFLICT_SUFFIX)
        make_dir(local_subdir)

        assert local_subdir not in self.fsm._idx_path
        self.assertRaises(DirectoryNotRemovable,
                          self.fsm.delete_file, local_dir)

        infos = [record.message for record in self.handler.records
                 if record.levelname == 'INFO']
        self.assertTrue(len(infos) == 1)
        self.assertTrue(repr(local_subdir) in infos[0])

    def test_no_warning_on_log_file_when_recursive_delete(self):
        """Test that sucessfully deleted dir does not log OSError."""
        local_dir = os.path.join(self.root_dir, "foo")
        make_dir(local_dir)
        self.fsm.create(local_dir, "", is_dir=True)
        self.fsm.set_node_id(local_dir, "uuid")

        local_file = os.path.join(local_dir, "bar.txt")
        open_file(local_file, 'w').close()  # touch bar.txt so it exists
        self.fsm.create(local_file, "")
        self.fsm.set_node_id(local_file, "uuid_file")

        previous = self.handler.records
        self.fsm.delete_file(local_dir)

        # no logs were added
        self.assertEqual(previous, self.handler.records)

    def test_warning_on_log_file_when_failing_delete(self):
        """Test that sucessfully deleted dir does not log OSError."""

        local_dir = os.path.join(self.root_dir, "foo")
        self.fsm.create(local_dir, "", is_dir=True)
        self.fsm.set_node_id(local_dir, "uuid")

        # local_dir does not exist on the file system
        self.fsm.delete_file(local_dir)

        warnings = [record.message for record in self.handler.records
                    if record.levelname == 'WARNING']
        self.assertTrue(len(warnings) == 1)
        # On linux, we get a [Errno 2], but in windows, [Error 3]
        self.assertTrue('OSError' in warnings[0])
        self.assertTrue(repr(local_dir) in warnings[0])

    def test_move_dir_to_conflict(self):
        """Test that the conflict to a dir removes children metadata."""
        tdir = os.path.join(self.share_path, "adir")
        mdid1 = self.fsm.create(tdir, "share", is_dir=True)
        self.fsm.set_node_id(tdir, "uuid1")
        make_dir(tdir)

        testfile = os.path.join(tdir, "path")
        mdid2 = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid2")
        with open_file(testfile, "w") as fh:
            fh.write("test!")

        # move the dir to conflict, the file is still there, but with no MD
        self.fsm.move_to_conflict(mdid1)
        self.assertFalse(path_exists(tdir))
        self.assertTrue(path_exists(tdir + self.fsm.CONFLICT_SUFFIX))
        testfile = os.path.join(self.share_path,
                                tdir + self.fsm.CONFLICT_SUFFIX, "path")
        self.assertTrue(path_exists(testfile))
        self.assertTrue(self.fsm.get_by_mdid(mdid1))
        self.assert_no_metadata(mdid2, testfile, "share", "uuid2")

    def test_move_dir_to_conflict_similar_path(self):
        """Test that the conflict to a dir removes children metadata."""
        tdir1 = os.path.join(self.share_path, "adirectory")
        mdid1 = self.fsm.create(tdir1, "share", is_dir=True)
        self.fsm.set_node_id(tdir1, "uuid1")
        make_dir(tdir1)

        tdir2 = os.path.join(self.share_path, "adir")
        mdid2 = self.fsm.create(tdir2, "share", is_dir=True)
        self.fsm.set_node_id(tdir2, "uuid2")
        make_dir(tdir2)

        testfile = os.path.join(tdir2, "path")
        mdid3 = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid3")
        with open_file(testfile, "w") as fh:
            fh.write("test!")

        # move the dir2 to conflict, see dir2 and file inside it went ok
        self.fsm.move_to_conflict(mdid2)
        self.assertFalse(path_exists(tdir2))
        self.assertTrue(path_exists(tdir2 + self.fsm.CONFLICT_SUFFIX))
        testfile = os.path.join(self.share_path,
                                tdir2 + self.fsm.CONFLICT_SUFFIX, "path")
        self.assertTrue(path_exists(testfile))
        self.assertTrue(self.fsm.get_by_mdid(mdid2))
        self.assertRaises(KeyError, self.fsm.get_by_mdid, mdid3)

        # and check that the one with similar path is untouched
        self.assertTrue(path_exists(tdir1))
        self.assertTrue(self.fsm.get_by_mdid(mdid1))


class LimboTests(FSMTestCase):
    """Test related to trash and move limbo."""

    def test_movelimbo_normal(self):
        """Test that a node is sent to and removed from the move limbo."""
        # move to limbo
        self.fsm.add_to_move_limbo("share", "uuid", "old_parent",
                                   "new_parent", "new_name", "pfrom", "pto")
        d = {("share", "uuid"):
             ("old_parent", "new_parent", "new_name", "pfrom", "pto")}
        self.assertEqual(self.fsm.move_limbo, d)
        r = [("share", "uuid", "old_parent", "new_parent",
              "new_name", "pfrom", "pto")]
        self.assertEqual(list(self.fsm.get_iter_move_limbo()), r)

        # remove from limbo
        self.fsm.remove_from_move_limbo("share", "uuid")
        self.assertEqual(self.fsm.move_limbo, {})
        self.assertEqual(list(self.fsm.get_iter_move_limbo()), [])

    def test_movelimbo_no_paths(self):
        """For old limbos, faked paths appear."""
        # fake old limbo info (note: no paths!)
        self.fsm.move_limbo = {
            ("share", "uuid"): ("old_parent", "new_parent", "new_name"),
        }
        r = [("share", "uuid", "old_parent", "new_parent",
              "new_name", "fake_path_from", "fake_path_to")]
        self.assertEqual(list(self.fsm.get_iter_move_limbo()), r)

    def test_trash_normal(self):
        """Test that a node is sent to and removed from trash."""
        testfile = os.path.join(self.share_path, "path")
        open_file(testfile, "w").close()
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")
        self.assertTrue(self.fsm.has_metadata(mdid=mdid))
        self.assertEqual(self.fsm.trash, {})
        self.assertEqual(list(self.fsm.get_iter_trash()), [])
        self.assertFalse(self.fsm.node_in_trash("share", "uuid"))

        # delete to trash
        self.fsm.delete_to_trash(mdid, "parent")
        self.assertFalse(self.fsm.has_metadata(mdid=mdid))
        self.assertEqual(
            self.fsm.trash,
            {("share", "uuid"): (mdid, "parent", testfile, False)})
        self.assertEqual(list(self.fsm.get_iter_trash()),
                         [("share", "uuid", "parent", testfile, False)])
        self.assertTrue(self.fsm.node_in_trash("share", "uuid"))

        # remove from trash
        self.fsm.remove_from_trash("share", "uuid")
        self.assertFalse(self.fsm.has_metadata(mdid=mdid))
        self.assertEqual(self.fsm.trash, {})
        self.assertEqual(list(self.fsm.get_iter_trash()), [])
        self.assertFalse(self.fsm.node_in_trash("share", "uuid"))

    def test_trash_older(self):
        """get_iter_trash supports older trash (no is_dir)."""
        self.fsm.trash = {("share", "uuid"): ("mdid", "parent", "path1")}
        self.assertEqual(list(self.fsm.get_iter_trash()),
                         [("share", "uuid", "parent", "path1", False)])

    def test_trash_oldest(self):
        """get_iter_trash supports oldest trash (no is_dir nor path)."""
        self.fsm.trash = {("share", "uuid"): ("mdid", "parent")}
        self.assertEqual(list(self.fsm.get_iter_trash()),
                         [("share", "uuid", "parent", "fake_unblocking_path",
                           False)])

    def test_trash_with_node_in_none(self):
        """Test that in trash is saved the marker if node_id is None."""
        testfile = os.path.join(self.share_path, "path")
        open_file(testfile, "w").close()
        mdid = self.fsm.create(testfile, "share")

        # delete to trash and check the marker
        self.fsm.delete_to_trash(mdid, "parent")
        marker = MDMarker(mdid)
        self.assertEqual(
            self.fsm.trash,
            {("share", marker): (mdid, "parent", testfile, False)})

    def test_dereference_ok_limbos_none(self):
        """Limbos' markers ok dereferencing is fine if no marker at all."""
        self.fsm.dereference_ok_limbos('nothing', "foo")

    def test_dereference_err_limbos_none(self):
        """Limbos' markers err dereferencing is fine if no marker at all."""
        self.fsm.dereference_err_limbos('nothing')

    def test_dereference_ok_trash_node(self):
        """Dereference possible marker in trash, node."""
        # set up
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "mrkr")
        self.fsm.delete_to_trash(mdid, "parent")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertFalse(self.fsm.node_in_trash("share", "mrkr"))
        self.assertTrue(self.fsm.node_in_trash("share", "final"))
        self.assertTrue(self.handler.check_debug("dereference ok trash",
                                                 "marker", "node"))

    def test_dereference_ok_trash_parent(self):
        """Dereference possible marker in trash, parent."""
        # set up
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "node")
        self.fsm.delete_to_trash(mdid, "mrkr")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertEqual(self.fsm.trash[("share", "node")][1], "final")
        self.assertTrue(self.handler.check_debug("dereference ok trash",
                                                 "marker", "parent"))

    def test_dereference_ok_trash_parent_node(self):
        """An unlinked node can be a parent of other."""
        # set up one node
        testfile = os.path.join(self.share_path, "path1")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "mrkr")
        self.fsm.delete_to_trash(mdid, "parent")

        # set up child node
        testfile = os.path.join(self.share_path, "path2")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "node")
        self.fsm.delete_to_trash(mdid, "mrkr")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertFalse(self.fsm.node_in_trash("share", "mrkr"))
        self.assertTrue(self.fsm.node_in_trash("share", "final"))
        self.assertEqual(self.fsm.trash[("share", "node")][1], "final")

    def test_dereference_err_trash_node(self):
        """Dereference with error possible marker in trash, node."""
        # set up
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "mrkr")
        self.fsm.delete_to_trash(mdid, "parent")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(self.fsm.node_in_trash("share", "mrkr"))
        self.assertTrue(
            self.handler.check_debug("dereference err trash", "marker"))

    def test_dereference_err_trash_parent(self):
        """Dereference with error possible marker in trash, parent."""
        # set up
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "node")
        self.fsm.delete_to_trash(mdid, "mrkr")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(self.fsm.node_in_trash("share", "node"))
        self.assertTrue(self.handler.check_debug(
            "dereference err trash", "marker"))

    def test_dereference_err_trash_parent_node(self):
        """An unlinked node can be a parent of other, both with failure."""
        # set up one node
        testfile = os.path.join(self.share_path, "path1")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "mrkr")
        self.fsm.delete_to_trash(mdid, "parent")

        # set up child node
        testfile = os.path.join(self.share_path, "path2")
        mdid = self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "node")
        self.fsm.delete_to_trash(mdid, "mrkr")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(self.fsm.node_in_trash("share", "mrkr"))
        self.assertFalse(self.fsm.node_in_trash("share", "node"))

    def test_dereference_ok_movelimbo_node(self):
        """Dereference possible marker in move limbo, node."""
        # set up
        self.fsm.add_to_move_limbo("sh", "mrkr", "oldparent", "newparent", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertFalse(("sh", "mrkr") in self.fsm.move_limbo)
        self.assertTrue(("sh", "final") in self.fsm.move_limbo)
        self.assertTrue(self.handler.check_debug("dereference ok move limbo",
                                                 "marker", "node"))

    def test_dereference_ok_movelimbo_oldparent(self):
        """Dereference possible marker in move limbo, oldparent."""
        # set up
        self.fsm.add_to_move_limbo("sh", "node", "mrkr", "newparent", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertEqual(self.fsm.move_limbo[("sh", "node")],
                         ("final", "newparent", "x", "path_from", "path_to"))
        self.assertTrue(self.handler.check_debug("dereference ok move limbo",
                                                 "marker", "old_parent"))

    def test_dereference_ok_movelimbo_newparent(self):
        """Dereference possible marker in move limbo, newparent."""
        # set up
        self.fsm.add_to_move_limbo("sh", "node", "oldparent", "mrkr", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertEqual(self.fsm.move_limbo[("sh", "node")],
                         ("oldparent", "final", "x", "path_from", "path_to"))
        self.assertTrue(self.handler.check_debug("dereference ok move limbo",
                                                 "marker", "new_parent"))

    def test_dereference_ok_movelimbo_bothparents(self):
        """Dereference possible marker in move limbo, both parents."""
        # set up
        self.fsm.add_to_move_limbo("sh", "node", "mrkr", "mrkr", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_ok_limbos("mrkr", "final")
        self.assertEqual(self.fsm.move_limbo[("sh", "node")],
                         ("final", "final", "x", "path_from", "path_to"))

    def test_dereference_err_movelimbo_node(self):
        """Dereference with error possible marker in move limbo, node."""
        # set up
        self.fsm.add_to_move_limbo("sh", "mrkr", "oldparent", "newparent", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(("sh", "mrkr") in self.fsm.move_limbo)
        self.assertTrue(self.handler.check_debug("dereference err move limbo",
                                                 "marker"))

    def test_dereference_err_movelimbo_oldparent(self):
        """Dereference with error possible marker in move limbo, oldparent."""
        # set up
        self.fsm.add_to_move_limbo("sh", "node", "mrkr", "newparent", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(("sh", "node") in self.fsm.move_limbo)
        self.assertTrue(self.handler.check_debug("dereference err move limbo",
                                                 "marker"))

    def test_dereference_err_movelimbo_newparent(self):
        """Dereference with error possible marker in move limbo, newparent."""
        # set up
        self.fsm.add_to_move_limbo("sh", "node", "oldparent", "mrkr", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(("sh", "node") in self.fsm.move_limbo)
        self.assertTrue(self.handler.check_debug("dereference err move limbo",
                                                 "marker"))

    def test_dereference_err_movelimbo_bothparents(self):
        """Dereference with error possible marker in move limbo, both."""
        # set up
        self.fsm.add_to_move_limbo("sh", "node", "mrkr", "mrkr", "x",
                                   "path_from", "path_to")

        # dereference and test
        self.fsm.dereference_err_limbos("mrkr")
        self.assertFalse(("sh", "node") in self.fsm.move_limbo)

    def test_make_dir_all_ok(self):
        """Create the dir, add a watch, mute the event."""
        called = []

        def add_watch(path):
            """Fake it."""
            called.append(path)
            return defer.succeed(True)

        self.eq.add_watch = add_watch
        self.eq.add_to_mute_filter = lambda e, **a: called.append((e, a))
        local_dir = os.path.join(self.root_dir, "foo")
        mdid = self.fsm.create(local_dir, "", is_dir=True)

        # create the dir and check
        self.fsm.make_dir(mdid)
        self.assertTrue(os.path.isdir(local_dir))
        self.assertEqual(called,
                         [('FS_DIR_CREATE', dict(path=local_dir)), local_dir])

    def test_make_dir_not_a_file(self):
        """Create the dir, add a watch."""
        local_dir = os.path.join(self.root_dir, "foo")
        mdid = self.fsm.create(local_dir, "", is_dir=False)
        self.assertRaises(ValueError, self.fsm.make_dir, mdid)

    def test_make_dir_already_there(self):
        """If the dir already exist, don't raise an error."""
        local_dir = os.path.join(self.root_dir, "foo")
        mdid = self.fsm.create(local_dir, "", is_dir=True)
        make_dir(local_dir)
        self.fsm.make_dir(mdid)
        self.assertTrue(path_exists(local_dir))

    @defer.inlineCallbacks
    def test_make_dir_in_ro_share(self):
        """Also works in a read only share."""
        share = yield self.create_share('ro_share_id', u'ro',
                                        access_level=ACCESS_LEVEL_RO)
        testdir = os.path.join(share.path, "foo")
        mdid = self.fsm.create(testdir, 'ro_share_id', is_dir=True)
        self.fsm.make_dir(mdid)
        self.assertTrue(path_exists(testdir))

    @defer.inlineCallbacks
    def test_make_dir_ro_watch(self):
        """Don't add the watch nor the mute on a RO share."""
        called = []

        def add_watch(path):
            """Fake it."""
            called.append(path)
            return defer.succeed(True)

        self.eq.add_watch = add_watch
        self.eq.add_to_mute_filter = lambda *a: called.append(a)
        share = yield self.create_share('ro_share_id', u'ro',
                                        access_level=ACCESS_LEVEL_RO)
        testdir = os.path.join(share.path, "foo")
        mdid = self.fsm.create(testdir, 'ro_share_id', is_dir=True)

        # create the dir and check
        self.fsm.make_dir(mdid)
        self.assertFalse(called)


class SyntheticInfoTests(FSMTestCase):
    """Test the methods that generates attributes."""

    def test_has_metadata(self):
        """Test the has_metadata option."""
        # not yet
        self.assertFalse(self.fsm.has_metadata(path="path"))
        self.assertFalse(
            self.fsm.has_metadata(node_id="uuid", share_id="share"))
        self.assertFalse(self.fsm.has_metadata(mdid="garbage"))

        # path created
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.assertTrue(self.fsm.has_metadata(path=path))
        self.assertFalse(self.fsm.has_metadata(node_id="uuid",
                                               share_id="share"))
        self.assertTrue(self.fsm.has_metadata(mdid=mdid))

        # uuid set
        self.fsm.set_node_id(path, "uuid")
        self.assertTrue(self.fsm.has_metadata(path=path))
        self.assertTrue(self.fsm.has_metadata(node_id="uuid",
                                              share_id="share"))
        self.assertTrue(self.fsm.has_metadata(mdid=mdid))
        self.assertRaises(
            ValueError, self.fsm.has_metadata, node_id=None, share_id="share")

    def test_is_dir(self):
        """Test the is_directory option."""
        # standard file
        testfiledir = os.path.join(self.share_path, "path1")
        mdid = self.fsm.create(testfiledir, "share", is_dir=False)
        self.fsm.set_node_id(testfiledir, "uuid1")
        self.assertFalse(self.fsm.is_dir(path=testfiledir))
        self.assertFalse(self.fsm.is_dir(node_id="uuid1", share_id="share"))
        self.assertFalse(self.fsm.is_dir(mdid=mdid))

        # directory
        testfiledir = os.path.join(self.share_path, "path2")
        mdid = self.fsm.create(testfiledir, "share", is_dir=True)
        self.fsm.set_node_id(testfiledir, "uuid2")
        self.assertTrue(self.fsm.is_dir(path=testfiledir))
        self.assertTrue(self.fsm.is_dir(node_id="uuid2", share_id="share"))
        self.assertTrue(self.fsm.is_dir(mdid=mdid))

    def test_changed_server(self):
        """Test the changed option when in SERVER state."""
        # SERVER means: local_hash != server_hash and is_partial
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        partial_path = os.path.join(
            self.fsm.partials_dir, mdid + ".u1partial." +
            os.path.basename(testfile))
        self.fsm.set_node_id(testfile, "uuid")

        # set conditions and test
        self.fsm.set_by_mdid(mdid, server_hash=98765)
        self.fsm.create_partial("uuid", "share")
        # local_hash is None so far
        self.assertEqual(self.fsm.changed(mdid=mdid), self.fsm.CHANGED_SERVER)
        self.assertEqual(self.fsm.changed(node_id="uuid", share_id="share"),
                         self.fsm.CHANGED_SERVER)
        self.assertEqual(self.fsm.changed(path=testfile),
                         self.fsm.CHANGED_SERVER)

        # remove the .partial by hand, to see it crash
        remove_file(partial_path)
        self.assertRaises(InconsistencyError,
                          self.fsm._check_partial, mdid=mdid)

    def test_changed_none(self):
        """Test the changed option when in NONE state."""
        # NONE means: local_hash == server_hash and is_partial == False
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        partial_path = os.path.join(
            self.fsm.partials_dir, mdid + ".u1partial." +
            os.path.basename(testfile))
        self.fsm.set_node_id(testfile, "uuid")

        # all conditions are set: by default, local_hash and server_hash
        # are both None
        self.assertEqual(self.fsm.changed(mdid=mdid), self.fsm.CHANGED_NONE)
        self.assertEqual(self.fsm.changed(node_id="uuid", share_id="share"),
                         self.fsm.CHANGED_NONE)
        self.assertEqual(
            self.fsm.changed(path=testfile), self.fsm.CHANGED_NONE)

        # put a .partial by hand, to see it crash
        open_file(partial_path, "w").close()
        self.assertRaises(InconsistencyError,
                          self.fsm._check_partial, mdid=mdid)

    def test_changed_local(self):
        """Test the changed option when in LOCAL state."""
        # LOCAL means: local_hash != server_hash and is not partial
        testfile = os.path.join(self.share_path, "path")
        mdid = self.fsm.create(testfile, "share")
        partial_path = os.path.join(
            self.fsm.partials_dir, mdid + ".u1partial." +
            os.path.basename(testfile))
        self.fsm.set_node_id(testfile, "uuid")

        # set conditions and test
        self.fsm.set_by_mdid(mdid, server_hash=98765)
        # local_hash is None so far
        self.assertEqual(self.fsm.changed(mdid=mdid), self.fsm.CHANGED_LOCAL)
        self.assertEqual(self.fsm.changed(node_id="uuid", share_id="share"),
                         self.fsm.CHANGED_LOCAL)
        self.assertEqual(self.fsm.changed(path=testfile),
                         self.fsm.CHANGED_LOCAL)

        # put a .partial by hand, to see it crash
        open_file(partial_path, "w").close()
        self.assertRaises(InconsistencyError,
                          self.fsm._check_partial, mdid=mdid)

    def test_dir_content(self):
        """Test the dir_content method."""
        # create a structure in md
        to_create = []
        dir1 = os.path.join(self.share_path, "foo")
        to_create.append((dir1, True))
        to_create.append((os.path.join(dir1, "file2"), False))
        to_create.append((os.path.join(dir1, "file1"), False))

        dir2 = os.path.join(dir1, "bar")
        to_create.append((dir2, True))
        to_create.append((os.path.join(dir2, "file3"), False))
        to_create.append((os.path.join(dir2, "file5"), False))
        to_create.append((os.path.join(dir2, "file4"), False))
        to_create.append((os.path.join(dir2, "file6"), False))

        dir3 = os.path.join(dir2, "baz")
        to_create.append((dir3, True))
        to_create.append((os.path.join(dir3, "file7"), False))
        to_create.append((os.path.join(dir3, "file9"), False))
        to_create.append((os.path.join(dir3, "file8"), False))

        dir4 = os.path.join(dir2, "other")
        to_create.append((dir4, True))

        for i, (path, is_dir) in enumerate(to_create):
            self.fsm.create(path, "share", is_dir=is_dir)
            self.fsm.set_node_id(path, "uuid" + str(i))

        # ask for the info for dir1
        should_be = [
            ("bar", True, "uuid3"),
            ("file1", False, "uuid2"),
            ("file2", False, "uuid1"),
        ]
        content = self.fsm.dir_content(dir1)
        self.assertEqual(should_be, content)

        # ask for the info for dir2
        should_be = [
            ("baz", True, "uuid8"),
            ("file3", False, "uuid4"),
            ("file4", False, "uuid6"),
            ("file5", False, "uuid5"),
            ("file6", False, "uuid7"),
            ("other", True, "uuid12"),
        ]
        content = self.fsm.dir_content(dir2)
        self.assertEqual(should_be, content)

        # ask for the info for dir3
        should_be = [
            ("file7", False, "uuid9"),
            ("file8", False, "uuid11"),
            ("file9", False, "uuid10"),
        ]
        content = self.fsm.dir_content(dir3)
        self.assertEqual(should_be, content)

        # ask for the info for an empty dir
        content = self.fsm.dir_content(dir4)
        self.assertEqual([], content)

        # ask for the info for an inexistant dir
        self.assertRaises(KeyError, self.fsm.dir_content, "no-such-dir")

        # ask for the info for file
        just_a_file = os.path.join(dir3, "file9")
        self.assertRaises(ValueError, self.fsm.dir_content, just_a_file)


class SharesTests(FSMTestCase):
    """Test fsm with ro and rw shares."""

    @skip_if_win32_and_uses_readonly
    @defer.inlineCallbacks
    def test_file_ro_share_fail(self):
        """ Test that manual creation of a file, fails on a ro-share. """
        share = yield self.create_share('ro_share', u'ro_share_name',
                                        access_level=ACCESS_LEVEL_RO)
        testfile = os.path.join(share.path, "a_file")
        self.assertRaises(IOError, open_file, testfile, 'w')

    @defer.inlineCallbacks
    def test_dir_ro_share(self):
        """ Test that the creation of a file using fsm, works on a ro-share."""
        share = yield self.create_share('ro_share', u'ro_share_name',
                                        access_level=ACCESS_LEVEL_RO)
        testdir = os.path.join(share.path, "path2")
        self.fsm.create(testdir, share.volume_id, is_dir=True)
        self.fsm.set_node_id(testdir, "uuid2")
        self.fsm.create_partial('uuid2', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', share.volume_id)
        fd.flush()
        fd.close()
        self.assertTrue(path_exists(testdir))

    @defer.inlineCallbacks
    def test_file_ro_share(self):
        """ Test that the creation of a file using fsm, works on a ro-share."""
        self.share = yield self.create_share('ro_share', u'ro_share_name',
                                             access_level=ACCESS_LEVEL_RO)
        testfile = os.path.join(self.share.path, "a_file")
        self.fsm.create(testfile, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', self.share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', self.share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', self.share.volume_id, None)
        self.assertTrue(path_exists(testfile))

    @defer.inlineCallbacks
    def test_delete_dir_ro_share(self):
        """ Test that fsm is able to delete a dir in a ro.share. """
        share = yield self.create_share('ro_share', u'ro_share_name',
                                        access_level=ACCESS_LEVEL_RO)
        testdir = os.path.join(share.path, "path2")
        self.fsm.create(testdir, share.volume_id, is_dir=True)
        self.fsm.set_node_id(testdir, "uuid2")
        self.fsm.create_partial('uuid2', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.remove_partial('uuid2', share.volume_id)
        self.assertTrue(path_exists(testdir))
        self.fsm.delete_file(testdir)
        self.assertFalse(path_exists(testdir))

    @defer.inlineCallbacks
    def test_delete_non_empty_dir_ro_share(self):
        """Test that fsm is able to delete a non-empty dir in a ro.share."""
        share = yield self.create_share('ro_share', u'ro_share_name',
                                        access_level=ACCESS_LEVEL_RO)
        testdir = os.path.join(share.path, "path2")
        mdid = self.fsm.create(testdir, share.volume_id, is_dir=True)
        self.fsm.set_node_id(testdir, "uuid2")
        self.fsm.create_partial('uuid2', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.remove_partial('uuid2', share.volume_id)
        self.fsm.upload_finished(mdid, self.fsm.get_by_mdid(mdid).local_hash)
        # crete a file inside the testdir
        testfile = os.path.join(testdir, "a_file")
        mdid = self.fsm.create(testfile, share.volume_id, is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', share.volume_id, None)
        self.fsm.upload_finished(mdid, self.fsm.get_by_mdid(mdid).local_hash)
        self.assertTrue(path_exists(testdir))
        self.assertTrue(path_exists(testfile))
        self.fsm.delete_file(testdir)
        self.assertFalse(path_exists(testdir))
        self.assertFalse(path_exists(testfile))

    @defer.inlineCallbacks
    def test_delete_non_empty_dir_rw_share(self):
        """Test that fsm is able to delete a non-empty dir in a rw.share."""
        share = yield self.create_share('rw_share', u'rw_share_name',
                                        access_level=ACCESS_LEVEL_RW)
        testdir = os.path.join(share.path, "path2")
        mdid = self.fsm.create(testdir, share.volume_id, is_dir=True)
        self.fsm.set_node_id(testdir, "uuid2")
        self.fsm.create_partial('uuid2', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.remove_partial('uuid2', share.volume_id)
        self.fsm.upload_finished(mdid, self.fsm.get_by_mdid(mdid).local_hash)
        # crete a file inside the testdir
        testfile = os.path.join(testdir, "a_file")
        mdid = self.fsm.create(testfile, share.volume_id, is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', share.volume_id, None)
        self.fsm.upload_finished(mdid, self.fsm.get_by_mdid(mdid).local_hash)
        self.assertTrue(path_exists(testdir))
        self.assertTrue(path_exists(testfile))
        self.fsm.delete_file(testdir)
        self.assertFalse(path_exists(testdir))
        self.assertFalse(path_exists(testfile))

    @skip_if_win32_and_uses_readonly
    @defer.inlineCallbacks
    def test_delete_non_empty_dir_bad_perms_rw_share(self):
        """Test that fsm is able to delete a non-empty dir in a rw.share."""
        share = yield self.create_share('rw_share', u'rw_share_name',
                                        access_level=ACCESS_LEVEL_RW)
        testdir = os.path.join(share.path, "path2")
        mdid = self.fsm.create(testdir, share.volume_id, is_dir=True)
        self.fsm.set_node_id(testdir, "uuid2")
        self.fsm.create_partial('uuid2', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.remove_partial('uuid2', share.volume_id)
        self.fsm.upload_finished(mdid, self.fsm.get_by_mdid(mdid).local_hash)
        # crete a file inside the testdir
        testfile = os.path.join(testdir, "a_file")
        mdid = self.fsm.create(testfile, share.volume_id, is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', share.volume_id, None)
        self.fsm.upload_finished(mdid, self.fsm.get_by_mdid(mdid).local_hash)
        self.assertTrue(path_exists(testdir))
        self.assertTrue(path_exists(testfile))

        # make the dir read-only, the error should be logged
        set_dir_readonly(testdir)
        self.addCleanup(set_dir_readwrite, testdir)

        self.fsm.delete_file(testdir)
        self.assertTrue(self.handler.check_warning("OSError", testdir,
                                                   "when trying to remove"))
        self.assertTrue(path_exists(testdir))
        self.assertTrue(path_exists(testfile))

    @defer.inlineCallbacks
    def test_delete_file_ro_share(self):
        """ Test that fsm is able to delete a file in a ro-share. """
        self.share = yield self.create_share(
            'ro_share', u'ro_share_name', access_level=ACCESS_LEVEL_RO)
        testfile = os.path.join(self.share.path, "a_file")
        self.fsm.create(testfile, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', self.share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', self.share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', self.share.volume_id, None)
        self.assertTrue(path_exists(testfile))
        self.fsm.delete_file(testfile)
        self.assertFalse(path_exists(testfile))

    @defer.inlineCallbacks
    def test_move_to_conflict_ro_share(self):
        """ Test that fsm is able to handle move_to_conflict in a ro-share. """
        self.share = yield self.create_share('ro_share', u'ro_share_name',
                                             access_level=ACCESS_LEVEL_RO)
        testfile = os.path.join(self.share.path, "a_file")
        file_mdid = self.fsm.create(testfile, self.share.volume_id,
                                    is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', self.share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', self.share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', self.share.volume_id, None)
        self.assertTrue(path_exists(testfile))
        self.fsm.move_to_conflict(file_mdid)
        self.assertTrue(path_exists(testfile + self.fsm.CONFLICT_SUFFIX))

    @defer.inlineCallbacks
    def test_file_rw_share_no_fail(self):
        """ Test that manual creation of a file, ona  rw-share. """
        share = yield self.create_share('ro_share', u'ro_share_name')
        testfile = os.path.join(share.path, "a_file")
        open_file(testfile, 'w').close()
        self.assertTrue(path_exists(testfile))

    @defer.inlineCallbacks
    def test_dir_rw_share(self):
        """ Test that the creation of a file using fsm, works on a rw-share."""
        share = yield self.create_share('ro_share', u'ro_share_name')
        testdir = os.path.join(share.path, "path2")
        self.fsm.create(testdir, share.volume_id, is_dir=True)
        self.fsm.set_node_id(testdir, "uuid2")
        self.fsm.create_partial('uuid2', share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', share.volume_id)
        fd.flush()
        fd.close()
        self.assertTrue(path_exists(testdir))

    @defer.inlineCallbacks
    def test_file_rw_share(self):
        """Test that the creation of a file using fsm, works on a rw-share."""
        self.share = yield self.create_share('ro_share', u'ro_share_name')
        testfile = os.path.join(self.share.path, "a_file")
        self.fsm.create(testfile, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(testfile, "uuid3")
        self.fsm.create_partial('uuid3', self.share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid3', self.share.volume_id)
        fd.flush()
        fd.close()
        self.fsm.commit_partial('uuid3', self.share.volume_id, None)
        self.assertTrue(path_exists(testfile))

    def test_share_and_root(self):
        """ Test the creation of a file with the same relative path in a share
        and in the root.
        """
        a_dir_root = os.path.join(self.root_dir, "a_dir")
        a_dir_share = os.path.join(self.share.path, "a_dir")
        self.fsm.create(a_dir_root, "", is_dir=True)
        self.fsm.set_node_id(a_dir_root, "uuid1")
        self.fsm.create(a_dir_share, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(a_dir_share, "uuid2")
        self.fsm.create_partial('uuid1', "")
        fd = self.fsm.get_partial_for_writing('uuid1', "")
        fd.flush()
        fd.close()
        self.fsm.create_partial('uuid2', self.share.volume_id)
        fd = self.fsm.get_partial_for_writing('uuid2', self.share.volume_id)
        fd.flush()
        fd.close()
        self.assertTrue(path_exists(self.fsm.get_abspath("", a_dir_root)))
        self.assertTrue(path_exists(a_dir_share))


class TestEnableShareWrite(FSMTestCase):
    """Tests for EnableShareWrite context manager"""

    @defer.inlineCallbacks
    def setUp(self):
        """Test setup"""
        yield super(TestEnableShareWrite, self).setUp()
        # create a ro share
        self.share_ro = yield self.create_share('share_ro', u'share_ro_name',
                                                access_level=ACCESS_LEVEL_RO)
        self.share_ro_path = self.share_ro.path

    @skip_if_win32_and_uses_readonly
    def test_write_in_ro_share(self):
        """Test the EnableShareWrite context manager in a ro share."""
        path = os.path.join(self.share_ro_path, 'foo', 'a_file_in_a_ro_share')
        data = 'yes I can write!'
        can_write_parent = os.access(os.path.dirname(self.share_ro_path),
                                     os.W_OK)
        with EnableShareWrite(self.share_ro, path) as enabled:
            self.assertTrue(enabled.ro)
            with open_file(path, 'w') as f:
                f.write(data)
        self.assertEqual(data, open_file(path, 'r').read())
        self.assertFalse(os.access(self.share_ro_path, os.W_OK))
        # check that the parent permissions are ok
        self.assertEqual(can_write_parent,
                         os.access(os.path.dirname(self.share_ro_path),
                                   os.W_OK))
        # fail to write directly in the share
        self.assertRaises(IOError, open, path, 'w')

    def test_write_in_rw_share(self):
        """test the EnableShareWrite context manager in a rw share"""
        path = os.path.join(self.share_path, 'a_file_in_a_rw_share')
        data = 'yes I can write!'
        can_write_parent = os.access(os.path.dirname(self.share_path), os.W_OK)
        with EnableShareWrite(self.share, path) as enabled:
            self.assertFalse(enabled.ro)
            with open_file(path, 'w') as f:
                f.write(data)
        self.assertEqual(data, open_file(path, 'r').read())
        self.assertTrue(os.access(self.share_path, os.W_OK))
        # check that the parent permissions are ok
        self.assertEqual(can_write_parent, os.access(self.share_path, os.W_OK))


class RealVMTestCase(FSMTestCase):

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(RealVMTestCase, self).setUp()
        self.shares_dir = self.mktemp('shares')
        self.root_dir = self.mktemp('root')
        self.data_dir = self.mktemp("data")
        self.partials_dir = self.mktemp("partials")
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.addCleanup(self.main.shutdown)
        self.fsm = self.main.fs
        self.share = yield self.create_share('share', u'share_name')
        self.share_path = self.share.path

    @defer.inlineCallbacks
    def create_share(self, share_id, share_name,
                     access_level=ACCESS_LEVEL_RW):
        with allow_writes(self.shares_dir):
            share = yield _create_share(share_id, share_name, self.fsm,
                                        self.shares_dir, access_level)

        defer.returnValue(share)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_None_missing_share(self):
        """test loading metadata v0. that points to a share that
        we don't have
        """
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        open_file(path, "w").close()
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        # create a path with the old layout
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid1")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, u'share1_name')
        make_link(self.shares_dir, old_shares_path)

        # put the old path in the mdobj
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md

        # break the node on purpose
        real_mdobj = self.fsm.fs[mdid]
        del real_mdobj["stat"]
        real_mdobj["path"] = unicode(real_mdobj["path"])
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # delete the version that should have left the previous fsm
        version_file = os.path.join(self.data_dir, "metadata_version")
        remove_file(version_file)

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # remove the share!
        del self.fsm.vm.shares[other_share.volume_id]

        # start up again, and check
        db = Tritcask(os.path.join(self.main.data_dir, 'tritcask.new'))
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.data_dir, self.partials_dir,
                                   self.fsm.vm, db)
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        newmdobj = newfsm.get_by_path(path)
        self.assertEqual(newmdobj.mdid, mdid)
        self.assertEqual(newmdobj.stat, stat_path(path))
        self.assertEqual(newmdobj.local_hash, "")
        self.assertEqual(newmdobj.server_hash, "")
        self.assertTrue(isinstance(newmdobj.path, str))
        self.assertTrue(other_share.path not in newfsm._idx_path)
        self.assertFalse(old_path in self.fsm._idx_path)
        self.assertFalse(old_path in newfsm._idx_path)
        self.assertRaises(KeyError, newfsm.get_by_mdid, share_mdid)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_1_missing_share(self):
        """test loading metadata v1. that points to a share that
        we don't have
        """
        # create some stuff
        path1 = os.path.join(self.share.path, 'path1')
        path2 = os.path.join(self.share.path, 'path2')
        mdid1 = self.fsm.create(path1, "share")
        self.fsm.set_node_id(path1, "uuid1")
        mdid2 = self.fsm.create(path2, "share")
        self.fsm.set_node_id(path2, "uuid2")

        # create a path with the old layout
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid3")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, u'share1_name')
        make_link(self.shares_dir, old_shares_path)

        # put the old path in the mdobj
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md

        # break the node on purpose, with unicode valid and not
        real_mdobj = self.fsm.fs[mdid1]
        real_mdobj["path"] = unicode(real_mdobj["path"])
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid1] = real_mdobj
        real_mdobj = self.fsm.fs[mdid2]
        real_mdobj["path"] = "asdas\x00\xff\xffasd"
        self.fsm.fs[mdid2] = real_mdobj

        # put the version file in 1
        version_file = os.path.join(self.data_dir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("1")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # remove the share!
        del self.fsm.vm.shares[other_share.volume_id]

        # start up again, and check
        db = Tritcask(os.path.join(self.main.data_dir, 'tritcask.new'))
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.data_dir, self.partials_dir,
                                   self.fsm.vm, db)
        version_file = os.path.join(self.data_dir, "metadata_version")
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        self.assertEqual(1, len(newfsm._idx_node_id))
        self.assertEqual(2, len(newfsm._idx_path))
        self.assertEqual('uuid1', newfsm.get_by_mdid(mdid1).node_id)
        self.assertRaises(KeyError, newfsm.get_by_mdid, share_mdid)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_2_missing_share(self):
        """test loading metadata v2. that points to a share that
        we don't have
        """
        # create some stuff
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        # create a path with the old layout
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid3")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, u'share1_name')
        make_link(self.shares_dir, old_shares_path)

        # put the old path in the mdobj
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md

        # break the node on purpose, with hashes in None
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["local_hash"] = None
        real_mdobj["server_hash"] = None
        self.fsm.fs[mdid] = real_mdobj

        # put the version file in 1
        version_file = os.path.join(self.data_dir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("2")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # remove the share!
        del self.fsm.vm.shares[other_share.volume_id]

        # start up again, and check
        db = Tritcask(os.path.join(self.main.data_dir, 'tritcask.new'))
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.data_dir, self.partials_dir,
                                   self.fsm.vm, db)
        version_file = os.path.join(self.data_dir, "metadata_version")
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        self.assertTrue(newfsm.get_by_mdid(mdid) is not None)
        self.assertEqual(1, len(newfsm._idx_node_id))
        self.assertEqual(2, len(newfsm._idx_path))
        self.assertRaises(KeyError, newfsm.get_by_mdid, share_mdid)

    @skip_if_win32_and_uses_metadata_older_than_5
    @defer.inlineCallbacks
    def test_old_metadata_3_missing_share(self):
        """test loading metadata v3. that points to a share that
        we don't have
        """
        # create a path with the old layout and metadata
        # the root
        root_mdid = self.fsm.get_by_path(self.root_dir).mdid
        self.fsm.set_node_id(self.root_dir, "uuid")
        # a share
        other_share = yield self.create_share('share1', u'share1_name')
        share_mdid = self.fsm.create(other_share.path, "share1")
        self.fsm.set_node_id(other_share.path, "uuid1")
        make_dir(os.path.join(self.root_dir, 'Magicicada'), recursive=True)
        old_shares_path = os.path.join(
            self.root_dir, 'Magicicada', 'Shared With Me')
        old_path = os.path.join(old_shares_path, u'share1_name')
        make_link(self.shares_dir, old_shares_path)
        old_root_path = os.path.join(os.path.dirname(self.root_dir),
                                     'Magicicada', 'My Files')

        # put the old path in the mdobjs
        share_md = self.fsm.fs[share_mdid]
        share_md['path'] = old_path
        self.fsm.fs[share_mdid] = share_md
        root_md = self.fsm.fs[root_mdid]
        root_md['path'] = old_root_path
        self.fsm.fs[root_mdid] = root_md

        # put the version file in 1
        version_file = os.path.join(self.data_dir, "metadata_version")
        with open_file(version_file, "w") as fh:
            fh.write("3")

        # create a old-style fs with the data:
        old_fs = FileShelf(self.fsm.old_fs._path)
        for k, v in self.fsm.fs.iteritems():
            old_fs[k] = v

        # remove the share!
        del self.fsm.vm.shares[other_share.volume_id]

        # start up again, and check
        db = Tritcask(os.path.join(self.main.data_dir, 'tritcask.new'))
        self.addCleanup(db.shutdown)
        newfsm = FileSystemManager(self.data_dir, self.partials_dir,
                                   self.fsm.vm, db)
        version_file = os.path.join(self.data_dir, "metadata_version")
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        self.assertTrue(newfsm.get_by_mdid(root_mdid) is not None)
        self.assertEqual(1, len(newfsm._idx_node_id))
        self.assertEqual(1, len(newfsm._idx_path))
        self.assertRaises(KeyError, newfsm.get_by_mdid, share_mdid)

    @defer.inlineCallbacks
    def test_metadata_missing_share(self):
        """test loading current metadata that points to a share
        that we don't have
        """
        with open_file(
                os.path.join(self.data_dir, "metadata_version")) as f:
            md_version = f.read()
        self.assertEqual(md_version, METADATA_VERSION)
        path = os.path.join(self.share.path, 'path')
        path1 = os.path.join(self.share.path, 'path1')
        other_share = yield self.create_share('share1', u'share1_name')

        path2 = os.path.join(other_share.path, 'broken_path2')
        for p in [path, path1, path2]:
            open_file(p, "w").close()
        mdid = self.fsm.create(path, "share")
        self.fsm.set_node_id(path, "uuid")
        mdid1 = self.fsm.create(path1, "share")
        self.fsm.set_node_id(path1, "uuid1")
        mdid2 = self.fsm.create(path2, "share1")
        self.fsm.set_node_id(path2, "uuid2")

        # remove the share!
        del self.fsm.vm.shares[other_share.volume_id]

        # start up again, and check
        newfsm = FileSystemManager(self.data_dir, self.partials_dir,
                                   self.fsm.vm, self.main.db)
        version_file = os.path.join(self.data_dir, "metadata_version")
        md_version = open_file(version_file).read()
        self.assertEqual(md_version, METADATA_VERSION)
        self.assertTrue(newfsm.get_by_mdid(mdid) is not None)
        self.assertEqual(2, len(newfsm._idx_node_id))
        self.assertEqual(3, len(newfsm._idx_path))
        # check that the broken mdid's load the old metadata
        self.assertEqual('uuid', newfsm.get_by_mdid(mdid).node_id)
        self.assertEqual('uuid1', newfsm.get_by_mdid(mdid1).node_id)
        self.assertRaises(KeyError, newfsm.get_by_mdid, mdid2)


class PathsStartingWithTestCase(FSMTestCase):
    """Test FSM.get_paths_starting_with utility."""

    @defer.inlineCallbacks
    def setUp(self):
        """Basic setup."""
        yield super(PathsStartingWithTestCase, self).setUp()

        self.some_dir = os.path.join(self.root_dir, 'foo')
        self.sub_dir = os.path.join(self.some_dir, 'baz')
        self.some_file = os.path.join(self.sub_dir, 'bar.txt')

        for d in (self.some_dir, self.sub_dir):
            make_dir(d)
            self.addCleanup(self.rmtree, d)
            self.fsm.create(d, '', is_dir=True)
            self.fsm.set_node_id(d, 'uuid')

        open_file(self.some_file, 'w').close()
        self.fsm.create(self.some_file, "")
        self.fsm.set_node_id(self.some_file, "uuid_file")

    def test_with_self(self):
        """Check paths starting with including some_dir."""
        expected = sorted([(self.some_dir, True), (self.sub_dir, True),
                           (self.some_file, False)])
        actual = self.fsm.get_paths_starting_with(self.some_dir)
        self.assertEqual(expected, sorted(actual))

    def test_dir_names_only(self):
        """Check paths starting with excluding directories with same prefix."""
        similar_dir = os.path.join(self.root_dir, 'fooo')
        make_dir(similar_dir)
        self.fsm.create(similar_dir, '', is_dir=True)
        self.fsm.set_node_id(similar_dir, 'uuid')

        expected = sorted([(self.some_dir, True), (self.sub_dir, True),
                           (self.some_file, False)])
        actual = self.fsm.get_paths_starting_with(self.some_dir)

        self.assertEqual(expected, sorted(actual))

    def test_without_self(self):
        """Check paths starting with excluding some_dir."""
        expected = sorted([(self.sub_dir, True), (self.some_file, False)])
        actual = self.fsm.get_paths_starting_with(self.some_dir,
                                                  include_base=False)
        self.assertEqual(expected, sorted(actual))


class ServerRescanDataTestCase(FSMTestCase):
    """Test FSM services to get server rescan data."""

    def test_get_for_server_rescan_by_path(self):
        """Test FSM.get_for_server_rescan_by_path method"""
        # create the share fsm object
        self.fsm.create(self.share_path, self.share.volume_id)
        self.fsm.set_node_id(self.share_path, "share_uuid")
        # create a few nodes
        path1 = os.path.join(self.share_path, "path1")
        path2 = os.path.join(self.share_path, "path1", "path2")
        path_out = os.path.join(self.root_dir, "path1")
        self.fsm.create(path1, "share", is_dir=True)
        self.fsm.create(path2, "share")
        self.fsm.create(path_out, "")
        self.fsm.set_node_id(path1, "uuid1")
        self.fsm.set_node_id(path2, "uuid2")
        self.fsm.set_node_id(path_out, "uuid3")
        data = list(self.fsm.get_for_server_rescan_by_path(self.share.path))
        self.assertEqual(len(data), 3)
        self.assertTrue(("share", "uuid1", "") in data)
        self.assertTrue(("share", "uuid2", "") in data)
        self.assertTrue(("share", "share_uuid", "") in data)
        self.assertFalse(("", "uuid3", "") in data)


class MutingTestCase(FSMTestCase):
    """Test FSM interaction with mutes."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up the test infrastructure."""
        yield super(MutingTestCase, self).setUp()
        self.muted = []

        # in-the-middle add
        _orig_add_mute = self.eq.add_to_mute_filter
        # in-the-middle remove
        _orig_rm_mute = self.eq.rm_from_mute_filter

        def _fake_add(event, **data):
            """Store what is added."""
            self.muted.append((event, data))
            return _orig_add_mute(event, **data)

        def _fake_rm(event, **data):
            """Store what is deleted."""
            self.muted.remove((event, data))
            return _orig_rm_mute(event, **data)

        self.eq.rm_from_mute_filter = _fake_rm
        self.eq.add_to_mute_filter = _fake_add
        self.addCleanup(setattr, self.eq, 'add_to_mute_filter', _orig_add_mute)
        self.addCleanup(setattr, self.eq, 'rm_from_mute_filter', _orig_rm_mute)

    def test_movefile_ok(self):
        """Move file adds a mute filter."""
        path1 = os.path.join(self.share.path, "thisfile1")
        path2 = os.path.join(self.share.path, "thisfile2")
        open_file(path1, "w").close()
        self.create_node(path1)

        # move and check
        self.fsm.move_file("share", path1, path2)
        self.assertEqual(self.muted, [('FS_FILE_MOVE',
                                      dict(path_from=path1, path_to=path2))])

    def test_movefile_error(self):
        """Move file adds and removes a mute filter."""
        path1 = os.path.join(self.share.path, "thisfile1")
        path2 = os.path.join(self.share.path, "thisfile2")
        self.create_node(path1)

        # move and check
        self.fsm.move_file("share", path1, path2)
        self.assertEqual(self.muted, [])

    def test_movedir_ok(self):
        """Move dir adds a mute filter."""
        path1 = os.path.join(self.share.path, "thisfile1")
        path2 = os.path.join(self.share.path, "thisfile2")
        make_dir(path1)
        self.create_node(path1, is_dir=True)

        # move and check
        self.fsm.move_file("share", path1, path2)
        self.assertEqual(self.muted, [('FS_DIR_MOVE',
                                      dict(path_from=path1, path_to=path2))])

    def test_movedir_error(self):
        """Move dir adds and removes a mute filter."""
        path1 = os.path.join(self.share.path, "thisfile1")
        path2 = os.path.join(self.share.path, "thisfile2")
        self.create_node(path1, is_dir=True)

        # move and check
        self.fsm.move_file("share", path1, path2)
        self.assertEqual(self.muted, [])

    def test_deletefile_ok(self):
        """Delete file adds a mute filter."""
        testfile = os.path.join(self.share_path, "path")
        open_file(testfile, "w").close()
        self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")

        # delete and check
        self.fsm.delete_file(testfile)
        self.assertEqual(self.muted, [('FS_FILE_DELETE', dict(path=testfile))])

    def test_deletefile_error(self):
        """Delete file adds and removes a mute filter."""
        testfile = os.path.join(self.share_path, "path")
        self.fsm.create(testfile, "share")
        self.fsm.set_node_id(testfile, "uuid")

        # delete and check
        self.fsm.delete_file(testfile)
        self.assertEqual(self.muted, [])

    def test_deletedir_ok(self):
        """Delete dir adds a mute filter."""
        testfile = os.path.join(self.share_path, "path")
        make_dir(testfile)
        self.fsm.create(testfile, "share", is_dir=True)
        self.fsm.set_node_id(testfile, "uuid")

        # delete and check
        self.fsm.delete_file(testfile)
        self.assertEqual(self.muted, [('FS_DIR_DELETE', dict(path=testfile))])

    def test_deletedir_error(self):
        """Delete dir adds and removes a mute filter."""
        testfile = os.path.join(self.share_path, "path")
        self.fsm.create(testfile, "share", is_dir=True)
        self.fsm.set_node_id(testfile, "uuid")

        # delete and check
        self.fsm.delete_file(testfile)
        self.assertEqual(self.muted, [])

    def test_conflict_movefile_ok(self):
        """Move file when conflict adds a mute filter.

        The muted event is a DELETE, because the .u1conflict is
        ignored (and that transforms the MOVE into DELETE).
        """
        path1 = os.path.join(self.share.path, "thisfile1")
        open_file(path1, "w").close()
        mdobj = self.create_node(path1)

        # move and check
        self.fsm.move_to_conflict(mdobj.mdid)
        self.assertEqual(self.muted, [('FS_FILE_DELETE', dict(path=path1))])

    def test_conflict_movefile_error(self):
        """Move file when conflict adds and removes a mute filter."""
        path1 = os.path.join(self.share.path, "thisfile1")
        mdobj = self.create_node(path1)

        # move and check
        self.fsm.move_to_conflict(mdobj.mdid)
        self.assertEqual(self.muted, [])

    def test_conflict_movedir_ok(self):
        """Move dir when conflict adds a mute filter.

        The muted event is a DELETE, because the .u1conflict is
        ignored (and that transforms the MOVE into DELETE).
        """
        path1 = os.path.join(self.share.path, "thisfile1")
        make_dir(path1)
        mdobj = self.create_node(path1, is_dir=True)

        # move and check
        self.fsm.move_to_conflict(mdobj.mdid)
        self.assertEqual(self.muted, [('FS_DIR_DELETE', dict(path=path1))])

    def test_conflict_movedir_error(self):
        """Move dir when conflict adds and removes a mute filter."""
        path1 = os.path.join(self.share.path, "thisfile1")
        mdobj = self.create_node(path1, is_dir=True)

        # move and check
        self.fsm.move_to_conflict(mdobj.mdid)
        self.assertEqual(self.muted, [])


class DirtyNodesTests(FSMTestCase):
    """Test all related to dirty nodes."""

    def test_get_set_dirty(self):
        """Dirty flag is allowed to be set."""
        path = os.path.join(self.root_dir, "path")
        mdid = self.fsm.create(path, "")

        self.fsm.set_by_mdid(mdid, dirty=True)
        self.assertTrue(self.fsm.get_by_mdid(mdid).dirty)

    def test_get_dirty_nodes_allempty(self):
        """No dirty nodes when no nodes at all."""
        self.assertEqual(list(self.fsm.get_dirty_nodes()), [])

    def test_get_dirty_nodes_all_ok(self):
        """No dirty nodes when other nodes are ok."""
        # create a node but keep it clean
        path = os.path.join(self.root_dir, "path")
        self.fsm.create(path, "")

        self.assertEqual(list(self.fsm.get_dirty_nodes()), [])

    def test_get_dirty_nodes_mixed(self):
        """Some dirty nodes betweeen the others."""
        # create a node but keep it clean
        path1 = os.path.join(self.root_dir, "path1")
        self.fsm.create(path1, "")
        path2 = os.path.join(self.root_dir, "path2")
        mdid2 = self.fsm.create(path2, "")
        path3 = os.path.join(self.root_dir, "path3")
        self.fsm.create(path3, "")
        path4 = os.path.join(self.root_dir, "path4")
        mdid4 = self.fsm.create(path4, "")

        # dirty some
        self.fsm.set_by_mdid(mdid2, dirty=True)
        self.fsm.set_by_mdid(mdid4, dirty=True)

        # get and compare
        all_dirty = list(self.fsm.get_dirty_nodes())
        dirty_mdids = [n.mdid for n in all_dirty]
        self.assertEqual(len(all_dirty), 2)
        self.assertTrue(mdid2 in dirty_mdids)
        self.assertTrue(mdid4 in dirty_mdids)


class TrashFileShelfTests(BaseTwistedTestCase):
    """Test the customized file shelf."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TrashFileShelfTests, self).setUp()
        self.trash_dir = self.mktemp('trash')
        self.tfs = TrashFileShelf(self.trash_dir)

    def test_one_value(self):
        """Test the file shelf with one value."""
        self.tfs[("foo", "bar")] = 'value'

        self.assertEqual(self.tfs[("foo", "bar")], 'value')
        self.assertEqual(list(self.tfs.keys()), [("foo", "bar")])

    def test_two_values(self):
        """Test the file shelf with two values."""
        self.tfs[("foo", "bar")] = 'value1'
        self.tfs[("xyz", "hfb")] = 'value2'

        self.assertEqual(self.tfs[("foo", "bar")], 'value1')
        self.assertEqual(self.tfs[("xyz", "hfb")], 'value2')
        self.assertEqual(sorted(self.tfs.keys()),
                         [("foo", "bar"), ("xyz", "hfb")])

    def test_node_id_None(self):
        """node_id can be None."""
        self.tfs[("foo", None)] = 'value'
        self.assertEqual(self.tfs[("foo", None)], 'value')
        self.assertEqual(list(self.tfs.keys()), [("foo", None)])

    def test_node_id_marker(self):
        """node_id can be a marker."""
        marker = MDMarker("bar")
        self.tfs[("foo", marker)] = 'value'
        self.assertEqual(self.tfs[("foo", marker)], 'value')
        self.assertEqual(list(self.tfs.keys()), [("foo", marker)])
        node_id = list(self.tfs.keys())[0][1]
        self.assertTrue(IMarker.providedBy(node_id))

    def test_share_id_marker(self):
        """share_id can be a marker."""
        marker = MDMarker("bar")
        self.tfs[(marker, "foo")] = 'value'
        self.assertEqual(self.tfs[(marker, "foo")], 'value')
        self.assertEqual(list(self.tfs.keys()), [(marker, "foo")])
        share_id = list(self.tfs.keys())[0][0]
        self.assertTrue(IMarker.providedBy(share_id))


class TrashTritcaskShelfTests(TrashFileShelfTests):

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TrashTritcaskShelfTests, self).setUp()
        self.trash_dir = self.mktemp('trash')
        self.db = Tritcask(self.trash_dir)
        self.addCleanup(self.db.shutdown)
        self.tfs = TrashTritcaskShelf(TRASH_ROW_TYPE, self.db)


class OsIntegrationTests(FSMTestCase, MockerTestCase):
    """Ensure that the correct os_helper methods are used."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(OsIntegrationTests, self).setUp()
        self.open_file = self.mocker.replace('ubuntuone.platform.open_file')
        self.normpath = self.mocker.replace('ubuntuone.platform.normpath')
        self.listdir = self.mocker.replace('ubuntuone.platform.listdir')

    def test_get_partial_for_writing(self):
        """Test that the get partial does use the correct os_helper method."""
        fd = 'file_descriptor'
        path = 'path'
        mdid = 'id'
        node_id = 'node_id'
        share_id = 'share_id'
        self.fsm._idx_node_id = {(share_id, node_id): mdid}
        self.fsm.fs = {'id': path}
        self.fsm._get_partial_path = self.mocker.mock()
        self.fsm._get_partial_path(path)
        self.mocker.result(path)
        self.open_file(path, 'wb')
        self.mocker.result(fd)
        self.mocker.replay()
        self.assertEqual(
            fd, self.fsm.get_partial_for_writing(node_id, share_id))

    def test_get_partial(self):
        """Test that the get partial does use the correct os_helper method."""
        fd = 'file_descriptor'
        path = 'path'
        mdid = 'id'
        node_id = 'node_id'
        share_id = 'share_id'
        self.fsm._idx_node_id = {(share_id, node_id): mdid}
        self.fsm.fs = {'id': path}
        self.fsm._get_partial_path = self.mocker.mock()
        self.fsm._check_partial = self.mocker.mock()
        # set the expectations
        self.fsm._check_partial(mdid)
        self.mocker.result(True)
        self.fsm._get_partial_path(path)
        self.mocker.result(path)
        self.open_file(path, 'rb')
        self.mocker.result(fd)
        self.mocker.replay()
        self.assertEqual(fd, self.fsm.get_partial(node_id, share_id))

    def test_open_file(self):
        """Test that the open file uses the correct os_helper method."""
        fd = 'file_descriptor'
        mdid = 'id'
        mdobj = dict(is_dir=False, share_id='share_id', path='path')
        self.fsm.get_abspath = self.mocker.mock()
        self.fsm.fs = dict(id=mdobj)
        self.fsm.get_abspath(mdobj['share_id'], mdobj['path'])
        self.mocker.result(mdobj['path'])
        self.open_file(mdobj['path'], 'rb')
        self.mocker.result(fd)
        self.mocker.replay()
        self.assertEqual(fd, self.fsm.open_file(mdid))

    def test_create(self):
        """Test that create uses the correct os_helper functions."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        path = 'path'
        share_id = 'share_id'
        mdid = 'id'
        self.fsm._idx_path = {path: mdid}
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertRaises(ValueError, self.fsm.create, path, share_id)

    def test_set_node_id(self):
        """Test that set_node_id uses the correct os_helper function."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        path = 'path'
        node_id = 'id'
        self.fsm._idx_path = {}
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertRaises(KeyError, self.fsm.set_node_id, path, node_id)

    def test_get_by_path(self):
        """Test that the get_by_path uses the correct os_helper function."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        path = 'path'
        self.fsm._idx_path = {}
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertRaises(KeyError, self.fsm.get_by_path, path)

    def test_set_by_path(self):
        """Test that set_by_path uses the correct os_helper function."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        path = 'path'
        self.fsm._idx_path = {}
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertRaises(KeyError, self.fsm.set_by_path, path)

    def test_move_file(self):
        """Test that move_file uses the correct os_helper function."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        new_share_id = 'id'
        moved_from = 'path_moved_from'
        moved_to = 'path_moved_to'
        self.fsm._idx_path = {}
        # set the expectations
        self.normpath(moved_from)
        self.mocker.result(moved_from)
        self.normpath(moved_to)
        self.mocker.result(moved_to)
        self.mocker.replay()
        self.assertRaises(KeyError, self.fsm.move_file, new_share_id,
                          moved_from, moved_to)

    def test_moved(self):
        """Test that moved uses the correct os_helper function."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        new_share_id = 'id'
        moved_from = 'path_moved_from'
        moved_to = 'path_moved_to'
        self.fsm._idx_path = {}
        # set the expectations
        self.normpath(moved_from)
        self.mocker.result(moved_from)
        self.normpath(moved_to)
        self.mocker.result(moved_to)
        self.mocker.replay()
        self.assertRaises(KeyError, self.fsm.moved, new_share_id, moved_from,
                          moved_to)

    def test_delete_metadata(self):
        """Test that delete_metadata uses the correct os_helper function."""
        mdid = 'id'
        path = 'path'
        mdobj = {'node_id': None}
        self.fsm._idx_path = {path: mdid}
        self.fsm.fs = {mdid: mdobj}
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.fsm.delete_metadata(path)

    def test_delete_file(self):
        """Test that delete_files uses the correct os_helper function."""
        # we do not care about the entire method, lets force and error and
        # test that the methods are called
        mdid = 'id'
        mdobj = {}
        path = 'path'
        self.fsm._idx_path = {path: mdid}
        self.fsm.fs = {mdid: mdobj}
        self.fsm.is_dir = self.mocker.mock()
        self.fsm.eq = self.mocker.mock()
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.fsm.is_dir(path=path)
        self.mocker.result(True)
        self.fsm.eq.add_to_mute_filter(ANY, path=path)
        self.listdir(path)
        self.mocker.throw(ValueError)
        self.mocker.replay()
        self.assertRaises(ValueError, self.fsm.delete_file, path)

    def test_get_mdid_from_args(self):
        """Test that get_mdid_from_args uses the correct os_helper function."""
        mdid = 'id'
        path = 'path'
        parent = None
        self.fsm._idx_path = {path: mdid}
        args = {'path': path}
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertEqual(mdid, self.fsm._get_mdid_from_args(args, parent))

    def test_has_metadata(self):
        """Test that has_metadata uses the correct os_helper function."""
        path = 'path'
        self.fsm._idx_path = {}
        # expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertFalse(self.fsm.has_metadata(path=path))

    def test_dir_content(self):
        """Test that dir_content uses the correct os_helper function."""
        path = 'path'
        mdid = 'id'
        # we are not testing the entire method, just that we cal the correct
        # os_helper, lets pass the wrong value and get an exception
        mdobj = {'is_dir': False}
        self.fsm._idx_path = {mdid: path}
        self.fsm.fs = {mdid: mdobj}
        # set the expectations
        self.normpath(path)
        self.mocker.result(path)
        self.mocker.replay()
        self.assertRaises(KeyError, self.fsm.dir_content, path)


class FSMSearchTestCase(BaseTwistedTestCase):
    """Base test case for FSM."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(FSMSearchTestCase, self).setUp()
        self.shares_dir = self.mktemp('shares')
        self.root_dir = self.mktemp('root')
        self.fsmdir = self.mktemp("fsmdir")
        self.partials_dir = self.mktemp("partials")
        self.tritcask_path = self.mktemp("tritcask")

        self.db = Tritcask(self.tritcask_path)
        self.addCleanup(self.db.shutdown)
        self.fsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                     FakeVolumeManager(self.root_dir), self.db)

        mdid1 = 'id1'
        self.path1 = 'test-root/path/to/file_test'
        mdid2 = 'id2'
        self.path2 = 'test-root/path/to/my_photos'
        self.mdobj1 = {'server_hash': 'asdqwe123', 'share_id': ''}
        self.mdobj2 = {'server_hash': 'asdqwe456', 'share_id': ''}

        serv_missing_mdid = 'serv_missing_id'
        self.serv_missing_path = 'test-root/path/to/other_photos'
        serv_missing_mdobj = {'server_hash': '', 'share_id': ''}

        # create a file in a UDF, no need to add it to the
        # FakeVolumeManager
        udfid1 = 'udfid'
        self.udfpath1 = 'test-udf/path/to/afile'
        self.udfmdobj = {'server_hash': 'asdqwe789',
                         'share_id': 'udf-share-id'}

        shareid1 = 'shareid'
        self.sharepath1 = 'test-shared-to-me/path/to/afile'
        self.sharemdobj = {'server_hash': 'sharehash',
                           'share_id': 'share-share-id'}
        self.fsm.vm.shares['share-share-id'] = {}  # value not used

        self.fsm._idx_path = {self.path1: mdid1, self.path2: mdid2,
                              self.serv_missing_path: serv_missing_mdid,
                              self.udfpath1: udfid1,
                              self.sharepath1: shareid1}
        self.fsm.fs = {mdid1: self.mdobj1, mdid2: self.mdobj2,
                       serv_missing_mdid: serv_missing_mdobj,
                       udfid1: self.udfmdobj,
                       shareid1: self.sharemdobj}

    def test_get_nothing_no_matches(self):
        """Check that we don't give matches for nonexisting queries."""
        self.assertEqual([], self.fsm.get_paths_by_pattern('does not exist'))

    def test_get_paths_by_pattern(self):
        expected = [self.path1]
        result = self.fsm.get_paths_by_pattern('file_test')
        self.assertEqual(result, expected)

    def test_get_paths_by_pattern_case_insensitive(self):
        """Check that we obtain the files that correspond to the filter."""
        expected = [self.path1]
        result = self.fsm.get_paths_by_pattern('FILE_tEsT')
        self.assertEqual(result, expected)

    def test_get_paths_by_pattern_avoid_shares_see_udfs(self):
        """Do not return paths in shares, but do return those in UDFs."""
        expected = [self.udfpath1]
        result = self.fsm.get_paths_by_pattern('afile')
        self.assertEqual(result, expected)

    def test_get_paths_by_pattern_welcome_shares_see_udfs(self):
        """Return paths in shares and UDFs if asked."""
        expected = [self.sharepath1, self.udfpath1]
        result = self.fsm.get_paths_by_pattern('afile', ignore_shares=False)
        self.assertEqual(result, expected)

    def test_get_paths_by_pattern_not_in_server(self):
        """Check that we ignore the files that are not still in the server."""
        expected = [self.path2]
        result = self.fsm.get_paths_by_pattern('photo')
        self.assertEqual(result, expected)

    def test_get_paths_by_pattern_sorted_result(self):
        """Results should be sorted."""
        expected = [self.udfpath1, self.path1]
        result = self.fsm.get_paths_by_pattern('file')
        self.assertNotEqual(result, expected)
        expected = sorted(expected)
        self.assertEqual(result, expected)

    def test_get_paths_from_udf_name(self):
        """Searching on a UDF name should return files in that UDF."""
        expected = [self.udfpath1]
        result = self.fsm.get_paths_by_pattern('udf')
        self.assertEqual(expected, result)

    def test_fuzzy_search(self):
        """Test that searching for path components without slashes works."""
        expected = [self.path1, self.udfpath1]
        result = self.fsm.get_paths_by_pattern('path file')
        self.assertEqual(expected, result)

    def test_fuzzy_search_in_udf(self):
        """Test that searching for path components without slashes works."""
        expected = [self.udfpath1]
        result = self.fsm.get_paths_by_pattern('udf afile')
        self.assertEqual(expected, result)
