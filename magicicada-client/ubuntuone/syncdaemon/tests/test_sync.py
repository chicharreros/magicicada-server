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
"""Tests for Sync."""

from __future__ import with_statement

import contextlib
import copy
from inspect import getmembers, getargspec, ismethod
import logging
import os
import unittest
import uuid

from twisted.internet import defer
from twisted.python.failure import Failure
from ubuntuone.devtools.testcases import skipIfOS

from contrib.testing.testcase import (
    FakeMain,
    FakeVolumeManager,
    BaseTwistedTestCase,
    Listener,
)

from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.platform import (
    make_dir,
    open_file,
    remove_file,
    stat_path,
)
from ubuntuone.syncdaemon.filesystem_manager import FileSystemManager
from ubuntuone.syncdaemon.tritcask import Tritcask
from ubuntuone.syncdaemon.fsm import fsm as fsm_module
from ubuntuone.syncdaemon.sync import FSKey, Sync, SyncStateMachineRunner
from ubuntuone.syncdaemon.volume_manager import Share
from ubuntuone.syncdaemon.event_queue import EventQueue, EVENTS
from ubuntuone.storageprotocol.request import ROOT
from ubuntuone.storageprotocol import delta
from ubuntuone.syncdaemon.marker import MDMarker


class TestSyncClassAPI(unittest.TestCase):
    """Tests that make sure the Sync class has the correct API."""

    def test_handle_signatures(self):
        """Make sure signatures match for the handlers.

        Each handle_<EVENT> should map to an EVENT in event_queue and have the
        same signature.
        """
        handls = (k for k in dict(getmembers(Sync)) if k.startswith('handle_'))
        for handle in handls:
            handler = getattr(Sync, handle, None)
            # it must be a method
            self.assertTrue(ismethod(handler))
            event = EVENTS[handle.replace('handle_', '')]
            spec = getargspec(handler).args[1:]
            # the argspec must also match (same order same variable names)
            self.assertEqual(
                list(event), spec,
                "Handler %s args do not match event args %s" % (handle, event))


class FSKeyTestCase(BaseTwistedTestCase):
    """ Base test case for FSKey """

    @defer.inlineCallbacks
    def setUp(self):
        """ Setup the test """
        yield super(FSKeyTestCase, self).setUp()
        self.shares_dir = self.mktemp('shares')
        self.root_dir = self.mktemp('root')
        self.fsmdir = self.mktemp("fsmdir")
        self.partials_dir = self.mktemp("partials")
        self.tritcask_dir = self.mktemp("tritcask_dir")
        self.db = Tritcask(self.tritcask_dir)
        self.addCleanup(self.db.shutdown)
        self.fsm = FileSystemManager(self.fsmdir, self.partials_dir,
                                     FakeVolumeManager(self.root_dir),
                                     self.db)
        self.eq = EventQueue(self.fsm)
        self.addCleanup(self.eq.shutdown)
        self.fsm.register_eq(self.eq)
        self.share = yield self.create_share('share', 'share_name')
        self.share_path = self.share.path

    @defer.inlineCallbacks
    def create_share(self, share_id, share_name, access_level='Modify'):
        """Create a share."""
        share_path = os.path.join(self.shares_dir, share_name)
        make_dir(share_path, recursive=True)
        share = Share(path=share_path, volume_id=share_id,
                      access_level=access_level)
        yield self.fsm.vm.add_share(share)
        defer.returnValue(share)


class FSKeyTests(FSKeyTestCase):
    """Test FSKey methods."""

    def test_get_mdid(self):
        """simple tests for get_mdid"""
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share", node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        self.assertEqual(mdid, key.get_mdid())
        key = FSKey(self.fsm, share_id='share', node_id='uuid1')
        self.assertEqual(mdid, key.get_mdid())
        key = FSKey(self.fsm, mdid=mdid)
        self.assertEqual(mdid, key.get_mdid())
        # with bad keys
        key = FSKey(self.fsm, share='share', node_id='uuid1')
        self.assertRaises(KeyError, key.get_mdid)
        # 1 valid and 1 invalid key
        key = FSKey(self.fsm, share='share', mdid=mdid)
        self.assertRaises(KeyError, key.get_mdid)

    def test_set(self):
        """test that changes to the key are keeped in _changes until sync"""
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share", node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        key.set(local_hash='a_hash')
        self.assertEqual('a_hash', key._changes['local_hash'])
        key.set(server_hash='a_hash_1')
        self.assertEqual('a_hash_1', key._changes['server_hash'])
        key.sync()
        self.assertEqual({}, key._changes)

    def test_sync(self):
        """test sync of the changes to the fsm"""
        path = os.path.join(self.share.path, 'path')
        mdid = self.fsm.create(path, "share", node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        # change it
        key.set(local_hash='local_hash', server_hash='server_hash')
        # sync!
        key.sync()
        # get the mdobj and check the values
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual('server_hash', mdobj.server_hash)
        self.assertEqual('local_hash', mdobj.local_hash)
        self.assertEqual('share', mdobj.share_id)
        self.assertEqual('uuid1', mdobj.node_id)

    def test_mdid_reset(self):
        """Test for mdid reset after a deletion"""
        # create a node
        path = os.path.join(self.share.path, 'path')
        open_file(path, 'w').close()
        self.fsm.create(path, "share", node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        # fake a conflict and delete the metadata
        key.move_to_conflict()
        key.delete_metadata()
        # create the node again
        self.fsm.create(path, "share", node_id='uuid1')
        key.set(server_hash="")
        key.set(local_hash="")
        # fail no more!
        key.sync()
        # now check the delete_file method
        # fake a conflict and delete the metadata
        key.delete_file()
        # create the node again
        self.fsm.create(path, "share", node_id='uuid1')
        key.set(server_hash="")
        key.set(local_hash="")
        # fail no more!
        key.sync()

    def test_changes_reset(self):
        """Test for _changes reset after a deletion"""
        # create a node
        path = os.path.join(self.share.path, 'path')
        self.fsm.create(path, "share", node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        # set a value and delete the metadata
        key.set(server_hash="server_hash")
        key.delete_metadata()
        # create the node again
        self.fsm.create(path, "share", node_id='uuid1')
        key.sync()
        self.assertNotEqual(
            'server_hash', self.fsm.get_by_path(path).server_hash)
        # now check the delete_file method
        key = FSKey(self.fsm, path=path)
        key.set(server_hash="server_hash1")
        # fake a conflict and delete the metadata
        key.delete_file()
        # create the node again
        self.fsm.create(path, "share", node_id='uuid1')
        key.sync()
        self.assertNotEqual('server_hash1',
                            self.fsm.get_by_path(path).server_hash)

    def test_subscribed_yes_nodecreated(self):
        """Ask if subscribed (yes) for a node that exists."""
        path = os.path.join(self.share.path, 'path')
        self.share.subscribed = True
        self.fsm.create(path, self.share.id, node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        self.assertTrue(key.is_subscribed())

    def test_subscribed_no_nodecreated(self):
        """Ask if subscribed (no) for a node that exists."""
        path = os.path.join(self.share.path, 'path')
        assert not self.share.subscribed
        self.fsm.create(path, self.share.id, node_id='uuid1')
        key = FSKey(self.fsm, path=path)
        self.assertFalse(key.is_subscribed())

    def test_subscribed_yes_newnode(self):
        """Ask if subscribed (yes) for a node that still has no metadata."""
        path = os.path.join(self.share.path, 'path')
        self.share.subscribed = True
        self.fsm.create(path, self.share.id, node_id='uuid1')
        child = os.path.join(path, 'child')
        key = FSKey(self.fsm, path=child)
        self.assertTrue(key.is_subscribed())

    def test_subscribed_no_newnode(self):
        """Ask if subscribed (no) for a node that still has no metadata."""
        path = os.path.join(self.share.path, 'path')
        assert not self.share.subscribed
        self.fsm.create(path, self.share.id, node_id='uuid1')
        child = os.path.join(path, 'child')
        key = FSKey(self.fsm, path=child)
        self.assertFalse(key.is_subscribed())


class BaseSync(BaseTwistedTestCase):
    """Base test infrastructure for Sync."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(BaseSync, self).setUp()
        self.root = self.mktemp('root')
        self.shares = self.mktemp('shares')
        self.data = self.mktemp('data')
        self.partials_dir = self.mktemp('partials_dir')
        self.handler = MementoHandler()
        self.handler.setLevel(logging.ERROR)
        FakeMain._sync_class = Sync
        self.main = FakeMain(root_dir=self.root, shares_dir=self.shares,
                             data_dir=self.data,
                             partials_dir=self.partials_dir)
        self.addCleanup(self.main.shutdown)
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)

    @defer.inlineCallbacks
    def tearDown(self):
        """Clean up."""
        FakeMain._sync_class = None
        for record in self.handler.records:
            exc_info = getattr(record, 'exc_info', None)
            if exc_info is not None:
                raise exc_info[0], exc_info[1], exc_info[2]
        yield super(BaseSync, self).tearDown()

    @defer.inlineCallbacks
    def create_share(self, share_id, share_name, access_level='Modify'):
        """Create a share."""
        share_path = os.path.join(self.shares, share_name)
        share = Share(path=share_path, volume_id=share_id, node_id='shrootid',
                      access_level=access_level, accepted=True)
        yield self.fsm.vm.add_share(share)
        defer.returnValue(share)


class TestUsingRealFSMonitor(BaseSync):
    """Class for tests that require a real FS monitor."""
    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Override self.main from BaseSync."""
        yield super(TestUsingRealFSMonitor, self).setUp()
        # FakeMain sends _monitor_class to EventQueue, which
        # uses platform default monitor when given None:
        self.patch(FakeMain, "_monitor_class", None)
        self.main = FakeMain(root_dir=self.root, shares_dir=self.shares,
                             data_dir=self.data,
                             partials_dir=self.partials_dir)
        self.addCleanup(self.main.shutdown)

    @skipIfOS('win32', 'In windows we can not unlink opened files.')
    def test_deleting_open_files_is_no_cause_for_despair(self):
        """test_deleting_open_files_is_no_cause_for_despair."""
        def cb(_):
            d0 = self.main.wait_for('HQ_HASH_NEW')
            fname = os.path.join(self.root, 'a_file')
            f = open_file(fname, 'w')
            f.write('hola')
            remove_file(fname)
            f.close()

            fname = os.path.join(self.root, 'b_file')
            f = open_file(fname, 'w')
            f.write('chau')
            return d0
        d = self.main.wait_for('SYS_LOCAL_RESCAN_DONE')
        self.main.start()
        d.addCallback(cb)
        return d


class TestSync(BaseSync):
    """Test for Sync."""

    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TestSync, self).setUp()
        self.sync = Sync(main=self.main)
        self.fsm = self.main.fs
        self.handler.setLevel(logging.DEBUG)

    def test_handle_AQ_DOWNLOAD_DOES_NOT_EXIST(self):
        """handle_AQ_DOWNLOAD_DOES_NOT_EXIST."""
        self.called = False

        def faked_nothing(ssmr, event, params, *args):
            """Wrap SSMR.nothing to test."""
            self.called = True
        self.patch(SyncStateMachineRunner, 'nothing', faked_nothing)

        kwargs = dict(share_id='share_id', node_id='node_id')
        self.sync.handle_AQ_DOWNLOAD_DOES_NOT_EXIST(**kwargs)
        self.assertTrue(self.called, 'nothing was called')

    def test_handle_FILE_CREATE_while_LOCAL(self):
        """A FS_FILE_CREATE is received with the node in LOCAL."""
        self.called = False

        def faked_nothing(ssmr, event, params, *args):
            """Wrap SSMR.nothing to test."""
            self.called = True
        self.patch(SyncStateMachineRunner, 'nothing', faked_nothing)

        # create a file and put it in local
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '')
        self.fsm.set_by_mdid(mdid, local_hash='somehash')

        # send the event, and check that it called its .nothing()
        self.sync.handle_FS_FILE_CREATE(somepath)
        self.assertTrue(self.called)

    def test_SV_HASH_NEW_with_file_uploadinterrupted(self):
        """A SV_HASH_NEW is received after upload interrupted."""
        self.called = False

        def fake_meth(_, event, params, hash):
            """Wrap SSMR.reput_file_from_local to test."""
            self.assertEqual(event, 'SV_HASH_NEW')
            self.assertEqual(hash, '')
            self.called = True
        self.patch(SyncStateMachineRunner, 'reput_file_from_local', fake_meth)

        # create a file and put it in local, without server_hash, as
        # if the upload was cut in the middle after the make file
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id')
        self.fsm.set_by_mdid(mdid, local_hash='somehash', crc32='crc32',
                             stat='stat', size='size')

        # send the event with no content and check
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync._handle_SV_HASH_NEW(mdobj.share_id, mdobj.node_id, '')
        self.assertTrue(self.called)

    def test_SV_HASH_NEW_with_special_hash(self):
        """A SV_HASH_NEW is received with hash in None, don't care state."""
        self.called = False

        def fake_meth(_, event, params, hash):
            """Wrap SSMR.reput_file_from_local to test."""
            self.assertEqual(event, 'SV_HASH_NEW')
            self.assertEqual(hash, '')
            self.called = True
        self.patch(SyncStateMachineRunner, 'reput_file_from_local', fake_meth)

        # create a file and leave it as NONE state
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id')
        self.fsm.set_by_mdid(mdid, local_hash='somehsh', server_hash='somehsh',
                             crc32='crc32', stat='stat', size='size')

        # send the event with no content and check
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync._handle_SV_HASH_NEW(mdobj.share_id, mdobj.node_id, '')
        self.assertTrue(self.called)
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.server_hash, '')

    def test_AQ_FILE_NEW_OK_with_md_in_none(self):
        """Created the file, and MD says it's in NONE."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'new_local_file_created',
                   lambda *a: called.extend(a))

        # create the node and set it up
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id')
        assert self.fsm.changed(mdid=mdid) == 'NONE', 'test badly set up'

        # send the event and check args after the ssmr instance
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync.handle_AQ_FILE_NEW_OK(mdobj.share_id, mdid, 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_FILE_NEW_OK', {}, 'new_id', mdid])

    def test_AQ_FILE_NEW_OK_with_md_in_local(self):
        """Created the file, and MD says it's in LOCAL."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'new_local_file_created',
                   lambda *a: called.extend(a))

        # create the node and set it up
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id')
        self.fsm.set_by_mdid(mdid, local_hash='somehash')
        assert self.fsm.changed(mdid=mdid) == 'LOCAL', 'test badly set up'

        # send the event and check args after the ssmr instance
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync.handle_AQ_FILE_NEW_OK(mdobj.share_id, mdid, 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_FILE_NEW_OK', {}, 'new_id', mdid])

    def test_AQ_FILE_NEW_OK_no_md(self):
        """Created the file, but MD is no longer there."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_ok',
                   lambda *a: called.extend(a))

        # send the event and check args after the ssmr instance
        self.sync.handle_AQ_FILE_NEW_OK('share', 'mrker', 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_FILE_NEW_OK', {}, 'new_id', 'mrker'])

    def test_AQ_FILE_NEW_OK_md_says_dir(self):
        """Created the file, but MD says it's now a directory."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_ok',
                   lambda *a: called.extend(a))

        # create the node as a dir
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id', is_dir=True)

        # send the event and check args after the ssmr instance
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync.handle_AQ_FILE_NEW_OK(mdobj.share_id, mdid, 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_FILE_NEW_OK', {}, 'new_id', mdid])

    def test_AQ_DIR_NEW_OK_md_says_file(self):
        """Created the dir, but MD says it's now a file."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_ok',
                   lambda *a: called.extend(a))

        # create the node as a file
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id')

        # send the event and check args after the ssmr instance
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync.handle_AQ_DIR_NEW_OK(mdobj.share_id, mdid, 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_DIR_NEW_OK', {}, 'new_id', mdid])

    def test_AQ_DIR_NEW_OK_no_md(self):
        """Created the dir, but MD is no longer there."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_ok',
                   lambda *a: called.extend(a))

        # send the event and check args after the ssmr instance
        self.sync.handle_AQ_DIR_NEW_OK('share', 'marker', 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_DIR_NEW_OK', {}, 'new_id', 'marker'])

    def test_AQ_DIR_NEW_OK_md_in_NONE(self):
        """Created the dir, and MD says it's in NONE."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'new_local_dir_created',
                   lambda *a: called.extend(a))

        # create the node and set it up
        somepath = os.path.join(self.root, 'somepath')
        mdid = self.fsm.create(somepath, '', node_id='node_id', is_dir=True)
        assert self.fsm.changed(mdid=mdid) == 'NONE', 'test badly set up'

        # send the event and check args after the ssmr instance
        mdobj = self.fsm.get_by_mdid(mdid)
        self.sync.handle_AQ_DIR_NEW_OK(mdobj.share_id, mdid, 'new_id', 'gen')
        self.assertEqual(called[1:], ['AQ_DIR_NEW_OK', {}, 'new_id', mdid])

    def test_AQ_FILE_NEW_ERROR_no_md(self):
        """Error creating the file, MD is no longer there."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_error',
                   lambda *a: called.extend(a))

        # send the event and check args after the ssmr instance
        failure = Failure(Exception('foo'))
        params = {'not_authorized': 'F', 'not_available': 'F'}
        self.sync.handle_AQ_FILE_NEW_ERROR('marker', failure)
        self.assertEqual(
            called[1:], ['AQ_FILE_NEW_ERROR', params, failure, 'marker'])

    def test_AQ_FILE_NEW_ERROR_md_ok(self):
        """Error creating the file, MD is ok."""
        # fake method
        called = []
        realf = SyncStateMachineRunner.filedir_error_in_creation

        def fake(*args):
            """Call the original function, but storing the args."""
            called.extend(args)
            realf(*args)
            SyncStateMachineRunner.filedir_error_in_creation = realf

        SyncStateMachineRunner.filedir_error_in_creation = fake

        # create the node
        somepath = os.path.join(self.root, 'somepath')
        open_file(somepath, 'w').close()
        mdid = self.fsm.create(somepath, '', node_id='node_id')

        # send the event and check args after the ssmr instance
        failure = Failure(Exception('foo'))
        params = {'not_authorized': 'F', 'not_available': 'F'}
        self.sync.handle_AQ_FILE_NEW_ERROR(mdid, failure)
        self.assertEqual(called[1:],
                         ['AQ_FILE_NEW_ERROR', params, failure, mdid])

    def test_AQ_FILE_NEW_ERROR_md_says_dir(self):
        """Error creating the file, MD says it's now a dir."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_error',
                   lambda *a: called.extend(a))

        # create the node as a dir
        somepath = os.path.join(self.root, 'somepath')
        self.fsm.create(somepath, '', node_id='node_id', is_dir=True)

        # send the event and check args after the ssmr instance
        failure = Failure(Exception('foo'))
        params = {'not_authorized': 'F', 'not_available': 'F'}
        self.sync.handle_AQ_FILE_NEW_ERROR('marker', failure)
        self.assertEqual(called[1:],
                         ['AQ_FILE_NEW_ERROR', params, failure, 'marker'])

    def test_AQ_DIR_NEW_ERROR_no_md(self):
        """Error creating the dir, MD is no longer there."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_error',
                   lambda *a: called.extend(a))

        # send the event and check args after the ssmr instance
        failure = Failure(Exception('foo'))
        params = {'not_authorized': 'F', 'not_available': 'F'}
        self.sync.handle_AQ_DIR_NEW_ERROR('marker', failure)
        self.assertEqual(called[1:],
                         ['AQ_DIR_NEW_ERROR', params, failure, 'marker'])

    def test_AQ_DIR_NEW_ERROR_md_ok(self):
        """Error creating the dir, MD is ok."""
        # fake method
        called = []
        realf = SyncStateMachineRunner.filedir_error_in_creation

        def fake(*args):
            """Call the original function, but storing the args."""
            called.extend(args)
            realf(*args)
            SyncStateMachineRunner.filedir_error_in_creation = realf

        SyncStateMachineRunner.filedir_error_in_creation = fake

        # create the node
        somepath = os.path.join(self.root, 'somepath')
        make_dir(somepath)
        mdid = self.fsm.create(somepath, '', node_id='node_id', is_dir=True)

        # send the event and check args after the ssmr instance
        failure = Failure(Exception('foo'))
        params = {'not_authorized': 'F', 'not_available': 'F'}
        self.sync.handle_AQ_DIR_NEW_ERROR(mdid, failure)
        self.assertEqual(called[1:],
                         ['AQ_DIR_NEW_ERROR', params, failure, mdid])

    def test_AQ_DIR_NEW_ERROR_md_says_file(self):
        """Error creating the dir, MD says it's now a file."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'release_marker_error',
                   lambda *a: called.extend(a))

        # create the node as a file
        somepath = os.path.join(self.root, 'somepath')
        self.fsm.create(somepath, '', node_id='node_id')

        # send the event and check args after the ssmr instance
        failure = Failure(Exception('foo'))
        params = {'not_authorized': 'F', 'not_available': 'F'}
        self.sync.handle_AQ_DIR_NEW_ERROR('marker', failure)
        self.assertEqual(called[1:],
                         ['AQ_DIR_NEW_ERROR', params, failure, 'marker'])

    def test_AQ_MOVE_OK_with_node(self):
        """Handle AQ_MOVE_OK having a node."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'clean_move_limbo',
                   lambda *a: called.extend(a))

        # create the node
        somepath = os.path.join(self.root, 'somepath')
        self.fsm.create(somepath, '', node_id='node_id')

        self.sync.handle_AQ_MOVE_OK('', 'node_id', 123)
        self.assertEqual(called[1:], ['AQ_MOVE_OK', {}, '', 'node_id'])

    def test_AQ_MOVE_OK_no_node(self):
        """Handle AQ_MOVE_OK not having a node."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'clean_move_limbo',
                   lambda *a: called.extend(a))

        self.sync.handle_AQ_MOVE_OK('', 'node_id', 123)
        self.assertEqual(called[1:], ['AQ_MOVE_OK', {}, '', 'node_id'])

    def test_AQ_MOVE_ERROR_with_node(self):
        """Handle AQ_MOVE_ERROR having a node."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'clean_move_limbo',
                   lambda *a: called.extend(a))

        # create the node
        somepath = os.path.join(self.root, 'somepath')
        self.fsm.create(somepath, '', node_id='node_id')

        self.sync.handle_AQ_MOVE_ERROR('', 'node_id', 'old_parent_id',
                                       'new_parent_id', 'new_name', 'error')
        self.assertEqual(called[1:], ['AQ_MOVE_ERROR', {}, '', 'node_id'])

    def test_AQ_MOVE_ERROR_no_node(self):
        """Handle AQ_MOVE_ERROR not having a node."""
        # fake method
        called = []
        self.patch(SyncStateMachineRunner, 'clean_move_limbo',
                   lambda *a: called.extend(a))

        self.sync.handle_AQ_MOVE_ERROR('', 'node_id', 'old_parent_id',
                                       'new_parent_id', 'new_name', 'error')
        self.assertEqual(called[1:], ['AQ_MOVE_ERROR', {}, '', 'node_id'])

    def test_SV_FILE_NEW_no_node(self):
        """Handle SV_FILE_NEW not having a node."""
        # fake method
        called = []
        orig = SyncStateMachineRunner.new_file
        self.patch(SyncStateMachineRunner, 'new_file',
                   lambda *a: called.extend(a) or orig(*a))

        # create the parent
        parentpath = os.path.join(self.root, 'somepath')
        self.fsm.create(parentpath, '', node_id='parent_id')

        # call and check
        r = self.sync._handle_SV_FILE_NEW('', 'node_id', 'parent_id', 'name')
        self.assertEqual(called[1:], ['SV_FILE_NEW', {}, '', 'node_id',
                                      'parent_id', 'name'])
        self.assertEqual(r.share_id, '')
        self.assertEqual(r.node_id, 'node_id')
        self.assertEqual(r.path, os.path.join('somepath', 'name'))

    def test_SV_FILE_NEW_node_no_id(self):
        """Handle SV_FILE_NEW having a node without node_id."""
        # fake method
        called = []
        orig = SyncStateMachineRunner.new_server_file_having_local
        self.patch(SyncStateMachineRunner, 'new_server_file_having_local',
                   lambda *a: called.extend(a) or orig(*a))

        # create the node and its parent, to match per path
        parentpath = os.path.join(self.root, 'somepath')
        self.fsm.create(parentpath, '', node_id='parent_id')
        childpath = os.path.join(parentpath, 'name')
        self.fsm.create(childpath, '')

        # call and check
        self.sync._handle_SV_FILE_NEW('', 'node_id', 'parent_id', 'name')
        self.assertEqual(called[1:], ['SV_FILE_NEW', {}, '', 'node_id',
                                      'parent_id', 'name'])

    def test_SV_FILE_NEW_node_same_id(self):
        """Handle SV_FILE_NEW having a node with the same node_id."""
        parentpath = os.path.join(self.root, 'somepath')
        self.fsm.create(parentpath, '', node_id='parent_id')
        childpath = os.path.join(parentpath, 'name')
        self.fsm.create(childpath, '', node_id='node_id')
        r = self.assertRaises(ValueError, self.sync._handle_SV_FILE_NEW,
                              '', 'node_id', 'parent_id', 'name')
        self.assertTrue("same node_id in handle_SV_FILE_NEW" in str(r))

    def test_SV_FILE_NEW_node_different_id(self):
        """Handle SV_FILE_NEW having a node with different node_id."""
        # create the node and its parent, to match per path
        parentpath = os.path.join(self.root, 'somepath')
        self.fsm.create(parentpath, '', node_id='parent_id')
        childpath = os.path.join(parentpath, 'name')
        self.fsm.create(childpath, '', node_id='other_id')

        # fake method
        called = []
        orig = self.fsm.delete_file
        self.patch(self.fsm, 'delete_file',
                   lambda path: called.append(path) or orig(path))

        # call and check
        self.sync._handle_SV_FILE_NEW('', 'node_id', 'parent_id', 'name')
        self.assertEqual(called, [childpath])
        self.assertTrue(self.handler.check_debug("Wanted to apply SV_FILE_NEW",
                                                 "found it with other id"))

    @defer.inlineCallbacks
    def test_handle_FILE_CREATE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and a path for the node
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_FILE_CREATE(somepath)
        self.assertFalse(called)
        should_logged = ("FS_FILE_CREATE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))

    @defer.inlineCallbacks
    def test_handle_DIR_CREATE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and a path for the node
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_DIR_CREATE(somepath)
        self.assertFalse(called)
        should_logged = ("FS_DIR_CREATE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))

    @defer.inlineCallbacks
    def test_handle_FILE_DELETE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and the node to be worked on
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')
        self.fsm.create(somepath, share.volume_id)

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_FILE_DELETE(somepath)
        self.assertFalse(called)
        should_logged = ("FS_FILE_DELETE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))

    @defer.inlineCallbacks
    def test_handle_DIR_DELETE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and the node to be worked on
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')
        self.fsm.create(somepath, share.volume_id)

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_DIR_DELETE(somepath)
        self.assertFalse(called)
        should_logged = ("FS_DIR_DELETE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))

    @defer.inlineCallbacks
    def test_handle_FILE_MOVE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and the node to be worked on
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')
        self.fsm.create(somepath, share.volume_id)

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_FILE_MOVE(somepath, 'otherpath')
        self.assertFalse(called)
        should_logged = ("FS_FILE_MOVE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))

    @defer.inlineCallbacks
    def test_handle_DIR_MOVE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and the node to be worked on
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')
        self.fsm.create(somepath, share.volume_id)

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_DIR_MOVE(somepath, 'otherpath')
        self.assertFalse(called)
        should_logged = ("FS_DIR_MOVE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))

    @defer.inlineCallbacks
    def test_handle_FILE_CLOSE_WRITE_unsubscribed(self):
        """The event is received in a volume that is no longer subscribed."""
        called = []
        self.patch(SyncStateMachineRunner, 'on_event',
                   lambda *a: called.append(True))

        # create the share and the node to be worked on
        share = yield self.create_share('share', 'someshare')
        somepath = os.path.join(share.path, 'somepath')
        self.fsm.create(somepath, share.volume_id)

        # send the event, and check that is not processed by SSMR
        self.sync.handle_FS_FILE_CLOSE_WRITE(somepath)
        self.assertFalse(called)
        should_logged = ("FS_FILE_CLOSE_WRITE", "discarded",
                         "volume not subscribed", repr(somepath))
        self.assertTrue(self.handler.check_debug(*should_logged))


class SyncStateMachineRunnerTestCase(BaseSync):
    """Tests for the SyncStateMachineRunner."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(SyncStateMachineRunnerTestCase, self).setUp()
        self.fsm = self.main.fs
        self.aq = self.main.action_q

        # create a file
        somepath = os.path.join(self.root, 'somepath')
        self.mdid = self.fsm.create(somepath, '', node_id='node_id')

        key = FSKey(self.main.fs, share_id='', node_id='node_id')
        self.ssmr = SyncStateMachineRunner(fsm=self.main.fs, main=self.main,
                                           key=key, logger=None)

        # log config
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        self.ssmr.log.addHandler(self.handler)
        self.addCleanup(self.ssmr.log.removeHandler, self.handler)

    def test_delete_file_without_hash(self):
        """Delete_file can be called without the server hash."""
        self.ssmr.delete_file(event='AQ_DOWNLOAD_ERROR', params=None)

    def test_delete_file_with_hash(self):
        """Delete_file can be called with the server hash."""
        self.ssmr.delete_file(event='AQ_DOWNLOAD_ERROR', params=None,
                              server_hash='')

    def test_validateactualdata_log(self):
        """This method should log detailed info."""
        # create testing data
        somepath = os.path.join(self.root, 'somepath')
        open_file(somepath, "w").close()
        oldstat = stat_path(somepath)
        f = open_file(somepath, "w")
        f.write("new")
        f.close()

        # call the method with args to not match
        self.ssmr.validate_actual_data(somepath, oldstat)

        # check log
        self.assertTrue(self.handler.check_debug("st_ino",
                                                 "st_size", "st_mtime"))

    def test_put_file_stores_info(self):
        """The put_file method should store the info in FSM."""
        self.ssmr.put_file('HQ_HASH_NEW', None, 'hash', 'crc', 'size', 'stt')

        # check the info is stored
        mdobj = self.fsm.get_by_mdid(self.mdid)
        self.assertEqual(mdobj.local_hash, 'hash')
        self.assertEqual(mdobj.crc32, 'crc')
        self.assertEqual(mdobj.size, 'size')
        self.assertEqual(mdobj.stat, 'stt')

    def test_reput_file_stores_info(self):
        """The reput_file method should store the info in FSM."""
        self.ssmr.reput_file('HQ_HASH_NEW', None, 'hash', 'crc', 'size', 'stt')

        # check the info is stored
        mdobj = self.fsm.get_by_mdid(self.mdid)
        self.assertEqual(mdobj.local_hash, 'hash')
        self.assertEqual(mdobj.crc32, 'crc')
        self.assertEqual(mdobj.size, 'size')
        self.assertEqual(mdobj.stat, 'stt')

    @contextlib.contextmanager
    def _test_putcontent_upload_id(self, with_upload_id=False):
        """Generic code to setup and check upload_id in put_content."""
        if with_upload_id:
            self.fsm.set_by_mdid(self.mdid, upload_id='hola')
        else:
            self.fsm.set_by_mdid(self.mdid, upload_id=None)
        called = []

        def my_upload(*args, **kwargs):
            """AQ.upload method that only collect the arguments."""
            called.append((args, kwargs))

        self.patch(self.aq, 'upload', my_upload)
        yield
        self.assertEqual(len(called), 1)
        kwargs = called[0][1]
        if with_upload_id:
            self.assertEqual(kwargs['upload_id'], 'hola')
        else:
            self.assertEqual(kwargs['upload_id'], None)

    def test_put_file_use_upload_id(self):
        """Test that sync calls put_file with the correct args."""
        with self._test_putcontent_upload_id():
            self.ssmr.put_file('HQ_HASH_NEW', None, 'hash',
                               'crc', 'size', 'stt')
        with self._test_putcontent_upload_id(with_upload_id=False):
            self.ssmr.put_file('HQ_HASH_NEW', None, 'hash',
                               'crc', 'size', 'stt')

    def test_reput_file_use_upload_id(self):
        """Test that sync calls reput_file with the correct args."""
        with self._test_putcontent_upload_id():
            self.ssmr.reput_file('HQ_HASH_NEW', None, 'hash',
                                 'crc', 'size', 'stt')
        with self._test_putcontent_upload_id(with_upload_id=False):
            self.ssmr.reput_file('HQ_HASH_NEW', None, 'hash',
                                 'crc', 'size', 'stt')

    def test_reput_file_from_local_use_upload_id(self):
        """Test that sync calls reput_file_from_local with the correct args."""
        self.fsm.set_by_mdid(self.mdid, local_hash='somehash', crc32='crc32',
                             stat='stat', size='size')
        # send the event with no content and check
        with self._test_putcontent_upload_id():
            self.ssmr.reput_file_from_local("SV_HASH_NEW", None, '')
        with self._test_putcontent_upload_id(with_upload_id=False):
            self.ssmr.reput_file_from_local("SV_HASH_NEW", None, '')

    def test_commit_file_without_partial(self):
        """The .partial is lost when commiting the file."""
        # create the partial correctly, and break it!
        self.fsm.create_partial('node_id', '')
        partial_path = self.fsm._get_partial_path(self.fsm.fs[self.mdid])
        remove_file(partial_path)

        # event!
        self.ssmr.commit_file('AQ_DOWNLOAD_COMMIT', None, 'hash')

        # check that we logged, and the node is still in partial
        self.assertTrue(self.handler.check_warning(
                        "Lost .partial when commiting node!", "node_id"))
        mdobj = self.fsm.get_by_mdid(self.mdid)
        self.assertTrue(mdobj.info.is_partial)

    @defer.inlineCallbacks
    def test_new_local_file_created(self):
        """Set the node_id in FSM, and release ok the marker in DeferredMap."""
        # set up FSM and the DeferredMap
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '')
        map_d = self.aq.uuid_map.get('marker')

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        ssmr.new_local_file_created('some event', {}, 'new_id', 'marker')

        # check
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.node_id, 'new_id')
        result = yield map_d
        self.assertEqual(result, 'new_id')

    @defer.inlineCallbacks
    def test_new_local_dir_created(self):
        """Set the node_id in FSM, and release ok the marker in DeferredMap."""
        # set up FSM and the DeferredMap
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=True)
        map_d = self.aq.uuid_map.get('marker')

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        ssmr.new_local_dir_created('some event', {}, 'new_id', 'marker')

        # check
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(mdobj.node_id, 'new_id')
        result = yield map_d
        self.assertEqual(result, 'new_id')

    @defer.inlineCallbacks
    def test_release_marker_ok(self):
        """Just release the marker ok in DeferredMap."""
        # set up the DeferredMap
        map_d = self.aq.uuid_map.get('marker')

        # patch to control the call to dereference the limbos
        called = []
        self.fsm.dereference_ok_limbos = lambda *a: called.append(a)

        # create context and call
        key = FSKey(self.main.fs)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        ssmr.release_marker_ok('some event', {}, 'new_id', 'marker')

        # check
        result = yield map_d
        self.assertEqual(result, 'new_id')
        self.assertEqual(called, [('marker', 'new_id')])

    def test_file_delete_on_server_sends_is_dir(self):
        """delete_on_server sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=False)

        # patch to control the call to key
        called = []

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.delete_on_server(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, False))

    def test_folder_delete_on_server_sends_is_dir(self):
        """delete_on_server sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=True)

        # patch to control the call to key
        called = []

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.delete_on_server(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, True))

    def test_file_deleted_dir_while_downloading_sends_is_dir(self):
        """Deleted parent while file is downloading sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=False)

        # patch to control the call to key
        called = []

        # create context and call
        self.patch(FSKey, "remove_partial", lambda o: None)
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "cancel_download",
                   lambda share_id, node_id: None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.deleted_dir_while_downloading(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, False))

    def test_folder_deleted_dir_while_downloading_sends_is_dir(self):
        """Deleted parent while dir is downloading sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=True)

        # patch to control the call to key
        called = []

        # create context and call
        self.patch(FSKey, "remove_partial", lambda o: None)
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "cancel_download",
                   lambda share_id, node_id: None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.deleted_dir_while_downloading(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, True))

    def test_file_cancel_download_and_delete_on_server_sends_is_dir(self):
        """cancel_download_and_delete_on_server sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=False)

        # patch to control the call to key
        called = []

        # create context and call
        self.patch(FSKey, "remove_partial", lambda o: None)
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "cancel_download",
                   lambda share_id, node_id: None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.cancel_download_and_delete_on_server(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, False))

    def test_folder_cancel_download_and_delete_on_server_sends_is_dir(self):
        """cancel_download_and_delete_on_server sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=True)

        # patch to control the call to key
        called = []

        # create context and call
        self.patch(FSKey, "remove_partial", lambda o: None)
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "cancel_download",
                   lambda share_id, node_id: None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.cancel_download_and_delete_on_server(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, True))

    def test_file_cancel_upload_and_delete_on_server_sends_is_dir(self):
        """cancel_upload_and_delete_on_server sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=False)

        # patch to control the call to key
        called = []

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "cancel_download",
                   lambda share_id, node_id: None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.cancel_upload_and_delete_on_server(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, False))

    def test_folder_cancel_upload_and_delete_on_server_sends_is_dir(self):
        """cancel_upload_and_delete_on_server sends the is_dir flag."""
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '', is_dir=True)

        # patch to control the call to key
        called = []

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        self.patch(self.main.action_q, "cancel_download",
                   lambda share_id, node_id: None)
        self.patch(self.main.action_q, "unlink",
                   lambda *args: called.append(args))

        ssmr.cancel_upload_and_delete_on_server(None, None, somepath)

        # check
        self.assertEqual(called[0][-3:], (mdid, somepath, True))

    @defer.inlineCallbacks
    def test_filedir_error_in_creation(self):
        """Conflict and delete metada, and release the marker with error."""
        # set up FSM and the DeferredMap
        somepath = os.path.join(self.root, 'foo')
        mdid = self.fsm.create(somepath, '')
        map_d = self.aq.uuid_map.get('mrker')

        # patch to control the call to key
        called = []
        self.fsm.move_to_conflict = lambda m: called.append(m)
        self.fsm.delete_metadata = lambda p: called.append(p)

        # create context and call
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        exc = Exception('foo')
        ssmr.filedir_error_in_creation('some event', {}, Failure(exc), 'mrker')

        # check
        self.assertEqual(called, [mdid, somepath])
        try:
            yield map_d
        except Exception, e:
            # silence the received exception
            self.assertEqual(e, exc)
        else:
            # no exception? fail!!
            self.fail("The marker was released without failure!")

    @defer.inlineCallbacks
    def test_release_marker_error(self):
        """Just release the marker with failure in DeferredMap."""
        # set up the DeferredMap
        map_d = self.aq.uuid_map.get('mrker')

        # patch to control the call to dereference the limbos
        called = []
        self.fsm.dereference_err_limbos = lambda *a: called.append(a)

        # create context and call
        key = FSKey(self.main.fs)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        exc = Exception('foo')
        ssmr.release_marker_error('some event', {}, Failure(exc), 'mrker')

        # check
        try:
            yield map_d
        except Exception, e:
            # silence the received exception
            self.assertEqual(e, exc)
            self.assertEqual(called, [('mrker',)])
        else:
            # no exception? fail!!
            self.fail("The marker was released without failure!")

    def test_client_moved_file(self):
        """Client moved a file."""
        # set up FSM and the DeferredMap
        somepath1 = os.path.join(self.root, 'foo')
        somepath2 = os.path.join(self.root, 'bar')
        self.fsm.create(somepath1, '', 'node_id')

        # patch HQ to don't hash the file
        self.main.hash_q.insert = lambda *a: None

        # record the calls
        called = []
        self.main.fs.add_to_move_limbo = lambda *a: called.append(a)
        self.main.action_q.pathlock.fix_path = lambda *a: called.append(a)

        # create context and call
        key = FSKey(self.main.fs, path=somepath1)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        parent_id = FSKey(self.main.fs, path=self.root)['node_id']
        ssmr.client_moved('some event', {}, somepath1, somepath2)
        self.assertEqual(called[0], (tuple(somepath1.split(os.path.sep)),
                                     tuple(somepath2.split(os.path.sep))))
        self.assertEqual(called[1], ('', 'node_id', parent_id, parent_id,
                                     'bar', somepath1, somepath2))

    def test_clean_move_limbo(self):
        """Clean the move limbo with what was called."""
        called = []
        self.main.fs.remove_from_move_limbo = lambda *a: called.append(a)

        # create context and call
        key = FSKey(self.main.fs)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)
        ssmr.clean_move_limbo('some event', {}, 'share_id', 'node_id')
        self.assertEqual(called, [('share_id', 'node_id')])

    def test_new_dir(self):
        """Creates a directory in disk and metadata."""
        # create context
        parent_path = os.path.join(self.root, 'foo')
        self.fsm.create(parent_path, '', 'parent_id', True)
        new_path = os.path.join(parent_path, 'name')
        key = FSKey(self.main.fs, path=new_path)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)

        # log the call to fsm; create will return 'mdid'
        called = []
        self.fsm.create = lambda *a: called.append(a) or 'mdid'
        self.fsm.make_dir = lambda m: called.append(m)

        # call the tested method
        ssmr.new_dir('event', {}, '', 'node_id', 'parent_id', 'name')

        # check the create and the make_dir
        self.assertEqual(called, [(new_path, '', 'node_id', True), 'mdid'])

    def test_new_new_server_file_having_local(self):
        """Set the node_id to the node."""
        # create context
        somepath = os.path.join(self.root, 'foo')
        self.fsm.create(somepath, '')
        key = FSKey(self.main.fs, path=somepath)
        ssmr = SyncStateMachineRunner(fsm=self.fsm, main=self.main,
                                      key=key, logger=None)

        # log the call to fsm
        called = []
        self.fsm.set_node_id = lambda *a: called.append(a)

        # call the tested method and check
        ssmr.new_server_file_having_local(
            'event', {}, '', 'node_id', 'parent_id', 'name')
        self.assertEqual(called, [(somepath, 'node_id')])


class FakedState(object):
    """A faked state."""

    def __init__(self, action_func):
        self.action_func = action_func
        self.values = []

    def get_transition(self, event_name, parameters):
        """A fake get_transition."""

        class A(object):
            pass

        result = A()
        result.action_func = self.action_func
        result.target = self.values
        return result


class StateMachineRunnerTestCase(BaseTwistedTestCase):
    """Test suite for StateMachineRunner."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(StateMachineRunnerTestCase, self).setUp()

        logger = logging.getLogger('ubuntuone.SyncDaemon.sync')
        self.smr = fsm_module.StateMachineRunner(None, logger)
        self.handler = MementoHandler()
        self.handler.setLevel(logging.INFO)
        logger.addHandler(self.handler)

    def test_on_event_logs_info(self):
        """Test proper logging in on_event."""
        event_name = 'TEST_EVENT'
        parameters = object()
        action_func = 'SOME_ACTION_FUNC'
        setattr(self.smr, action_func, lambda *_: None)
        self.patch(self.smr, 'get_state', lambda: FakedState(action_func))
        self.smr.on_event(event_name=event_name, parameters=parameters)

        # assert over logging
        self.assertTrue(len(self.handler.records), 1)

        record = self.handler.records[0]
        self.assertEqual(record.levelno, logging.INFO)

        msg = record.message
        error = '%s must be in record.message (%s)'
        self.assertTrue(event_name in msg, error % (event_name, msg))
        self.assertTrue(str(parameters) in msg, error % (parameters, msg))
        self.assertTrue(action_func in msg, error % (action_func, msg))


class TestNewGenerationOnOperations(BaseSync):
    """Test we handle ok the new generation in some operations."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TestNewGenerationOnOperations, self).setUp()
        self.sync = Sync(main=self.main)
        self.handler.setLevel(logging.DEBUG)

        key = FSKey(self.main.fs, share_id='', node_id='node_id')
        self.ssmr = SyncStateMachineRunner(fsm=self.main.fs, main=self.main,
                                           key=key, logger=None)
        self.vm = self.main.vm

    def test_handle_AQ_UNLINK_OK(self):
        """Test that AQ_UNLINK_OK calls the generation handler."""
        called = []
        self.patch(SyncStateMachineRunner, 'update_generation',
                   lambda s, *a: called.append(a))

        d = dict(share_id='volume_id', node_id='node_id', parent_id='parent',
                 new_generation=77, was_dir=False, old_path="test path")
        self.sync.handle_AQ_UNLINK_OK(**d)
        self.assertEqual(called, [('volume_id', "node_id", 77)])

    def test_handle_AQ_MOVE_OK(self):
        """Test that AQ_MOVE_OK calls the generation handler."""
        called = []
        self.patch(SyncStateMachineRunner, 'update_generation',
                   lambda s, *a: called.append(a))

        d = dict(share_id='volume_id', node_id='node_id', new_generation=32)
        self.sync.handle_AQ_MOVE_OK(**d)
        self.assertEqual(called, [('volume_id', "node_id", 32)])

    def test_handle_AQ_UPLOAD_FINISHED(self):
        """Test that AQ_UPLOAD_FINISHED calls the generation handler."""
        called = []
        self.patch(SyncStateMachineRunner, 'update_generation',
                   lambda s, *a: called.append(a))

        d = dict(share_id='volume_id', node_id='node_id',
                 hash='hash', new_generation=15)
        self.sync.handle_AQ_UPLOAD_FINISHED(**d)
        self.assertEqual(called, [('volume_id', "node_id", 15)])

    def test_handle_AQ_FILE_NEW_OK(self):
        """Test that AQ_FILE_NEW_OK calls the generation handler."""
        called = []
        self.patch(SyncStateMachineRunner, 'update_generation',
                   lambda s, *a: called.append(a))

        d = dict(marker='mdid', new_id='new_id', new_generation=12,
                 volume_id=ROOT)
        self.sync.handle_AQ_FILE_NEW_OK(**d)
        self.assertEqual(called, [(ROOT, "new_id", 12)])

    def test_handle_AQ_DIR_NEW_OK(self):
        """Test that AQ_DIR_NEW_OK calls the generation handler."""
        called = []
        self.patch(SyncStateMachineRunner, 'update_generation',
                   lambda s, *a: called.append(a))

        d = dict(marker='mdid', new_id='new_id', new_generation=17,
                 volume_id=ROOT)
        self.sync.handle_AQ_DIR_NEW_OK(**d)
        self.assertEqual(called, [(ROOT, "new_id", 17)])

    def test_checknewvol_no_volume(self):
        """Log warning if volume does not exist."""
        not_existant_vol = str(uuid.uuid4())
        self.ssmr.update_generation(not_existant_vol, "node_id", 77)
        self.assertTrue(self.handler.check_warning('Volume not found'))

    def test_checknewvol_smaller_gen(self):
        """Only log debug if new generation smaller than current."""
        self.vm.update_generation(ROOT, 15)
        self.ssmr.update_generation(ROOT, "node_id", 14)
        self.assertTrue(self.handler.check_info(
                        'Got smaller or equal generation'))

    def test_checknewvol_same_gen(self):
        """Only log debug if new generation equal than current."""
        self.vm.update_generation(ROOT, 15)
        self.ssmr.update_generation(ROOT, "node_id", 15)
        self.assertTrue(self.handler.check_info(
                        'Got smaller or equal generation'))

    def test_checknewvol_gen_current_plus_one(self):
        """Set new volume generation if current plus one."""
        self.vm.update_generation(ROOT, 15)
        self.ssmr.update_generation(ROOT, "node_id", 16)
        self.assertEqual(self.vm.get_volume(ROOT).generation, 16)
        self.assertTrue(self.handler.check_info('Updating current generation'))

    def test_checknewvol_lot_bigger(self):
        """Ask for new delta if new generation is much bigger than current."""
        # set up
        called = []
        self.main.action_q.get_delta = lambda *a: called.append(a)
        self.vm.update_generation(ROOT, 15)

        # call the method
        self.ssmr.update_generation(ROOT, "node_id", 17)

        # check that generation didn't change, we asked for delta, and logged
        self.assertEqual(self.vm.get_volume(ROOT).generation, 15)
        self.assertEqual(called, [(ROOT, 15)])
        self.assertTrue(self.handler.check_info('Generation much bigger'))

    def test_checknewvol_new_gen_is_None(self):
        """Log warning if volume does not exist."""
        self.vm.update_generation(ROOT, 1)
        self.ssmr.update_generation(ROOT, "node_id", None)
        self.assertTrue(self.handler.check_debug(
                        'Client not ready for generations'))

    def test_checknewvol_volume_gen_is_None(self):
        """Log warning if volume does not exist."""
        assert self.vm.get_volume(ROOT).generation is None
        self.ssmr.update_generation(ROOT, "node_id", 15)
        self.assertTrue(self.handler.check_debug(
                        'Client not ready for generations'))

    def test_check_generation_on_node_set(self):
        """Check that we update the generation of the node."""
        # create the fake file
        self.main.vm._got_root("parent_id")
        self.sync._handle_SV_FILE_NEW(ROOT, "node_id", "parent_id", "file")

        # update generation
        self.ssmr.update_generation(ROOT, "node_id", 15)

        # test
        node = self.main.fs.get_by_node_id(ROOT, "node_id")
        self.assertEqual(node.generation, 15)

    def test_check_generation_on_node_set_wont_fail(self):
        """Check that if there is no node we dont fail."""
        # update generation
        self.ssmr.update_generation(ROOT, "node_id", 15)

    def test_save_generation_after_seting_node_id(self):
        """Test that we call update_generation after the ssmr handler."""
        root_id = uuid.uuid4()
        self.main.vm._got_root(root_id)
        mdobj = self.main.fs.get_by_node_id(ROOT, root_id)
        path = os.path.join(
            self.main.fs.get_abspath(ROOT, mdobj.path), "file")
        self.main.fs.create(path=path, share_id=ROOT, is_dir=False)
        node = self.main.fs.get_by_path(path)
        d = dict(marker=MDMarker(node.mdid),
                 new_id='new_id', new_generation=12,
                 volume_id=ROOT)
        self.sync.handle_AQ_FILE_NEW_OK(**d)

        # test
        node = self.main.fs.get_by_node_id(ROOT, "new_id")
        self.assertEqual(node.generation, 12)


class TestSyncDelta(BaseSync):
    """Base class for testing sync stuff related to deltas."""

    @defer.inlineCallbacks
    def setUp(self):
        """Do the setUp."""
        yield super(TestSyncDelta, self).setUp()
        self.sync = Sync(main=self.main)
        self.root_id = root_id = "roootid"
        self.main.vm._got_root(root_id)

        self.filetxtdelta = delta.FileInfoDelta(
            generation=5, is_live=True, file_type=delta.FILE,
            parent_id=root_id, share_id=ROOT, node_id=uuid.uuid4(),
            name=u"fileñ.txt", is_public=False, content_hash="hash",
            crc32=1, size=10, last_modified=0)

        self.dirdelta = delta.FileInfoDelta(
            generation=6, is_live=True, file_type=delta.DIRECTORY,
            parent_id=root_id, share_id=ROOT, node_id=uuid.uuid4(),
            name=u"directory_ñ", is_public=False, content_hash="hash",
            crc32=1, size=10, last_modified=0)

    def create_filetxt(self, dt=None):
        """Create a file based on self.filetxtdelta."""
        if dt is None:
            dt = self.filetxtdelta
        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)
        path = os.path.join(
            self.main.fs.get_abspath(dt.share_id, mdobj.path),
            dt.name.encode("utf-8"))
        self.main.fs.create(
            path=path, share_id=dt.share_id, node_id=dt.node_id,
            is_dir=False)
        node = self.main.fs.get_by_node_id(dt.share_id, dt.node_id)
        self.main.fs.set_by_mdid(node.mdid, generation=dt.generation)
        return node

    def create_dir(self, dt=None):
        """Create a directory based on self.dirdelta."""
        if dt is None:
            dt = self.dirdelta
        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)
        path = os.path.join(
            self.main.fs.get_abspath(dt.share_id, mdobj.path),
            dt.name.encode("utf-8"))
        self.main.fs.create(
            path=path, share_id=dt.share_id, node_id=dt.node_id,
            is_dir=True)
        node = self.main.fs.get_by_node_id(dt.share_id, dt.node_id)
        self.main.fs.set_by_mdid(node.mdid, generation=dt.generation)


class TestHandleAqDeltaOk(TestSyncDelta):
    """Test case for Sync.handle_AQ_DELTA_OK.

    Assert that handles the recepcion of a new delta and applies all the
    changes that came from it.

    """

    def test_not_full(self):
        """If we dont have a full delta, we need to ask for another one."""
        sync = Sync(main=self.main)
        called = []
        self.main.action_q.get_delta = lambda *a: called.append(a)

        kwargs = dict(volume_id=ROOT, delta_content=[], end_generation=11,
                      full=False, free_bytes=0)
        sync.handle_AQ_DELTA_OK(**kwargs)

        self.assertEqual(called, [(ROOT, 11)])

    def test_free_bytes_set(self):
        """The volume gets the free bytes set."""
        sync = Sync(main=self.main)

        kwargs = dict(volume_id=ROOT, delta_content=[], end_generation=11,
                      full=True, free_bytes=10)
        sync.handle_AQ_DELTA_OK(**kwargs)

        self.assertEqual(self.main.vm.get_volume(ROOT).free_bytes, 10)

    def test_end_generation_set(self):
        """The volume gets the end generation set."""
        sync = Sync(main=self.main)

        kwargs = dict(volume_id=ROOT, delta_content=[], end_generation=11,
                      full=True, free_bytes=10)
        sync.handle_AQ_DELTA_OK(**kwargs)

        self.assertEqual(self.main.vm.get_volume(ROOT).generation, 11)

    def test_node_generation_older_skip(self):
        """The node does not get the new generation set."""
        self.create_filetxt()

        dt2 = copy.copy(self.filetxtdelta)
        dt2.generation = self.filetxtdelta.generation - 1
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        node = self.main.fs.get_by_node_id(ROOT, self.filetxtdelta.node_id)
        self.assertEqual(node.generation, self.filetxtdelta.generation)

    def test_new_file(self):
        """Make sure a live file in the delta is in fs after executed."""
        deltas = [self.filetxtdelta]
        kwargs = dict(volume_id=ROOT, delta_content=deltas, end_generation=11,
                      full=True, free_bytes=10)
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the file is created
        node = self.main.fs.get_by_node_id(ROOT, self.filetxtdelta.node_id)
        self.assertEqual(node.path, self.filetxtdelta.name.encode('utf8'))
        self.assertEqual(node.is_dir, False)
        self.assertEqual(node.generation, self.filetxtdelta.generation)

    def test_existing_file_still_there(self):
        """A file will still exist after a delta arrives."""
        self.create_filetxt()

        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.generation = 8
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the file is still there
        node = self.main.fs.get_by_node_id(ROOT, self.filetxtdelta.node_id)
        self.assertEqual(node.generation, dt2.generation)

    def test_not_new_file_while_in_trash(self):
        """Don't issue SV_FILE_NEW if file is in trash."""
        # create the file and move it to trash
        node = self.create_filetxt()
        self.main.fs.delete_to_trash(node.mdid, self.root_id)

        # flag the SV_FILE_NEW calling
        called = []
        self.sync._handle_SV_FILE_NEW = lambda *a: called.append(True)

        kwargs = dict(volume_id=ROOT, delta_content=[self.filetxtdelta],
                      end_generation=11, full=True, free_bytes=10)
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that we didn't call the method
        self.assertFalse(called)

    def test_existing_file_dead(self):
        """The handler for SV_FILE_DELETED is called"""
        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.is_live = False
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_FILE_DELETED = (
            lambda *args, **kwargs: called.append((args, kwargs)))
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handler is called
        self.assertTrue(called)

    def test_new_dir(self):
        """Make sure a live dir in the delta is in fs after executed."""
        deltas = [self.dirdelta]
        kwargs = dict(volume_id=ROOT, delta_content=deltas, end_generation=11,
                      full=True, free_bytes=10)
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the dir is created
        node = self.main.fs.get_by_node_id(ROOT, self.dirdelta.node_id)
        self.assertEqual(node.path, self.dirdelta.name.encode('utf8'))
        self.assertEqual(node.is_dir, True)
        self.assertEqual(node.generation, self.dirdelta.generation)

    def test_sv_hash_new_called_for_file(self):
        """The handler for SV_HASH_NEW is called"""
        self.create_filetxt()

        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.generation = self.filetxtdelta.generation + 1
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_HASH_NEW = (
            lambda *args, **kwargs: called.append((args, kwargs)))
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handler is called
        self.assertTrue(called)

    def test_sv_hash_new_not_called_for_dir(self):
        """The handler for SV_HASH_NEW is not called"""
        self.create_dir()

        # send a new delta
        dt2 = copy.copy(self.dirdelta)
        dt2.generation = self.dirdelta.generation + 1
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_HASH_NEW = (
            lambda *args, **kwargs: called.append((args, kwargs)))
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handler is called
        self.assertFalse(called)

    def test_sv_moved_called(self):
        """The handler for SV_MOVED is called"""
        self.create_dir()
        self.create_filetxt()

        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.generation = self.dirdelta.generation + 1
        dt2.parent_id = self.dirdelta.node_id
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_MOVED = (
            lambda *args, **kwargs: called.append((args, kwargs)))
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handler is called
        self.assertTrue(called)

    def test_sv_moved_called_name(self):
        """The handler for SV_MOVED is called"""
        self.create_dir()
        self.create_filetxt()

        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.generation = self.dirdelta.generation + 1
        dt2.name = "newname"
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_MOVED = (
            lambda *args, **kwargs: called.append((args, kwargs)))
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handler is called
        self.assertTrue(called)

    def test_sv_moved_not_called(self):
        """The handler for SV_MOVED is not called"""
        self.create_dir()
        self.create_filetxt()

        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.generation = self.dirdelta.generation + 1
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_MOVED = (
            lambda *args, **kwargs: called.append((args, kwargs)))
        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handler is called
        self.assertFalse(called)

    def test_exception_logged(self):
        """We call self.logger.exception on error."""
        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.is_live = False
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        self.sync._handle_SV_FILE_DELETED = lambda *args, **kwargs: 1/0
        handler = MementoHandler()
        handler.setLevel(logging.ERROR)
        self.sync.logger.addHandler(handler)

        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check log
        self.assertEqual(len(handler.records), 1)
        log_msg = handler.records[0].message
        self.assertTrue("can't be applied." in log_msg)
        self.sync.logger.removeHandler(handler)
        self.handler.records = []

    def test_handle_deletes_last(self):
        """The handler for SV_FILE_DELETED is not called last

        If we reorder deletes we will get a fake conflict when a
        delete and move that overwrites the deleted file arrives.
        """

        self.create_filetxt()
        self.create_dir()

        # send a new delta
        dt2 = copy.copy(self.dirdelta)
        dt2.generation = 20
        dt2.is_live = False

        dt3 = copy.copy(self.filetxtdelta)
        dt3.generation = 21

        kwargs = dict(volume_id=ROOT, delta_content=[dt2, dt3],
                      end_generation=22,
                      full=True, free_bytes=10)
        called = []
        self.sync._handle_SV_HASH_NEW = (
            lambda *args, **kwargs: called.append("hash"))
        self.sync._handle_SV_FILE_DELETED = (
            lambda *args, **kwargs: called.append("delete"))

        self.sync.handle_AQ_DELTA_OK(**kwargs)

        # check that the handlers are called in order
        self.assertEqual(called, ['delete', 'hash'])

    def test_exception_mark_node_as_dirty(self):
        """We mark the node as dirty and send an event on error."""
        called = []
        self.sync.mark_node_as_dirty = lambda *a: called.append(a)

        # send a new delta
        dt2 = copy.copy(self.filetxtdelta)
        dt2.is_live = False
        kwargs = dict(volume_id=ROOT, delta_content=[dt2], end_generation=11,
                      full=True, free_bytes=10)
        self.sync._handle_SV_FILE_DELETED = lambda *args, **kwargs: 1/0

        # send the delta and check
        self.sync.handle_AQ_DELTA_OK(**kwargs)
        self.assertEqual(called, [(dt2.share_id, dt2.node_id)])
        self.handler.records = []

    def test_dirty_node_is_dirty(self):
        """When a node is marked dirty, it's marked in FSM."""
        listener = Listener()
        self.main.event_q.subscribe(listener)
        self.create_filetxt()
        dt = self.filetxtdelta
        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)

        # call to mark it as dirty
        self.sync.mark_node_as_dirty(mdobj.share_id, mdobj.node_id)

        # check that it's marked as dirty
        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)
        self.assertTrue(mdobj.dirty)

    def test_dirty_node_sends_event_ok(self):
        """When a node is marked dirty, an event should fly with node info."""
        listener = Listener()
        self.main.event_q.subscribe(listener)
        self.create_filetxt()
        dt = self.filetxtdelta
        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)

        # call to mark it as dirty
        self.sync.mark_node_as_dirty(mdobj.share_id, mdobj.node_id)

        # check event
        kwargs = dict(volume_id=mdobj.share_id, node_id=mdobj.node_id,
                      path=mdobj.path, mdid=mdobj.mdid)
        self.assertTrue(("SYS_BROKEN_NODE", kwargs) in listener.events)

    def test_dirty_node_sends_event_nonode(self):
        """When a node is marked dirty, an event should fly, no node."""
        listener = Listener()
        self.main.event_q.subscribe(listener)

        # call to mark it as dirty
        self.sync.mark_node_as_dirty('volume', 'node')

        # check event
        kwargs = dict(volume_id='volume', node_id='node', path=None, mdid=None)
        self.assertTrue(("SYS_BROKEN_NODE", kwargs) in listener.events)

    def test_dirty_node_logs_special(self):
        """When a node is marked dirty, it should log in a special handler."""
        handler = MementoHandler()
        log = logging.getLogger('ubuntuone.SyncDaemon.BrokenNodes')
        log.addHandler(handler)

        # create the node
        self.create_filetxt()
        dt = self.filetxtdelta
        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)

        # call to mark it as dirty
        self.sync.mark_node_as_dirty(mdobj.share_id, mdobj.node_id)

        # check that log has the title and at least share and node
        self.assertTrue(handler.check_info("Broken node",
                                           mdobj.share_id, mdobj.node_id))


class TestHandleAqRescanFromScratchOk(TestSyncDelta):
    """Sync.handle_AQ_RESCAN_FROM_SCRATCH_OK handles rescan from scratch."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup."""
        yield super(TestHandleAqRescanFromScratchOk, self).setUp()

        self.rootdt = delta.FileInfoDelta(
            generation=5, is_live=True, file_type=delta.DIRECTORY,
            parent_id=None, share_id=ROOT, node_id=self.root_id,
            name="/", is_public=False, content_hash="hash",
            crc32=1, size=10, last_modified=0)

    def test_calls_handle_aq_delta_ok(self):
        """Make sure it calls handle_AQ_DELTA_OK."""
        called = []
        self.sync.handle_AQ_DELTA_OK = (
            lambda *args, **kwargs: called.append((args, kwargs)))

        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(ROOT, [self.rootdt], 0, 0)

        # we must remove root node for delta
        self.assertEqual(called, [((ROOT, [], 0, True, 0), {})])

    def test_deletes_file_not_in_delta(self):
        """Files not in delta should be deleted."""
        self.create_filetxt()

        called = []
        self.sync._handle_SV_FILE_DELETED = (
            lambda *args, **kwargs: called.append((args, kwargs)))

        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(ROOT, [self.rootdt],
                                                   100, 100)

        args = (ROOT, self.filetxtdelta.node_id, False)
        self.assertEqual(called, [(args, {})])

    def test_deletes_file_in_delta(self):
        """Files in delta should not be deleted."""
        self.create_filetxt()

        called = []
        self.sync._handle_SV_FILE_DELETED = \
            lambda *args, **kwargs: called.append((args, kwargs))

        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(
            ROOT, [self.rootdt, self.filetxtdelta], 100, 100)

        self.assertEqual(called, [])

    def test_dont_delete_if_node_id_is_none(self):
        """Make sure we dont fail if we have a node without node_id."""
        dt = copy.copy(self.filetxtdelta)
        dt.name = "anotherfile"
        dt.node_id = "anothernodeid"

        mdobj = self.main.fs.get_by_node_id(dt.share_id, dt.parent_id)
        path = os.path.join(
            self.main.fs.get_abspath(dt.share_id, mdobj.path), dt.name)
        self.main.fs.create(
            path=path, share_id=dt.share_id, is_dir=False)

        called = []
        self.sync._handle_SV_FILE_DELETED = \
            lambda *args, **kwargs: called.append((args, kwargs))

        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(
            ROOT, [self.rootdt], 100, 100)

        self.assertEqual(called, [])

    def test_deletes_sorted_by_path(self):
        """Make sure deletes get sorted by path reversed."""
        self.create_dir()
        dt = copy.copy(self.filetxtdelta)
        dt.parent_id = self.dirdelta.node_id
        self.create_filetxt(dt)

        called = []
        self.sync._handle_SV_FILE_DELETED = \
            lambda *args: called.append(args)

        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(
            ROOT, [self.rootdt], 100, 100)

        self.assertEqual(called, [(ROOT, dt.node_id, False),
                                  (ROOT, self.dirdelta.node_id, True)])


class TestChunkedRescanFromScratchOk(TestHandleAqRescanFromScratchOk):

    def test_change_in_the_middle(self):
        """Chunked delta handling with a change in the middle."""
        directories = [self.rootdt]
        files = []
        for i in range(1, 5):
            d = delta.FileInfoDelta(
                generation=i, is_live=True, file_type=delta.DIRECTORY,
                parent_id=self.root_id, share_id=ROOT, node_id=uuid.uuid4(),
                name=u"directory_ñ_%d" % i, is_public=False,
                content_hash="hash", crc32=i, size=10, last_modified=0)
            directories.append(d)
            self.create_dir(dt=d)
        for i in range(6, 10):
            f = delta.FileInfoDelta(
                generation=i, is_live=True, file_type=delta.FILE,
                parent_id=self.root_id, share_id=ROOT, node_id=uuid.uuid4(),
                name=u"fileñ.%d.txt" % i, is_public=False, content_hash="hash",
                crc32=i, size=10, last_modified=0)
            f.parent_id = directories[i-5].node_id
            self.create_filetxt(dt=f)
            files.append(f)

        called = []
        orig__handle_SV_FILE_DELETED = self.sync._handle_SV_FILE_DELETED
        self.sync._handle_SV_FILE_DELETED = lambda *args: called.append(args)
        self.sync._handle_SV_FILE_DELETED = lambda *args: called.append(args)

        # build a delta with files[3] node missing, caused by a change by other
        # client while building the delta
        fake_delta = directories + files[0:2] + files[3:5]
        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(
            ROOT, fake_delta, files[-1].generation, 100)

        self.assertEqual(
            called, [(ROOT, files[2].node_id, False)])

        # call the real delete method.
        orig__handle_SV_FILE_DELETED(*called[0])

        # now fake the get_delta for the changed node that was missing in the
        # rescan_from_scratch
        changed_file = files[2]
        changed_file.generation = files[-1].generation+1
        changed_file.hash = "hash-1"

        called = []
        self.sync._handle_SV_FILE_DELETED = (
            lambda *args: called.append(("delete",) + args))
        self.sync._handle_SV_MOVED = (
            lambda *args: called.append(("move",) + args))
        self.sync._handle_SV_HASH_NEW = (
            lambda *args: called.append(("new_hash",) + args))
        self.sync._handle_SV_FILE_NEW = (
            lambda *args: called.append(("new_file",) + args))
        self.sync._handle_SV_DIR_NEW = (
            lambda *args: called.append(("new_dir",) + args))

        self.sync.handle_AQ_DELTA_OK(
            ROOT, [changed_file], changed_file.generation, True, 100)
        expected = [
            ("new_file", ROOT, changed_file.node_id, changed_file.parent_id,
             changed_file.name.encode("utf-8"))]
        self.assertEqual(called, expected)

    def test_move_in_the_middle(self):
        """Chunked delta handling with a move in the middle."""
        directories = [self.rootdt]
        files = []
        for i in range(1, 5):
            d = delta.FileInfoDelta(
                generation=i, is_live=True, file_type=delta.DIRECTORY,
                parent_id=self.root_id, share_id=ROOT, node_id=uuid.uuid4(),
                name=u"directory_ñ_%d" % i, is_public=False,
                content_hash="hash", crc32=i, size=10, last_modified=0)
            directories.append(d)
            self.create_dir(dt=d)
        for i in range(6, 10):
            f = delta.FileInfoDelta(
                generation=i, is_live=True, file_type=delta.FILE,
                parent_id=self.root_id, share_id=ROOT, node_id=uuid.uuid4(),
                name=u"fileñ.%d.txt" % i, is_public=False, content_hash="hash",
                crc32=i, size=10, last_modified=0)
            f.parent_id = directories[i-5].node_id
            self.create_filetxt(dt=f)
            files.append(f)

        called = []
        orig__handle_SV_FILE_DELETED = self.sync._handle_SV_FILE_DELETED
        self.sync._handle_SV_FILE_DELETED = lambda *args: called.append(args)
        self.sync._handle_SV_FILE_DELETED = lambda *args: called.append(args)

        # build a delta with files[3] node missing, caused by a change by other
        # client while building the delta
        fake_delta = directories + files[0:2] + files[3:5]
        self.sync.handle_AQ_RESCAN_FROM_SCRATCH_OK(
            ROOT, fake_delta, files[-1].generation, 100)

        self.assertEqual(called, [
            (ROOT, files[2].node_id, False)])

        # call the real delete method.
        orig__handle_SV_FILE_DELETED(*called[0])

        # now fake the get_delta for the moved node that was missing in the
        # rescan_from_scratch
        changed_file = files[2]
        changed_file.generation = files[-1].generation+1
        changed_file.parent_id = directories[1].node_id

        called = []
        self.sync._handle_SV_FILE_DELETED = (
            lambda *args: called.append(("delete",) + args))
        self.sync._handle_SV_MOVED = (
            lambda *args: called.append(("move",) + args))
        self.sync._handle_SV_HASH_NEW = (
            lambda *args: called.append(("new_hash",) + args))
        self.sync._handle_SV_FILE_NEW = (
            lambda *args: called.append(("new_file",) + args))
        self.sync._handle_SV_DIR_NEW = (
            lambda *args: called.append(("new_dir",) + args))

        self.sync.handle_AQ_DELTA_OK(
            ROOT, [changed_file], changed_file.generation, True, 100)
        expected = [
            ("new_file", ROOT, changed_file.node_id, changed_file.parent_id,
             changed_file.name.encode("utf-8"))]
        self.assertEqual(called, expected)


class TestSyncEvents(TestSyncDelta):
    """Testing sync stuff related to events."""

    @defer.inlineCallbacks
    def setUp(self):
        """Do the setUp."""
        yield super(TestSyncEvents, self).setUp()
        self.sync = Sync(main=self.main)
        self.handler.setLevel(logging.DEBUG)

        key = FSKey(self.main.fs, share_id='', node_id='node_id')
        self.ssmr = SyncStateMachineRunner(fsm=self.main.fs, main=self.main,
                                           key=key, logger=None)
        self.vm = self.main.vm
        self.listener = Listener()
        self.main.event_q.subscribe(self.listener)

    def test_server_new_file_sends_event(self):
        """When a new file is created on the server, an event is sent."""
        # create the fake file
        parent_id = self.root_id
        self.sync._handle_SV_FILE_NEW(ROOT, "node_id", parent_id, "file")

        # check event
        kwargs = dict(volume_id=ROOT, node_id='node_id', parent_id=parent_id,
                      name="file")
        self.assertIn(("SV_FILE_NEW", kwargs), self.listener.events)

    def test_server_new_dir_sends_event(self):
        """When a new directory is created on the server, an event is sent."""
        # create the fake dir
        parent_id = self.root_id
        self.sync._handle_SV_DIR_NEW(ROOT, "node_id", parent_id, "file")

        # check event
        kwargs = dict(volume_id=ROOT, node_id='node_id', parent_id=parent_id,
                      name="file")
        self.assertIn(("SV_DIR_NEW", kwargs), self.listener.events)

    def test_server_file_deleted_sends_event(self):
        """When a file is deleted, an event is sent."""
        node = self.create_filetxt()
        full_path = self.main.fs.get_abspath(node.share_id, node.path)

        # delete the fake file
        self.sync._handle_SV_FILE_DELETED(ROOT, node.node_id, True)

        # check event
        kwargs = dict(volume_id=ROOT, node_id=node.node_id, was_dir=True,
                      old_path=full_path)
        self.assertIn(("SV_FILE_DELETED", kwargs), self.listener.events)

    def test_server_file_deleted_ignores_missing_mdid(self):
        """On file delete, we ignore missing metadata."""
        node = self.create_filetxt()

        # delete the fake file *twice*
        self.sync._handle_SV_FILE_DELETED(ROOT, node.node_id, True)
        self.listener.events = []
        self.sync._handle_SV_FILE_DELETED(ROOT, node.node_id, True)

        # the old_path is not available on the second call
        kwargs = dict(volume_id=ROOT, node_id=node.node_id, was_dir=True,
                      old_path="")
        # check event
        self.assertIn(("SV_FILE_DELETED", kwargs), self.listener.events)
