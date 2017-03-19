# -*- coding: utf-8 -*-
#
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
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
"""Tests for the Volume Manager."""

from __future__ import with_statement

import collections
import cPickle
import inspect
import logging
import os
import sys
import uuid

from mocker import Mocker, MATCH
from twisted.internet import defer, reactor
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipIfOS
from ubuntuone.storageprotocol import volumes, request
from ubuntuone.storageprotocol.client import ListShares
from ubuntuone.storageprotocol.sharersp import (
    NotifyShareHolder,
    ShareResponse,
)

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    FakeMain,
)
from ubuntuone import platform
from ubuntuone.syncdaemon import config, event_queue, tritcask, volume_manager
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    ACCESS_LEVEL_RW,
    get_udf_path,
    Share,
    Shared,
    UDF,
    Root,
    _Share,
    allow_writes,
    get_share_dir_name,
    VolumeManager,
    LegacyShareFileShelf,
    MetadataUpgrader,
    VMFileShelf,
    VMTritcaskShelf,
    VolumeDoesNotExist,
)
from ubuntuone.platform import (
    make_link,
    make_dir,
    open_file,
    path_exists,
    remove_file,
    remove_link,
    rename,
    set_dir_readonly,
    set_dir_readwrite,
)

# grab the metadata version before tests fiddle with it
CURRENT_METADATA_VERSION = VolumeManager.METADATA_VERSION


class BaseVolumeManagerTests(BaseTwistedTestCase):
    """ Bas TestCase for Volume Manager tests """

    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(BaseVolumeManagerTests, self).setUp()
        self.log = logging.getLogger("ubuntuone.SyncDaemon.TEST")
        self.log.info("starting test %s.%s", self.__class__.__name__,
                      self._testMethodName)
        self.root_dir = self.mktemp(
            os.path.join('ubuntuonehacker', 'root_dir'))
        self.data_dir = self.mktemp('data_dir')
        self.shares_dir = self.mktemp('shares_dir')
        self.partials_dir = self.mktemp('partials_dir')
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)

        self.watches = set()  # keep track of added watches

        orig_add_watch = self.main.event_q.add_watch

        def fake_add_watch(path):
            self.watches.add(path)
            return orig_add_watch(path)

        orig_rm_watch = self.main.event_q.rm_watch

        def fake_rm_watch(path):
            self.watches.remove(path)
            return orig_rm_watch(path)

        self.patch(self.main.event_q, 'add_watch', fake_add_watch)
        self.patch(self.main.event_q, 'rm_watch', fake_rm_watch)
        self.vm = self.main.vm
        self.addCleanup(self.main.shutdown)

        self.handler = MementoHandler()
        self.handler.setLevel(logging.INFO)
        self.vm.log.addHandler(self.handler)
        self.addCleanup(self.vm.log.removeHandler, self.handler)

    @defer.inlineCallbacks
    def tearDown(self):
        """ cleanup main and remove the temp dir """
        self.log.info("finished test %s.%s", self.__class__.__name__,
                      self._testMethodName)
        VolumeManager.METADATA_VERSION = CURRENT_METADATA_VERSION
        yield super(BaseVolumeManagerTests, self).tearDown()

    def _listen_for(self, event, callback, count=1, collect=False):
        """Setup a EQ listener for the especified event."""
        event_q = self.main.event_q

        class Listener(object):
            """A basic listener to handle the pushed event."""

            def __init__(self):
                self.hits = 0
                self.events = []

            def _handle_event(self, **kwargs):
                self.hits += 1
                if collect:
                    self.events.append(kwargs)
                if self.hits == count:
                    event_q.unsubscribe(self)
                    if collect:
                        callback(self.events)
                    else:
                        callback(kwargs)

        listener = Listener()
        setattr(listener, 'handle_' + event, listener._handle_event)
        event_q.subscribe(listener)
        return listener

    def _create_udf_volume(self, volume_id=None, node_id=None,
                           suggested_path=u'~/Documents',
                           generation=None, free_bytes=100):
        """Return a new UDFVolume."""
        # match protocol expected types
        assert isinstance(suggested_path, unicode)

        if volume_id is None:
            volume_id = str(uuid.uuid4())
        if node_id is None:
            node_id = str(uuid.uuid4())

        volume = volumes.UDFVolume(volume_id=volume_id, node_id=node_id,
                                   generation=generation,
                                   free_bytes=free_bytes,
                                   suggested_path=suggested_path)
        return volume

    def _create_udf(self, volume_id=None, node_id=None,
                    suggested_path=u'~/Documents',
                    subscribed=True, generation=None, free_bytes=100):
        """Create an UDF and returns it and the volume"""
        # match protocol expected types
        assert isinstance(suggested_path, unicode)

        volume = self._create_udf_volume(volume_id=volume_id, node_id=node_id,
                                         suggested_path=suggested_path,
                                         generation=generation,
                                         free_bytes=free_bytes)

        udf = UDF.from_udf_volume(volume, get_udf_path(suggested_path))
        udf.subscribed = subscribed
        udf.generation = generation
        return udf

    def _create_share_volume(
            self, volume_id=None, node_id=None, name=u'fake_share',
            generation=None, free_bytes=10, access_level=ACCESS_LEVEL_RO,
            accepted=True, other_visible_name='visible_username'):
        """Return a new ShareVolume."""
        # match protocol expected types
        assert isinstance(name, unicode)

        if volume_id is None:
            volume_id = str(uuid.uuid4())
        if node_id is None:
            node_id = str(uuid.uuid4())

        volume = volumes.ShareVolume(volume_id=volume_id,
                                     node_id=node_id, generation=generation,
                                     free_bytes=free_bytes, direction='to_me',
                                     share_name=name,
                                     other_username='username',
                                     other_visible_name=other_visible_name,
                                     accepted=accepted,
                                     access_level=access_level)
        return volume

    def _create_share(self, volume_id=None, node_id=None, name=u'fake_share',
                      generation=None, free_bytes=1024,
                      access_level=ACCESS_LEVEL_RO,
                      accepted=True, subscribed=False,
                      other_visible_name='visible_username'):
        """Return a new Share."""
        # match protocol expected types
        assert isinstance(name, unicode)

        share_volume = self._create_share_volume(
            volume_id=volume_id, node_id=node_id, name=name,
            generation=generation, free_bytes=free_bytes,
            access_level=access_level, accepted=accepted,
            other_visible_name=other_visible_name)
        dir_name = get_share_dir_name(share_volume)
        share_path = os.path.join(self.shares_dir, dir_name)
        share = Share.from_share_volume(share_volume, share_path)
        share.subscribed = subscribed
        share.accepted = accepted
        return share


class VolumeManagerTests(BaseVolumeManagerTests):
    """ Tests for Volume Manager internal API. """

    @defer.inlineCallbacks
    def test__got_root_ok_first(self):
        """Test _got_root method first time."""
        d = defer.Deferred()
        self._listen_for('SYS_ROOT_RECEIVED', d.callback)
        self.vm._got_root('root_uuid')

        res = yield d
        mdobj = self.main.fs.get_by_path(self.root_dir)
        self.assertEqual(res, dict(root_id='root_uuid', mdid=mdobj.mdid))

    @defer.inlineCallbacks
    def test__got_root_ok_twice(self):
        """Test _got_root method twice."""
        d = defer.Deferred()
        # first time
        self.vm._got_root('root_uuid')

        # now listen and receive it again
        self._listen_for('SYS_ROOT_RECEIVED', d.callback)
        self.vm._got_root('root_uuid')

        res = yield d
        mdobj = self.main.fs.get_by_path(self.root_dir)
        self.assertEqual(res, dict(root_id='root_uuid', mdid=mdobj.mdid))

    @defer.inlineCallbacks
    def test__got_root_mismatch(self):
        """Test for _got_root with different root node_id."""
        self.vm._got_root('root_uuid')
        d = defer.Deferred()
        self._listen_for('SYS_ROOT_MISMATCH', d.callback)
        self.vm._got_root('other_root_uuid')
        yield d


class VolumeManagerSharesTests(BaseVolumeManagerTests):
    """Tests for Volume Manager Shares management."""

    def test_share_is_equal(self):
        """Test for share comparison."""
        share1 = self._create_share(volume_id='volume_id', node_id='node_id',
                                    subscribed=True)
        share2 = self._create_share(volume_id='volume_id', node_id='node_id',
                                    subscribed=True)

        self.assertEqual(share1, share2)

    def test_share_is_not_equal(self):
        """Test for share comparison."""
        share1 = self._create_share(volume_id='volume_id', node_id='node_id',
                                    subscribed=True)
        share2 = self._create_share(volume_id='volume_id', node_id='node_id',
                                    subscribed=False)

        self.assertNotEqual(share1, share2)

    @defer.inlineCallbacks
    def test_add_share_access_level_view(self):
        """Test for add_share for a View share."""
        share = self._create_share(access_level=ACCESS_LEVEL_RO,
                                   subscribed=False)
        yield self.vm.add_share(share)

        dir_name = get_share_dir_name(share)
        share_path = os.path.join(self.shares_dir, dir_name)
        self.assertEqual(share_path, share.path)
        self.assertEqual(2, len(self.vm.shares))  # root and share
        self.assertIn(share.volume_id, self.vm.shares)

        # check that the share is in the fsm metadata
        mdobj = self.main.fs.get_by_path(share.path)
        self.assertEqual(mdobj.node_id, share.node_id)
        self.assertEqual(mdobj.share_id, share.volume_id)

        # check that there isn't a watch in the share (subscribed is False)
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)

        # remove the share
        self.vm.share_deleted(share.volume_id)

        # add it again, but this time with subscribed = True
        share.subscribed = True
        yield self.vm.add_share(share)

        self.assertEqual(share_path, share.path)
        self.assertEqual(2, len(self.vm.shares))
        self.assertIn(share.volume_id, self.vm.shares)

        # check that the share is in the fsm metadata
        mdobj = self.main.fs.get_by_path(share.path)
        self.assertEqual(mdobj.node_id, share.node_id)
        self.assertEqual(mdobj.share_id, share.volume_id)

        # check that there isn't a watch in the share (subscribed is False)
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)

    @defer.inlineCallbacks
    def test_add_share_access_level_modify(self):
        """Test for add_share for a Modify share."""
        share = self._create_share(access_level=ACCESS_LEVEL_RW,
                                   subscribed=False)
        yield self.vm.add_share(share)

        dir_name = get_share_dir_name(share)
        share_path = os.path.join(self.shares_dir, dir_name)
        self.assertEqual(share_path, share.path)
        self.assertEqual(2, len(self.vm.shares))  # root and share
        self.assertIn(share.volume_id, self.vm.shares)

        # check that the share is in the fsm metadata
        mdobj = self.main.fs.get_by_path(share.path)
        self.assertEqual(mdobj.node_id, share.node_id)
        self.assertEqual(mdobj.share_id, share.volume_id)

        # check that there isn't a watch in the share (subscribed is False)
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)

        # remove the share
        self.vm.share_deleted(share.volume_id)

        # add it again, but this time with subscribed = True
        share.subscribed = True
        yield self.vm.add_share(share)

        self.assertEqual(share_path, share.path)
        self.assertEqual(2, len(self.vm.shares))
        self.assertIn(share.volume_id, self.vm.shares)

        # check that the share is in the fsm metadata
        mdobj = self.main.fs.get_by_path(share.path)
        self.assertEqual(mdobj.node_id, share.node_id)
        self.assertEqual(mdobj.share_id, share.volume_id)

        # check that there is a watch in the share
        self.assertIn(share.path, self.watches,
                      'watch for %r should be present.' % share.path)

    @defer.inlineCallbacks
    def test_add_share_view_does_not_local_scan_share(self):
        """Test that add_share does not scan the View share."""
        share = self._create_share(access_level=ACCESS_LEVEL_RO,
                                   subscribed=True)

        self.patch(self.main.lr, 'scan_dir', lambda *a, **kw: self.fail(a))
        server_rescan_d = defer.Deferred()
        self.main.action_q.rescan_from_scratch = server_rescan_d.callback

        yield self.vm.add_share(share)

        yield server_rescan_d

        self.assertEqual(2, len(self.vm.shares))
        mdobj = self.main.fs.get_by_path(share.path)
        # check that the share is in the fsm metadata
        self.assertEqual(mdobj.node_id, share.node_id)
        self.assertEqual(mdobj.share_id, share.volume_id)
        self.assertTrue(self.vm.shares[share.volume_id].subscribed)
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)

    @defer.inlineCallbacks
    def test_add_share_modify_scans_share(self):
        """Test that add_share scans the share."""
        share = self._create_share(
            access_level=ACCESS_LEVEL_RW, subscribed=True)

        scan_d = defer.Deferred()

        def fake_scan_dir(mdid, path, udfmode):
            """A fake scan share that check the arguments."""
            mdobj = self.main.fs.get_by_path(share.path)
            # check that the share is in the fsm metadata
            self.assertEqual(mdobj.node_id, share.node_id)
            self.assertEqual(mdobj.share_id, share.volume_id)
            self.assertEqual(mdid, mdobj.mdid)
            self.assertEqual(path, share.path)
            self.assertTrue(udfmode)
            scan_d.callback(None)
            return scan_d

        self.patch(self.main.lr, 'scan_dir', fake_scan_dir)

        scratch_d = defer.Deferred()

        def fake_rescan_from_scratch(volume_id):
            """A fake scan share that check the arguments."""
            self.assertEqual(share.volume_id, volume_id)
            scratch_d.callback(None)
            return scratch_d
        self.main.action_q.rescan_from_scratch = fake_rescan_from_scratch

        yield self.vm.add_share(share)
        yield scan_d
        yield scratch_d

        self.assertEqual(2, len(self.vm.shares))
        self.assertTrue(self.vm.shares[share.volume_id].subscribed)
        self.assertIn(share.path, self.watches,
                      'watch for %r should be present.' % share.path)

    @defer.inlineCallbacks
    def test_share_deleted(self):
        """Test for share_deleted when empty."""
        share = self._create_share()
        yield self.vm.add_share(share)

        self.assertEqual(2, len(self.vm.shares))  # root and share
        self.assertIn(share.volume_id, self.vm.shares)

        self.vm.share_deleted(share.volume_id)

        self.assertEqual(1, len(self.vm.shares))
        self.assertNotIn(share.volume_id, self.vm.shares)

        # check that the share isn't in the fsm metadata
        self.assertRaises(KeyError, self.main.fs.get_by_path, share.path)
        # check that there isn't a watch in the share
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)

    @defer.inlineCallbacks
    def test_share_deleted_with_content(self):
        """Test for share_deleted when non empty."""
        share = self._create_share(access_level=ACCESS_LEVEL_RW,
                                   accepted=True, subscribed=True)
        yield self.vm.add_share(share)
        self.assertEqual(2, len(self.vm.shares))

        # create a few files and directories
        dirs = ['dir', os.path.join('dir', 'subdir'),
                os.path.join('dir', 'empty_dir')]
        for i, dir in enumerate(dirs):
            path = os.path.join(share.path, dir)
            with allow_writes(os.path.split(share.path)[0]):
                if not path_exists(path):
                    make_dir(path, recursive=True)
            self.main.fs.create(path, share.volume_id, is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
            # add a inotify watch to the dir
            yield self.vm._add_watch(path)
        files = ['a_file', os.path.join('dir', 'file'),
                 os.path.join('dir', 'subdir', 'file')]
        for i, file in enumerate(files):
            path = os.path.join(share.path, file)
            self.main.fs.create(path, share.volume_id)
            self.main.fs.set_node_id(path, 'file_node_id' + str(i))

        paths = list(self.main.fs.get_paths_starting_with(share.path))
        self.assertEqual(len(paths), len(dirs + files) + 1)
        for path, is_dir in paths:
            self.assertTrue(self.main.fs.get_by_path(path))
            if is_dir:
                self.assertIn(path, self.watches,
                              'watch for %r should be present.' % path)
        self.assertIn(share.volume_id, self.vm.shares)
        self.vm.share_deleted(share.volume_id)
        self.assertNotIn(share.volume_id, self.vm.shares)
        for path, is_dir in paths:
            self.assertRaises(KeyError, self.main.fs.get_by_path, path)
            if is_dir:
                self.assertNotIn(path, self.watches,
                                 'watch for %r should not be present.' % path)

        self.assertEqual(1, len(self.vm.shares))
        # check that the share isn't in the fsm metadata
        self.assertRaises(KeyError, self.main.fs.get_by_path, share.path)
        # check that there isn't a watch in the share
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)
        # check that there isn't any share childs around
        for path, _ in paths:
            self.assertRaises(KeyError, self.main.fs.get_by_path, path)
        # get the childs (should be an empty list)
        paths = self.main.fs.get_paths_starting_with(share.path)
        self.assertEqual(0, len(paths))

    @defer.inlineCallbacks
    def test_share_changed(self):
        """Check that VM.share_changed updates the access_level."""
        share_holder = NotifyShareHolder.from_params('share_id', None,
                                                     'fake_share',
                                                     'test_username',
                                                     'visible_name',
                                                     ACCESS_LEVEL_RW)
        # initialize the the root
        self.vm._got_root('root_uuid')
        share_path = os.path.join(self.shares_dir, share_holder.share_name)
        share = Share(path=share_path, volume_id=share_holder.share_id,
                      access_level=ACCESS_LEVEL_RO)
        yield self.vm.add_share(share)
        self.vm.share_changed(share_holder)
        self.assertEqual(ACCESS_LEVEL_RW,
                         self.vm.shares[share.volume_id].access_level)

    def test_share_changed_no_share(self):
        """Test share_changed for a share we don't have."""
        called = []
        self.vm.refresh_volumes = lambda: called.append(True)
        holder = collections.namedtuple('Holder', 'share_id')('not such id')
        self.vm.share_changed(holder)
        self.assertTrue(called)
        self.assertTrue(self.handler.check_warning("don't have the share"))

    def test_handle_AQ_SHARES_LIST(self):
        """Test the handling of the AQ_SHARE_LIST event."""
        share_id = uuid.uuid4()
        share_response = ShareResponse.from_params(share_id, 'to_me',
                                                   'fake_share_uuid',
                                                   'fake_share', 'username',
                                                   'visible_username', 'yes',
                                                   ACCESS_LEVEL_RO)
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = ListShares(None)
        response.shares = [share_response]
        self.vm.handle_AQ_SHARES_LIST(response)
        self.assertEqual(2, len(self.vm.shares))  # the new shares and root
        # check that the share is in the shares dict
        self.assertIn(str(share_id), self.vm.shares)
        share = self.vm.shares[str(share_id)]
        self.assertEqual('fake_share', share.name)
        self.assertEqual('fake_share_uuid', share.node_id)

    @defer.inlineCallbacks
    def test_handle_SV_SHARE_CHANGED(self):
        """ test the handling of the AQ_SHARE_LIST event. """
        share_id = uuid.uuid4()
        share_holder = NotifyShareHolder.from_params(share_id, None,
                                                     'fake_share',
                                                     'test_username',
                                                     'visible_name',
                                                     ACCESS_LEVEL_RW)
        # initialize the the root
        self.vm._got_root('root_uuid')
        # create a share
        share_path = os.path.join(self.shares_dir, share_holder.share_name)
        share = Share(path=share_path, volume_id=str(share_holder.share_id),
                      access_level=ACCESS_LEVEL_RO)
        yield self.vm.add_share(share)
        self.vm.handle_SV_SHARE_CHANGED(info=share_holder)
        self.assertEqual(
            ACCESS_LEVEL_RW, self.vm.shares[str(share_id)].access_level)
        self.vm.handle_SV_SHARE_DELETED(share_holder.share_id)
        self.assertNotIn('share_id', self.vm.shares)

    @defer.inlineCallbacks
    def test_persistence(self):
        """ Test that the persistence of shares works as expected. """
        # create the folders layout
        share = self._create_share()
        yield self.vm.add_share(share)
        other_vm = VolumeManager(self.main)
        for key in self.vm.shares:
            self.assertEqual(
                self.vm.shares[key].__dict__, other_vm.shares[key].__dict__)

    def test_handle_AQ_SHARES_LIST_shared(self):
        """test the handling of the AQ_SHARE_LIST event, with a shared dir."""
        share_id = uuid.uuid4()
        share_response = ShareResponse.from_params(
            share_id, 'to_me', 'fake_share_uuid', 'fake_share', 'username',
            'visible_username', 'yes', ACCESS_LEVEL_RO)
        shared_id = uuid.uuid4()
        shared_response = ShareResponse.from_params(
            shared_id, 'from_me', 'shared_uuid', 'fake_shared', 'myname',
            'my_visible_name', 'yes', ACCESS_LEVEL_RW)
        # initialize the the root
        self.vm._got_root('root_uuid')
        shared_dir = os.path.join(self.root_dir, 'shared_dir')
        self.main.fs.create(path=shared_dir, share_id="", is_dir=True)
        self.main.fs.set_node_id(shared_dir, shared_response.subtree)
        response = ListShares(None)
        response.shares = [share_response, shared_response]
        self.vm.handle_AQ_SHARES_LIST(response)
        self.assertEqual(2, len(self.vm.shares))  # the new share and root
        self.assertEqual(1, len(self.vm.shared))  # the new shared
        shared = self.vm.shared[str(shared_id)]
        self.assertEqual('fake_shared', shared.name)
        # check that the uuid is stored in fs
        mdobj = self.main.fs.get_by_path(shared.path)
        self.assertEqual(shared.node_id, mdobj.node_id)

    def test_add_shared(self):
        """ Test VolumeManager.add_shared """
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        self.main.fs.get_by_node_id("", 'node_id')

        def fake_create_share(node_id, user, name, access_level, marker, path):
            self.assertIn(marker, self.vm.marker_share_map)
            self.vm.handle_AQ_CREATE_SHARE_OK(share_id='share_id',
                                              marker=marker)
        self.main.action_q.create_share = fake_create_share
        self.vm.create_share(path, 'fake_user', 'shared_name', ACCESS_LEVEL_RO)

        self.assertTrue(self.vm.shared.get('share_id') is not None)
        share = self.vm.shared.get('share_id')
        self.assertEqual('fake_user', share.other_username)
        self.assertEqual('shared_name', share.name)
        self.assertEqual(ACCESS_LEVEL_RO, share.access_level)
        self.assertEqual('node_id', share.node_id)
        self.assertEqual('share_id', share.volume_id)

    def test_create_share(self):
        """ Test VolumeManager.create_share """
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        self.main.fs.get_by_node_id("", 'node_id')

        def fake_create_share(node_id, user, name, access_level, marker, path):
            self.assertEqual('node_id', node_id)
            self.assertEqual('fake_user', user)
            self.assertEqual('shared_name', name)
            self.assertEqual(ACCESS_LEVEL_RO, access_level)
            self.assertTrue(marker is not None)
            share = self.vm.marker_share_map[marker]
            self.assertEqual(path, share.path)
            self.assertEqual(ACCESS_LEVEL_RO, share.access_level)
            self.assertEqual(marker, share.volume_id)
            self.assertEqual('fake_user', share.other_username)
            self.assertEqual('node_id', share.node_id)

        self.main.action_q.create_share = fake_create_share
        self.vm.create_share(path, 'fake_user', 'shared_name', ACCESS_LEVEL_RO)

    def test_create_share_error(self):
        """ Test VolumeManager.create_share """
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        self.main.fs.get_by_node_id("", 'node_id')

        def fake_create_share(node_id, user, name, access_level, marker, path):
            self.vm.handle_AQ_CREATE_SHARE_ERROR(marker, 'a fake error')

        self.main.action_q.create_share = fake_create_share
        self.vm.create_share(path, 'fake_user', 'shared_name', ACCESS_LEVEL_RO)

    @defer.inlineCallbacks
    def test_create_share_missing_node_id(self):
        """Test VolumeManager.create_share in the case of missing node_id."""
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        expected_node_id = uuid.uuid4()
        expected_share_id = uuid.uuid4()

        def fake_create_share(node_id, user, name, access_level, marker, path):
            # some sanity checks
            share = self.vm.marker_share_map[marker]
            self.assertEqual(path, share.path)
            self.assertEqual(ACCESS_LEVEL_RO, share.access_level)
            self.assertEqual(marker, share.volume_id)
            self.assertEqual('fake_user', share.other_username)
            self.assertEqual(marker, share.node_id)
            # fake a node_id demark and set the node_id
            self.main.fs.set_node_id(path, str(expected_node_id))
            self.main.event_q.push("AQ_CREATE_SHARE_OK",
                                   share_id=expected_share_id, marker=marker)

        d = defer.Deferred()
        self._listen_for('AQ_CREATE_SHARE_OK', d.callback)
        self.main.action_q.create_share = fake_create_share
        self.vm.create_share(path, 'fake_user', 'shared_name', ACCESS_LEVEL_RO)
        yield d
        share = self.vm.shared[str(expected_share_id)]
        self.assertEqual(str(expected_node_id), share.node_id)

    @defer.inlineCallbacks
    def test_delete_shared(self):
        """Test VolumeManager.delete_share."""
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        share = Shared(path=path, volume_id='share_id', node_id="node_id")
        yield self.vm.add_shared(share)

        def fake_delete_share(share_id):
            """Fake delete_share."""
            self.assertEqual(share_id, share.volume_id)
            self.main.event_q.push('AQ_DELETE_SHARE_OK', share_id=share_id)

        self.patch(self.main.action_q, 'delete_share', fake_delete_share)
        d = defer.Deferred()
        self._listen_for('VM_SHARE_DELETED', d.callback, 1, collect=True)
        self.vm.delete_share(share.volume_id)
        events = yield d
        event = events[0]
        self.assertEqual(event['share'], share)

    @defer.inlineCallbacks
    def test_delete_shared_error(self):
        """Test VolumeManager.delete_share."""
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        share = Shared(path=path, volume_id='share_id', node_id="node_id")
        yield self.vm.add_shared(share)

        def fake_delete_share(share_id):
            """Fake delete_share that always fails."""
            self.main.event_q.push('AQ_DELETE_SHARE_ERROR',
                                   share_id=share_id, error='a fake error')

        self.patch(self.main.action_q, 'delete_share', fake_delete_share)
        d = defer.Deferred()
        self._listen_for('VM_SHARE_DELETE_ERROR', d.callback, 1, collect=True)
        self.vm.delete_share(share.volume_id)
        events = yield d
        self.assertEqual(events[0],
                         dict(share_id=share.volume_id, error='a fake error'))

    @defer.inlineCallbacks
    def test_delete_shared_error_missing_share(self):
        """Test VolumeManager.delete_share with a non-existent share."""
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        d = defer.Deferred()
        self._listen_for('VM_SHARE_DELETE_ERROR', d.callback, 1, collect=True)
        self.vm.delete_share('fake_share_id')
        events = yield d
        self.assertEqual(
            events[0], dict(share_id='fake_share_id', error='DOES_NOT_EXIST'))

    @defer.inlineCallbacks
    def test_accept_share(self):
        """ Test the accept_share method. """
        d = defer.Deferred()
        self.vm._got_root('root_uuid')
        share_path = os.path.join(self.shares_dir, 'fake_share')
        share = Share(path=share_path, volume_id='share_id', node_id="node_id")
        yield self.vm.add_share(share)
        self.assertIn(share.volume_id, self.vm.shares)
        self.assertEqual(False, share.accepted)

        def answer_share(share_id, answer):
            reactor.callLater(0.2, d.callback, (share_id, answer))
            return d

        self.main.action_q.answer_share = answer_share

        def callback(result):
            share_id, answer = result
            self.assertEqual(share.volume_id, share_id)
            self.assertEqual('Yes', answer)
        d.addCallback(callback)
        self.vm.accept_share(share.volume_id, True)
        yield d

    def test_handle_AQ_SHARES_LIST_shared_missing_md(self):
        """test the handling of the AQ_SHARE_LIST event, when the md
        isn't there yet.
        """
        shared_response = ShareResponse.from_params(
            'shared_id', 'from_me', 'shared_uuid', 'fake_shared', 'myname',
            'my_visible_name', 'yes', ACCESS_LEVEL_RW)
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = ListShares(None)
        response.shares = [shared_response]
        self.vm.handle_AQ_SHARES_LIST(response)
        self.assertEqual(1, len(self.vm.shared))  # the new shares and root
        shared = self.vm.shared['shared_id']
        self.assertEqual('fake_shared', shared.name)
        # check that the uuid is stored in fs
        self.assertEqual(shared_response.subtree, shared.node_id)
        self.assertEqual(None, shared.path)

    @defer.inlineCallbacks
    def test_handle_SV_SHARE_ANSWERED(self):
        """ test the handling of the AQ_SHARE_ANSWERED. """
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        self.main.fs.get_by_node_id("", 'node_id')
        # initialize the the root
        self.vm._got_root('root_uuid')
        # add the shared folder
        share = Share(
            path=path, volume_id='share_id', access_level=ACCESS_LEVEL_RO)
        yield self.vm.add_shared(share)
        self.assertEqual(False, self.vm.shared['share_id'].accepted)
        # check that a answer notify of a missing share don't blowup
        self.vm.handle_SV_SHARE_ANSWERED('share_id', 'Yes')
        self.assertEqual(True, self.vm.shared['share_id'].accepted)

    def test_handle_SV_SHARE_ANSWERED_missing(self):
        """ test the handling of the AQ_SHARE_ANSWERED. """
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        self.main.fs.get_by_node_id("", 'node_id')
        # initialize the the root
        self.vm._got_root('root_uuid')
        self.assertNotIn('share_id', self.vm.shared)
        # check that a answer notify of a missing share don't blowup
        self.vm.handle_SV_SHARE_ANSWERED('share_id', 'Yes')
        self.assertNotIn('share_id', self.vm.shared)

    def test_delete_share(self):
        """Test the deletion of a share and if it's removed from the MD."""
        share_response = ShareResponse.from_params(
            'share_id', 'to_me', 'fake_share_uuid', 'fake_share', 'username',
            'visible_username', False, ACCESS_LEVEL_RO)
        share_response_1 = ShareResponse.from_params(
            'share_id_1', 'to_me', 'fake_share_uuid_1', 'fake_share_1',
            'username', 'visible_username', False, ACCESS_LEVEL_RO)
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = ListShares(None)
        response.shares = [share_response, share_response_1]
        self.vm.handle_AQ_SHARES_LIST(response)
        self.assertEqual(3, len(self.vm.shares))  # the new shares and root
        # check that the share is in the shares dict
        self.assertIn('share_id', self.vm.shares)
        self.assertIn('share_id_1', self.vm.shares)
        share = self.vm.shares['share_id']
        self.assertEqual('fake_share', share.name)
        self.assertEqual('fake_share_uuid', share.node_id)
        share = self.vm.shares['share_id_1']
        self.assertEqual('fake_share_1', share.name)
        self.assertEqual('fake_share_uuid_1', share.node_id)
        # inject a new ListShares response
        new_response = ListShares(None)
        new_response.shares = [share_response]
        self.vm.handle_AQ_SHARES_LIST(new_response)
        # check that the missing share was removed
        self.assertIn('share_id', self.vm.shares)
        self.assertFalse('share_id_1' in self.vm.shares)
        share = self.vm.shares['share_id']
        self.assertEqual('fake_share', share.name)
        self.assertEqual('fake_share_uuid', share.node_id)
        self.assertEqual(None, self.vm.shares.get('share_id_1'))

    @defer.inlineCallbacks
    def test_remove_watch(self):
        """Test for VolumeManager._remove_watch"""
        path = os.path.join(self.root_dir, 'dir')
        make_dir(path, recursive=True)
        yield self.vm._add_watch(path)
        self.assertIn(path, self.watches,
                      'watch for %r should be present.' % path)
        self.vm._remove_watch(path)
        self.assertNotIn(path, self.watches,
                         'watch for %r should not be present.' % path)

    @defer.inlineCallbacks
    def test_remove_watches(self):
        """Test for VolumeManager._remove_watches"""
        dirs = ['dir', os.path.join('dir', 'subdir'), 'emptydir']
        paths = [os.path.join(self.root_dir, dir) for dir in dirs]
        # create metadata and add watches
        for i, path in enumerate(paths):
            if not path_exists(path):
                make_dir(path, recursive=True)
            self.main.fs.create(path, "", is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
            yield self.vm._add_watch(path)
        # insert the root_dir in the list
        yield self.vm._add_watch(self.root_dir)
        paths.insert(0, self.root_dir)
        for path in paths:
            self.assertIn(path, self.watches,
                          'watch for %r should be present.' % path)
        # remove the watches
        self.vm._remove_watches(self.root_dir)
        for path in paths:
            self.assertNotIn(path, self.watches,
                             'watch for %r should not be present.' % path)

    @defer.inlineCallbacks
    def test_remove_watches_after_dir_rename(self):
        """Test for VolumeManager._remove_watches after dir rename."""
        path = os.path.join(self.root_dir, 'testit')
        make_dir(path)
        self.main.fs.create(path, "", is_dir=True)
        self.main.fs.set_node_id(path, 'dir_node_id')
        yield self.vm._add_watch(path)

        rename(path, path + '.old')
        # remove the watches
        self.vm._remove_watches(self.root_dir)

        self.assertNotIn(path, self.watches,
                         'watch for %r should not be present' % path)

    @defer.inlineCallbacks
    def test_delete_fsm_object(self):
        """Test for VolumeManager._delete_fsm_object"""
        path = os.path.join(self.root_dir, 'dir')
        make_dir(path, recursive=True)
        self.main.fs.create(path, "", is_dir=True)
        self.main.fs.set_node_id(path, 'dir_node_id')
        yield self.vm._add_watch(path)
        self.assertIn(path, self.watches,
                      'watch for %r should be present.' % path)
        self.assertTrue(self.main.fs.get_by_path(path), path)
        # remove the watch
        self.vm._delete_fsm_object(path)
        self.assertRaises(KeyError, self.main.fs.get_by_path, path)
        self.assertIn(path, self.watches,
                      'watch for %r should be present.' % path)

    def test_create_fsm_object(self):
        """Test for VolumeManager._create_fsm_object"""
        path = os.path.join(self.root_dir, 'node')
        self.assertRaises(KeyError, self.main.fs.get_by_path, path)
        self.vm._create_fsm_object(path, "", "node_id")
        self.assertTrue(self.main.fs.get_by_path(path), path)

    @defer.inlineCallbacks
    def test_root_mismatch(self):
        """Test that SYS_ROOT_MISMATCH is pushed."""
        self.vm._got_root('root_node_id')
        d = defer.Deferred()
        self._listen_for('SYS_ROOT_MISMATCH', d.callback)
        self.vm._got_root('root_id')
        info = yield d
        self.assertEqual('root_node_id', info['root_id'])
        self.assertEqual('root_id', info['new_root_id'])

    def test_handle_SYS_QUOTA_EXCEEDED_is_called(self):
        """Test that we handle the event."""
        # set up to record the call
        called = []
        self.vm.handle_SYS_QUOTA_EXCEEDED = lambda **k: called.append(k)
        self.main.event_q.subscribe(self.vm)

        # send the event
        data = dict(volume_id=request.ROOT, free_bytes=123987)
        self.main.event_q.push('SYS_QUOTA_EXCEEDED', **data)

        # check that we handled it
        self.assertEqual(called, [data])

    def test_handle_SYS_QUOTA_EXCEEDED_root(self):
        """Test that it updates the free space when error is on root."""
        self.vm.handle_SYS_QUOTA_EXCEEDED(request.ROOT, 11221)
        self.assertEqual(self.vm.get_volume(request.ROOT).free_bytes, 11221)

    @defer.inlineCallbacks
    def test_handle_SYS_QUOTA_EXCEEDED_udf(self):
        """Test that it updates the free space when error is on an UDF."""
        volume_id = str(uuid.uuid4())
        udf = self._create_udf(volume_id=volume_id)
        yield self.vm.add_udf(udf)

        # call the handler
        self.vm.handle_SYS_QUOTA_EXCEEDED(volume_id, 1122)

        # but check the free bytes from root, that is who stores this info
        self.assertEqual(self.vm.get_volume(request.ROOT).free_bytes, 1122)

    @defer.inlineCallbacks
    def test_handle_SYS_QUOTA_EXCEEDED_share(self):
        """Test that it updates the free space when error is on a share."""
        # build the share
        share_id = str(uuid.uuid4())
        share = self._create_share(volume_id=share_id)
        yield self.vm.add_share(share)

        # call and check
        self.vm.handle_SYS_QUOTA_EXCEEDED(share_id, 1122)
        self.assertEqual(self.vm.get_volume(share_id).free_bytes, 1122)

    @defer.inlineCallbacks
    def test_handle_AQ_ANSWER_SHARE_OK(self):
        """Test for handle_AQ_ANSWER_SHARE_OK."""
        share = self._create_share()

        scratch_d = defer.Deferred()

        def fake_rescan_from_scratch(volume_id):
            """A fake get_delta that check the arguments."""
            self.assertEqual(share.volume_id, volume_id)
            scratch_d.callback(None)
        self.main.action_q.rescan_from_scratch = fake_rescan_from_scratch

        yield self.vm.add_share(share)
        self.vm.handle_AQ_ANSWER_SHARE_OK(share.volume_id, 'Yes')
        yield scratch_d
        share = self.vm.get_volume(share.volume_id)
        self.assertTrue(share.accepted, 'accepted != True')
        self.assertTrue(self.main.fs.get_by_path(share.path),
                        'No metadata for share root node.')
        self.assertTrue(path_exists(share.path),
                        'share path missing on disk!')

    @defer.inlineCallbacks
    def test_handle_AQ_DELETE_SHARE_OK(self):
        """Test for handle_AQ_DELETE_SHARE_OK."""
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        share = Shared(path=path, volume_id='share_id', node_id="node_id")
        yield self.vm.add_shared(share)
        d = defer.Deferred()
        self._listen_for('VM_SHARE_DELETED', d.callback, 1, collect=True)
        self.main.event_q.push('AQ_DELETE_SHARE_OK', share_id='share_id')
        events = yield d
        self.assertEqual(events[0], dict(share=share))

    @defer.inlineCallbacks
    def test_handle_AQ_DELETE_SHARE_ERROR(self):
        """Test for handle_AQ_DELETE_SHARE_ERROR."""
        path = os.path.join(self.vm.root.path, 'shared_path')
        self.main.fs.create(path, "")
        self.main.fs.set_node_id(path, 'node_id')
        share = Shared(path=path, volume_id='share_id', node_id="node_id")
        yield self.vm.add_shared(share)
        d = defer.Deferred()
        self._listen_for('VM_SHARE_DELETE_ERROR', d.callback, 1, collect=True)
        self.main.event_q.push('AQ_DELETE_SHARE_ERROR',
                               share_id='share_id', error='a fake error')
        events = yield d
        self.assertEqual(events[0],
                         dict(share_id=share.volume_id, error='a fake error'))

    def test_event_listener(self):
        """All event listeners should define methods with correct signature."""
        for evtname, evtargs in event_queue.EVENTS.iteritems():
            meth = getattr(VolumeManager, 'handle_' + evtname, None)
            if meth is not None:
                defined_args = inspect.getargspec(meth)[0]
                self.assertEqual(defined_args[0], 'self')
                self.assertEqual(set(defined_args[1:]), set(evtargs))


class ViewSharesSubscriptionTests(BaseVolumeManagerTests):
    """Test Shares subscription operations when access_level is View."""

    access_level = ACCESS_LEVEL_RO

    @defer.inlineCallbacks
    def test_subscribe_share(self):
        """Test subscribe_share method."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=False)
        yield self.vm.add_share(share)
        self.assertFalse(self.vm.shares[share.volume_id].subscribed)
        # subscribe to it
        yield self.vm.subscribe_share(share.volume_id)
        self.assertTrue(self.vm.shares[share.volume_id].subscribed)

    @defer.inlineCallbacks
    def test_subscribe_share_missing_path(self):
        """Test subscribe_share with a missing path """
        share = self._create_share(access_level=self.access_level,
                                   subscribed=False)
        yield self.vm.add_share(share)
        self.assertFalse(path_exists(share.path))
        self.assertFalse(self.vm.shares[share.id].subscribed)
        # subscribe to it
        yield self.vm.subscribe_share(share.id)
        self.assertTrue(self.vm.shares[share.id].subscribed)
        self.assertTrue(path_exists(share.path))

    @defer.inlineCallbacks
    def test_subscribe_share_missing_volume(self):
        """Test subscribe_share with a invalid volume_id."""
        try:
            yield self.vm.subscribe_share('invalid_share_id')
        except VolumeDoesNotExist, e:
            self.assertEqual('DOES_NOT_EXIST', e.args[0])
            self.assertEqual('invalid_share_id', e.args[1])
        else:
            self.fail('Must get a VolumeDoesNotExist!')

    @defer.inlineCallbacks
    def test_unsubscribe_share(self):
        """Test unsubscribe_share method."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=True)
        yield self.vm.add_share(share)
        self.assertTrue(self.vm.shares[share.volume_id].subscribed)
        # unsubscribe from it
        self.vm.unsubscribe_share(share.volume_id)
        self.assertFalse(self.vm.shares[share.volume_id].subscribed)

    @defer.inlineCallbacks
    def test_unsubscribe_share_with_content(self):
        """Test unsubscribe_share method in a share with content."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=True)
        yield self.vm.add_share(share)

        self.assertTrue(self.vm.shares[share.volume_id].subscribed)
        # create a few files and directories
        dirs = ['dir', os.path.join('dir', 'subdir'),
                os.path.join('dir', 'empty_dir')]
        for i, dir in enumerate(dirs):
            path = os.path.join(share.path, dir)
            with allow_writes(os.path.split(share.path)[0]):
                with allow_writes(share.path):
                    if not path_exists(path):
                        make_dir(path, recursive=True)
            self.main.fs.create(path, share.volume_id, is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
            # add a inotify watch to the dir
            yield self.vm._add_watch(path)
        files = ['a_file', os.path.join('dir', 'file'),
                 os.path.join('dir', 'subdir', 'file')]
        for i, file in enumerate(files):
            path = os.path.join(share.path, file)
            with allow_writes(os.path.split(share.path)[0]):
                with allow_writes(share.path):
                    open_file(path, 'w').close()
            self.main.fs.create(path, share.volume_id)
            self.main.fs.set_node_id(path, 'file_node_id' + str(i))
        paths = self.main.fs.get_paths_starting_with(share.path)
        self.assertEqual(len(paths), len(dirs + files) + 1)

        # unsubscribe from it
        self.vm.unsubscribe_share(share.volume_id)

        self.assertEqual(2, len(self.vm.shares))  # share and root
        self.assertFalse(self.vm.shares[share.volume_id].subscribed)
        # check that the share is in the fsm metadata
        self.assertTrue(self.main.fs.get_by_path(share.path))
        # get the childs (should be an empty list)
        paths = list(self.main.fs.get_paths_starting_with(share.path))
        self.assertEqual(len(dirs + files) + 1, len(paths))
        # check that there isn't a watch in the share
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)
        # check that the childs don't have a watch
        for path, is_dir in paths:
            if is_dir:
                self.assertNotIn(path, self.watches,
                                 'watch for %r should not be present.' % path)

    @defer.inlineCallbacks
    def _test_subscribe_share_generations(self, share):
        """Test subscribe_share with a generation."""
        scratch_d = defer.Deferred()

        def fake_rescan_from_scratch(volume_id):
            """A fake rescan_from_scratch that check the arguments."""
            self.assertEqual(share.volume_id, volume_id)
            scratch_d.callback(None)
        self.main.action_q.rescan_from_scratch = fake_rescan_from_scratch
        # subscribe to it
        yield self.vm.subscribe_share(share.volume_id)
        yield scratch_d
        self.assertTrue(self.vm.shares[share.volume_id].subscribed)

    @defer.inlineCallbacks
    def test_subscribe_share_valid_generation(self):
        """Test subscribe_share with a valid generation."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=False)
        yield self.vm.add_share(share)
        self.assertFalse(self.vm.shares[share.volume_id].subscribed)
        # update share generation
        self.vm.update_generation(share.volume_id, 0)
        yield self._test_subscribe_share_generations(share)

    @defer.inlineCallbacks
    def test_subscribe_share_without_generation(self):
        """Test subscribe_share without a valid generation."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=False)
        yield self.vm.add_share(share)
        self.assertFalse(self.vm.shares[share.volume_id].subscribed)
        # update share generation
        self.vm.update_generation(share.volume_id, None)
        yield self._test_subscribe_share_generations(share)


class ModifySharesSubscriptionTests(ViewSharesSubscriptionTests):
    """Test Shares subscription operations when access_level is Modify."""

    access_level = ACCESS_LEVEL_RW

    @defer.inlineCallbacks
    def test_subscribe_share_missing_fsm_md(self):
        """Test subscribe_share with a missing node in fsm."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=False)
        yield self.vm.add_share(share)
        self.assertFalse(path_exists(share.path))
        self.assertFalse(self.vm.shares[share.id].subscribed)
        yield self.vm.subscribe_share(share.id)
        yield self.vm.unsubscribe_share(share.id)
        # delete the fsm metadata
        self.main.fs.delete_metadata(share.path)
        # subscribe to it and fail!
        try:
            yield self.vm.subscribe_share(share.id)
        except KeyError, e:
            self.assertIn(share.path, e.args[0])
        else:
            self.fail('Must get a KeyError!')

    @defer.inlineCallbacks
    def test_unsubscribe_subscribe_share_with_content(self):
        """Test for re-subscribing to a share."""
        share = self._create_share(access_level=self.access_level,
                                   subscribed=True)
        yield self.vm.add_share(share)
        self.main.event_q.rm_watch(share.path)
        self.assertTrue(self.vm.shares[share.volume_id].subscribed)
        # create a few files and directories
        dirs = ['dir', os.path.join('dir', 'subdir'),
                os.path.join('dir', 'empty_dir')]
        for i, dir in enumerate(dirs):
            path = os.path.join(share.path, dir)
            with allow_writes(os.path.split(share.path)[0]):
                with allow_writes(share.path):
                    if not path_exists(path):
                        make_dir(path, recursive=True)
            self.main.fs.create(path, share.volume_id, is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
        files = ['a_file', os.path.join('dir', 'file'),
                 os.path.join('dir', 'subdir', 'file')]
        for i, path in enumerate(files):
            path = os.path.join(share.path, path)
            with allow_writes(os.path.split(share.path)[0]):
                with allow_writes(share.path):
                    open_file(path, 'w').close()
            self.main.fs.create(path, share.volume_id)
            self.main.fs.set_node_id(path, 'file_node_id' + str(i))
        paths = list(self.main.fs.get_paths_starting_with(share.path))
        # add a inotify watch to the dirs
        for path, is_dir in paths:
            if is_dir:
                yield self.vm._add_watch(path)
        self.assertEqual(len(paths), len(dirs + files) + 1, paths)

        # unsubscribe from it
        self.vm.unsubscribe_share(share.volume_id)

        self.assertEqual(2, len(self.vm.shares))  # share and root
        self.assertFalse(self.vm.shares[share.volume_id].subscribed)
        # check that the share is in the fsm metadata
        self.assertTrue(self.main.fs.get_by_path(share.path))
        # check that there isn't a watch in the share
        self.assertNotIn(share.path, self.watches,
                         'watch for %r should not be present.' % share.path)
        # check that the childs don't have a watch
        for path, is_dir in paths:
            if is_dir:
                self.assertNotIn(path, self.watches,
                                 'watch for %r should not be present.' % path)
        # check the childs
        paths = self.main.fs.get_paths_starting_with(share.path)
        self.assertEqual(len(dirs + files) + 1, len(paths))
        # resubscribe to it
        yield self.vm.subscribe_share(share.volume_id)
        paths = list(self.main.fs.get_paths_starting_with(share.path))
        # we should only have the dirs, as the files metadata is
        # delete by local rescan (both hashes are '')
        self.assertEqual(len(dirs) + 1, len(paths))
        # check that there is a watch in the share
        self.assertIn(share.path, self.watches,
                      'watch for %r should be present.' % share.path)
        # check that the child dirs have a watch
        for path, is_dir in paths:
            if is_dir:
                self.assertIn(path, self.watches,
                              'watch for %r should be present.' % path)
                self.vm._remove_watch(path)

    def test_support_old_root_without_subscribed(self):
        """Old Roots were pickled without subscribed attribute."""
        # generate the situation
        old_attr = Root.subscribed
        del Root.subscribed
        root = Root(node_id='root_node_id')
        del root.subscribed
        assert not hasattr(root, 'subscribed')
        serialized = cPickle.dumps(root)
        Root.subscribed = old_attr

        # unserialize
        new_root = cPickle.loads(serialized)
        self.assertTrue(new_root.subscribed)


class VolumeManagerUnicodeTests(BaseVolumeManagerTests):
    """Tests for Volume Manager unicode capabilities."""

    def test_handle_SHARES_sharename(self):
        """test the handling of AQ_SHARE_LIST with non-ascii share name."""
        share_response = ShareResponse.from_params('share_id', 'to_me',
                                                   'fake_share_uuid',
                                                   u'montón', 'username',
                                                   'visible', 'yes',
                                                   ACCESS_LEVEL_RO)
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = ListShares(None)
        response.shares = [share_response]
        self.vm.handle_AQ_SHARES_LIST(response)

        # check
        share = self.vm.shares['share_id']
        shouldbe_dir = os.path.join(self.shares_dir,
                                    get_share_dir_name(share_response))
        self.assertEqual(shouldbe_dir, share.path)

    def test_handle_SHARES_visible_username(self):
        """test the handling of AQ_SHARE_LIST with non-ascii visible uname."""
        share_response = ShareResponse.from_params('share_id', 'to_me',
                                                   'fake_share_uuid',
                                                   'sharename', 'username',
                                                   u'Darío Toño', 'yes',
                                                   ACCESS_LEVEL_RO)
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = ListShares(None)
        response.shares = [share_response]
        self.vm.handle_AQ_SHARES_LIST(response)

        # check
        share = self.vm.shares['share_id']
        shouldbe_dir = os.path.join(self.shares_dir,
                                    get_share_dir_name(share_response))
        self.assertEqual(shouldbe_dir, share.path)

    def test_handle_SV_SHARE_CHANGED_sharename(self):
        """test the handling of SV_SHARE_CHANGED for non-ascii share name."""
        share_holder = NotifyShareHolder.from_params(
            'share_id', None, u'año', 'test_username', 'visible',
            ACCESS_LEVEL_RW)
        self.vm._got_root('root_uuid')
        self.vm.handle_SV_SHARE_CHANGED(info=share_holder)
        shouldbe_dir = os.path.join(self.shares_dir,
                                    get_share_dir_name(share_holder))
        self.assertEqual(shouldbe_dir, self.vm.shares['share_id'].path)

    def test_handle_SV_SHARE_CHANGED_visible(self):
        """test the handling of SV_SHARE_CHANGED for non-ascii visible name."""
        share_holder = NotifyShareHolder.from_params(
            'share_id', None, 'share', 'test_username', u'Ramón',
            ACCESS_LEVEL_RW)
        self.vm._got_root('root_uuid')
        self.vm.handle_SV_SHARE_CHANGED(info=share_holder)
        shouldbe_dir = os.path.join(self.shares_dir,
                                    get_share_dir_name(share_holder))
        self.assertEqual(shouldbe_dir, self.vm.shares['share_id'].path)


class VolumeManagerVolumesTests(BaseVolumeManagerTests):
    """Test UDF/Volumes bits of the VolumeManager."""

    def test_udf_ancestors(self):
        """UDF's ancestors are correctly returned."""
        suggested_path = u'~/Documents/Reading Años/Books/PDFs'
        expected = [u'~',
                    os.path.join(u'~', u'Documents'),
                    os.path.join(u'~', u'Documents', u'Reading Años'),
                    os.path.join(u'~', u'Documents', u'Reading Años',
                                 u'Books')]
        expected = [platform.expand_user(p.encode('utf-8')) for p in expected]

        udf = self._create_udf(suggested_path=suggested_path)
        self.assertEqual(expected, udf.ancestors)

    @defer.inlineCallbacks
    def test_add_udf(self):
        """Test for VolumeManager.add_udf."""
        suggested_path = u"~/suggested_path"
        udf = self._create_udf(suggested_path=suggested_path, subscribed=False)
        yield self.vm.add_udf(udf)
        path = get_udf_path(suggested_path)
        self.assertEqual(path, udf.path)
        self.assertEqual(1, len(self.vm.udfs))
        # check that the UDF is in the fsm metadata
        mdobj = self.main.fs.get_by_path(udf.path)
        self.assertEqual(mdobj.node_id, udf.node_id)
        self.assertEqual(mdobj.share_id, udf.volume_id)
        # check that there isn't a watch in the UDF (we aren't
        # subscribed to it)
        self.assertNotIn(udf.path, self.watches,
                         'watch for %r should not be present.' % udf.path)
        # remove the udf
        self.vm.udf_deleted(udf.volume_id)
        # add it again, but this time with subscribed = True
        udf.subscribed = True
        yield self.vm.add_udf(udf)
        path = get_udf_path(suggested_path)
        self.assertEqual(path, udf.path)
        self.assertEqual(1, len(self.vm.udfs))
        # check that the UDF is in the fsm metadata
        mdobj = self.main.fs.get_by_path(udf.path)
        self.assertEqual(mdobj.node_id, udf.node_id)
        self.assertEqual(mdobj.share_id, udf.volume_id)
        # check that there is a watch in the UDF
        self.assertIn(udf.path, self.watches,
                      'watch for %r should be present.' % udf.path)

    @defer.inlineCallbacks
    def test_add_udf_calls_AQ(self):
        """Test that VolumeManager.add_udf calls AQ.rescan_from_scratch."""
        udf = self._create_udf(subscribed=True)
        scratch_d = defer.Deferred()

        def fake_rescan_from_scratch(volume_id):
            """A fake rescan_from_scratch that check the arguments."""
            self.assertEqual(udf.volume_id, volume_id)
            scratch_d.callback(None)
        self.main.action_q.rescan_from_scratch = fake_rescan_from_scratch

        yield self.vm.add_udf(udf)
        yield scratch_d

        self.assertEqual(1, len(self.vm.udfs))
        # check that the UDF is in the fsm metadata
        mdobj = self.main.fs.get_by_path(udf.path)
        self.assertEqual(mdobj.node_id, udf.node_id)
        self.assertEqual(mdobj.share_id, udf.volume_id)
        self.assertIn(udf.path, self.watches,
                      'watch for %r should be present.' % udf.path)

    @defer.inlineCallbacks
    def test_udf_deleted(self):
        """Test for VolumeManager.udf_deleted."""
        udf = self._create_udf()
        yield self.vm.add_udf(udf)
        self.assertEqual(1, len(self.vm.udfs))
        self.vm.udf_deleted(udf.volume_id)
        self.assertEqual(0, len(self.vm.udfs))
        # check that the UDF isn't in the fsm metadata
        self.assertRaises(KeyError, self.main.fs.get_by_path, udf.path)
        # check that there isn't a watch in the UDF
        self.assertNotIn(udf.path, self.watches,
                         'watch for %r should not be present.' % udf.path)

    @defer.inlineCallbacks
    def test_udf_deleted_with_content(self):
        """
        Test for VolumeManager.udf_deleted when the UDF
        contains files and directories.

        """
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        self.assertEqual(1, len(self.vm.udfs))
        # create a few files and directories
        dirs = ['dir', os.path.join('dir', 'subdir'),
                os.path.join('dir', 'empty_dir')]
        for i, dir in enumerate(dirs):
            path = os.path.join(udf.path, dir)
            if not path_exists(path):
                make_dir(path, recursive=True)
            self.main.fs.create(path, udf.volume_id, is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
            # add a inotify watch to the dir
            yield self.vm._add_watch(path)
        files = ['a_file', os.path.join('dir', 'file'),
                 os.path.join('dir', 'subdir', 'file')]
        for i, file in enumerate(files):
            path = os.path.join(udf.path, file)
            self.main.fs.create(path, udf.volume_id)
            self.main.fs.set_node_id(path, 'file_node_id' + str(i))
        paths = self.main.fs.get_paths_starting_with(udf.path)
        self.assertEqual(len(paths), len(dirs + files) + 1)
        self.vm.udf_deleted(udf.volume_id)
        self.assertEqual(0, len(self.vm.udfs))
        # check that the UDF isn't in the fsm metadata
        self.assertRaises(KeyError, self.main.fs.get_by_path, udf.path)
        # check that there isn't a watch in the UDF
        self.assertNotIn(udf.path, self.watches,
                         'watch for %r should not be present.' % udf.path)
        # check that there isn't any udf childs around
        for path, _ in paths:
            self.assertRaises(KeyError, self.main.fs.get_by_path, path)
        # get the childs (should be an empty list)
        paths = self.main.fs.get_paths_starting_with(udf.path)
        self.assertEqual(0, len(paths))

    @defer.inlineCallbacks
    def test_get_volume(self):
        """Test for VolumeManager.get_volume."""
        # create a Share
        share_id = uuid.uuid4()
        share = self._create_share(volume_id=share_id)
        # create a UDF
        udf_id = uuid.uuid4()
        udf = self._create_udf(volume_id=udf_id)
        yield self.vm.add_udf(udf)
        yield self.vm.add_share(share)
        self.assertEqual(1, len(self.vm.udfs))
        self.assertEqual(2, len(self.vm.shares))
        self.assertEqual(udf.volume_id,
                         self.vm.get_volume(str(udf_id)).id)
        self.assertEqual(udf.path, self.vm.get_volume(str(udf_id)).path)
        self.assertEqual(share.volume_id, self.vm.get_volume(str(share_id)).id)


class HandleListVolumesTestCase(BaseVolumeManagerTests):
    """Test the handling of the AQ_LIST_VOLUMES event."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(HandleListVolumesTestCase, self).setUp()
        # the UDF part makes sense if UDF autosubscribe is True
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES(self):
        """Test the handling of the AQ_LIST_VOLUMES event."""
        share_id = uuid.uuid4()
        share_name = u'a share name'
        share_node_id = 'something'
        share_volume = self._create_share_volume(volume_id=share_id,
                                                 name=share_name,
                                                 node_id=share_node_id)
        udf_id = uuid.uuid4()
        udf_node_id = 'yadda-yadda'
        suggested_path = u'~/UDF'
        udf_path = get_udf_path(suggested_path)
        udf_volume = self._create_udf_volume(volume_id=udf_id,
                                             node_id=udf_node_id,
                                             suggested_path=suggested_path)
        root_volume = volumes.RootVolume(uuid.uuid4(), 17, 10)
        response = [share_volume, udf_volume, root_volume]
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        self.vm.refresh_volumes = lambda: d1.errback('refresh_volumes called!')
        self._listen_for('VM_UDF_CREATED', d1.callback)
        self._listen_for('SV_VOLUME_NEW_GENERATION', d2.callback)
        self.vm.handle_AQ_LIST_VOLUMES(response)
        yield d1
        yield d2
        self.assertEqual(2, len(self.vm.shares))  # the new share and root
        self.assertEqual(1, len(self.vm.udfs))  # the new udf
        # check that the share is in the shares dict
        self.assertIn(str(share_id), self.vm.shares)
        self.assertIn(str(udf_id), self.vm.udfs)
        share = self.vm.shares[str(share_id)]
        self.assertEqual(share_name, share.name)
        self.assertEqual(share_node_id, share.node_id)
        udf = self.vm.udfs[str(udf_id)]
        self.assertEqual(udf_node_id, udf.node_id)
        self.assertEqual(udf_path, udf.path)
        # check that the root it's there, have right node_id and generation
        self.assertIn(request.ROOT, self.vm.shares)
        root = self.vm.shares[request.ROOT]
        self.assertEqual(root.node_id, str(root_volume.node_id))
        # now send the same list again and check
        self.vm.handle_AQ_LIST_VOLUMES(response)
        self.assertEqual(2, len(self.vm.shares))  # the share and root
        self.assertEqual(1, len(self.vm.udfs))  # one udf
        # check that the udf is the same.
        new_udf = self.vm.udfs[str(udf_id)]
        self.assertEqual(udf.__dict__, new_udf.__dict__)

    def test_handle_AQ_LIST_VOLUMES_ERROR(self):
        """Test the handling of the AQ_LIST_VOLUMES_ERROR event."""
        # patch AQ.list_volumes
        class Helper(object):
            """Helper class to keep count of the retries"""
            retries = 0

            def list_volumes(self):
                """Fake list_volumes"""
                self.retries += 1

        helper = Helper()
        self.main.action_q = helper
        self.vm.handle_AQ_LIST_VOLUMES_ERROR("ERROR!")
        self.assertEqual(self.vm.list_volumes_retries, helper.retries)
        self.vm.handle_AQ_LIST_VOLUMES_ERROR("ERROR!")
        self.assertEqual(self.vm.list_volumes_retries, helper.retries)
        # reset the retry counter
        helper.retries = 0
        response = []
        self.vm.handle_AQ_LIST_VOLUMES(response)
        self.assertEqual(self.vm.list_volumes_retries, helper.retries)
        self.assertEqual(0, self.vm.list_volumes_retries)

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES_unicode(self):
        """Test the handling of the AQ_LIST_VOLUMES event."""
        share_id = uuid.uuid4()
        name = u'ñoño'
        share_volume = self._create_share_volume(volume_id=share_id, name=name,
                                                 node_id='fake_share_uuid')
        udf_id = uuid.uuid4()
        udf_volume = self._create_udf_volume(volume_id=udf_id,
                                             node_id='udf_uuid',
                                             generation=None, free_bytes=10,
                                             suggested_path=u'~/ñoño')
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = [share_volume, udf_volume]
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', d.callback)
        self.vm.handle_AQ_LIST_VOLUMES(response)
        yield d
        self.assertEqual(2, len(self.vm.shares))  # the new shares and root
        self.assertEqual(1, len(self.vm.udfs))  # the new shares and root
        # check that the share is in the shares dict
        self.assertIn(str(share_id), self.vm.shares)
        self.assertIn(str(udf_id), self.vm.udfs)
        share = self.vm.shares[str(share_id)]
        self.assertEqual(name, share.name)
        self.assertEqual('fake_share_uuid', share.node_id)
        udf = self.vm.udfs[str(udf_id)]
        self.assertEqual('udf_uuid', udf.node_id)
        self.assertEqual(get_udf_path(udf_volume.suggested_path),
                         udf.path)

    def test_handle_AQ_LIST_VOLUMES_root(self):
        """Test the handling of the AQ_LIST_VOLUMES event."""
        root_volume = volumes.RootVolume(uuid.uuid4(), None, 10)
        response = [root_volume]
        self.vm.refresh_volumes = lambda: self.fail('refresh_volumes called!')
        self.vm.handle_AQ_LIST_VOLUMES(response)
        self.assertEqual(1, len(self.vm.shares))  # the new share and root
        # check that the root is in the shares dict
        self.assertIn(request.ROOT, self.vm.shares)
        self.assertEqual(self.vm.shares[request.ROOT].node_id,
                         str(root_volume.node_id))

    @defer.inlineCallbacks
    def _test_handle_AQ_LIST_VOLUMES_accepted_share(self, auto_subscribe):
        """Test handle_AQ_LIST_VOLUMES event with an accepted share."""
        user_conf = config.get_user_config()
        user_conf.set_share_autosubscribe(auto_subscribe)

        # handle_AQ_SHARES_LIST is tested on test_handle_AQ_SHARES_LIST

        # create a volume list
        root_volume = volumes.RootVolume(uuid.uuid4(), 17, 10)
        share_id = uuid.uuid4()
        share_volume = self._create_share_volume(
            volume_id=share_id, node_id='fake_share_uuid', generation=10,
            accepted=True)
        response = [share_volume, root_volume]

        share_created_d = defer.Deferred()
        vol_new_gen_d = defer.Deferred()

        # patch aq.rescan_from_scratch in order to intercept the calls
        root_from_scratch_d = defer.Deferred()
        share_from_scratch_d = defer.Deferred()
        from_scratch_deferreds = {
            '': root_from_scratch_d, str(share_id): share_from_scratch_d}
        self.patch(
            self.main.action_q, 'rescan_from_scratch',
            lambda vol_id: from_scratch_deferreds.pop(vol_id).callback(vol_id))

        self.vm.refresh_volumes = lambda: self.fail('refresh_volumes called!')
        # listen for VM_SHARE_CREATED event for the new share
        self._listen_for('VM_SHARE_CREATED', share_created_d.callback)
        if auto_subscribe:
            expected_events = [{'generation': 17, 'volume_id': ''}]
            self._listen_for('SV_VOLUME_NEW_GENERATION',
                             vol_new_gen_d.callback, 1, collect=True)
        else:
            expected_events = {'generation': 17, 'volume_id': ''}
            self.patch(self.vm, '_scan_share', lambda *a, **kw: self.fail(a))
            self._listen_for(
                'SV_VOLUME_NEW_GENERATION', vol_new_gen_d.callback)

        self.vm.handle_AQ_LIST_VOLUMES(response)

        yield share_created_d
        events = yield vol_new_gen_d
        self.assertEqual(events, expected_events)

        vol_id = yield root_from_scratch_d
        self.assertEqual(vol_id, '')
        if auto_subscribe:
            vol_id = yield share_from_scratch_d
            self.assertEqual(vol_id, str(share_id))

        def check():
            """The test itself."""
            self.assertEqual(2, len(self.vm.shares))  # the share and the root
            # check that the share is in the shares dict
            self.assertIn(str(share_id), self.vm.shares)
            share = self.vm.shares[str(share_id)]
            self.assertEqual('fake_share', share.name)
            self.assertEqual('fake_share_uuid', share.node_id)
            self.assertTrue(share.accepted, "The share is accepted")
            if auto_subscribe:
                # root and share
                self.assertEqual(2, len(list(self.vm.get_volumes())))
                self.assertTrue(share.active)
            else:  # share was added to VM, but isn't active
                self.assertEqual(1, len(list(self.vm.get_volumes())))
                self.assertFalse(share.active)

        check()

        # root was already checked on test_handle_AQ_LIST_VOLUMES_root
        # patch aq.rescan_from_scratch in order to intercept the calls
        root_from_scratch_d = defer.Deferred()
        share_from_scratch_d = defer.Deferred()
        from_scratch_deferreds = {
            '': root_from_scratch_d, str(share_id): share_from_scratch_d}
        self.patch(
            self.main.action_q, 'rescan_from_scratch',
            lambda vol_id: from_scratch_deferreds.pop(vol_id).callback(vol_id))

        self.vm.handle_AQ_LIST_VOLUMES(response)

        vol_id = yield root_from_scratch_d
        self.assertEqual(vol_id, '')
        if auto_subscribe:
            vol_id = yield share_from_scratch_d
            self.assertEqual(vol_id, str(share_id))

        check()

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES_accepted_share_with_autosubscribe(self):
        """Test handle_AQ_LIST_VOLUMES event with an active share."""
        yield self._test_handle_AQ_LIST_VOLUMES_accepted_share(True)

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES_accepted_share_without_autosubscribe(self):
        """Test handle_AQ_LIST_VOLUMES event with an inactive share."""
        yield self._test_handle_AQ_LIST_VOLUMES_accepted_share(False)

    @defer.inlineCallbacks
    def _test_handle_AQ_LIST_VOLUMES_udf(self, auto_subscribe):
        """Test handle_AQ_LIST_VOLUMES event with an udf."""
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(auto_subscribe)

        # create a volume list
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_uuid', 23, 100, u'~/UDF')
        root_volume = volumes.RootVolume(uuid.uuid4(), 17, 10)
        response = [udf_volume, root_volume]

        self.vm.refresh_volumes = lambda: self.fail('refresh_volumes called!')

        udf_created_d = defer.Deferred()
        vol_new_gen_d = defer.Deferred()

        # patch aq.rescan_from_scratch in order to intercept the calls
        root_from_scratch_d = defer.Deferred()
        share_from_scratch_d = defer.Deferred()
        from_scratch_deferreds = {'': root_from_scratch_d,
                                  str(udf_id): share_from_scratch_d}
        self.patch(
            self.main.action_q, 'rescan_from_scratch',
            lambda vol_id: from_scratch_deferreds.pop(vol_id).callback(vol_id))

        # listen for VM_UDF_CREATED event for the new UDF
        self._listen_for('VM_UDF_CREATED', udf_created_d.callback)
        if auto_subscribe:
            expected_events = [{'generation': 17, 'volume_id': ''}]
            self._listen_for('SV_VOLUME_NEW_GENERATION',
                             vol_new_gen_d.callback, 1, collect=True)
        else:
            expected_events = {'generation': 17, 'volume_id': ''}
            self.patch(self.vm, '_scan_udf', self.fail)
            self._listen_for(
                'SV_VOLUME_NEW_GENERATION', vol_new_gen_d.callback)

        self.vm.handle_AQ_LIST_VOLUMES(response)

        yield udf_created_d
        events = yield vol_new_gen_d
        self.assertEqual(events, expected_events)

        vol_id = yield root_from_scratch_d
        self.assertEqual(vol_id, '')
        if auto_subscribe:
            vol_id = yield share_from_scratch_d
            self.assertEqual(vol_id, str(udf_id))

        def check():
            """The test itself."""
            self.assertEqual(1, len(self.vm.udfs))  # the new udf
            # check that the UDF is in the udfs dict
            self.assertIn(str(udf_id), self.vm.udfs)
            udf = self.vm.udfs[str(udf_id)]
            self.assertEqual('udf_uuid', udf.node_id)
            self.assertEqual(get_udf_path(udf_volume.suggested_path), udf.path)
            if auto_subscribe:
                # root and udf
                self.assertEqual(2, len(list(self.vm.get_volumes())))
                self.assertTrue(udf.active)
            else:  # udf was added to VM, but isn't active
                self.assertEqual(1, len(list(self.vm.get_volumes())))
                self.assertFalse(udf.active)

        check()

        # root was already checked on test_handle_AQ_LIST_VOLUMES_root

        # now send the same list again and check
        self.vm.handle_AQ_LIST_VOLUMES(response)

        check()

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES_udf_with_autosubscribe(self):
        """Test handle_AQ_LIST_VOLUMES event with an active udf."""
        yield self._test_handle_AQ_LIST_VOLUMES_udf(True)

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES_udf_without_autosubscribe(self):
        """Test handle_AQ_LIST_VOLUMES event with an inactive udf."""
        yield self._test_handle_AQ_LIST_VOLUMES_udf(False)

    @defer.inlineCallbacks
    def test_handle_AQ_LIST_VOLUMES_emits_volumes_changed(self):
        """When handling a new volume list, VM_VOLUMES_CHANGED is pushed."""
        share = self._create_share_volume()
        udf = self._create_udf_volume()
        root_volume = volumes.RootVolume(uuid.uuid4(), 17, 10)
        response = [share, udf, root_volume]

        udf_created_d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', udf_created_d.callback)

        volumes_changed_d = defer.Deferred()
        self._listen_for('VM_VOLUMES_CHANGED', volumes_changed_d.callback)

        self.vm.handle_AQ_LIST_VOLUMES(response)

        yield udf_created_d
        actual = yield volumes_changed_d
        expected = {'volumes': list(self.vm.get_volumes(all_volumes=True))}
        self.assertEqual(expected, actual)


class VolumeManagerOpTestsRequiringRealFSMonitor(BaseVolumeManagerTests):
    """Tests of UDF/Volumes operations which require a real FSMonitor."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(VolumeManagerOpTestsRequiringRealFSMonitor, self).setUp()
        # FakeMain sends _monitor_class to EventQueue, which
        # uses platform default monitor when given None:
        self.patch(FakeMain, "_monitor_class", None)
        self.main = FakeMain(root_dir=self.root_dir,
                             shares_dir=self.shares_dir,
                             data_dir=self.data_dir,
                             partials_dir=self.partials_dir)
        # re-do the patching from super that alters main or its
        # event_q:
        orig_add_watch = self.main.event_q.add_watch

        def fake_add_watch(path):
            self.watches.add(path)
            return orig_add_watch(path)

        orig_rm_watch = self.main.event_q.rm_watch

        def fake_rm_watch(path):
            self.watches.remove(path)
            return orig_rm_watch(path)

        self.patch(self.main.event_q, 'add_watch', fake_add_watch)
        self.patch(self.main.event_q, 'rm_watch', fake_rm_watch)
        self.vm = self.main.vm
        self.main.event_q.push('SYS_INIT_DONE')
        self.addCleanup(self.main.shutdown)

    @defer.inlineCallbacks
    def test_add_udf_with_content(self):
        """Test for VolumeManager.add_udf with content on disk."""
        # create a sync instance
        from ubuntuone.syncdaemon import sync
        sync = sync.Sync(self.main)
        suggested_path = u"~/suggested_path"
        udf = self._create_udf(suggested_path=suggested_path,
                               subscribed=True)
        # create some files inside it
        make_dir(udf.path)
        for i in range(10):
            with open_file(os.path.join(udf.path, 'file_%d' % i), 'wb') as f:
                f.write(os.urandom(10))
        self.assertEqual(len(os.listdir(udf.path)), 10)
        # patch the fake action queue to intercept make_file calls
        called = []
        self.main.action_q.make_file = lambda *a: called.append(a)
        yield self.vm.add_udf(udf)
        self.assertEqual(len(called), 10)
        # check that the UDF is in the fsm metadata
        mdobj = self.main.fs.get_by_path(udf.path)
        self.assertEqual(mdobj.node_id, udf.node_id)
        self.assertEqual(mdobj.share_id, udf.volume_id)
        # check that there is a watch in the UDF
        self.assertIn(udf.path, self.watches,
                      'watch for %r should be present.' % udf.path)


class VolumeManagerOperationsTests(BaseVolumeManagerTests):
    """Test UDF/Volumes operations."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(VolumeManagerOperationsTests, self).setUp()
        self.main.event_q.push('SYS_INIT_DONE')

    def test_create_udf(self):
        """
        Test that VolumeManager.create_udf calls AQ.create_udf and
        AQ_CREATE_UDF_OK is correctly handled.

        """
        d = defer.Deferred()
        suggested_path = u"~/MyUDF"
        path = get_udf_path(suggested_path)
        udf_id = uuid.uuid4()
        node_id = uuid.uuid4()
        # patch AQ.create_udf

        def create_udf(path, name, marker):
            """Fake create_udf"""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=udf_id,
                                   node_id=node_id, marker=marker)
        self.main.action_q.create_udf = create_udf

        def check(info):
            """Check the udf attributes."""
            udf = info['udf']
            self.assertEqual(udf.path, path)
            self.assertEqual(udf.volume_id, str(udf_id))
            self.assertEqual(udf.node_id, str(node_id))
            self.assertEqual(udf.suggested_path, suggested_path)
            self.assertTrue(isinstance(udf.suggested_path, unicode),
                            'suggested_path should be unicode')
            self.assertIn(udf.volume_id, self.vm.udfs)

        self._listen_for('VM_UDF_CREATED', d.callback)
        self.vm.create_udf(path)
        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_create_udf_unicode(self):
        """Test VolumeManager.create_udf.

        Check that VM calls AQ.create_udf with unicode values.
        """
        d = defer.Deferred()
        path = get_udf_path(u"~/ñoño/mirá que lindo mi udf")
        # patch AQ.create_udf

        def create_udf(path, name, marker):
            """Fake create_udf"""
            d.callback((path, name))

        self.patch(self.main.action_q, 'create_udf', create_udf)
        self.vm.create_udf(path)

        path, name = yield d
        self.assertIsInstance(
            name, unicode, 'name should be unicode but is: %s' % type(name))
        self.assertIsInstance(
            path, unicode, 'path should be unicode but is: %s' % type(path))

    @defer.inlineCallbacks
    def test_delete_volume(self):
        """
        Test that VolumeManager.delete_volume calls AQ.delete_volume and
        AQ_DELETE_VOLUME_OK is correctly handled.

        """
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        share = self._create_share()
        yield self.vm.add_share(share)
        d = defer.Deferred()
        # patch AQ.delete_volume

        def delete_volume(volume_id, path):
            """Fake delete_volume"""
            self.main.event_q.push("AQ_DELETE_VOLUME_OK", volume_id=volume_id)
        self.main.action_q.delete_volume = delete_volume

        def check_udf(info):
            """Check the udf attributes."""
            deleted_udf = info['volume']
            self.assertEqual(deleted_udf.path, udf.path)
            self.assertEqual(deleted_udf.volume_id, udf.volume_id)
            self.assertEqual(deleted_udf.node_id, udf.node_id)
            self.assertEqual(deleted_udf.suggested_path, udf.suggested_path)
            self.assertNotIn(deleted_udf.volume_id, self.vm.udfs)
            d = defer.Deferred()
            self._listen_for('VM_VOLUME_DELETED', d.callback)
            self.vm.delete_volume(share.volume_id)
            return d

        def check_share(info):
            """Check the share attributes."""
            deleted_share = info['volume']
            self.assertEqual(deleted_share.path, share.path)
            self.assertEqual(deleted_share.volume_id, share.volume_id)
            self.assertEqual(deleted_share.node_id, share.node_id)
            self.assertNotIn(deleted_share.volume_id, self.vm.shares)

        self._listen_for('VM_VOLUME_DELETED', d.callback)
        d.addCallback(check_udf)
        d.addCallback(check_share)
        self.vm.delete_volume(udf.volume_id)
        yield d

    @defer.inlineCallbacks
    def test_delete_volume_aq_args(self):
        """Test that VolumeManager.delete_volume calls AQ.delete_volume."""
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        d = defer.Deferred()
        # patch AQ.delete_volume

        def delete_volume(volume_id, path):
            """Fake AQ.delete_volume."""
            if volume_id == udf.volume_id and path == udf.path:
                d.callback(None)
            else:
                d.errback(Exception(""))
        self.patch(self.main.action_q, 'delete_volume', delete_volume)
        self.vm.delete_volume(udf.volume_id)
        yield d

    @defer.inlineCallbacks
    def test_subscribe_udf(self):
        """Test VolumeManager.subscribe_udf method."""
        # create and add a UDF
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        self.assertFalse(self.vm.udfs[udf.volume_id].subscribed)
        # subscribe to it
        yield self.vm.subscribe_udf(udf.volume_id)
        self.assertTrue(self.vm.udfs[udf.volume_id].subscribed)

    @defer.inlineCallbacks
    def test_subscribe_udf_missing_path(self):
        """Test VolumeManager.subscribe_udf with a missing path """
        # create and add a UDF
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        self.assertFalse(path_exists(udf.path))
        self.assertFalse(self.vm.udfs[udf.id].subscribed)
        # subscribe to it
        yield self.vm.subscribe_udf(udf.id)
        self.assertTrue(self.vm.udfs[udf.id].subscribed)
        self.assertTrue(path_exists(udf.path))

    @defer.inlineCallbacks
    def test_subscribe_udf_missing_fsm_md(self):
        """Test VolumeManager.subscribe_udf with a missing node in fsm."""
        # create and add a UDF
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        self.assertFalse(path_exists(udf.path))
        self.assertFalse(self.vm.udfs[udf.id].subscribed)
        yield self.vm.subscribe_udf(udf.id)
        yield self.vm.unsubscribe_udf(udf.id)
        # delete the fsm metadata
        self.main.fs.delete_metadata(udf.path)
        # subscribe to it and fail!
        try:
            yield self.vm.subscribe_udf(udf.id)
        except KeyError, e:
            self.assertIn(udf.path, e.args[0])
        else:
            self.fail('Must get a KeyError!')

    @defer.inlineCallbacks
    def test_subscribe_udf_missing_volume(self):
        """Test VolumeManager.subscribe_udf with a invalid volume_id."""
        # create and add a UDF
        try:
            yield self.vm.subscribe_udf('invalid_udf_id')
        except VolumeDoesNotExist, e:
            self.assertEqual('DOES_NOT_EXIST', e.args[0])
            self.assertEqual('invalid_udf_id', e.args[1])
        else:
            self.fail('Must get a VolumeDoesNotExist!')

    @defer.inlineCallbacks
    def _test_subscribe_udf_generations(self, udf):
        """Test subscribe_udf with a generation."""
        scratch_d = defer.Deferred()

        def fake_rescan_from_scratch(volume_id):
            """A fake rescan_from_scratch that check the arguments."""
            self.assertEqual(udf.volume_id, volume_id)
            scratch_d.callback(None)
        self.main.action_q.rescan_from_scratch = fake_rescan_from_scratch
        # subscribe to it
        yield self.vm.subscribe_udf(udf.volume_id)
        yield scratch_d
        self.assertTrue(self.vm.udfs[udf.volume_id].subscribed)

    @defer.inlineCallbacks
    def test_subscribe_udf_valid_generation(self):
        """Test subscribe_udf with a valid generation."""
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        self.assertFalse(self.vm.udfs[udf.volume_id].subscribed)
        # update udf generation
        self.vm.update_generation(udf.volume_id, 0)
        yield self._test_subscribe_udf_generations(udf)

    @defer.inlineCallbacks
    def test_subscribe_udf_without_generation(self):
        """Test subscribe_udf without a valid generation."""
        # create and add a UDF
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        self.assertFalse(self.vm.udfs[udf.volume_id].subscribed)
        # update udf generation
        self.vm.update_generation(udf.volume_id, None)
        yield self._test_subscribe_udf_generations(udf)

    @defer.inlineCallbacks
    def test_unsubscribe_udf(self):
        """Test VolumeManager.unsubscribe_udf method."""
        # create and add a UDF
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        self.assertTrue(self.vm.udfs[udf.volume_id].subscribed)
        # unsubscribe from it
        self.vm.unsubscribe_udf(udf.volume_id)
        self.assertFalse(self.vm.udfs[udf.volume_id].subscribed)

    @defer.inlineCallbacks
    def test_unsubscribe_udf_with_content(self):
        """Test VolumeManager.unsubscribe_udf method in a UDF with content."""
        # create and add a UDF
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        self.assertTrue(self.vm.udfs[udf.volume_id].subscribed)
        # create a few files and directories
        dirs = ['dir', os.path.join('dir', 'subdir'),
                os.path.join('dir', 'empty_dir')]
        for i, dir in enumerate(dirs):
            path = os.path.join(udf.path, dir)
            if not path_exists(path):
                make_dir(path, recursive=True)
            self.main.fs.create(path, udf.volume_id, is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
            # add a inotify watch to the dir
            yield self.vm._add_watch(path)
        files = ['a_file', os.path.join('dir', 'file'),
                 os.path.join('dir', 'subdir', 'file')]
        for i, file in enumerate(files):
            path = os.path.join(udf.path, file)
            open_file(path, 'w').close()
            self.main.fs.create(path, udf.volume_id)
            self.main.fs.set_node_id(path, 'file_node_id' + str(i))
        paths = self.main.fs.get_paths_starting_with(udf.path)
        self.assertEqual(len(paths), len(dirs + files) + 1)

        # unsubscribe from it
        self.vm.unsubscribe_udf(udf.volume_id)

        self.assertEqual(1, len(self.vm.udfs))
        self.assertFalse(self.vm.udfs[udf.volume_id].subscribed)
        # check that the UDF is in the fsm metadata
        self.assertTrue(self.main.fs.get_by_path(udf.path))
        # get the childs (should be an empty list)
        paths = list(self.main.fs.get_paths_starting_with(udf.path))
        self.assertEqual(len(dirs + files) + 1, len(paths))
        # check that there isn't a watch in the UDF
        self.assertNotIn(udf.path, self.watches,
                         'watch for %r should not be present.' % udf.path)
        # check that the childs don't have a watch
        for path, is_dir in paths:
            if is_dir:
                self.assertNotIn(path, self.watches,
                                 'watch for %r should not be present.' % path)

    @defer.inlineCallbacks
    def test_unsubscribe_subscribe_udf_with_content(self):
        """Test for re-subscribing to a UDF."""
        # create and add a UDF
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        self.main.event_q.rm_watch(udf.path)
        self.assertTrue(self.vm.udfs[udf.volume_id].subscribed)
        # create a few files and directories
        dirs = ['dir', os.path.join('dir', 'subdir'),
                os.path.join('dir', 'empty_dir')]
        for i, path in enumerate(dirs):
            path = os.path.join(udf.path, path)
            if not path_exists(path):
                make_dir(path, recursive=True)
            self.main.fs.create(path, udf.volume_id, is_dir=True)
            self.main.fs.set_node_id(path, 'dir_node_id' + str(i))
        files = ['a_file', os.path.join('dir', 'file'),
                 os.path.join('dir', 'subdir', 'file')]
        for i, path in enumerate(files):
            path = os.path.join(udf.path, path)
            open_file(path, 'w').close()
            self.main.fs.create(path, udf.volume_id)
            self.main.fs.set_node_id(path, 'file_node_id' + str(i))
        paths = list(self.main.fs.get_paths_starting_with(udf.path))
        # add a inotify watch to the dirs
        for path, is_dir in paths:
            if is_dir:
                yield self.vm._add_watch(path)
        self.assertEqual(len(paths), len(dirs + files) + 1, paths)

        # unsubscribe from it
        self.vm.unsubscribe_udf(udf.volume_id)

        self.assertEqual(1, len(self.vm.udfs))
        self.assertFalse(self.vm.udfs[udf.volume_id].subscribed)
        # check that the UDF is in the fsm metadata
        self.assertTrue(self.main.fs.get_by_path(udf.path))
        # check that there isn't a watch in the UDF
        self.assertNotIn(udf.path, self.watches,
                         'watch for %r should not be present.' % udf.path)
        # check that the childs don't have a watch
        for path, is_dir in paths:
            if is_dir:
                self.assertNotIn(path, self.watches,
                                 'watch for %r should not be present.' % path)
        # check the childs
        paths = self.main.fs.get_paths_starting_with(udf.path)
        self.assertEqual(len(dirs + files) + 1, len(paths))
        # resubscribe to it
        yield self.vm.subscribe_udf(udf.volume_id)
        paths = list(self.main.fs.get_paths_starting_with(udf.path))
        # we should only have the dirs, as the files metadata is
        # delete by local rescan (both hashes are '')
        self.assertEqual(len(dirs) + 1, len(paths))
        # check that there is a watch in the UDF
        self.assertIn(udf.path, self.watches,
                      'watch for %r should be present.' % udf.path)
        # check that the child dirs have a watch
        for path, is_dir in paths:
            if is_dir:
                self.assertIn(path, self.watches,
                              'watch for %r should be present.' % path)
                self.vm._remove_watch(path)

    @defer.inlineCallbacks
    def test_cleanup_volumes(self):
        """Test for VolumeManager._cleanup_volumes"""
        share_path = os.path.join(self.shares_dir, 'fake_share')
        share = Share(path=share_path, volume_id='share_id')
        yield self.vm.add_share(share)
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        self.assertIn(share.volume_id, self.vm.shares)
        self.assertIn(udf.volume_id, self.vm.udfs)
        self.vm._cleanup_volumes(shares=[])
        self.assertNotIn(share.volume_id, self.vm.shares)
        self.assertIn(udf.volume_id, self.vm.udfs)
        self.vm._cleanup_volumes(udfs=[])
        self.assertNotIn(udf.volume_id, self.vm.udfs)
        # all at once
        yield self.vm.add_share(share)
        yield self.vm.add_udf(udf)
        self.assertIn(share.volume_id, self.vm.shares)
        self.assertIn(udf.volume_id, self.vm.udfs)
        self.vm._cleanup_volumes(shares=[], udfs=[])
        self.assertNotIn(share.volume_id, self.vm.shares)
        self.assertNotIn(udf.volume_id, self.vm.udfs)

    @defer.inlineCallbacks
    def test_cleanup_shared(self):
        """Test for VolumeManager._cleanup_shared"""
        shared_path = os.path.join(self.root_dir, 'fake_shared')
        shared = Share(path=shared_path, volume_id='shared_id')
        yield self.vm.add_shared(shared)
        self.assertIn(shared.volume_id, self.vm.shared)
        self.vm._cleanup_shared([shared.volume_id])
        self.assertIn(shared.volume_id, self.vm.shared)
        self.vm._cleanup_shared([])
        self.assertNotIn(shared.volume_id, self.vm.shared)

    @defer.inlineCallbacks
    def test_cleanup_shares(self):
        """Test for VolumeManager._cleanup_shares"""
        share_path = os.path.join(self.shares_dir, 'fake_share')
        share = Share(path=share_path, volume_id='share_id')
        share_2_path = os.path.join(self.root_dir, 'fake_share_2')
        share_2 = Share(path=share_2_path, volume_id='share_2_id')
        yield self.vm.add_share(share)
        yield self.vm.add_share(share_2)
        self.assertIn(share.volume_id, self.vm.shares)
        self.assertIn(share_2.volume_id, self.vm.shares)
        self.vm._cleanup_shares([])
        self.assertNotIn(share.volume_id, self.vm.shares)
        self.assertNotIn(share_2.volume_id, self.vm.shares)
        yield self.vm.add_share(share)
        yield self.vm.add_share(share_2)
        self.vm._cleanup_shares([share.volume_id])
        self.assertIn(share.volume_id, self.vm.shares)
        self.assertNotIn(share_2.volume_id, self.vm.shares)
        yield self.vm.add_share(share)
        yield self.vm.add_share(share_2)
        self.vm._cleanup_shares([share.volume_id, share_2.volume_id])
        self.assertIn(share.volume_id, self.vm.shares)
        self.assertIn(share_2.volume_id, self.vm.shares)

    @defer.inlineCallbacks
    def test_handle_AQ_CREATE_UDF_OK(self):
        """Test AQ_CREATE_UDF_OK. The UDF is always subscribed."""
        d = defer.Deferred()
        path = get_udf_path(u'~/ñoño')
        udf_id = uuid.uuid4()
        node_id = uuid.uuid4()
        # patch AQ.create_udf

        def create_udf(path, name, marker):
            """Fake create_udf"""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=udf_id,
                                   node_id=node_id, marker=marker)
        self.main.action_q.create_udf = create_udf
        self._listen_for('VM_UDF_CREATED', d.callback)
        # fake VM state, call create_udf
        self.vm.create_udf(path)

        info = yield d

        udf = info['udf']
        self.assertEqual(udf.path, path)
        self.assertEqual(udf.volume_id, str(udf_id))
        self.assertEqual(udf.node_id, str(node_id))
        self.assertEqual(0, len(self.vm.marker_udf_map))
        self.assertTrue(self.vm.udfs[str(udf_id)])
        self.assertTrue(self.vm.udfs[str(udf_id)].subscribed)
        self.assertTrue(path_exists(udf.path))

    def test_handle_AQ_CREATE_UDF_ERROR(self):
        """Test for handle_AQ_CREATE_UDF_ERROR."""
        d = defer.Deferred()
        path = get_udf_path(u'~/ñoño')
        # patch AQ.create_udf

        def create_udf(path, name, marker):
            """Fake create_udf"""
            self.main.event_q.push("AQ_CREATE_UDF_ERROR",
                                   marker=marker, error="ERROR!")
        self.main.action_q.create_udf = create_udf
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        # fake VM state, call create_udf
        self.vm.create_udf(path)

        def check(info):
            """The callback"""
            self.assertEqual(info['path'], path)
            self.assertEqual(info['error'], "ERROR!")
            self.assertEqual(0, len(self.vm.marker_udf_map))
        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_handle_AQ_DELETE_VOLUME_OK(self):
        """Test for handle_AQ_DELETE_VOLUME_OK."""
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        d = defer.Deferred()
        # patch AQ.delete_volume

        def delete_volume(vol_id, path):
            """Fake delete_volume"""
            self.main.event_q.push("AQ_DELETE_VOLUME_OK", volume_id=vol_id)
        self.main.action_q.delete_volume = delete_volume

        def check(info):
            """Check the udf attributes."""
            deleted_udf = info['volume']
            self.assertEqual(deleted_udf.path, udf.path)
            self.assertEqual(deleted_udf.volume_id, udf.volume_id)
            self.assertEqual(deleted_udf.node_id, udf.node_id)
            self.assertEqual(deleted_udf.suggested_path, udf.suggested_path)
            self.assertNotIn(deleted_udf.volume_id, self.vm.udfs)
        self._listen_for('VM_VOLUME_DELETED', d.callback)
        d.addCallback(check)
        self.vm.delete_volume(udf.volume_id)
        yield d

    @defer.inlineCallbacks
    def test_handle_AQ_DELETE_VOLUME_ERROR(self):
        """Test for handle_AQ_DELETE_VOLUME_ERROR."""
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)
        d = defer.Deferred()
        # patch AQ.delete_volume

        def delete_volume(vol_id, path):
            """Fake delete_volume"""
            self.main.event_q.push("AQ_DELETE_VOLUME_ERROR",
                                   volume_id=vol_id, error="ERROR!")
        self.main.action_q.delete_volume = delete_volume

        def check(info):
            """Check the udf attributes."""
            deleted_udf, error = info['volume_id'], info['error']
            self.assertEqual(deleted_udf, udf.volume_id)
            self.assertIn(deleted_udf, self.vm.udfs)
            self.assertEqual(error, 'ERROR!')
        self._listen_for('VM_VOLUME_DELETE_ERROR', d.callback)
        d.addCallback(check)
        self.vm.delete_volume(udf.volume_id)
        yield d

    def test_handle_AQ_DELETE_VOLUME_ERROR_missing_volume(self):
        """Test for handle_AQ_DELETE_VOLUME_ERROR for a missing volume."""
        called = []
        self.vm.refresh_volumes = lambda: called.append(True)
        self.vm.handle_AQ_DELETE_VOLUME_ERROR('unknown vol id', 'error')
        self.assertTrue(called)
        self.assertTrue(self.handler.check_warning("missing volume id"))

    @defer.inlineCallbacks
    def _test_handle_SV_VOLUME_CREATED_share(self, auto_subscribe):
        """Test for handle_SV_VOLUME_CREATED with shares."""
        user_conf = config.get_user_config()
        user_conf.set_share_autosubscribe(auto_subscribe)

        # start the test
        share_volume = self._create_share_volume(accepted=False,
                                                 access_level=ACCESS_LEVEL_RW)
        # initialize the the root
        self.vm._got_root('root_uuid')

        share_created_d = defer.Deferred()
        self._listen_for('VM_SHARE_CREATED', share_created_d.callback)

        local_scan_d = defer.Deferred()
        server_rescan_d = defer.Deferred()

        if auto_subscribe:
            self.patch(self.main.lr, 'scan_dir',
                       lambda *a, **kw: local_scan_d.callback(a))
            self.patch(self.main.action_q, 'rescan_from_scratch',
                       server_rescan_d.callback)
        else:
            self.patch(self.main.lr, 'scan_dir', lambda *a: self.fail(a))
            self.patch(self.main.action_q, 'rescan_from_scratch', self.fail)

        # fire SV_VOLUME_CREATED with a share
        self.vm.handle_SV_VOLUME_CREATED(share_volume)

        info = yield share_created_d
        share_id = info['share_id']
        share = self.vm.get_volume(share_id)
        self.assertEqual(share.volume_id, str(share_id))
        self.assertIn(str(share_id), self.vm.shares)

        if auto_subscribe:
            self.assertTrue(share.subscribed)
            self.assertTrue(path_exists(share.path))
            # check that scan_dir and rescan_from_scratch is called
            yield local_scan_d
            vol_id = yield server_rescan_d
            self.assertEqual(vol_id, share.volume_id)
        else:
            self.assertFalse(share.subscribed)
            self.assertFalse(path_exists(share.path))

    def test_handle_SV_VOLUME_CREATED_share_subscribe(self):
        """Test SV_VOLUME_CREATED with share auto_subscribe """
        return self._test_handle_SV_VOLUME_CREATED_share(True)

    def test_handle_SV_VOLUME_CREATED_share_no_subscribe(self):
        """Test SV_VOLUME_CREATED without share auto_subscribe """
        return self._test_handle_SV_VOLUME_CREATED_share(False)

    @defer.inlineCallbacks
    def _test_handle_SV_VOLUME_CREATED_udf(self, auto_subscribe):
        """Test for handle_SV_VOLUME_CREATED with udfs."""
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(auto_subscribe)
        # start the test
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_uuid', None, 10, u'~/ñoño')
        # initialize the the root
        self.vm._got_root('root_uuid')

        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', d.callback)
        rescan_cb = defer.Deferred()
        self.patch(
            self.main.action_q, 'rescan_from_scratch', rescan_cb.callback)

        self.vm.handle_SV_VOLUME_CREATED(udf_volume)
        info = yield d
        udf = info['udf']
        self.assertEqual(udf.volume_id, str(udf_id))
        self.assertIn(str(udf_id), self.vm.udfs)
        if auto_subscribe:
            self.assertTrue(self.vm.udfs[udf.id].subscribed)
            self.assertTrue(path_exists(udf.path))
            # check that rescan_from_scratch is called
            vol_id = yield rescan_cb
            self.assertEqual(vol_id, udf.volume_id)
        else:
            self.assertFalse(self.vm.udfs[udf.id].subscribed)
            self.assertFalse(path_exists(udf.path))

    def test_handle_SV_VOLUME_CREATED_udf_subscribe(self):
        """Test SV_VOLUME_CREATED with udf auto_subscribe """
        return self._test_handle_SV_VOLUME_CREATED_udf(True)

    def test_handle_SV_VOLUME_CREATED_udf_no_subscribe(self):
        """Test SV_VOLUME_CREATED without udf auto_subscribe """
        return self._test_handle_SV_VOLUME_CREATED_udf(False)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_DELETED(self):
        """Test for handle_SV_VOLUME_DELETED."""
        share = self._create_share()
        # create a UDF
        suggested_path = u'~/ñoño'
        path = get_udf_path(suggested_path)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_uuid', None, 10,
                                       suggested_path)
        udf = UDF.from_udf_volume(udf_volume, path)
        yield self.vm.add_udf(udf)
        yield self.vm.add_share(share)
        # initialize the the root
        self.vm._got_root('root_uuid')
        d = defer.Deferred()
        self._listen_for('VM_VOLUME_DELETED', d.callback)
        self.vm.handle_SV_VOLUME_DELETED(udf_volume.volume_id)
        info = yield d

        udf = info['volume']
        self.assertEqual(udf.volume_id, str(udf_id))
        self.assertNotIn(str(udf_id), self.vm.udfs)
        # subscribe a new listener, for deleting a share.
        share_deferred = defer.Deferred()
        self._listen_for('VM_VOLUME_DELETED', share_deferred.callback)
        # fire SV_VOLUME_DELETED with a share
        self.vm.handle_SV_VOLUME_DELETED(share.volume_id)
        share_info = yield share_deferred
        new_share = share_info['volume']
        self.assertEqual(new_share.volume_id, share.volume_id)
        self.assertNotIn(str(share.volume_id), self.vm.shares)

    @defer.inlineCallbacks
    def test_get_volumes(self):
        """Tests for VolumeManager.get_volumes.

        This is a legacy test where all the volume types are mixed. Dedicated
        tests in a per volume basis follow below.

        """
        share_path = os.path.join(self.shares_dir, 'fake_share')
        share_modify = Share(
            path=share_path, volume_id='share_id', node_id=str(uuid.uuid4()),
            access_level=ACCESS_LEVEL_RW, accepted=True, subscribed=True)
        share_no_accepted_path = os.path.join(self.shares_dir, 'fake_share')
        share_no_accepted = Share(
            path=share_no_accepted_path, node_id=str(uuid.uuid4()),
            volume_id='accepted_share_id', access_level=ACCESS_LEVEL_RW,
            accepted=False, subscribed=True)
        share_view = Share(
            path=share_path, volume_id='share_id_view',
            access_level=ACCESS_LEVEL_RO, accepted=True, subscribed=True)
        yield self.vm.add_share(share_modify)
        yield self.vm.add_share(share_view)
        yield self.vm.add_share(share_no_accepted)
        shared_path = os.path.join(self.root_dir, 'fake_shared')
        shared = Shared(path=shared_path, volume_id='shared_id')
        yield self.vm.add_shared(shared)
        udf_subscribed = self._create_udf(subscribed=True)
        udf_unsubscribed = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf_subscribed)
        yield self.vm.add_udf(udf_unsubscribed)
        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertNotIn(share_no_accepted.id, volumes_ids)
        self.assertIn(share_modify.id, volumes_ids)
        self.assertIn(share_view.id, volumes_ids)
        self.assertNotIn(shared.id, volumes_ids)
        self.assertIn(udf_subscribed.id, volumes_ids)
        self.assertNotIn(udf_unsubscribed.id, volumes_ids)
        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertIn(share_no_accepted.id, all_volumes_ids)
        self.assertIn(share_modify.id, all_volumes_ids)
        self.assertIn(share_view.id, all_volumes_ids)
        self.assertNotIn(shared.id, all_volumes_ids)
        self.assertIn(udf_subscribed.id, all_volumes_ids)
        self.assertIn(udf_unsubscribed.id, all_volumes_ids)

    @defer.inlineCallbacks
    def test_get_volumes_shared(self):
        """Tests for VolumeManager.get_volumes."""
        shared_path = os.path.join(self.root_dir, 'fake_shared')
        shared = Shared(path=shared_path, volume_id='shared_id')
        yield self.vm.add_shared(shared)

        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertNotIn(shared.id, volumes_ids)

        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertNotIn(shared.id, all_volumes_ids)

    @defer.inlineCallbacks
    def test_get_volumes_share_active_modify(self):
        """Tests for VolumeManager.get_volumes."""
        share = self._create_share(access_level=ACCESS_LEVEL_RW,
                                   accepted=True, subscribed=True)
        yield self.vm.add_share(share)

        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertIn(share.id, volumes_ids)

        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertIn(share.id, all_volumes_ids)

    @defer.inlineCallbacks
    def test_get_volumes_share_active_view(self):
        """Tests for VolumeManager.get_volumes."""
        share = self._create_share(access_level=ACCESS_LEVEL_RO,
                                   accepted=True, subscribed=True)
        yield self.vm.add_share(share)

        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertIn(share.id, volumes_ids)

        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertIn(share.id, all_volumes_ids)

    @defer.inlineCallbacks
    def test_get_volumes_share_inactive(self):
        """Tests for VolumeManager.get_volumes."""
        share_no_accepted = self._create_share(accepted=False,
                                               subscribed=True)
        yield self.vm.add_share(share_no_accepted)
        share_no_subscribed = self._create_share(accepted=True,
                                                 subscribed=False)
        yield self.vm.add_share(share_no_subscribed)

        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertNotIn(share_no_accepted.id, volumes_ids)
        self.assertNotIn(share_no_subscribed.id, volumes_ids)

        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertIn(share_no_accepted.id, all_volumes_ids)
        self.assertIn(share_no_subscribed.id, all_volumes_ids)

    @defer.inlineCallbacks
    def test_get_volumes_udf_inactive(self):
        """Tests for VolumeManager.get_volumes."""
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)

        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertNotIn(udf.id, volumes_ids)

        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertIn(udf.id, all_volumes_ids)

    @defer.inlineCallbacks
    def test_get_volumes_udf_active(self):
        """Tests for VolumeManager.get_volumes."""
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)

        volumes = list(self.vm.get_volumes())
        volumes_ids = [v.id for v in volumes]
        self.assertIn(udf.id, volumes_ids)

        all_volumes = list(self.vm.get_volumes(all_volumes=True))
        all_volumes_ids = [v.id for v in all_volumes]
        self.assertIn(udf.id, all_volumes_ids)

    def test_udf_can_write(self):
        """Test that UDF class match Share.can_write() API."""
        udf = self._create_udf(subscribed=False)
        self.assertTrue(udf.can_write())

    def test_udf_from_udf_volume(self):
        """Test for UDF.from_udf_volume."""
        suggested_path = u'~/foo/bar'
        path = get_udf_path(suggested_path)
        volume = volumes.UDFVolume(uuid.uuid4(), uuid.uuid4(), None,
                                   10, suggested_path)
        udf = UDF.from_udf_volume(volume, path)
        self.assertTrue(isinstance(udf.id, basestring))
        self.assertTrue(isinstance(udf.node_id, basestring))

    def test_share_from_share_volume(self):
        """Test for Share.from_share_volume."""
        share = self._create_share()
        self.assertTrue(isinstance(share.id, basestring))
        self.assertTrue(isinstance(share.node_id, basestring))

    @defer.inlineCallbacks
    def test_volumes_list_args_as_AQ_wants(self):
        """Test that handle_AQ_LIST_VOLUMES match the kwargs used by AQ."""
        root_volume = volumes.RootVolume(uuid.uuid4(), None, 10)
        d = defer.Deferred()
        self.vm._got_root = lambda node_id, free_bytes: d.callback(
                                                        (node_id, free_bytes))
        self.main.event_q.push('AQ_LIST_VOLUMES', volumes=[root_volume])
        root_node_id, free_bytes = yield d
        self.assertEqual(str(root_volume.node_id), root_node_id)
        self.assertEqual(root_volume.free_bytes, free_bytes)

    def test_validate_UDF_path_inside_home(self):
        """Test proper validation of path for creating folders."""
        folder_path = os.path.join(self.home_dir, 'Test Me')

        result, msg = self.vm.validate_path_for_folder(folder_path)
        self.assertTrue(result)
        self.assertIs(
            msg, "",
            '%r must be a valid path for creating a folder.' % folder_path)

    def test_validate_UDF_path_if_folder_shares_a_prefix_with_an_udf(self):
        """Test proper validation of path for creating folders.

        If the user chooses a folder with the same prefix as an UDF, but
        outside every UDF, the path is valid.

        """
        tricky_path = self.root_dir
        assert not tricky_path.endswith(os.path.sep)
        tricky_path += ' Suffix'
        assert tricky_path.startswith(self.root_dir)

        result, msg = self.vm.validate_path_for_folder(tricky_path)
        self.assertTrue(result)
        self.assertIs(
            msg, "",
            '%r must be a valid path for creating a folder.' % tricky_path)

    def test_validate_UDF_path_not_valid_if_outside_home(self):
        """A folder outside ~ is not valid."""
        outside_home = os.path.abspath(
            os.path.join(self.home_dir, os.path.pardir))

        result, msg = self.vm.validate_path_for_folder(outside_home)
        self.assertFalse(result)
        self.assertIsNot(
            msg, "",
            '%r must be an invalid path for creating a folder.' % outside_home)

    def test_validate_UDF_not_valid_if_folder_inside_root(self):
        """A folder inside the root is not valid."""
        root_path = self.root_dir
        # create a valid path inside the root
        inside_root = os.path.abspath(os.path.join(root_path, 'test'))

        result, msg = self.vm.validate_path_for_folder(inside_root)
        self.assertFalse(result)
        self.assertIsNot(
            msg, "",
            '%r must be an invalid path for creating a folder.' % inside_root)

    @defer.inlineCallbacks
    def test_validate_UDF_not_valid_if_folder_inside_an_udf(self):
        """A folder inside an UDF is not valid."""
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        # create a valid path inside an existing UDF
        inside_udf = os.path.abspath(os.path.join(udf.path, 'test'))

        result, msg = self.vm.validate_path_for_folder(inside_udf)
        self.assertFalse(result)
        self.assertIsNot(
            msg, "",
            '%r must be an invalid path for creating a folder.' % inside_udf)

    @defer.inlineCallbacks
    def test_validate_UDF_not_valid_if_folder_is_parent_of_an_udf(self):
        """A folder parent of an UDF is not valid."""
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        # create a valid path that is parent from an existing UDF
        udf_parent = os.path.abspath(
            os.path.join(self.home_dir, os.path.pardir))

        result, msg = self.vm.validate_path_for_folder(udf_parent)
        self.assertFalse(result)
        self.assertIsNot(
            msg, "",
            '%r must be an invalid path for creating a folder.' % udf_parent)

    def test_not_valid_if_folder_is_file(self):
        """A link path is not valid."""
        self.patch(volume_manager.os.path, 'isdir', lambda p: False)
        self.patch(volume_manager, 'path_exists', lambda p: True)
        path_link = os.path.join(self.home_dir, 'Test Me')

        result, msg = self.vm.validate_path_for_folder(path_link)
        self.assertFalse(result)
        self.assertIsNot(
            msg, "",
            '%r must be an invalid path for creating a folder.' % path_link)

    def test_not_valid_if_folder_is_link(self):
        """A link path is not valid."""
        self.patch(volume_manager, 'is_link', lambda p: True)
        path_link = os.path.join(self.home_dir, 'Test Me')

        result, msg = self.vm.validate_path_for_folder(path_link)
        self.assertFalse(result)
        self.assertIsNot(
            msg, "",
            '%r must be an invalid path for creating a folder.' % path_link)

    @defer.inlineCallbacks
    def test_no_UDFs_outside_home(self):
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        # Use a directory surely outside home
        # Drive root on Windows, or root on linux
        outside_path = os.path.splitdrive(udf.path)[0] or "/"

        def create_udf(path, name, marker):
            """Fake create_udf"""
            d = dict(volume_id=uuid.uuid4(), node_id=uuid.uuid4(),
                     marker=marker)
            self.main.event_q.push("AQ_CREATE_UDF_OK", **d)

        # patch FakeAQ
        self.main.action_q.create_udf = create_udf
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        self._listen_for('VM_UDF_CREATED', lambda r: d.errback(Exception(r)))
        self.vm.create_udf(outside_path)
        result = yield d
        self.assertEqual(1, len(list(self.vm.udfs.keys())))
        self.assertEqual(
            result, dict(path=outside_path, error="UDFs must be within home"))

    @defer.inlineCallbacks
    def test_no_UDFs_inside_root(self):
        """Test that a UDF can't be created inside the root"""
        # initialize the root
        self.vm._got_root('root_uuid')
        udf_path = os.path.join(self.root_dir, 'udf_inside_root')
        # patch FakeAQ

        def create_udf(path, name, marker):
            """Fake create_udf"""
            d = dict(volume_id=uuid.uuid4(), node_id=uuid.uuid4(),
                     marker=marker)
            self.main.event_q.push("AQ_CREATE_UDF_OK", **d)

        self.main.action_q.create_udf = create_udf
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        self._listen_for('VM_UDF_CREATED', lambda r: d.errback(Exception(r)))
        self.vm.create_udf(udf_path)
        result = yield d
        self.assertEqual(0, len(list(self.vm.udfs.keys())))
        self.assertEqual(result,
                         dict(path=udf_path, error="UDFs can not be nested"))

    @defer.inlineCallbacks
    def test_no_UDFs_inside_udf(self):
        """Test that a UDF can't be created inside a UDF."""
        udf = self._create_udf(subscribed=True)
        udf_child = os.path.join(udf.path, 'd')
        yield self.vm.add_udf(udf)
        # patch FakeAQ

        def create_udf(path, name, marker):
            """Fake create_udf"""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=uuid.uuid4(),
                                   node_id=uuid.uuid4(), marker=marker)
        self.main.action_q.create_udf = create_udf
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        self._listen_for('VM_UDF_CREATED', lambda r: d.errback(Exception(r)))
        self.vm.create_udf(udf_child)
        result = yield d
        self.assertEqual(1, len(list(self.vm.udfs.keys())))
        self.assertEqual(result,
                         dict(path=udf_child, error="UDFs can not be nested"))

    @defer.inlineCallbacks
    def test_no_UDFs_as_UDF_parent(self):
        """Test that a UDF can't be created if there is a UDF inside."""
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        udf_parent_path = os.path.dirname(udf.path)
        # patch FakeAQ

        def create_udf(path, name, marker):
            """Fake create_udf."""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=uuid.uuid4(),
                                   node_id=uuid.uuid4(), marker=marker)
        self.main.action_q.create_udf = create_udf
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        self._listen_for('VM_UDF_CREATED', lambda r: d.errback(Exception(r)))
        self.vm.create_udf(udf_parent_path)
        result = yield d
        self.assertEqual(1, len(list(self.vm.udfs.keys())))
        d = dict(path=udf_parent_path, error="UDFs can not be nested")
        self.assertEqual(result, d)

    @defer.inlineCallbacks
    def test_UDF_ok_name_similar_shorter(self):
        """UDF can be created if name is similar but shorter than other UDF."""
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        similar_path = udf.path[:-2]  # shorter!

        def create_udf(path, name, marker):
            """Fake create_udf."""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=uuid.uuid4(),
                                   node_id=uuid.uuid4(), marker=marker)
        self.main.action_q.create_udf = create_udf

        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', d.callback)
        self._listen_for('VM_UDF_CREATE_ERROR',
                         lambda r: d.errback(Exception(r)))
        self.vm.create_udf(similar_path)
        yield d

    @defer.inlineCallbacks
    def test_UDF_ok_name_similar_longer(self):
        """UDF can be created if name is similar but longer than other UDF."""
        udf = self._create_udf(subscribed=True)
        yield self.vm.add_udf(udf)
        similar_path = udf.path + 'foo'  # longer!

        def create_udf(path, name, marker):
            """Fake create_udf."""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=uuid.uuid4(),
                                   node_id=uuid.uuid4(), marker=marker)
        self.main.action_q.create_udf = create_udf

        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', d.callback)
        self._listen_for('VM_UDF_CREATE_ERROR',
                         lambda r: d.errback(Exception(r)))
        self.vm.create_udf(similar_path)
        yield d

    @defer.inlineCallbacks
    def test_dont_delete_volumes_on_handle_AQ_SHARES_LIST(self):
        """Test that VM don't delete shares when handling AQ_SHARE_LIST."""
        # the UDF part makes sense if UDF autosubscribe is True
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)

        share_volume = self._create_share_volume()
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_uuid', None, 10, u'~/UDF')
        root_volume = volumes.RootVolume(uuid.uuid4(), None, 10)
        response = [share_volume, udf_volume, root_volume]
        d = defer.Deferred()
        self.vm.refresh_volumes = lambda: d.errback('refresh_volumes called!')
        self._listen_for('VM_UDF_CREATED', d.callback)
        self.vm.handle_AQ_LIST_VOLUMES(response)
        yield d
        self.assertEqual(2, len(self.vm.shares))  # the new share and root
        self.assertEqual(1, len(self.vm.udfs))  # the new udf
        shared_id = uuid.uuid4()
        shared_response = ShareResponse.from_params(
            shared_id, 'from_me', 'fake_share_uuid', 'fake_share', 'username',
            'visible_username', 'yes', ACCESS_LEVEL_RO)
        shares_response = ListShares(None)
        shares_response.shares = [shared_response]
        self.vm.handle_AQ_SHARES_LIST(shares_response)
        # check that all the shares are still there
        self.assertEqual(2, len(self.vm.shares))  # the new share and root

    @defer.inlineCallbacks
    def test_handle_SV_FREE_SPACE(self):
        """Test for VolumeManager.handle_SV_FREE_SPACE."""
        share = self._create_share(free_bytes=None)
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_uuid')
        # create a UDF
        udf = self._create_udf()
        yield self.vm.add_share(share)
        yield self.vm.add_udf(udf)
        # override AQ.check_conditions
        d = defer.Deferred()

        def check_conditions():
            """Fake check_conditions that just keep count of calls."""
            if d.called:
                d.addCallback(lambda _: defer.succeed(d.result + 1))
            else:
                d.callback(1)
        self.main.action_q.check_conditions = check_conditions
        # now start playing
        assert root.free_bytes is None, 'root free_bytes should be None'
        assert share.free_bytes is None, 'share free_bytes should be None'
        self.vm.handle_SV_FREE_SPACE(root.volume_id, 10)
        self.assertEqual(10, self.vm.get_free_space(root.volume_id))
        self.vm.handle_SV_FREE_SPACE(share.volume_id, 20)
        self.assertEqual(20, self.vm.get_free_space(share.volume_id))
        self.vm.handle_SV_FREE_SPACE(udf.volume_id, 50)
        self.assertEqual(50, self.vm.get_free_space(udf.volume_id))
        # udf free space is root free space, check it's the same
        self.assertEqual(50, self.vm.get_free_space(root.volume_id))
        counter = yield d
        # check that check_conditions was called 3 times
        self.assertEqual(3, counter)

    @defer.inlineCallbacks
    def test_update_and_get_free_space(self):
        """Test for VolumeManager.update_free_space and get_free_space."""
        share = self._create_share(free_bytes=None)
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_node_id')
        # create a UDF
        udf = self._create_udf()
        yield self.vm.add_share(share)
        yield self.vm.add_udf(udf)
        self.assertEqual(None, self.vm.get_free_space(share.volume_id))
        self.assertEqual(None, self.vm.get_free_space(udf.volume_id))
        self.assertEqual(None, self.vm.get_free_space(root.volume_id))
        self.vm.update_free_space(share.volume_id, 10)
        self.vm.update_free_space(udf.volume_id, 20)
        self.vm.update_free_space('missing_id', 20)
        self.assertEqual(10, self.vm.get_free_space(share.volume_id))
        self.assertEqual(20, self.vm.get_free_space(udf.volume_id))
        self.assertEqual(20, self.vm.get_free_space(root.volume_id))
        self.assertEqual(0, self.vm.get_free_space('missing_id'))
        self.vm.update_free_space(root.volume_id, 30)
        self.assertEqual(30, self.vm.get_free_space(udf.volume_id))
        self.assertEqual(30, self.vm.get_free_space(root.volume_id))

    def test_get_free_space_no_volume(self):
        """Test get_free_space for a volume we don't have."""
        called = []
        self.vm.refresh_volumes = lambda: called.append(True)
        self.vm.get_free_space('unknown vol id')
        self.assertTrue(called)
        self.assertTrue(self.handler.check_warning("there is no such volume"))

    def test_update_free_space_no_volume(self):
        """Test update_free_space for a volume we don't have."""
        called = []
        self.vm.refresh_volumes = lambda: called.append(True)
        self.vm.update_free_space('unknown vol id', 123)
        self.assertTrue(called)
        self.assertTrue(self.handler.check_warning("no such volume_id"))

    @defer.inlineCallbacks
    def test_UDF_cant_be_a_symlink(self):
        """Test that a UDF can't be a symlink."""
        # initialize the root
        self.vm._got_root('root_uuid')
        real_udf_path = os.path.join(self.home_dir, "my_udf")
        udf_path = os.path.join(self.home_dir, "MyUDF")
        # patch FakeAQ

        def create_udf(path, name, marker):
            """Fake create_udf"""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=uuid.uuid4(),
                                   node_id=uuid.uuid4(), marker=marker)
        self.main.action_q.create_udf = create_udf
        # create the symlink
        make_dir(real_udf_path, recursive=True)
        make_link(real_udf_path, udf_path)
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        self._listen_for('VM_UDF_CREATED', lambda r: d.errback(Exception(r)))
        self.vm.create_udf(udf_path)
        result = yield d
        self.assertEqual(0, len(list(self.vm.udfs.keys())))
        self.assertEqual(result, dict(path=udf_path,
                                      error="UDFs can not be a symlink"))

    @defer.inlineCallbacks
    def test_UDF_cant_be_inside_symlink(self):
        """Test that a UDF can't be inside a symlink."""
        # initialize the root
        self.vm._got_root('root_uuid')
        real_udf_path = os.path.join(self.home_dir, "udf_parent", "my_udf")
        udf_path = os.path.join(self.home_dir, "MyUDF")
        # patch FakeAQ

        def create_udf(path, name, marker):
            """Fake create_udf"""
            self.main.event_q.push("AQ_CREATE_UDF_OK", volume_id=uuid.uuid4(),
                                   node_id=uuid.uuid4(), marker=marker)
        self.main.action_q.create_udf = create_udf
        # create the symlink
        make_dir(real_udf_path, recursive=True)
        make_link(real_udf_path, udf_path)
        d = defer.Deferred()
        self._listen_for('VM_UDF_CREATE_ERROR', d.callback)
        self._listen_for('VM_UDF_CREATED', lambda r: d.errback(Exception(r)))
        self.vm.create_udf(udf_path)
        result = yield d
        self.assertEqual(0, len(list(self.vm.udfs.keys())))
        self.assertEqual(result, dict(path=udf_path,
                                      error="UDFs can not be a symlink"))

    @defer.inlineCallbacks
    def test_server_rescan(self):
        """Test the server_rescan method."""
        share_volume = self._create_share_volume()
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_node_id', 1, 200, u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]

        # patch fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)
        vol_rescan_d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION',
                         vol_rescan_d.callback)  # autosubscribe is False
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        volumes_changed_d = defer.Deferred()
        self._listen_for('VM_VOLUMES_CHANGED', volumes_changed_d.callback)
        yield self.vm.server_rescan()
        yield server_rescan_d
        events = yield vol_rescan_d
        vols = yield volumes_changed_d

        self.assertEqual({'generation': 1, 'volume_id': ''}, events)

        expected = list(self.vm.get_volumes(all_volumes=True))
        self.assertEqual({'volumes': expected}, vols)

    @defer.inlineCallbacks
    def test_server_rescan_with_share_autosubscribe(self):
        """Test the server_rescan method."""
        user_conf = config.get_user_config()
        user_conf.set_share_autosubscribe(True)

        share_id = uuid.uuid4()
        share_volume = self._create_share_volume(volume_id=share_id,
                                                 generation=17)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(
            udf_id, 'udf_node_id', 13, 200, u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]

        # patch the fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)

        # patch aq.rescan_from_scratch in order to intercept the calls
        root_from_scratch_d = defer.Deferred()
        share_from_scratch_d = defer.Deferred()
        from_scratch_deferreds = {'': root_from_scratch_d,
                                  str(share_id): share_from_scratch_d}
        self.patch(
            self.main.action_q, 'rescan_from_scratch',
            lambda vol_id: from_scratch_deferreds.pop(vol_id).callback(vol_id))

        vol_rescan_d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION',
                         vol_rescan_d.callback, 1, collect=True)
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        yield self.vm.server_rescan()

        yield server_rescan_d
        events = yield vol_rescan_d
        expected_events = [{'generation': 1, 'volume_id': ''}]
        self.assertEqual(expected_events, events)

        vol_id = yield root_from_scratch_d
        self.assertEqual(vol_id, '')
        vol_id = yield share_from_scratch_d
        self.assertEqual(vol_id, str(share_id))

    @defer.inlineCallbacks
    def test_server_rescan_with_udf_autosubscribe(self):
        """Test the server_rescan method."""
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)

        share_volume = self._create_share_volume()
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_node_id', 13, 200,
                                       u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]

        # patch the fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)

        # patch aq.rescan_from_scratch in order to intercept the calls
        root_from_scratch_d = defer.Deferred()
        udf_from_scratch_d = defer.Deferred()
        from_scratch_deferreds = {'': root_from_scratch_d,
                                  str(udf_id): udf_from_scratch_d}
        self.patch(
            self.main.action_q, 'rescan_from_scratch',
            lambda vol_id: from_scratch_deferreds.pop(vol_id).callback(vol_id))

        # patch LR
        self.patch(self.main.lr, 'scan_dir', lambda *a, **k: None)

        vol_rescan_d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION',
                         vol_rescan_d.callback, 1, collect=True)
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        yield self.vm.server_rescan()

        events = yield vol_rescan_d

        expected_events = [{'generation': 1, 'volume_id': ''}]
        self.assertEqual(expected_events, events)
        vol_id = yield root_from_scratch_d
        self.assertEqual(vol_id, '')
        vol_id = yield udf_from_scratch_d
        self.assertEqual(vol_id, str(udf_id))
        yield server_rescan_d

    @defer.inlineCallbacks
    def test_server_rescan_with_autosubscribe(self):
        """Test the server_rescan method."""
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)
        user_conf.set_share_autosubscribe(True)

        share_id = uuid.uuid4()
        share_volume = self._create_share_volume(volume_id=share_id,
                                                 generation=17)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_node_id', 13, 200,
                                       u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]

        # patch the fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)

        # patch aq.rescan_from_scratch in order to intercept the calls
        root_from_scratch_d = defer.Deferred()
        share_from_scratch_d = defer.Deferred()
        udf_from_scratch_d = defer.Deferred()
        from_scratch_deferreds = {'': root_from_scratch_d,
                                  str(share_id): share_from_scratch_d,
                                  str(udf_id): udf_from_scratch_d}
        self.patch(
            self.main.action_q, 'rescan_from_scratch',
            lambda vol_id: from_scratch_deferreds.pop(vol_id).callback(vol_id))

        # patch LR
        self.patch(self.main.lr, 'scan_dir', lambda *a, **k: None)

        vol_rescan_d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION',
                         vol_rescan_d.callback, 1, collect=True)
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        yield self.vm.server_rescan()

        yield server_rescan_d
        events = yield vol_rescan_d

        expected_events = [{'generation': 1, 'volume_id': ''}]
        self.assertEqual(expected_events, events)

        vol_id = yield root_from_scratch_d
        self.assertEqual(vol_id, '')
        vol_id = yield share_from_scratch_d
        self.assertEqual(vol_id, str(share_id))
        vol_id = yield udf_from_scratch_d
        self.assertEqual(vol_id, str(udf_id))

    @defer.inlineCallbacks
    def test_server_rescan_error(self):
        """Test the server_rescan method."""
        # patch fake action queue
        self.main.action_q.query_volumes = lambda: defer.fail(
            Exception('foo bar'))
        d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_ERROR', d.callback)
        yield self.vm.server_rescan()
        yield d
        # now when _volumes_rescan_cb fails
        # patch fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed([])
        # patch volume manager

        def broken_volumes_rescan_cb(_):
            raise ValueError('die!')
        self.vm._volumes_rescan_cb = broken_volumes_rescan_cb
        d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_ERROR', d.callback)
        yield self.vm.server_rescan()
        yield d

    @defer.inlineCallbacks
    def test_refresh_shares_called_after_server_rescan(self):
        """Test that refresh_shares is called after server_rescan."""
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [root_volume]

        # patch fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)
        d = defer.Deferred()
        self.vm.refresh_shares = lambda: d.callback(True)
        yield self.vm.server_rescan()
        called = yield d
        self.assertTrue(called)
    test_refresh_shares_called_after_server_rescan.timeout = 1

    @defer.inlineCallbacks
    def test_server_rescan_clean_dead_udf(self):
        """Test cleanup of dead volumes after server_rescan method."""
        # the UDF part makes sense if UDF autosubscribe is True
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)
        share_volume = self._create_share_volume()
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_node_id', 1, 200,
                                       u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]

        # patch fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        udf_created_d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', udf_created_d.callback)
        yield self.vm.server_rescan()
        yield server_rescan_d
        yield udf_created_d
        self.assertIn(request.ROOT, self.vm.shares)
        self.assertIn(str(share_volume.volume_id), self.vm.shares)
        self.assertEqual(1, len(self.vm.udfs))
        self.assertEqual(2, len(self.vm.shares))
        # remove the udf from the response list
        response = [share_volume, root_volume]
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        yield self.vm.server_rescan()
        yield server_rescan_d

        self.assertIn(request.ROOT, self.vm.shares)
        self.assertIn(str(share_volume.volume_id), self.vm.shares)
        self.assertEqual(0, len(self.vm.udfs))
        self.assertEqual(2, len(self.vm.shares))

    @defer.inlineCallbacks
    def test_server_rescan_clean_dead_shares(self):
        """Test cleanup of dead volumes after server_rescan method."""
        # the UDF part makes sense if UDF autosubscribe is True
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)
        share_volume = self._create_share_volume()
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_node_id', 1, 200,
                                       u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]
        # patch fake action queue
        self.main.action_q.query_volumes = lambda: defer.succeed(response)
        self.patch(self.main.lr, 'scan_dir', lambda *a, **kw: defer.succeed(a))
        self.patch(self.main.action_q, 'rescan_from_scratch', defer.succeed)
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        udf_created_d = defer.Deferred()
        # wait for the VM_UDF_CREATED event in order to properly shutdown
        # (local rescan/udf scan is running)
        self._listen_for('VM_UDF_CREATED', udf_created_d.callback)
        yield self.vm.server_rescan()
        yield server_rescan_d
        yield udf_created_d
        self.assertIn(request.ROOT, self.vm.shares)
        self.assertIn(str(udf_volume.volume_id), self.vm.udfs)
        self.assertEqual(1, len(self.vm.udfs))
        self.assertEqual(2, len(self.vm.shares))
        # remove the share from the response list
        response = [udf_volume, root_volume]
        server_rescan_d = defer.Deferred()
        self._listen_for('SYS_SERVER_RESCAN_DONE', server_rescan_d.callback)
        yield self.vm.server_rescan()
        yield server_rescan_d
        self.assertIn(request.ROOT, self.vm.shares)
        self.assertIn(str(udf_volume.volume_id), self.vm.udfs)
        self.assertEqual(1, len(self.vm.udfs))
        self.assertEqual(1, len(self.vm.shares))

    @defer.inlineCallbacks
    def test_volumes_rescan_cb(self):
        """Test for _volumes_rescan_cb."""
        # the UDF part makes sense if UDF autosubscribe is True
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)
        user_conf.set_share_autosubscribe(True)

        share_id = uuid.uuid4()
        share_volume = self._create_share_volume(volume_id=share_id,
                                                 generation=1)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_node_id', 1, 200, u'~/UDF')
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [share_volume, udf_volume, root_volume]

        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback, 1, True)
        udf_d = defer.Deferred()
        self._listen_for('VM_UDF_CREATED', udf_d.callback)
        shares, udfs = yield self.vm._volumes_rescan_cb(response)
        events = yield d
        # check the returned shares and udfs
        self.assertEqual(shares, [str(share_id), ''])
        self.assertEqual(udfs, [str(udf_id)])
        # wait for the UDF local and server rescan
        yield udf_d
        events_dict = dict((event['volume_id'], event['generation'])
                           for event in events)
        # new udfs server rescan is triggered after local rescan.
        self.assertNotIn(str(udf_id), events_dict)
        self.assertIn(request.ROOT, events_dict)
        self.assertEqual(1, events_dict[request.ROOT])
        # set the local metadata generation to new value
        share = self.vm.shares[str(share_id)]
        share.generation = share_volume.generation
        self.vm.shares[str(share_id)] = share
        udf = self.vm.udfs[str(udf_id)]
        udf.generation = udf_volume.generation
        self.vm.udfs[str(udf_id)] = udf
        root = self.vm.root
        root.generation = root_volume.generation
        self.vm.shares[request.ROOT] = root
        # now that we have the volumes in metadata, try with a higher  value.
        share_volume.generation = 10
        udf_volume.generation = 5
        root_volume.generation = 1
        response = [share_volume, udf_volume, root_volume]
        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback, 2, True)
        self.vm._volumes_rescan_cb(response)
        events = yield d
        events_dict = dict((event['volume_id'], event['generation'])
                           for event in events)
        self.assertIn(str(share_id), events_dict)
        self.assertIn(str(udf_id), events_dict)
        self.assertNotIn(request.ROOT, events_dict)  # same gen as metadata
        self.assertEqual(10, events_dict[str(share_id)])
        self.assertEqual(5, events_dict[str(udf_id)])
        # now only change the root volume generation
        share_volume.generation = 1
        udf_volume.generation = 1
        root_volume.generation = 100
        response = [share_volume, udf_volume, root_volume]
        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback, 1, True)
        self.vm._volumes_rescan_cb(response)
        events = yield d
        events_dict = dict((event['volume_id'], event['generation'])
                           for event in events)
        self.assertNotIn(str(share_id), events_dict)
        self.assertNotIn(str(udf_id), events_dict)
        self.assertIn(request.ROOT, events_dict)  # same generation as metadata
        self.assertEqual(100, events_dict[request.ROOT])

    @defer.inlineCallbacks
    def test_volumes_rescan_cb_handle_root_node_id(self):
        """Test _volumes_rescan_cb handling of the root node id."""
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [root_volume]
        self.assertEqual(None, self.vm.root.node_id)
        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback, 1, True)
        self.vm._volumes_rescan_cb(response)
        events = yield d
        events_dict = dict((event['volume_id'], event['generation'])
                           for event in events)
        self.assertIn(request.ROOT, events_dict)
        self.assertEqual(str(root_id), self.vm.root.node_id)
        self.assertTrue(self.main.fs.get_by_node_id(request.ROOT,
                                                    str(root_id)))

    @defer.inlineCallbacks
    def test_volumes_rescan_cb_root_node_id_not_in_fsm(self):
        """Test _volumes_rescan_cb with the root node id missing from fsm."""
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [root_volume]
        # set the node_id
        root = self.vm.root
        root.node_id = str(root_id)
        self.vm.shares[request.ROOT] = root
        self.assertEqual(str(root_id), self.vm.root.node_id)
        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback, 1, True)
        self.vm._volumes_rescan_cb(response)
        events = yield d
        events_dict = dict((event['volume_id'], event['generation'])
                           for event in events)
        self.assertIn(request.ROOT, events_dict)
        self.assertEqual(str(root_id), self.vm.root.node_id)
        self.assertTrue(self.main.fs.get_by_node_id(request.ROOT,
                                                    str(root_id)))

    @defer.inlineCallbacks
    def test_volumes_rescan_cb_inactive_volume(self):
        """Test _volumes_rescan_cb with inactive volume."""
        suggested_path = u'~/ñoño/ñandú'
        path = get_udf_path(suggested_path)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, uuid.uuid4(), 10, 100,
                                       suggested_path)
        udf = UDF.from_udf_volume(udf_volume, path)
        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [udf_volume, root_volume]
        yield self.vm.add_udf(udf)
        # unsubscribe the udf
        self.vm.unsubscribe_udf(udf.volume_id)
        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback)
        self.vm._volumes_rescan_cb(response)
        event = yield d
        self.assertEqual(len(event), 2)
        events_dict = {event['volume_id']: event['generation']}
        self.assertNotIn(udf.volume_id, events_dict)
        self.assertIn(request.ROOT, events_dict)

    @defer.inlineCallbacks
    def test_volumes_rescan_cb_missing_fsm_md(self):
        """Test _volumes_rescan_cb with a missing fsm node."""
        # the UDF part makes sense if UDF autosubscribe is True
        user_conf = config.get_user_config()
        user_conf.set_udf_autosubscribe(True)

        # create a UDF
        suggested_path = u'~/ñoño/ñandú'
        path = get_udf_path(suggested_path)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_uuid', 10, 100,
                                       suggested_path)
        udf = UDF.from_udf_volume(udf_volume, path)
        udf.subscribed = True

        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [udf_volume, root_volume]
        yield self.vm.add_udf(udf)
        # delete the fsm metadata
        self.main.fs.delete_metadata(udf.path)
        d = defer.Deferred()
        self._listen_for(
            'SV_VOLUME_NEW_GENERATION', d.callback, 2, collect=True)
        self.patch(self.vm, '_scan_volume', defer.succeed)
        self.vm._volumes_rescan_cb(response)
        events = yield d
        self.assertEqual(len(events), 2)
        events_dict = dict((evt['volume_id'], evt['generation'])
                           for evt in events)
        self.assertIn(udf.volume_id, events_dict)
        self.assertIn(request.ROOT, events_dict)
        # check that the fsm metadata is there
        mdobj = self.main.fs.get_by_path(udf.path)
        self.assertEqual(udf.node_id, mdobj.node_id)
        self.assertEqual(udf.id, mdobj.share_id)
        self.assertEqual(udf.path, mdobj.path)

    @defer.inlineCallbacks
    def test_volumes_rescan_cb_active_udf(self):
        """Test _volumes_rescan_cb with an active UDF and no-autosubscribe."""
        # create a UDF
        suggested_path = u'~/ñoño/ñandú'
        path = get_udf_path(suggested_path)
        udf_id = uuid.uuid4()
        udf_volume = volumes.UDFVolume(udf_id, 'udf_uuid', None, 10,
                                       suggested_path)
        udf = UDF.from_udf_volume(udf_volume, path)

        root_id = uuid.uuid4()
        root_volume = volumes.RootVolume(root_id, 1, 500)
        response = [udf_volume, root_volume]
        yield self.vm.add_udf(udf)
        # subscribe the udf
        yield self.vm.subscribe_udf(udf.volume_id)
        d = defer.Deferred()
        self._listen_for('SV_VOLUME_NEW_GENERATION', d.callback, 1)
        shares, udfs = self.vm._volumes_rescan_cb(response)
        self.assertIn(udf.volume_id, udfs)
        yield d

    @defer.inlineCallbacks
    def test_update_generation(self):
        """Test for the update_generation method."""
        share = self._create_share()
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_node_id')
        # create a UDF
        udf = self._create_udf()
        yield self.vm.add_share(share)
        yield self.vm.add_udf(udf)
        self.assertEqual(None, udf.generation)
        self.assertEqual(None, share.generation)
        self.assertEqual(None, root.generation)
        self.vm.update_generation(udf.volume_id, 1)
        self.vm.update_generation(share.volume_id, 2)
        self.vm.update_generation(root.volume_id, 3)
        udf = self.vm.get_volume(udf.volume_id)
        share = self.vm.get_volume(share.volume_id)
        root = self.vm.root
        self.assertEqual(1, udf.generation)
        self.assertEqual(2, share.generation)
        self.assertEqual(3, root.generation)
        # try to update the generation of non-existing volume_id
        self.assertRaises(VolumeDoesNotExist, self.vm.update_generation,
                          str(uuid.uuid4()), 1)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_udf(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for udf."""
        # create a UDF
        udf = self._create_udf()
        yield self.vm.add_udf(udf)
        self.vm.update_generation(udf.volume_id, 10)
        d = defer.Deferred()
        self.patch(
            self.main.action_q, 'get_delta', lambda v, g: d.callback((v, g)))
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=udf.volume_id, generation=100)
        vol_id, gen = yield d
        vol = self.vm.get_volume(vol_id)
        self.assertEqual(vol_id, vol.volume_id)
        self.assertEqual(gen, vol.generation)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_udf_from_scratch(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for udf."""
        # create a UDF
        udf = self._create_udf()
        yield self.vm.add_udf(udf)
        self.vm.update_generation(udf.volume_id, None)
        d = defer.Deferred()
        self.patch(self.main.action_q, 'rescan_from_scratch', d.callback)
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=udf.volume_id, generation=100)
        vol_id = yield d
        self.assertEqual(vol_id, udf.volume_id)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_udf_eq(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for udf."""
        # get the root
        udf = self._create_udf()
        yield self.vm.add_udf(udf)
        self.vm.update_generation(udf.volume_id, 100)
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=udf.volume_id, generation=100)
        msg = ('Got SV_VOLUME_NEW_GENERATION(%r, %r) but volume'
               ' is at generation: %r') % (udf.volume_id, 100, 100)
        self.assertTrue(self.handler.check_info(msg))

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_udf_inactive(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for an inactive udf."""
        udf = self._create_udf(subscribed=False)
        yield self.vm.add_udf(udf)

        gen = 10
        self.vm.update_generation(udf.volume_id, gen)

        self.patch(self.main.action_q, 'get_delta', lambda *a: defer.fail(a))
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=udf.volume_id, generation=100)

        self.assertEqual(gen, self.vm.get_volume(udf.volume_id).generation)
        msgs = ('SV_VOLUME_NEW_GENERATION', udf.volume_id, 'not active')
        self.assertTrue(self.handler.check_info(*msgs), 'logging was made')

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_root(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for root share."""
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_node_id')
        self.vm.update_generation(root.volume_id, 10)
        d = defer.Deferred()
        self.patch(
            self.main.action_q, 'get_delta', lambda v, g: d.callback((v, g)))
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=root.volume_id, generation=100)
        vol_id, gen = yield d
        vol = self.vm.get_volume(vol_id)
        self.assertEqual(vol_id, vol.volume_id)
        self.assertEqual(gen, vol.generation)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_root_from_scratch(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for root share."""
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_node_id')
        self.vm.update_generation(root.volume_id, None)
        d = defer.Deferred()
        self.patch(self.main.action_q, 'rescan_from_scratch', d.callback)
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=root.volume_id, generation=100)
        vol_id = yield d
        self.assertEqual(vol_id, root.volume_id)

    def test_handle_SV_VOLUME_NEW_GENERATION_root_eq(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for root share."""
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_node_id')
        self.vm.update_generation(root.volume_id, 100)
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=root.volume_id, generation=100)
        self.assertEqual(1, len(self.handler.records))
        msg = ('Got SV_VOLUME_NEW_GENERATION(%r, %r) but volume'
               ' is at generation: %r')
        self.assertEqual(msg % (root.volume_id, 100, 100),
                         self.handler.records[0].message)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_share(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for a share."""
        share = self._create_share(subscribed=True)
        yield self.vm.add_share(share)
        self.vm.update_generation(share.volume_id, 10)
        d = defer.Deferred()
        self.patch(
            self.main.action_q, 'get_delta', lambda v, g: d.callback((v, g)))
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=share.volume_id, generation=100)
        vol_id, gen = yield d
        vol = self.vm.get_volume(vol_id)
        self.assertEqual(vol_id, vol.volume_id)
        self.assertEqual(gen, vol.generation)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_share_from_scratch(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for a share."""
        share = self._create_share(subscribed=True)
        yield self.vm.add_share(share)
        self.vm.update_generation(share.volume_id, None)
        d = defer.Deferred()
        self.patch(self.main.action_q, 'rescan_from_scratch', d.callback)
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=share.volume_id, generation=100)
        vol_id = yield d
        self.assertEqual(vol_id, share.volume_id)

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_share_eq(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for a share."""
        share = self._create_share(subscribed=True)
        yield self.vm.add_share(share)
        self.vm.update_generation(share.volume_id, 100)
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=share.volume_id, generation=100)
        self.assertTrue(self.handler.check_info(
                        'Got SV_VOLUME_NEW_GENERATION(%r, %r) but volume '
                        'is at generation: %r' % (share.volume_id, 100, 100)))

    @defer.inlineCallbacks
    def test_handle_SV_VOLUME_NEW_GENERATION_share_inactive(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for an inactive share."""
        share = self._create_share(subscribed=False)
        yield self.vm.add_share(share)

        gen = 10
        self.vm.update_generation(share.volume_id, gen)

        self.patch(self.main.action_q, 'get_delta', lambda *a: defer.fail(a))
        self.main.event_q.push('SV_VOLUME_NEW_GENERATION',
                               volume_id=share.volume_id, generation=100)

        self.assertEqual(gen, self.vm.get_volume(share.volume_id).generation)
        msgs = ('SV_VOLUME_NEW_GENERATION', share.volume_id, 'not active')
        self.assertTrue(self.handler.check_info(*msgs), 'logging was made')

    def test_handle_SV_VOLUME_NEW_GENERATION_no_volume(self):
        """Test handle_SV_VOLUME_NEW_GENERATION for a volume we don't have."""
        called = []
        self.vm.refresh_volumes = lambda: called.append(True)
        self.vm.handle_SV_VOLUME_NEW_GENERATION('unknown vol id', 123)
        self.assertTrue(called)
        self.assertTrue(self.handler.check_warning("missing volume"))

    @defer.inlineCallbacks
    def test_handle_AQ_DELTA_NOT_POSSIBLE(self):
        """Test for handle_AQ_DELTA_NOT_POSSIBLE."""
        share_id = uuid.uuid4()
        share = self._create_share(volume_id=share_id)
        # get the root
        root = self.vm.get_volume(request.ROOT)
        self.vm._got_root('root_node_id')
        # create a UDF
        udf_id = uuid.uuid4()
        udf = self._create_udf(volume_id=udf_id)
        yield self.vm.add_share(share)
        yield self.vm.add_udf(udf)
        # patch AQ.rescan_from_scratch
        calls = []
        self.patch(self.main.action_q, 'rescan_from_scratch', calls.append)
        self.vm.handle_AQ_DELTA_NOT_POSSIBLE(udf_id)
        self.vm.handle_AQ_DELTA_NOT_POSSIBLE(share_id)
        self.vm.handle_AQ_DELTA_NOT_POSSIBLE(root.volume_id)
        for i, vol in enumerate([udf, share, root]):
            self.assertEqual(calls[i], str(vol.volume_id))

    def test_handle_AQ_DELTA_NOT_POSSIBLE_missing_volume(self):
        """Test for handle_AQ_DELTA_NOT_POSSIBLE with an missing volume."""
        called = []
        self.vm.refresh_volumes = lambda: called.append(True)
        self.vm.handle_AQ_DELTA_NOT_POSSIBLE(uuid.uuid4())
        self.assertTrue(called)
        self.assertTrue(self.handler.check_warning(
                        'Got a AQ_DELTA_NOT_POSSIBLE for a missing volume'))

    @defer.inlineCallbacks
    def test_handle_AQ_SHARES_LIST_shared_in_UDF(self):
        """Test the handling of the AQ_SHARE_LIST event.

        This tests the case of a receiving shared directory inside a UDF.
        """
        udf = self._create_udf()
        yield self.vm.add_udf(udf)
        share_id = uuid.uuid4()
        share_response = ShareResponse.from_params(
            share_id, 'from_me', uuid.UUID(udf.node_id), 'fake_share',
            'username', 'visible_username', True, ACCESS_LEVEL_RO,
            uuid.UUID(udf.volume_id))
        # initialize the the root
        self.vm._got_root('root_uuid')
        response = ListShares(None)
        response.shares = [share_response]
        self.vm.handle_AQ_SHARES_LIST(response)
        self.assertEqual(1, len(self.vm.shared))  # the new shares and root
        # check that the share is in the shares dict
        self.assertIn(str(share_id), self.vm.shared)
        shared = self.vm.shared[str(share_id)]
        # check that path is correctly set
        self.assertEqual(udf.path, shared.path)
        self.assertEqual('fake_share', shared.name)
        self.assertEqual(udf.node_id, shared.node_id)


class MetadataTestCase(BaseTwistedTestCase):

    md_version_None = False
    main = None
    share_md_dir = None
    shared_md_dir = None
    shares_dir = None
    shares_dir_link = None

    @defer.inlineCallbacks
    def setUp(self):
        """Create some directories."""
        yield super(MetadataTestCase, self).setUp()
        self.root_dir = self.mktemp(
            os.path.join('ubuntuonehacker', 'Magicicada'))
        self.data_dir = os.path.join(self.tmpdir, 'data_dir')
        self.vm_data_dir = os.path.join(self.tmpdir, 'data_dir', 'vm')
        self.partials_dir = self.mktemp('partials')
        self.u1_dir = self.root_dir
        self.version_file = os.path.join(self.vm_data_dir, '.version')

    @defer.inlineCallbacks
    def tearDown(self):
        """Cleanup all the cruft."""
        if self.main:
            self.main.shutdown()
        VolumeManager.METADATA_VERSION = CURRENT_METADATA_VERSION
        yield super(MetadataTestCase, self).tearDown()

    def check_version(self):
        """Check if the current version in the version file is the last one."""
        with open_file(self.version_file, 'r') as fd:
            self.assertEqual(CURRENT_METADATA_VERSION, fd.read().strip())

    def set_md_version(self, md_version):
        """Write md_version to the .version file."""
        if not path_exists(self.vm_data_dir):
            make_dir(self.vm_data_dir, recursive=True)
        with open_file(self.version_file, 'w') as fd:
            fd.write(md_version)


class GenerationsMetadataTestCase(MetadataTestCase):
    """Tests for VM metadata with generations."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(GenerationsMetadataTestCase, self).setUp()
        self.share_md_dir = self.mktemp(
            os.path.join(self.vm_data_dir, 'shares'))
        self.shared_md_dir = self.mktemp(
            os.path.join(self.vm_data_dir, 'shared'))
        self.shares_dir = self.mktemp('shares')
        self.shares_dir_link = os.path.join(self.u1_dir, 'Shared With Me')
        make_link(self.shares_dir, self.shares_dir_link)

    def test_vol_without_generation_is_None(self):
        """Test that volumes without generations, get gen = None by default."""
        self.set_md_version('6')
        self.udfs_md_dir = os.path.join(self.vm_data_dir, 'udfs')
        legacy_shares = LegacyShareFileShelf(self.share_md_dir)
        legacy_udfs = LegacyShareFileShelf(self.udfs_md_dir)
        # add a 'new' Share dict to the shelf
        share_name = 'share_1'
        share = Share(path=os.path.join(self.shares_dir, share_name),
                      volume_id=str(uuid.uuid4()), name=share_name,
                      access_level=ACCESS_LEVEL_RW,
                      other_username='other_username',
                      other_visible_name='other_visible_name',
                      node_id=None)
        share.__dict__.pop('generation')
        legacy_shares[share.volume_id] = share.__dict__
        root = Root(node_id='root_node_id')
        root.__dict__.pop('generation')
        legacy_shares[root.volume_id] = root.__dict__
        udf = UDF(volume_id=str(uuid.uuid4()), node_id='udf_node_id',
                  suggested_path='~/UDF',
                  path=os.path.join('a', 'fake', 'UDF'))
        udf.__dict__.pop('generation')
        legacy_udfs[udf.volume_id] = udf.__dict__
        shares = VMFileShelf(self.share_md_dir)
        udfs = VMFileShelf(self.udfs_md_dir)
        self.assertEqual(None, shares[share.volume_id].generation)
        self.assertEqual(None, shares[root.volume_id].generation)
        self.assertEqual(None, udfs[udf.volume_id].generation)
        # add a value to the generation attribute
        share = shares[share.volume_id]
        share.generation = 1
        shares[share.volume_id] = share
        root = shares[root.volume_id]
        root.generation = 2
        shares[root.volume_id] = root
        udf = udfs[udf.volume_id]
        udf.generation = 3
        udfs[udf.volume_id] = udf
        # cleanup the cache
        del shares._cache[share.volume_id]
        del shares._cache[root.volume_id]
        del udfs._cache[udf.volume_id]
        # check again
        self.assertEqual(1, shares[share.volume_id].generation)
        self.assertEqual(2, shares[root.volume_id].generation)
        self.assertEqual(3, udfs[udf.volume_id].generation)


class MetadataUpgraderTests(MetadataTestCase):
    """MetadataUpgrader tests."""

    @defer.inlineCallbacks
    def setUp(self):
        """Create the MetadataUpgrader instance."""
        yield super(MetadataUpgraderTests, self).setUp()
        self.share_md_dir = self.mktemp(
            os.path.join(self.vm_data_dir, 'shares'))
        self.shared_md_dir = self.mktemp(
            os.path.join(self.vm_data_dir, 'shared'))
        self.udfs_md_dir = os.path.join(self.vm_data_dir, 'udfs')
        self._tritcask_dir = self.mktemp('tritcask')
        self.shares_dir = self.mktemp('shares')
        self.shares_dir_link = os.path.join(self.u1_dir, 'Shared With Me')
        make_link(self.shares_dir, self.shares_dir_link)
        self.db = tritcask.Tritcask(self._tritcask_dir)
        self.addCleanup(self.db.shutdown)
        self.old_get_md_version = MetadataUpgrader._get_md_version
        MetadataUpgrader._get_md_version = lambda _: None
        self.md_upgrader = MetadataUpgrader(
            self.vm_data_dir, self.share_md_dir, self.shared_md_dir,
            self.udfs_md_dir, self.root_dir, self.shares_dir,
            self.shares_dir_link, self.db)

    @defer.inlineCallbacks
    def tearDown(self):
        """Restorre _get_md_version"""
        MetadataUpgrader._get_md_version = self.old_get_md_version
        yield super(MetadataUpgraderTests, self).tearDown()

    def test_guess_metadata_version_None(self):
        """Test _guess_metadata_version method for pre-version."""
        # fake a version None layout
        if path_exists(self.version_file):
            remove_file(self.version_file)
        for path in [self.share_md_dir, self.shared_md_dir,
                     self.root_dir, self.shares_dir]:
            if path_exists(path):
                self.rmtree(path)
        make_dir(os.path.join(self.root_dir, 'My Files'), recursive=True)
        shares_dir = os.path.join(self.root_dir, 'Shared With Me')
        make_dir(shares_dir, recursive=True)
        set_dir_readonly(self.root_dir)
        self.addCleanup(set_dir_readwrite, self.root_dir)
        set_dir_readonly(shares_dir)
        self.addCleanup(set_dir_readwrite, shares_dir)
        version = self.md_upgrader._guess_metadata_version()
        self.assertEqual(None, version)

    def test_guess_metadata_version_1_or_2(self):
        """Test _guess_metadata_version method for version 1 or 2."""
        # fake a version 1 layout
        if path_exists(self.version_file):
            remove_file(self.version_file)
        self.rmtree(self.root_dir)
        make_dir(os.path.join(self.root_dir, 'My Files'), recursive=True)
        shares_dir = os.path.join(self.root_dir, 'Shared With Me')
        remove_link(shares_dir)
        make_dir(shares_dir, recursive=True)
        set_dir_readonly(self.root_dir)
        self.addCleanup(set_dir_readwrite, self.root_dir)
        set_dir_readonly(shares_dir)
        self.addCleanup(set_dir_readwrite, shares_dir)
        self.rmtree(self.shares_dir)
        version = self.md_upgrader._guess_metadata_version()
        self.assertIn(version, ['1', '2'])

    def test_guess_metadata_version_4(self):
        """Test _guess_metadata_version method for version 4."""
        # fake a version 4 layout
        if path_exists(self.version_file):
            remove_file(self.version_file)
        remove_link(self.shares_dir_link)
        make_link(self.shares_dir_link, self.shares_dir_link)
        version = self.md_upgrader._guess_metadata_version()
        self.assertEqual(version, '4')

    def test_guess_metadata_version_5(self):
        """Test _guess_metadata_version method for version 5."""
        # fake a version 5 layout and metadata
        shelf = LegacyShareFileShelf(self.share_md_dir)
        shelf['foobar'] = _Share(path=os.path.join('foo', 'bar'),
                                 share_id='foobar')
        version = self.md_upgrader._guess_metadata_version()
        self.assertEqual(version, '5')

    def test_guess_metadata_version_6(self):
        """Test _guess_metadata_version method for version 6."""
        # fake a version 6 layout and metadata
        shelf = VMFileShelf(self.share_md_dir)
        shelf['foobar'] = Share(path=os.path.join('foo', 'bar'),
                                volume_id='foobar')
        version = self.md_upgrader._guess_metadata_version()
        self.assertEqual(version, '6')

    def test_guess_mixed_metadata_5_and_6(self):
        """Test _guess_metadata_version method for mixed version 5 and 6."""
        # fake a version 6 layout and metadata
        shelf = LegacyShareFileShelf(self.share_md_dir)
        shelf['old_share'] = _Share(path=os.path.join('foo', 'bar'),
                                    share_id='old_share')
        shelf['new_share'] = Share(path=os.path.join('bar', 'foo'),
                                   volume_id='new_share').__dict__
        version = self.md_upgrader._guess_metadata_version()
        self.assertEqual(version, '5')

    def test_upgrade_names_metadata_2_no_os_rename(self):
        """Test that when names are upgraded we use the os_helper.rename."""
        dirpath = os.path.join('path', 'to', 'metadata')
        files = ['not_yet.partial', ]
        mocker = Mocker()
        # ensure that we do use the platform method and not the renamed one
        os_helper_rename = mocker.replace('ubuntuone.platform.rename')

        def is_string(x):
            return isinstance(x, str)

        os_helper_rename(MATCH(is_string), MATCH(is_string))
        with mocker:
            self.md_upgrader._upgrade_names(dirpath, files)

    def test_upgrade_metadata_5_no_os_rename(self):
        """Test that when we upgrade we use the os_helper.rename."""
        shelf = LegacyShareFileShelf(self.share_md_dir)
        shelf['foobar'] = _Share(path=os.path.join('foo', 'bar'),
                                 share_id='foobar')
        mocker = Mocker()
        # ensure that we do use the platform method and not the renamed one
        self.md_upgrader._upgrade_metadata_6 = mocker.mock()
        os_helper_rename = mocker.replace('ubuntuone.platform.rename')

        def is_string(x):
            return isinstance(x, str)

        os_helper_rename(MATCH(is_string), MATCH(is_string))
        mocker.count(3)
        self.md_upgrader._upgrade_metadata_6(6)
        with mocker:
            self.md_upgrader._upgrade_metadata_5(6)


@skipIfOS('linux2', 'On linux paths are bytes so this tests do not apply')
class MetadataVersionFileTestCase(MetadataTestCase):
    """Check that the metadata version file can have unicode characters."""

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize this testcase."""
        yield super(MetadataVersionFileTestCase, self).setUp()
        self.fake_version = "FAKE"
        self.patch(VolumeManager, "METADATA_VERSION", self.fake_version)
        self.temp_dir = os.path.join(self.mktemp(), u"Ñandú")
        self.version_file = os.path.join(self.temp_dir, ".version").encode(
                                                 sys.getfilesystemencoding())
        self.md_upgrader = MetadataUpgrader(self.temp_dir.encode("utf-8"),
                                            "", "", "", "", "", "", None)

    def test_metadata_version_write(self):
        """The metadata .version file is written on unicode paths."""
        self.md_upgrader.update_metadata_version()

        with open(self.version_file) as fh:
            result = fh.read().strip()
        self.assertEqual(result, self.fake_version)

    def test_metadata_version_read(self):
        """The metadata .version file is read from unicode paths."""
        with open(self.version_file, "w") as fh:
            fh.write(self.fake_version)

        result = self.md_upgrader._get_md_version()
        self.assertEqual(result, self.fake_version)


class VMTritcaskShelfTests(BaseTwistedTestCase):
    """Tests for VMTritcaskShelf."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(VMTritcaskShelfTests, self).setUp()
        self._tritcask_dir = self.mktemp('tritcask')
        self.db = tritcask.Tritcask(self._tritcask_dir)
        self.addCleanup(self.db.shutdown)
        # use a fake row type.
        self.shelf = VMTritcaskShelf(1000, self.db)

    def test_store_dicts(self):
        """Test that the info stored for a volume is actually a dict."""
        udf = UDF(volume_id=str(uuid.uuid4()), node_id='udf_node_id',
                  suggested_path='~/UDF',
                  path=os.path.join('a', 'fake', 'UDF'))
        self.shelf[udf.volume_id] = udf
        self.assertEqual(udf, self.shelf[udf.volume_id])
        pickled_dict = self.shelf._db.get(1000, udf.volume_id)
        udf_dict = cPickle.loads(pickled_dict)
        self.assertEqual(udf.__dict__, udf_dict)

    def test_get_key(self):
        """Test for the _get_key method."""
        self.assertEqual(self.shelf._root_key,
                         self.shelf._get_key(request.ROOT))
        self.assertEqual('foo', self.shelf._get_key('foo'))
