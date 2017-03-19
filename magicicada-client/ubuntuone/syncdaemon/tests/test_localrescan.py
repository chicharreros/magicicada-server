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
"""Tests for the Local Re-scanner."""

from __future__ import with_statement

import logging
import os
import uuid

from twisted.internet import defer, reactor
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipIfOS

from contrib.testing.testcase import (
    BaseTwistedTestCase,
    FakeVolumeManager,
    skip_if_win32_and_uses_readonly,
)
from ubuntuone.platform import (
    make_dir,
    make_link,
    open_file,
    path_exists,
    remove_dir,
    remove_file,
    remove_tree,
    rename,
    set_dir_readwrite,
    set_file_readwrite,
    set_no_rights,
    stat_path,
)
from ubuntuone.syncdaemon import (
    event_queue, filesystem_manager, local_rescan, volume_manager
)
from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.syncdaemon.tritcask import Tritcask
from ubuntuone.storageprotocol import (
    content_hash as storage_hash, volumes
)
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    ACCESS_LEVEL_RW,
)

# our logging level
TRACE = logging.getLevelName('TRACE')


class Listener(object):

    def __init__(self):
        self.events = []

    def handle_default(self, *args, **kwargs):
        self.events.append(args + tuple(kwargs.values()))


class FakeEQ(object):
    """Fake EQ"""
    def __init__(self):
        self.pushed = []

    def push(self, event, **kwargs):
        """Store stuff as pushed."""
        self.pushed.append((event, kwargs))

    def _fake(self, *a, **k):
        """fake"""
    add_watch = freeze_rollback = is_frozen = _fake
    rm_watch = freeze_begin = add_to_mute_filter = _fake

    def add_watches_to_udf_ancestors(self, volume):
        """Fake ancestors addition."""
        return defer.succeed(True)

    def freeze_commit(self, events):
        """just store events"""
        self.pushed.extend(events)


class FakeAQ(object):
    """Fake AQ"""
    def __init__(self):
        self.unlinked = []
        self.moved = []
        self.uploaded = None
        self.downloaded = None

    def upload(self, *args, **kwargs):
        """Store stuff as uploaded."""
        self.uploaded = (args, kwargs)

    def download(self, *args):
        """Store stuff as downloaded."""
        self.downloaded = args

    def unlink(self, *args):
        """Store stuff as unlinked."""
        self.unlinked.append(args)

    def move(self, *args):
        """Store stuff as moved."""
        self.moved.append(args)


class BaseTestCase(BaseTwistedTestCase):
    """ Base test case """

    @defer.inlineCallbacks
    def setUp(self):
        """ Setup the test """
        yield super(BaseTestCase, self).setUp()
        self.shares_dir = self.mktemp('shares')
        usrdir = self.mktemp("usrdir")
        self.fsmdir = self.mktemp("fsmdir")
        self.partials_dir = self.mktemp("partials")
        self.tritcask_dir = self.mktemp("tritcask")

        self.vm = FakeVolumeManager(usrdir)
        self.db = Tritcask(self.tritcask_dir)
        self.addCleanup(self.db.shutdown)
        self.fsm = filesystem_manager.FileSystemManager(self.fsmdir,
                                                        self.partials_dir,
                                                        self.vm, self.db)
        self.fsm.create(usrdir, "", is_dir=True)
        self.eq = FakeEQ()
        self.fsm.register_eq(self.eq)
        self.aq = FakeAQ()

    @defer.inlineCallbacks
    def create_share(
            self, share_id, share_name, access_level=ACCESS_LEVEL_RW,
            accepted=True, subscribed=True):
        """Create a share."""
        assert isinstance(share_name, unicode)

        share_path = os.path.join(self.shares_dir, share_name.encode('utf-8'))
        make_dir(share_path, recursive=True)
        share = volume_manager.Share(path=share_path, volume_id=share_id,
                                     access_level=access_level,
                                     accepted=accepted,
                                     subscribed=subscribed)
        yield self.fsm.vm.add_share(share)
        defer.returnValue(share)

    @defer.inlineCallbacks
    def create_udf(self, udf_id, node_id, suggested_path=u'~/myudf',
                   subscribed=True, generation=None, free_bytes=100):
        """Create an UDF and add it to the volume manager."""
        assert isinstance(suggested_path, unicode)

        volume = volumes.UDFVolume(volume_id=udf_id, node_id=node_id,
                                   generation=generation,
                                   free_bytes=free_bytes,
                                   suggested_path=suggested_path)
        path = volume_manager.get_udf_path(suggested_path)
        udf = volume_manager.UDF.from_udf_volume(volume, path)
        udf.subscribed = subscribed
        make_dir(udf.path, recursive=True)
        yield self.fsm.vm.add_udf(udf)
        defer.returnValue(udf)

    def create_node(self, path, is_dir, real=True, which_share=None):
        """Creates a node, really (maybe) and in the metadata."""
        if which_share is None:
            which_share = self.share
        filepath = os.path.join(which_share.path, path)
        if real:
            if is_dir:
                make_dir(filepath)
            else:
                open_file(filepath, "w").close()

        self.fsm.create(filepath, which_share.volume_id, is_dir=is_dir)
        self.fsm.set_node_id(filepath, "uuid" + path)

        # for files we put hashes to signal them not non-content
        if not is_dir:
            self.fsm.set_by_path(filepath, local_hash="h", server_hash="h")
        return filepath


class CollectionTests(BaseTestCase):
    """Test to check how LocalRescan gathers the dirs to scan."""

    def test_init(self):
        """Test the init params."""
        self.assertRaises(TypeError, local_rescan.LocalRescan, 1)
        self.assertRaises(TypeError, local_rescan.LocalRescan, 1, 2)
        self.assertRaises(TypeError, local_rescan.LocalRescan, 1, 2, 3)
        self.assertRaises(TypeError, local_rescan.LocalRescan, 1, 2, 3, 4, 5)

    def test_empty_ro(self):
        """Test with one empty View share."""
        # create the share
        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = []

        def f():
            """helper"""
            toscan.extend(x[1] for x in lr._queue)
            return defer.Deferred()

        lr._queue_scan = f
        lr.start()
        self.assertEqual(toscan, [self.vm.root.path])

    @defer.inlineCallbacks
    def test_empty_rw(self):
        """Test with one empty Modify share."""
        # create the share
        share = yield self.create_share('share_id', u'rw_share',
                                        access_level=ACCESS_LEVEL_RW)
        self.fsm.create(share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(share.path, "uuid")

        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = []

        def f():
            """helper"""
            toscan.extend(x[1] for x in lr._queue)
            return defer.Deferred()

        lr._queue_scan = f
        lr.start()
        self.assertItemsEqual(toscan, [share.path, self.vm.root.path])

    @defer.inlineCallbacks
    def test_not_empty_rw(self):
        """Test with a Modify share with info."""
        # create the share
        share = yield self.create_share('share_id', u'ro_share',
                                        access_level=ACCESS_LEVEL_RW)
        self.fsm.create(share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(share.path, "uuid1")

        # create a node in the share
        filepath = os.path.join(share.path, "a")
        self.fsm.create(filepath, "share_id")
        self.fsm.set_node_id(filepath, "uuid2")
        open_file(filepath, "w").close()

        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = []

        def f():
            """helper"""
            toscan.extend(x[1] for x in lr._queue)
            return defer.Deferred()

        lr._queue_scan = f
        lr.start()
        self.assertItemsEqual(toscan, [share.path, self.vm.root.path])

    @defer.inlineCallbacks
    def test_deleted_rw(self):
        """Test with a deleted rw share."""
        # create the share
        share = yield self.create_share('share_id', u'rw_share',
                                        access_level=ACCESS_LEVEL_RW)
        self.fsm.create(share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(share.path, "uuid")

        # remove the share from disk
        remove_tree(share.path)

        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = []

        def f():
            """helper"""
            toscan.extend(x[1] for x in lr._queue)
            return defer.Deferred()

        lr._queue_scan = f
        # patch share_deleted to check we are calling it
        d = defer.Deferred()
        self.patch(self.vm, 'share_deleted', d.callback)
        lr.start()
        vol_id = yield d
        self.assertEqual(vol_id, share.volume_id)
        self.assertItemsEqual(toscan, [self.vm.root.path])

    @defer.inlineCallbacks
    def test_deleted_rw_not_empty(self):
        """Test with a deleted rw share with some nodes in it."""
        # create the share
        share = yield self.create_share('share_id', u'rw_share',
                                        access_level=ACCESS_LEVEL_RW)
        self.fsm.create(share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(share.path, "uuid")

        for name in ['a', 'b', 'c']:
            # create a node in the share
            filepath = os.path.join(share.path, name)
            self.fsm.create(filepath, share.id)
            self.fsm.set_node_id(filepath, str(uuid.uuid4()))
            open_file(filepath, "w").close()

        # remove the share from disk
        remove_tree(share.path)

        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = []

        def f():
            """helper"""
            toscan.extend(x[1] for x in lr._queue)
            return defer.Deferred()

        lr._queue_scan = f
        # patch share_deleted to check we are calling it
        d = defer.Deferred()
        self.patch(self.vm, 'share_deleted', d.callback)
        lr.start()
        vol_id = yield d
        self.assertEqual(vol_id, share.volume_id)
        self.assertItemsEqual(toscan, [self.vm.root.path])

    @defer.inlineCallbacks
    def test_deleted_udf(self):
        """Test with a deleted udf."""
        # create the udf
        udf = yield self.create_udf('udf_id', 'udf_root_node_id')
        self.fsm.create(udf.path, 'udf_id', is_dir=True)

        # remove the udf from disk
        remove_tree(udf.path)

        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = []

        def f():
            """helper"""
            toscan.extend(x[1] for x in lr._queue)
            return defer.Deferred()

        lr._queue_scan = f
        # patch unsubscribe_udf to check we are calling it
        d = defer.Deferred()
        self.patch(self.vm, 'unsubscribe_udf', d.callback)
        lr.start()
        vol_id = yield d
        self.assertEqual(vol_id, udf.volume_id)
        self.assertItemsEqual(toscan, [self.vm.root.path])


class VolumeTestCase(BaseTestCase):
    """Test how LocalRescan manages volumes."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(VolumeTestCase, self).setUp()

        self.lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        self.volumes = []
        self.expected = [self.vm.root.path]  # root volume has to be scanned
        paths = [u'~/Documents', u'~/PDFs', u'~/yadda/yadda/doo']
        for i, suggested_path in enumerate(paths):
            # create UDF
            udf_id, node_id = 'udf_id%i' % i, 'node_id%i' % i
            udf = yield self.create_udf(udf_id, node_id, suggested_path, True)
            self.volumes.append(udf)

            # make FSM aware of it
            self.fsm.create(udf.path, udf_id, is_dir=True)
            self.fsm.set_node_id(udf.path, node_id)

            # one more to assert over
            self.expected.append(udf.path)

        self.expected.sort()

    def test_start_with_udf(self):
        """LR start() on an udf."""
        toscan = []

        def f():
            """helper"""
            for _, path, _, udfmode in self.lr._queue:
                toscan.append(path)
                self.assertFalse(udfmode)
            return defer.Deferred()

        self.lr._queue_scan = f
        self.lr.start()
        self.assertEqual(self.expected, sorted(toscan))

    def test_scan_with_udf_normal(self):
        """LR scan_dir() on an udf, normal."""
        udf_path = self.expected[0]

        def f():
            """helper"""
            self.assertTrue(len(self.lr._queue), 1)
            _, path, _, udfmode = self.lr._queue[0]
            self.assertEqual(path, udf_path)
            self.assertFalse(udfmode)
            return defer.Deferred()

        self.lr._queue_scan = f
        self.lr.scan_dir("mdid", udf_path)

    def test_scan_with_udf_udfmode(self):
        """LR scan_dir() on an udf, udf mode."""
        udf_path = self.expected[0]

        def f():
            """helper"""
            self.assertTrue(len(self.lr._queue), 1)
            _, path, _, udfmode = self.lr._queue[0]
            self.assertEqual(path, udf_path)
            self.assertTrue(udfmode)
            return defer.Deferred()

        self.lr._queue_scan = f
        self.lr.scan_dir("mdid", udf_path, udfmode=True)

    def test_scan_dir_with_udf(self):
        """Scan a dir with an UDF."""
        udf = self.volumes[0]
        mdobj = self.fsm.get_by_path(udf.path)
        d = self.lr.scan_dir(mdobj.mdid, udf.path)
        # scan_dir would fail if volumes are not included
        self.assertTrue(isinstance(d, defer.Deferred))
        return d

    def test_start_without_udf_itself(self):
        """LR start() having removed UDFs."""
        vol_to_unsub = self.volumes[0]
        vol_to_keep = self.volumes[1:]
        remove_tree(vol_to_unsub.path)
        d = self.lr.start()

        def check(_):
            """Removed UDF should be desubscribed."""
            # these should remain ok
            for vol in vol_to_keep:
                self.assertTrue(vol.subscribed)
            # this should be unsubscribed
            self.assertFalse(vol_to_unsub.subscribed)

        d.addCallback(check)
        return d

    def test_start_without_udf_ancestors(self):
        """LR start() having removed UDFs parents."""
        vol_to_unsub = self.volumes[-1]  # grab the one that has lot of parents
        vol_to_keep = self.volumes[:-1]
        remove_tree(os.path.dirname(vol_to_unsub.path))
        d = self.lr.start()

        def check(_):
            """Removed UDF should be desubscribed."""
            # these should remain ok
            for vol in vol_to_keep:
                self.assertTrue(vol.subscribed)
            # this should be unsubscribed
            self.assertFalse(vol_to_unsub.subscribed)

        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_start_with_udf_unsubscribed(self):
        """LR start() having removed UDFs."""
        unsub_vol = self.volumes.pop(0)
        path_idx = self.expected.index(unsub_vol.path)
        unsub_path = self.expected.pop(path_idx)
        assert unsub_vol.path == unsub_path
        self.fsm.vm.unsubscribe_udf(unsub_vol.volume_id)
        toscan = []

        def f():
            """helper"""
            for _, path, _, udfmode in self.lr._queue:
                toscan.append(path)
            return defer.succeed(None)

        self.lr._queue_scan = f
        yield self.lr.start()
        self.assertEqual(self.expected, sorted(toscan))


class TwistedBase(BaseTestCase):
    """Base class for twisted tests."""

    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Set up the test."""
        yield super(TwistedBase, self).setUp()
        self.deferred = defer.Deferred()
        self.lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)

        # create a share
        self.share = yield self.create_share('share_id', u'ro_share',
                                             access_level=ACCESS_LEVEL_RW)
        self.fsm.create(self.share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(self.share.path, "uuidshare")
        self.share.node_id = "uuidshare"
        self.vm.shares['share_id'] = self.share

        self.handler = MementoHandler()
        self._logger = logging.getLogger('ubuntuone.SyncDaemon.local_rescan')
        self._logger.setLevel(TRACE)
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)


class ComparationTests(TwistedBase):
    """Test LocalRescan checking differences between disk and metadata."""

    timeout = 20

    @defer.inlineCallbacks
    def setUp(self):
        yield super(ComparationTests, self).setUp()

        # create an udf
        self.udf = yield self.create_udf('udf_id', 'udf_root_node_id')
        self.fsm.create(self.udf.path, 'udf_id', is_dir=True)
        self.fsm.set_node_id(self.udf.path, 'udf_root_node_id')

    @defer.inlineCallbacks
    def test_empty(self):
        """Test with an empty share."""
        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])

    @defer.inlineCallbacks
    def test_equal_file(self):
        """Test with a share with the same files as metadata."""
        # create a node in the share
        self.create_node("a", is_dir=False)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertTrue(self.handler.check(TRACE,
                        "comp yield", "was here, let's check stat"))

    @defer.inlineCallbacks
    def test_equal_dir(self):
        """Test with a share with the same files as metadata."""
        # create a node in the share
        self.create_node("a", is_dir=True)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertTrue(self.handler.check(TRACE, "comp yield",
                        "will be scaned later because it's in NONE!"))

    @defer.inlineCallbacks
    def test_disc_more_file_empty_normal(self):
        """Test having an empty file more in disc than in MD, normal volume."""
        # create a node in the share
        self.create_node("a", is_dir=False)

        # and another file in disk
        path = os.path.join(self.share.path, "b")
        open_file(path, "w").close()

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path),
                                          ('FS_FILE_CLOSE_WRITE', path)])

    @defer.inlineCallbacks
    def test_disc_more_file_empty_udf(self):
        """Test having an empty file more in disc than in MD, udf mode."""
        # create a node in the share
        self.create_node("a", is_dir=False, which_share=self.udf)

        # and another file in disk
        path = os.path.join(self.share.path, "b")
        open_file(path, "w").close()

        yield self.lr.scan_dir("mdid", self.share.path, udfmode=True)
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path),
                                          ('FS_FILE_CLOSE_WRITE', path)])

    @defer.inlineCallbacks
    def test_disc_more_file_content(self):
        """Test having a file (with content) more in disc than in metadata."""
        # create a node in the share
        self.create_node("a", is_dir=False)

        # and another file in disk
        path = os.path.join(self.share.path, "b")
        with open_file(path, "w") as fh:
            fh.write("foo")

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path),
                                          ('FS_FILE_CLOSE_WRITE', path)])

    @defer.inlineCallbacks
    def test_disc_symlink(self):
        """Test having a symlink in disc."""
        # create a node in the share
        source = self.create_node("a", is_dir=False)

        # and a symlink to ignore!
        symlname = 'a_symlink'
        symlpath = os.path.join(self.share.path, symlname)
        make_link(source, symlpath)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertTrue(self.handler.check_info("Ignoring path",
                                                "symlink", symlname))

    @skipIfOS('win32', "Windows paths are already unicode, "
                       "can't make this explode there")
    @defer.inlineCallbacks
    def test_disc_non_utf8_file(self):
        """Test having a utf-8 file."""
        # create a broken path
        path = os.path.join(self.share.path, "non utf-8 \xff path")
        with open_file(path, "w") as fh:
            fh.write("broken")

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertTrue(self.handler.check_info("Ignoring path",
                                                "invalid (non utf-8)"))

    @skipIfOS('win32', "Windows paths are already unicode, "
                       "can't make this explode there")
    @defer.inlineCallbacks
    def test_disc_non_utf8_dir(self):
        """Test having a utf-8 dir."""
        # create a broken path
        path = os.path.join(self.share.path, "non utf-8 \xff path")
        make_dir(path)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertTrue(self.handler.check_info("Ignoring path",
                                                "invalid (non utf-8)"))

    @defer.inlineCallbacks
    def test_disc_more_dir_normal(self):
        """Test having a dir more in disc than in metadata, normal volume."""
        # create a node in the share
        self.create_node("a", is_dir=False)

        # and another dir in disk
        otherpath = os.path.join(self.share.path, "b")
        make_dir(otherpath)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_DIR_CREATE', otherpath)])

    @defer.inlineCallbacks
    def test_disc_more_dir_udf(self):
        """Test having a dir more in disc than in metadata, udf_mode."""
        # create a node in the share
        self.create_node("a", is_dir=False, which_share=self.udf)

        # and another dir in disk
        otherpath = os.path.join(self.share.path, "b")
        make_dir(otherpath)

        yield self.lr.scan_dir("mdid", self.share.path, udfmode=True)
        self.assertEqual(self.eq.pushed, [('FS_DIR_CREATE', otherpath)])

    @defer.inlineCallbacks
    def test_disc_less_file_normal(self):
        """Test having less in disc than in metadata, normal volume."""
        # create a node in the share, but no in disk
        filepath = self.create_node("a", is_dir=False, real=False)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_DELETE', filepath)])

    @defer.inlineCallbacks
    def test_disc_less_file_udf(self):
        """Test having less in disc than in metadata, udf mode."""
        # create a node in the share, but no in disk
        filepath = self.create_node("a", is_dir=False, real=False,
                                    which_share=self.udf)
        assert self.fsm.has_metadata(path=filepath)
        parentpath = os.path.dirname(filepath)
        self.fsm.set_by_path(parentpath, local_hash="foo", server_hash="foo")

        yield self.lr.scan_dir("mdid", self.udf.path, udfmode=True)

        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=filepath))
        parent = self.fsm.get_by_path(parentpath)
        self.assertEqual(parent.local_hash, "")
        self.assertEqual(parent.server_hash, "")

    @defer.inlineCallbacks
    def test_no_file_no_hash(self):
        """Test useless metadata."""
        path = os.path.join(self.share.path, "b")
        self.fsm.create(path, self.share.volume_id)
        self.assertTrue(self.fsm.has_metadata(path=path))

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_disc_less_dir_normal(self):
        """Test having less in disc than in metadata, normal volume."""
        # create a node in the share, but no in disk
        filepath = self.create_node("a", is_dir=True, real=False)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_DIR_DELETE', filepath)])

    @defer.inlineCallbacks
    def test_disc_less_dir_udf(self):
        """Test having less in disc than in metadata, udf mode."""
        # create a node in the share, but no in disk
        filepath = self.create_node("a", is_dir=True, real=False,
                                    which_share=self.udf)
        assert self.fsm.has_metadata(path=filepath)
        parentpath = os.path.dirname(filepath)
        self.fsm.set_by_path(parentpath, local_hash="foo", server_hash="foo")

        yield self.lr.scan_dir("mdid", self.udf.path, udfmode=True)

        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=filepath))
        parent = self.fsm.get_by_path(parentpath)
        self.assertEqual(parent.local_hash, "")
        self.assertEqual(parent.server_hash, "")

    @defer.inlineCallbacks
    def test_differenttype_dir(self):
        """Test that it should be a dir but now it's a file."""
        # create one type in the share, other in disk
        thispath = self.create_node("a", is_dir=True, real=False)
        open_file(thispath, "w").close()

        yield self.lr.start()
        # don't sort, as the DELETE must come before the CREATE
        events = self.eq.pushed
        self.assertEqual(events[0], ('FS_DIR_DELETE', thispath))
        self.assertEqual(events[1], ('FS_FILE_CREATE', thispath))
        self.assertEqual(events[2], ('FS_FILE_CLOSE_WRITE', thispath))

    @defer.inlineCallbacks
    def test_differenttype_file(self):
        """Test that it should be a file but now it's a dir."""
        # create one type in the share, other in disk
        thispath = self.create_node("a", is_dir=False, real=False)
        make_dir(thispath)

        yield self.lr.start()
        # don't sort, as the DELETE must come before the CREATE
        events = self.eq.pushed
        self.assertEqual(events[0], ('FS_FILE_DELETE', thispath))
        self.assertEqual(events[1], ('FS_DIR_CREATE', thispath))

    @defer.inlineCallbacks
    def test_complex_scenario(self):
        """Several dirs, several files, some differences."""
        self.create_node("a", is_dir=True)
        self.create_node(os.path.join("a", "b"), is_dir=True)
        sh1 = self.create_node(os.path.join("a", "b", "e"),
                               is_dir=True, real=False)
        self.create_node(os.path.join("a", "c"), is_dir=True)
        self.create_node(os.path.join("a", "c", "d"), is_dir=False)
        sh2 = self.create_node(os.path.join("a", "c", "e"),
                               is_dir=False, real=False)
        self.create_node("d", is_dir=True)
        sh3 = self.create_node("e", is_dir=False, real=False)
        sh4 = self.create_node("f", is_dir=True, real=False)
        sh5 = os.path.join(self.share.path, "j")
        open_file(sh5, "w").close()
        sh6 = os.path.join(self.share.path, "a", "c", "q")
        open_file(sh6, "w").close()
        sh7 = os.path.join(self.share.path, "k")
        make_dir(sh7)
        sh8 = os.path.join(self.share.path, "a", "p")
        make_dir(sh8)

        # scan!
        yield self.lr.start()
        self.assertItemsEqual(self.eq.pushed, [
            ('FS_DIR_CREATE', sh8),
            ('FS_DIR_CREATE', sh7),
            ('FS_DIR_DELETE', sh1),
            ('FS_DIR_DELETE', sh4),
            ('FS_FILE_CLOSE_WRITE', sh6),
            ('FS_FILE_CLOSE_WRITE', sh5),
            ('FS_FILE_CREATE', sh6),
            ('FS_FILE_CREATE', sh5),
            ('FS_FILE_DELETE', sh2),
            ('FS_FILE_DELETE', sh3),
        ])

    @defer.inlineCallbacks
    def test_deep_and_wide(self):
        """Lot of files in a dir, and lots of dirs."""
        # almost all known, to force the system to go deep
        dirs = "abcdefghijklmnopq" * 20
        for i in range(1, len(dirs)+1):
            dirpath = os.path.join(*dirs[:i])
            self.create_node(dirpath, is_dir=True)
        basedir = os.path.join(*dirs)
        self.create_node(os.path.join(basedir, "file1"), is_dir=False)
        path = os.path.join(basedir, "file2")
        sh1 = self.create_node(path, is_dir=False, real=False)

        # some files in some dirs
        files = "rstuvwxyz"
        for f in files:
            path = os.path.join(*dirs[:3]+f)
            self.create_node(path, is_dir=False)
            path = os.path.join(*dirs[:6]+f)
            self.create_node(path, is_dir=False)
        sh2 = os.path.join(self.share.path, *dirs[:6]+"q")
        open_file(sh2, "w").close()

        # scan!
        yield self.lr.start()
        self.assertItemsEqual(self.eq.pushed, [
            ('FS_FILE_CLOSE_WRITE', sh2),
            ('FS_FILE_CREATE', sh2),
            ('FS_FILE_DELETE', sh1),
        ])

    @defer.inlineCallbacks
    def test_subtree_removal_normal(self):
        """A whole subtree was removed, normal volume."""
        self.create_node("a", is_dir=True)
        sh1 = self.create_node(os.path.join("a", "b"), is_dir=True)
        sh2 = self.create_node(os.path.join("a", "b", "c"), is_dir=True)
        sh3 = self.create_node(os.path.join("a", "b", "c", "d"), is_dir=False)
        self.create_node(os.path.join("a", "bar"), is_dir=False)

        # remove the whole subtree
        remove_tree(sh1)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [
            ('FS_FILE_DELETE', sh3),
            ('FS_DIR_DELETE', sh2),
            ('FS_DIR_DELETE', sh1),
        ])

    @defer.inlineCallbacks
    def test_subtree_removal_udf(self):
        """A whole subtree was removed, udf mode."""
        self.create_node("a", is_dir=True, which_share=self.udf)
        sh1 = self.create_node(os.path.join("a", "b"),
                               is_dir=True, which_share=self.udf)
        sh2 = self.create_node(os.path.join("a", "b", "c"),
                               is_dir=True, which_share=self.udf)
        sh3 = self.create_node(os.path.join("a", "b", "c", "d"),
                               is_dir=False, which_share=self.udf)

        # remove the whole subtree
        parentpath = os.path.dirname(sh1)
        self.fsm.set_by_path(parentpath, local_hash="foo", server_hash="foo")
        remove_tree(sh1)

        # scan!
        yield self.lr.scan_dir("mdid", self.udf.path, udfmode=True)

        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=sh1))
        self.assertFalse(self.fsm.has_metadata(path=sh2))
        self.assertFalse(self.fsm.has_metadata(path=sh3))
        parent = self.fsm.get_by_path(parentpath)
        self.assertEqual(parent.local_hash, "")
        self.assertEqual(parent.server_hash, "")

    @defer.inlineCallbacks
    def test_one_dir_only(self):
        """Specific subtree only."""
        self.create_node("a", is_dir=True)
        self.create_node(os.path.join("a", "b"), is_dir=True)

        # one in both, one only in share, one only in disk
        self.create_node(os.path.join("a", "b", "c"), is_dir=True)
        sh1 = self.create_node(os.path.join("a", "b", "d"),
                               is_dir=True, real=False)
        sh2 = os.path.join(self.share.path, "a", "b", "e")
        open_file(sh2, "w").close()

        # more differences, but not in dir to check
        self.create_node(os.path.join("a", "c"), is_dir=False)
        make_dir(os.path.join(self.share.path, "a", "k"))

        # scan!
        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        toscan = os.path.join(self.share.path, "a", "b")

        yield lr.scan_dir("mdid", toscan)
        self.assertEqual(len(self.eq.pushed), 3)
        events = sorted(self.eq.pushed)
        self.assertEqual(events[0], ('FS_DIR_DELETE', sh1))
        self.assertEqual(events[1], ('FS_FILE_CLOSE_WRITE', sh2))
        self.assertEqual(events[2], ('FS_FILE_CREATE', sh2))

    def test_one_nonexistant_dir(self):
        """Specific subtree for a dir that's not in a share or not at all."""
        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)

        # real dir, but not in share
        self.assertRaises(ValueError, lr.scan_dir, "mdid", "/tmp")

        # no dir at all
        self.assertRaises(ValueError, lr.scan_dir, "mdid", "no-dir-at-all")

        # inside a share, but no real dir
        # this does not generate a direct error, but sends an event
        nodir = os.path.join(self.share.path, "no-dir-at-all")
        lr.scan_dir("mdid", nodir)

        # inside a share, and real, but no really a dir
        nodir = self.create_node("a", is_dir=False)
        self.assertRaises(ValueError, lr.scan_dir, "mdid", nodir)

        # need to wait the generated event before finishing the test
        reactor.callLater(.2, self.deferred.callback, None)
        return self.deferred

    @defer.inlineCallbacks
    def test_one_dir_ro_share(self):
        """The dir is in a share that's RO, no error but no action."""
        # create the share
        share = yield self.create_share('share_id', u'ro_share2',
                                        access_level=ACCESS_LEVEL_RO)
        self.fsm.create(share.path, "share_id", is_dir=True)
        self.fsm.set_node_id(share.path, "uuidshare")

        lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)
        yield lr.scan_dir("mdid", share.path)

    @defer.inlineCallbacks
    def test_content_changed(self):
        """Test that it detects the content change."""
        # create a node in metadata, change it in disk
        path = self.create_node("a", is_dir=False)
        with open_file(path, "w") as fh:
            fh.write("foo")

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CLOSE_WRITE', path)])
        self.assertTrue(self.handler.check_debug("comp yield",
                                                 "file content changed"))
        self.assertTrue(self.handler.check_debug("differ", "Old", "New"))

    @skipIfOS('win32', 'Windows does not report inode info, see bug #823284.')
    @defer.inlineCallbacks
    def test_inode_changed(self):
        """Test that it detects a change using the filedate."""
        # two files with same dates
        pathx = os.path.join(self.share.path, "x")
        pathy = os.path.join(self.share.path, "y")
        open_file(pathx, "w").close()
        open_file(pathy, "w").close()
        self.create_node("x", is_dir=False)

        # move the second into the first one
        rename(pathy, pathx)

        # a & m times will be the same, but not the inode or change time
        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CLOSE_WRITE', pathx)])

    def test_scandir_no_dir_normal(self):
        """Attempt to scan a dir that is not there."""
        nodir = os.path.join(self.share.path, "no-dir-at-all")
        self.lr.scan_dir("mdid", nodir)

        # scan!
        def check(_):
            """check"""
            self.assertEqual(self.eq.pushed, [
                ('LR_SCAN_ERROR', dict(mdid="mdid", udfmode=False)),
            ])

        self.deferred.addCallback(check)
        # trigger the control later, as it the scan error es slightly delayed
        reactor.callLater(.2, self.deferred.callback, None)
        return self.deferred

    def test_scandir_no_dir_udfmode(self):
        """Attempt to scan a dir that is not there."""
        nodir = os.path.join(self.share.path, "no-dir-at-all")
        self.lr.scan_dir("mdid", nodir, udfmode=True)

        # scan!
        def check(_):
            """check"""
            self.assertEqual(self.eq.pushed, [
                ('LR_SCAN_ERROR', dict(mdid="mdid", udfmode=True)),
            ])

        self.deferred.addCallback(check)
        # trigger the control later, as it the scan error es slightly delayed
        reactor.callLater(.2, self.deferred.callback, None)
        return self.deferred

    @skip_if_win32_and_uses_readonly
    @defer.inlineCallbacks
    def test_no_read_perms_file(self):
        """Test with a file that we can't read"""
        # and another file in disk
        path = os.path.join(self.share.path, "b")
        open_file(path, "w").close()
        set_no_rights(path)
        self.addCleanup(set_file_readwrite, path)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])

    @skip_if_win32_and_uses_readonly
    @defer.inlineCallbacks
    def test_no_read_perms_dir(self):
        """Test with a dir that we can't read"""
        # and another file in disk
        path = os.path.join(self.share.path, "b")
        make_dir(path, recursive=True)
        set_no_rights(path)
        self.addCleanup(set_dir_readwrite, path)

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])


class InotifyTests(TwistedBase):
    """Test LocalRescan pushing events to the EventQueue."""
    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(InotifyTests, self).setUp()
        self.eq = event_queue.EventQueue(self.fsm)
        self.addCleanup(self.eq.shutdown)
        self.lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)

        # do not use patch since we need to assign local_rescan.stat_path
        # at specific timings
        self.real_os_stat = local_rescan.stat_path
        self.addCleanup(setattr, local_rescan, 'stat_path', self.real_os_stat)

    @skipIfOS('win32', 'Fails due to missing FS event. See bug #824003.')
    @defer.inlineCallbacks
    def test_man_in_the_middle(self):
        """Intercept normal work and change the disk."""
        for c in "abcdefghijk":
            self.create_node(c, is_dir=False)

        # remove a couple, create some new
        sh1 = os.path.join(self.share.path, "d")
        remove_file(sh1)
        sh2 = os.path.join(self.share.path, "f")
        remove_file(sh2)
        sh3 = os.path.join(self.share.path, "jj")
        open_file(sh3, "w").close()
        sh4 = os.path.join(self.share.path, "kk")
        make_dir(sh4)

        # this sh5 will be written in the middle of the scan
        sh5 = os.path.join(self.share.path, "zz")

        should_receive_events = [
            ('FS_DIR_CREATE', sh4),
            ('FS_FILE_CLOSE_WRITE', sh3),
            ('FS_FILE_CLOSE_WRITE', sh5),
            ('FS_FILE_CREATE', sh3),
            ('FS_FILE_CREATE', sh5),
            ('FS_FILE_DELETE', sh1),
            ('FS_FILE_DELETE', sh2),
        ]

        hm = Listener()
        self.eq.subscribe(hm)

        # we need to intercept compare, as the stat interception needs
        # to be done after compare() starts for the comparing path
        # use stat_path to get in the middle of the process, to put some
        # dirt in the testing scenario

        real_compare = self.lr._compare
        real_commit = self.eq.freeze_commit
        events_pushed = []

        def middle_stat(*a, **k):
            """Put a new file in the directory to dirt the LR process."""
            local_rescan.stat_path = self.real_os_stat
            events_pushed[:] = []
            open_file(sh5, "w").close()
            return self.real_os_stat(*a, **k)

        def fake_commit(events):
            """Commit that will be delayed until the new file is processed."""
            d = defer.Deferred()
            d.addCallback(real_commit)

            def check_events():
                """Trigger the deferred only if the file was processed."""
                if events_pushed:
                    d.callback(events)
                else:
                    reactor.callLater(.1, check_events)
            reactor.callLater(.1, check_events)
            return d

        def middle_compare(*args, **kwargs):
            """If started to work on the tested path, put fakes in place."""
            if args[0] == self.share.path:
                self.lr._compare = real_compare
                local_rescan.stat_path = middle_stat
                self.eq.freeze_commit = fake_commit
            return real_compare(*args, **kwargs)

        self.lr._compare = middle_compare

        def fake_pusher(event):
            """Just log the pushed events."""
            events_pushed.append(event)
            real_push(event)

        real_push = self.eq.monitor._processor.general_processor.push_event
        self.patch(self.eq.monitor._processor.general_processor,
                   'push_event', fake_pusher)

        yield self.lr.start()
        self.assertItemsEqual(hm.events, should_receive_events)


class QueuingTests(BaseTestCase):
    """Test that simultaneus calls are queued."""
    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """set up the test."""
        yield super(QueuingTests, self).setUp()
        self.eq = event_queue.EventQueue(self.fsm)
        self.addCleanup(self.eq.shutdown)
        self.lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)

        # create two shares
        self.share1 = yield self.create_share('share_id1', u'ro_share_1',
                                              access_level=ACCESS_LEVEL_RW)
        self.fsm.create(self.share1.path, "share_id1", is_dir=True)
        self.fsm.set_node_id(self.share1.path, "uuidshare1")
        self.share2 = yield self.create_share('share_id2', u'ro_share_2',
                                              access_level=ACCESS_LEVEL_RW)
        self.fsm.create(self.share2.path, "share_id2", is_dir=True)
        self.fsm.set_node_id(self.share2.path, "uuidshare2")

        # do not use patch since we need to assign local_rescan.stat_path
        # at specific timings
        self.real_os_stat = local_rescan.stat_path
        self.addCleanup(setattr, local_rescan, 'stat_path', self.real_os_stat)

    @defer.inlineCallbacks
    def test_intercept_generate_second(self):
        """Intercept the first work and generate a second scan."""
        # fill and alter first share
        for c in "abcdefgh":
            self.create_node(c, is_dir=False, which_share=self.share1)
        sh1 = os.path.join(self.share1.path, "d")
        remove_file(sh1)
        sh2 = os.path.join(self.share1.path, "jj")
        open_file(sh2, "w").close()

        # fill and alter second share
        for c in "abcdefgh":
            self.create_node(c, is_dir=False, which_share=self.share2)
        sh3 = os.path.join(self.share2.path, "e")
        remove_file(sh3)
        sh4 = os.path.join(self.share2.path, "kk")
        open_file(sh4, "w").close()

        should_receive_events = [
            ('FS_FILE_CLOSE_WRITE', sh2),
            ('FS_FILE_CLOSE_WRITE', sh4),
            ('FS_FILE_CREATE', sh2),
            ('FS_FILE_CREATE', sh4),
            ('FS_FILE_DELETE', sh1),
            ('FS_FILE_DELETE', sh3),
        ]

        hm = Listener()
        self.eq.subscribe(hm)

        # we need to intercept compare, as the stat interception needs
        # to be done after compare() starts.
        # use stat_path to get in the middle of the process, to put some
        # dirt in the testing scenario

        real_compare = self.lr._compare

        def middle_compare(*a1, **k1):
            """Changes stat_path."""
            self.lr._compare = real_compare

            def middle_stat(*a2, **k2):
                """Dirt!"""
                local_rescan.stat_path = self.real_os_stat
                self.lr.scan_dir("mdid", self.share2.path)
                return self.real_os_stat(*a2, **k2)

            local_rescan.stat_path = middle_stat
            return real_compare(*a1, **k1)

        self.lr._compare = middle_compare

        yield self.lr.scan_dir("mdid", self.share1.path)
        self.assertItemsEqual(hm.events, should_receive_events)


class PushTests(TwistedBase):
    """Test LocalRescan pushing events to the EventQueue."""

    maxDiff = None
    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(PushTests, self).setUp()
        self.eq = event_queue.EventQueue(self.fsm)
        self.addCleanup(self.eq.shutdown)
        self.lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)

    @defer.inlineCallbacks
    def test_one_dir_create(self):
        """Check that an example dir create is really pushed."""
        l = Listener()
        self.eq.subscribe(l)
        self.addCleanup(self.eq.unsubscribe, l)

        # push some event
        filepath = os.path.join(self.share.path, "a")
        make_dir(filepath)

        yield self.lr.start()
        self.assertItemsEqual(l.events, [('FS_DIR_CREATE', filepath)])

    @defer.inlineCallbacks
    def test_one_file_create(self):
        """Check that an example file create is really pushed."""
        l = Listener()
        self.eq.subscribe(l)
        self.addCleanup(self.eq.unsubscribe, l)

        # push some event
        filepath = os.path.join(self.share.path, "a")
        open_file(filepath, "w").close()

        yield self.lr.start()
        expected = [
            ('FS_FILE_CREATE', filepath),
            ('FS_FILE_CLOSE_WRITE', filepath),
        ]
        self.assertItemsEqual(l.events, expected)

    @defer.inlineCallbacks
    def test_one_dir_delete(self):
        """Check that an example dir delete is really pushed."""
        l = Listener()
        self.eq.subscribe(l)
        self.addCleanup(self.eq.unsubscribe, l)

        # push some event
        filepath = os.path.join(self.share.path, "a")
        self.fsm.create(filepath, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(filepath, "uuid1")

        yield self.lr.start()
        self.assertItemsEqual(l.events, [('FS_DIR_DELETE', filepath)])

    @defer.inlineCallbacks
    def test_one_file_delete(self):
        """Check that an example file delete is really pushed."""
        l = Listener()
        self.eq.subscribe(l)
        self.addCleanup(self.eq.unsubscribe, l)

        # push some event
        filepath = os.path.join(self.share.path, "a")
        self.fsm.create(filepath, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(filepath, "uuid1")
        self.fsm.set_by_path(filepath, local_hash="hash", server_hash="hash")

        yield self.lr.start()
        self.assertItemsEqual(l.events, [('FS_FILE_DELETE', filepath)])

    @defer.inlineCallbacks
    def test_file_changed(self):
        """Check that an example close write is pushed."""
        l = Listener()
        self.eq.subscribe(l)
        self.addCleanup(self.eq.unsubscribe, l)

        # push some event
        filepath = os.path.join(self.share.path, "a")
        self.fsm.create(filepath, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(filepath, "uuid1")
        with open_file(filepath, "w") as fh:
            fh.write("foo")

        yield self.lr.start()
        expected = [
            ('FS_FILE_CREATE', filepath),
            ('FS_FILE_CLOSE_WRITE', filepath),
        ]
        self.assertItemsEqual(l.events, expected)

    @defer.inlineCallbacks
    def test_file_changed_in_nestedstruct(self):
        """Check that an example close write is pushed."""
        l = Listener()
        self.eq.subscribe(l)
        self.addCleanup(self.eq.unsubscribe, l)

        # create nested struct
        path = os.path.join(self.share.path, "a")
        self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid1")
        make_dir(path)
        path = os.path.join(self.share.path, "a", "b")
        self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid2")
        make_dir(path)
        path = os.path.join(self.share.path, "a", "b", "c")
        self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path, "uuid3")
        open_file(path, "w").close()

        # push some event
        with open_file(path, "w") as fh:
            fh.write("foo")

        yield self.lr.start()
        expected = [
            ('FS_FILE_CREATE', path),
            ('FS_FILE_CLOSE_WRITE', path),
        ]
        self.assertItemsEqual(l.events, expected)

    @defer.inlineCallbacks
    def test_conflict_file(self):
        """Found a .conflict file."""
        listener = Listener()
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # push some event
        path = os.path.join(self.share.path, "foobar.u1conflict")
        open_file(path, "w").close()

        yield self.lr.start()
        self.assertFalse(listener.events)
        self.assertTrue(path_exists(path))

    @defer.inlineCallbacks
    def test_conflict_dir(self):
        """Found a .conflict dir."""
        listener = Listener()
        self.eq.subscribe(listener)
        self.addCleanup(self.eq.unsubscribe, listener)

        # push some event
        path = os.path.join(self.share.path, "foobar.u1conflict")
        make_dir(path)

        yield self.lr.start()
        self.assertFalse(listener.events)
        self.assertTrue(path_exists(path))


class BadStateTests(TwistedBase):
    """Test what happens with those files left in a bad state last time."""

    def _hash(self, path):
        """Hashes a file."""
        hasher = storage_hash.content_hash_factory()
        with open_file(path) as fh:
            while True:
                cont = fh.read(65536)
                if not cont:
                    break
                hasher.update(cont)
        return hasher.content_hash()

    @defer.inlineCallbacks
    def test_no_uuid_empty(self):
        """Found an empty file that does not have uuid yet."""
        path = os.path.join(self.share.path, "a")
        self.fsm.create(path, self.share.volume_id, is_dir=False)
        open_file(path, "w").close()

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path),
                                          ('FS_FILE_CLOSE_WRITE', path)])
        self.assertEqual(self.fsm.has_metadata(path=path), False)

    @defer.inlineCallbacks
    def test_no_uuid_all_family(self):
        """Fast creation paths: all without uuid."""
        path1 = os.path.join(self.share.path, "a")
        self.fsm.create(path1, self.share.volume_id, is_dir=True)
        make_dir(path1)
        path2 = os.path.join(self.share.path, "a", "b")
        self.fsm.create(path2, self.share.volume_id, is_dir=False)
        open_file(path2, "w").close()

        yield self.lr.scan_dir("mdid", path1)
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path2),
                                          ('FS_FILE_CLOSE_WRITE', path2)])
        self.assertEqual(self.fsm.has_metadata(path=path1), True)
        self.assertEqual(self.fsm.has_metadata(path=path2), False)

    @defer.inlineCallbacks
    def test_no_uuid_content(self):
        """Found a non empty file that does not have uuid yet."""
        path = os.path.join(self.share.path, "a")
        self.fsm.create(path, self.share.volume_id, is_dir=False)
        with open_file(path, "w") as fh:
            fh.write("foo")

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path),
                                          ('FS_FILE_CLOSE_WRITE', path)])
        self.assertEqual(self.fsm.has_metadata(path=path), False)

    @defer.inlineCallbacks
    def test_LOCAL_same(self):
        """Uploading the file, interrupted, and file is the same."""
        # create the file in metadata and real
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path, "uuid")
        with open_file(path, "w") as fh:
            fh.write("foo")

        # start a put file, and assume we got interrupted (no server hash)
        pathhash = self._hash(path)
        self.fsm.set_by_mdid(mdid, local_hash=pathhash, crc32='foo')
        mdobj = self.fsm.fs[mdid]
        mdobj["stat"] = stat_path(path)
        self.fsm.fs[mdid] = mdobj

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(self.aq.uploaded[0][:7],
                         (mdobj.share_id, mdobj.node_id, mdobj.server_hash,
                          mdobj.local_hash, mdobj.crc32, mdobj.size, mdid))
        self.assertEqual(self.aq.uploaded[1], {'upload_id': None})
        self.assertTrue(self.handler.check_debug("resuming upload",
                                                 "interrupted"))

    @defer.inlineCallbacks
    def test_LOCAL_different(self):
        """Uploading the file, interrupted, and changed while SD was off."""
        # create the file in metadata and real
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path, "uuid")
        with open_file(path, "w") as fh:
            fh.write("foo")

        # start a put file, and assume we got interrupted (no server hash)
        pathhash = self._hash(path)
        self.fsm.set_by_mdid(mdid, local_hash=pathhash, crc32='foo')
        mdobj = self.fsm.fs[mdid]
        mdobj["stat"] = None  # stat comparison will fail :)
        self.fsm.fs[mdid] = mdobj

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CLOSE_WRITE', path)])
        self.assertTrue(self.handler.check_debug("comp yield", repr(path),
                                                 "LOCAL and changed"))

    @defer.inlineCallbacks
    def test_LOCAL_with_upload_id(self):
        """We were uploading the file, but it was interrupted."""
        # create the file in metadata and real
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path, "uuid")
        with open_file(path, "w") as fh:
            fh.write("foo")

        # start a put file, and assume we got interrupted (no server hash)
        pathhash = self._hash(path)
        self.fsm.set_by_mdid(mdid, local_hash=pathhash, crc32='foo')
        mdobj = self.fsm.fs[mdid]
        mdobj["stat"] = stat_path(path)
        mdobj["upload_id"] = 'hola'
        self.fsm.fs[mdid] = mdobj

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(self.aq.uploaded[0][:7],
                         (mdobj.share_id, mdobj.node_id, mdobj.server_hash,
                          mdobj.local_hash, mdobj.crc32, mdobj.size, mdid))
        self.assertEqual(self.aq.uploaded[1], {'upload_id': 'hola'})
        self.assertTrue(self.handler.check_debug("resuming upload",
                                                 "interrupted"))

    @defer.inlineCallbacks
    def test_SERVER_file_empty(self):
        """We were downloading the file, but it was interrupted."""
        # create the file in metadata
        path = os.path.join(self.share.path, "a")
        open_file(path, "w").close()
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", self.share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", self.share.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(self.aq.downloaded[:4],
                         (mdobj.share_id, mdobj.node_id,
                          mdobj.server_hash, mdid))
        self.assertTrue(self.handler.check_debug("comp yield", "SERVER"))

    @defer.inlineCallbacks
    def test_SERVER_no_file(self):
        """We just queued the Download, and it was interrupted."""
        # create the file in metadata
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False,
                               node_id="uuid")
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))

        # this mimic Sync.get_file
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", self.share.volume_id)

        # now, for some reason, we lose the partial file
        remove_file(partial_path)

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(self.aq.downloaded[:4],
                         (mdobj.share_id, mdobj.node_id,
                          mdobj.server_hash, mdid))
        self.assertTrue(self.handler.check_debug("comp yield", "SERVER"))

    @defer.inlineCallbacks
    def test_SERVER_file_content(self):
        """We were downloading the file, but it was interrupted, and changed"""
        # create the file in metadata
        path = os.path.join(self.share.path, "a")
        with open_file(path, 'w') as fh:
            fh.write("previous content")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", self.share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", self.share.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        # also change the original file
        with open_file(path, "w") as fh:
            fh.write("I see dead people")

        yield self.lr.start()
        # The MD should be left as is, and issue the CLOSE_WRITE.
        # This will mimic what happens when the user touches the file
        # while downloading, with SD running. As the file changed, we don't
        # start a new download, an remove the old .partial.
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertTrue(mdobj.info.is_partial)
        self.assertEqual(mdobj.local_hash, '')
        self.assertEqual(mdobj.server_hash, "blah-hash-blah")
        self.assertFalse(path_exists(partial_path))
        self.assertEqual(self.eq.pushed, [('FS_FILE_CLOSE_WRITE', path)])
        self.assertTrue(self.handler.check_debug("differ", "Old", "New"))

    @defer.inlineCallbacks
    def test_SERVER_dir(self):
        """Found a dir in SERVER.

        This was valid before, but no more, so we just fix and log in warning.
        """
        # create the dir in metadata
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", self.share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", self.share.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        # also put a file inside the directory, to check that LR enters in it
        fpath = os.path.join(path, "file")
        open_file(fpath, "w").close()

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        # it should be in NONE
        self.assertFalse(mdobj.info.is_partial)
        self.assertEqual(mdobj.server_hash, mdobj.local_hash)
        self.assertFalse(path_exists(partial_path))

        # file inside dir should be found
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', fpath),
                                          ('FS_FILE_CLOSE_WRITE', fpath)])
        # logged in warning
        self.assertTrue(
            self.handler.check_warning("Found a directory in SERVER"))

    @defer.inlineCallbacks
    def test_partial_nomd(self):
        """Found a .partial with no metadata at all."""
        path = os.path.join(
            self.fsm.partials_dir, 'anduuid' + ".u1partial.foo")
        open_file(path, "w").close()

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(path_exists(path), path)

    @defer.inlineCallbacks
    def test_directory_bad_changed(self):
        """Found a dir with 'changed' not SERVER nor NONE."""
        path1 = os.path.join(self.share.path, "onedir")
        self.fsm.create(path1, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path1, "uuid1")
        make_dir(path1)
        self.fsm.set_by_path(path1, server_hash="foo")

        # create a child to it
        path2 = os.path.join(path1, "file_inside")
        self.fsm.create(path2, self.share.volume_id)
        self.fsm.set_node_id(path2, "uuid2")
        open_file(path2, "w").close()

        yield self.lr.start()
        self.assertFalse(path_exists(path1))
        self.assertTrue(path_exists(path1 + ".u1conflict"))
        self.assertFalse(self.fsm.has_metadata(path=path1))

        # check MD is gone also for children
        self.assertFalse(self.fsm.has_metadata(path=path2),
                         "no metadata for %r" % path2)

    @defer.inlineCallbacks
    def test_file_partial_dir(self):
        """Found a .partial of a file, but MD says it's a dir."""
        # create the dir in metadata
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", self.share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", self.share.volume_id)
        fh.write("foobar")
        fh.close()
        partial_path = os.path.join(self.fsm.partials_dir,
                                    mdid + ".u1partial.a")
        self.assertTrue(path_exists(partial_path))

        # now change the dir for a file, for LR to find it
        remove_dir(path)
        open_file(path, "w").close()

        yield self.lr.start()
        # The partial should be gone, the path should be there (the file!),
        # with its metadata.
        self.assertTrue(path_exists(path))
        self.assertFalse(path_exists(partial_path), partial_path)
        self.assertTrue(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_partial_for_dir_in_NONE(self):
        """Found a .partial of a directory whose MD said changed=NONE."""
        # create the dir in metadata
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")
        make_dir(path)

        # create the partial (not through FSM to don't signal the MD)
        partial_path = os.path.join(self.fsm.partials_dir,
                                    mdid + ".u1partial.a")
        with open_file(partial_path, "w") as fh:
            fh.write("foobar")

        yield self.lr.start()
        self.assertTrue(path_exists(path))
        self.assertTrue(self.fsm.has_metadata(path=path))
        self.assertFalse(path_exists(partial_path))

    @defer.inlineCallbacks
    def test_file_noSERVER(self):
        """We were downloading the file, it was interrupted, but no SERVER."""
        # create the file in metadata
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        open_file(path, "w").close()
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", self.share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", self.share.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        # trick it to not return "SERVER"
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["info"]["is_partial"] = False
        self.fsm.fs[mdid] = real_mdobj

        yield self.lr.start()
        # As it's a corrupted MD situation, the safest path is to just remove
        # the partial, and leave the file as it is.
        self.assertTrue(path_exists(path), path)
        self.assertFalse(path_exists(partial_path), partial_path)
        self.assertTrue(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_no_file_broken_metadata(self):
        """Found broken metadata but no file."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path, "uuid")

        # break the metadata
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["info"]["is_partial"] = True
        self.fsm.fs[mdid] = real_mdobj

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_no_dir_broken_metadata_deep(self):
        """Found broken metadata but no dir."""
        path1 = os.path.join(self.share.path, "a")
        mdid1 = self.fsm.create(path1, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path1, "uuid1")

        path2 = os.path.join(self.share.path, "a", "b")
        mdid2 = self.fsm.create(path2, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path2, "uuid2")

        # break both metadatas
        real_mdobj = self.fsm.fs[mdid1]
        real_mdobj["info"]["is_partial"] = True
        self.fsm.fs[mdid1] = real_mdobj

        real_mdobj = self.fsm.fs[mdid2]
        real_mdobj["info"]["is_partial"] = True
        self.fsm.fs[mdid2] = real_mdobj

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=path1))
        self.assertFalse(self.fsm.has_metadata(path=path2))

    @defer.inlineCallbacks
    def test_no_dir_broken_metadata(self):
        """Found broken metadata but no dir."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")

        # break the metadata
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["info"]["is_partial"] = True
        self.fsm.fs[mdid] = real_mdobj

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_no_dir_LOCAL_metadata(self):
        """Found metadata with 'changed' in LOCAL but no dir."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")

        # break the metadata
        real_mdobj = self.fsm.fs[mdid]
        real_mdobj["info"]["is_partial"] = False
        real_mdobj["server_hash"] = "different-than-local"
        self.fsm.fs[mdid] = real_mdobj

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_just_created_no_real_hash(self):
        """Found a file that has content, but MD doesn't know it."""
        # this is a case when a file is written with content, the make_file
        # to the server was ok (we have the file uuid), but before
        # HQ finishes everything is stopped; when started again, it needs
        # to generate the corresponding events, to start the hash&upload
        # process again
        path = os.path.join(self.share.path, "a")
        self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path, "uuid")
        self.fsm.set_by_path(path, local_hash="", server_hash="")
        with open_file(path, "w") as fh:
            fh.write("foo")

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [('FS_FILE_CREATE', path),
                                          ('FS_FILE_CLOSE_WRITE', path)])

    @defer.inlineCallbacks
    def test_notcontent_file(self):
        """The file is created but never started to download."""
        # create the file in metadata
        path = os.path.join(self.share.path, "a")
        # open_file(path, "w").close()
        self.fsm.create(path, self.share.volume_id, is_dir=False, node_id="1")

        yield self.lr.start()
        self.assertEqual(self.eq.pushed, [])
        self.assertFalse(self.fsm.has_metadata(path=path))

    @defer.inlineCallbacks
    def test_SERVER_file_ro_share(self):
        """We were downloading the file, but it was interrupted in RO share."""
        # create the file in metadata
        ro_share = yield self.create_share('share_ro_id', u'share_ro2',
                                           access_level=ACCESS_LEVEL_RO)
        self.fsm.create(ro_share.path, ro_share.id, is_dir=True)
        self.fsm.set_node_id(ro_share.path, "uuidshare")
        path = os.path.join(ro_share.path, "a")
        with self.fsm._enable_share_write(ro_share.id, path):
            open_file(path, "w").close()
        mdid = self.fsm.create(path, ro_share.volume_id, is_dir=False)
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", ro_share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", ro_share.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertEqual(self.aq.downloaded[:4],
                         (mdobj.share_id, mdobj.node_id,
                          mdobj.server_hash, mdid))
        self.assertTrue(self.handler.check_debug("comp yield", "SERVER"))

    @defer.inlineCallbacks
    def test_SERVER_dir_ro_share(self):
        """Found a dir in SERVER in a ro_share.

        This was valid before, but no more, so we just fix and log in warning.
        """
        # create the dir in metadata
        ro_share = yield self.create_share('share_ro_id', u'share_ro2',
                                           access_level=ACCESS_LEVEL_RO)
        self.fsm.create(ro_share.path, ro_share.id, is_dir=True)
        self.fsm.set_node_id(ro_share.path, "uuidshare")

        path = os.path.join(ro_share.path, "a")
        mdid = self.fsm.create(path, ro_share.volume_id, is_dir=True)
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))
        self.fsm.set_node_id(path, "uuid")

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial("uuid", ro_share.volume_id)
        fh = self.fsm.get_partial_for_writing("uuid", ro_share.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        yield self.lr.start()
        mdobj = self.fsm.get_by_mdid(mdid)
        # it should be in NONE
        self.assertFalse(mdobj.info.is_partial)
        self.assertEqual(mdobj.server_hash, mdobj.local_hash)
        self.assertFalse(path_exists(partial_path))
        # logged in warning
        self.assertTrue(self.handler.check_warning(
                                                "Found a directory in SERVER"))

    def test_check_stat_None(self):
        """Test check_stat with oldstat = None."""
        # create the file in metadata
        path = os.path.join(self.share.path, "a_file")
        self.fsm.create(path, self.share.volume_id, is_dir=False)
        self.assertTrue(self.lr.check_stat(path, None))


class RootBadStateTests(TwistedBase):
    """Test what happens with volume roots left in a bad state last time."""

    @defer.inlineCallbacks
    def _test_it(self, volume):
        """Run the bad state test for a specific volume."""
        path = volume.path
        mdid = self.fsm.get_by_path(path).mdid
        partial_path = os.path.join(
            self.fsm.partials_dir,
            mdid + ".u1partial." + os.path.basename(path))

        # start the download, never complete it
        self.fsm.set_by_mdid(mdid, server_hash="blah-hash-blah")
        self.fsm.create_partial(volume.node_id, volume.volume_id)
        fh = self.fsm.get_partial_for_writing(volume.node_id, volume.volume_id)
        fh.write("foobar")
        fh.close()
        self.assertTrue(path_exists(partial_path))

        yield self.lr.start()
        # arrange the metadata so later server_rescan will do ok
        mdobj = self.fsm.get_by_mdid(mdid)
        self.assertFalse(mdobj.info.is_partial)
        self.assertEqual(mdobj.server_hash, mdobj.local_hash)
        self.assertFalse(path_exists(partial_path))

    @defer.inlineCallbacks
    def test_SERVER_root(self):
        """We were downloading the root dir, but it was interrupted."""
        # create the root
        self.fsm.set_node_id(self.vm.root.path, self.vm.root.node_id)
        yield self._test_it(self.vm.root)

    @defer.inlineCallbacks
    def test_SERVER_share(self):
        """We were downloading the share root dir but it was interrupted."""
        # create a share
        share = yield self.create_share('share_id_1', u'rw_share',
                                        access_level=ACCESS_LEVEL_RW)
        self.fsm.create(share.path, "share_id_1", is_dir=True)
        self.fsm.set_node_id(share.path, "uuid_share_1")
        share.node_id = "uuid_share_1"
        self.vm.shares['share_id_1'] = share
        yield self._test_it(share)

    @defer.inlineCallbacks
    def test_SERVER_udf(self):
        """We were downloading the udf root dir, but it was interrupted."""
        udf = yield self.create_udf('udf_id', 'udf_root_node_id')
        self.fsm.create(udf.path, 'udf_id', is_dir=True)
        self.fsm.set_node_id(udf.path, 'udf_root_node_id')
        yield self._test_it(udf)


class LimboTests(TwistedBase):
    """Test handling limbos."""

    @defer.inlineCallbacks
    def test_nothing(self):
        """No trash, no moves."""
        yield self.lr.start()
        self.assertEqual(self.aq.unlinked, [])
        self.assertEqual(self.aq.moved, [])

    @defer.inlineCallbacks
    def test_trash_one(self):
        """Something in the trash."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")
        self.fsm.delete_to_trash(mdid, "parent_id")

        yield self.lr.start()
        self.assertEqual(self.aq.moved, [])
        self.assertEqual(self.aq.unlinked, [(self.share.volume_id,
                                             "parent_id", "uuid", path, True)])
        self.assertTrue(self.handler.check_info(
                         "generating Unlink from trash"))

    @defer.inlineCallbacks
    def test_trash_two(self):
        """Two nodes (file and dir) in the trash."""
        path1 = os.path.join(self.share.path, "a")
        mdid1 = self.fsm.create(path1, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path1, "uuid1")
        self.fsm.delete_to_trash(mdid1, "parent_id")

        path2 = os.path.join(self.share.path, "b")
        mdid2 = self.fsm.create(path2, self.share.volume_id, is_dir=False)
        self.fsm.set_node_id(path2, "uuid2")
        self.fsm.delete_to_trash(mdid2, "parent_id")

        yield self.lr.start()
        self.assertEqual(self.aq.moved, [])
        self.assertItemsEqual(self.aq.unlinked, [
            (self.share.volume_id, "parent_id", "uuid1", path1, True),
            (self.share.volume_id, "parent_id", "uuid2", path2, False),
        ])

    @defer.inlineCallbacks
    def test_no_double_unlink(self):
        """Avoid double unlinks.

        This happens because we signal a deletion and move to trash, and then
        delete from trash.

        There's no way to test this here, because it will need all working
        machinery (EQ, Sync, FSM) and not mockups, so we just look into the
        logs to assert order.
        """
        yield self.lr.start()
        msgs = [x.msg for x in self.handler.records]
        pos_trash = msgs.index('processing trash')
        pos_compares = msgs.index('comparing directory %r')
        self.assertTrue(pos_trash < pos_compares)

    @defer.inlineCallbacks
    def test_trash_node_marker(self):
        """Trash with node_id being a marker."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.delete_to_trash(mdid, "parent_id")

        yield self.lr.start()
        self.assertEqual(self.aq.unlinked, [])
        self.assertTrue(self.handler.check_info("removing from trash"))

    @defer.inlineCallbacks
    def test_trash_parent_marker(self):
        """Trash with parent_id being a marker."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")
        self.fsm.delete_to_trash(mdid, MDMarker("parent_id"))

        yield self.lr.start()
        self.assertEqual(self.aq.unlinked, [])
        self.assertTrue(self.handler.check_info("removing from trash"))

    @defer.inlineCallbacks
    def test_move_limbo_one(self):
        """Something in the move_limbo."""
        self.fsm.add_to_move_limbo("share", "uuid", "old_parent",
                                   "new_parent", "new_name", "p_from", "p_to")

        yield self.lr.start()
        self.assertEqual(self.aq.unlinked, [])
        self.assertEqual(self.aq.moved,
                         [("share", "uuid", "old_parent",
                           "new_parent", "new_name", "p_from", "p_to")])
        self.assertTrue(self.handler.check_info(
                        "generating Move from limbo"))

    @defer.inlineCallbacks
    def test_move_limbo_two(self):
        """Two nodes (file and dir) in the move_limbo."""
        self.fsm.add_to_move_limbo("s1", "u1", "op1", "np1", "n1",
                                   "p_from", "p_to")
        self.fsm.add_to_move_limbo("s2", "u2", "op2", "np2", "n2",
                                   "p_from", "p_to")

        yield self.lr.start()
        self.assertEqual(self.aq.unlinked, [])
        self.assertItemsEqual(self.aq.moved, [
            ("s1", "u1", "op1", "np1", "n1", "p_from", "p_to"),
            ("s2", "u2", "op2", "np2", "n2", "p_from", "p_to"),
        ])

    @defer.inlineCallbacks
    def test_mixed_trash_moves(self):
        """Mixed limbo with trash and moves."""
        path = os.path.join(self.share.path, "a")
        mdid = self.fsm.create(path, self.share.volume_id, is_dir=True)
        self.fsm.set_node_id(path, "uuid")
        self.fsm.delete_to_trash(mdid, "parent_id")

        self.fsm.add_to_move_limbo("share", "uuid", "old_parent",
                                   "new_parent", "new_name", "p_from", "p_to")

        yield self.lr.start()
        self.assertEqual(self.aq.moved,
                         [("share", "uuid", "old_parent", "new_parent",
                           "new_name", "p_from", "p_to")])
        self.assertEqual(self.aq.unlinked, [(self.share.volume_id,
                                             "parent_id", "uuid", path, True)])

    @defer.inlineCallbacks
    def test_move_limbo_markers(self):
        """Trash with node_id in None."""
        # load 4 things in move limbo, each with a MDMarker (not for 'name')
        n = ("sh", "node", "old_parent", "new_parent", "name", "pfrom", "pto")
        for i in range(4):
            m = list(n)
            m[1] = 'node_%d' % i
            m[i] = MDMarker(m[i])
        self.fsm.add_to_move_limbo(*m)

        yield self.lr.start()
        self.assertEqual(self.aq.moved, [])
        self.assertTrue(self.handler.check_info(
                        "removing from move limbo"))
        self.assertFalse(self.handler.check_info("generating Move"))


class ParentWatchForUDFTestCase(BaseTestCase):
    """Tests over watches for UDF's parent dir."""

    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(ParentWatchForUDFTestCase, self).setUp()
        self._deferred = defer.Deferred()
        self.eq = event_queue.EventQueue(self.fsm)
        self.addCleanup(self.eq.shutdown)
        self.watches = []

        def fake_add(path):
            """Fake watch handler."""
            if path in self.watches:
                return defer.succeed(False)
            else:
                self.watches.append(path)
                return defer.succeed(True)

        @defer.inlineCallbacks
        def fake_add_watches_to_udf_ancestors(volume):
            """Fake the addition of the ancestors watches."""
            for ancestor in volume.ancestors:
                self._logger.debug("Adding watch to UDF's %r", ancestor)
                yield fake_add(ancestor)
            defer.returnValue(True)

        self.patch(self.eq, 'add_watch', fake_add)
        self.patch(self.eq, 'add_watches_to_udf_ancestors',
                   fake_add_watches_to_udf_ancestors)

        self.lr = local_rescan.LocalRescan(self.vm, self.fsm, self.eq, self.aq)

        # create UDF
        suggested_path = u'~/Documents/Reading/Books/PDFs'
        udf_id, node_id = 'udf_id', 'node_id'
        self.udf = yield self.create_udf(udf_id, node_id, suggested_path)
        self.ancestors = self.udf.ancestors  # need a fake HOME

        # make FSM aware of it
        self.fsm.create(self.udf.path, udf_id, is_dir=True)
        self.fsm.set_node_id(self.udf.path, node_id)

        # logging
        self.handler = MementoHandler()
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)

    @defer.inlineCallbacks
    def test_ancestors_have_watch(self):
        """UDF's ancestors have a watch."""
        yield self.lr.start()

        expected = set(self.ancestors)
        actual = set(self.watches)
        difference = expected.symmetric_difference(actual)
        msg = (
            'Expected (%s)\n\nIs not subset of real watches (%s).\n\nSet '
            'symmetric difference is: %s.' % (expected, actual, difference))
        self.assertTrue(expected.issubset(actual), msg)
        self.assertTrue(self.handler.check_debug("Adding watch to UDF's",
                                                 repr(self.ancestors[0])))

    @defer.inlineCallbacks
    def test_watch_is_not_added_if_present(self):
        """Watches are not added if present."""
        for path in self.ancestors:
            yield self.eq.add_watch(path)

        yield self.lr.start()

        for path in self.udf.ancestors:
            self.assertEqual(1, self.watches.count(path))


class BrokenNodesTests(TwistedBase):
    """Test that LR logs all broken nodes at start."""

    @defer.inlineCallbacks
    def test_nothing(self):
        """No broken nodes."""
        yield self.lr.start()
        self.assertFalse(self.handler.check_info('Broken node'))

    @defer.inlineCallbacks
    def test_one(self):
        """Something in the broken nodes list."""
        path = os.path.join(self.share.path, "brokennodepath")
        mdid = self.fsm.create(path, self.share.volume_id, node_id="uuid")
        self.fsm.set_by_mdid(mdid, dirty=True, local_hash='foo')

        yield self.lr.start()
        self.assertTrue(self.handler.check_info('Broken node',
                                                'brokennodepath', mdid))

    @defer.inlineCallbacks
    def test_several(self):
        """Several in the broken nodes list."""
        path1 = os.path.join(self.share.path, "brokenpath1")
        mdid1 = self.fsm.create(path1, self.share.volume_id, node_id='uuid1')
        self.fsm.set_by_mdid(mdid1, dirty=True, local_hash='foo')
        path2 = os.path.join(self.share.path, "brokenpath2")
        mdid2 = self.fsm.create(path2, self.share.volume_id, node_id='uuid2')
        self.fsm.set_by_mdid(mdid2, dirty=True, local_hash='foo')

        yield self.lr.start()
        self.assertTrue(self.handler.check_info('Broken node',
                                                'brokenpath1', mdid1))
        self.assertTrue(self.handler.check_info('Broken node',
                                                'brokenpath2', mdid2))
