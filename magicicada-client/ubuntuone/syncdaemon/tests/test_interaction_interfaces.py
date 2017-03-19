# -*- coding: utf-8 -*-
#
# Copyright 2011-2015 Canonical Ltd.
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
"""Test the interaction_interfaces module."""

import logging
import os

from twisted.internet import defer
from ubuntuone.devtools.handlers import MementoHandler
try:
    from ubuntuone.networkstate.networkstates import ONLINE
except ImportError:
    from ubuntuone.networkstate import ONLINE
from ubuntuone.platform.tests.ipc.test_perspective_broker import (
    FakeNetworkManagerState,
)

from contrib.testing.testcase import (
    FAKED_CREDENTIALS,
    FakeCommand,
    FakeDownload,
    FakeUpload,
    FakedObject,
    FakeMainTestCase,
    skipIfOS,
)
from ubuntuone.platform import make_dir, make_link
from ubuntuone.storageprotocol.protocol_pb2 import AccountInfo
from ubuntuone.syncdaemon import (
    config,
    interaction_interfaces,
    states,
)
from ubuntuone.syncdaemon.interaction_interfaces import (
    bool_str,
    get_share_dict,
    get_udf_dict,
    logger,
    NoAccessToken,
    request,
    SyncdaemonConfig,
    SyncdaemonEvents,
    SyncdaemonEventListener,
    SyncdaemonFileSystem,
    SyncdaemonFolders,
    SyncdaemonPublicFiles,
    SyncdaemonService,
    SyncdaemonShares,
    SyncdaemonStatus,
)
from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    ACCESS_LEVEL_RW,
    get_udf_path,
    Share,
    Shared,
    UDF,
    VolumeDoesNotExist,
)


class CustomError(Exception):
    """A custom error, for testing only."""


class FakedExternalInterface(object):
    """A faked external interface."""

    clients = (
        'config',
        'events',
        'file_system',
        'folders',
        'public_files',
        'shares',
        'status',
        'sync_daemon',
    )

    def __init__(self, service=None):
        for client in self.clients:
            setattr(self, client, FakedObject(service))


class BaseTestCase(FakeMainTestCase):
    """The base test case."""

    sd_class = None
    kwargs = {}

    @defer.inlineCallbacks
    def setUp(self):
        self.patch(interaction_interfaces, 'ExternalInterface',
                   FakedExternalInterface)
        yield super(BaseTestCase, self).setUp()

        self.kwargs['main'] = self.main
        self.kwargs['interface'] = FakedExternalInterface()
        self.addCleanup(self.kwargs.clear)

        self.sd_obj = None
        if self.sd_class is not None:
            self.sd_obj = self.sd_class(**self.kwargs)

        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        interaction_interfaces.logger.addHandler(self.handler)
        self.addCleanup(interaction_interfaces.logger.removeHandler,
                        self.handler)

    def _raise_error(self, *args, **kwargs):
        """Make patched calls fail."""
        raise CustomError(*args, **kwargs)

    def _create_share(self, volume_id=None, node_id=None,
                      access_level=ACCESS_LEVEL_RO,
                      accepted=True, subscribed=False):
        """Create a Share and return it."""
        if volume_id is None:
            volume_id = 'share_id'
        if node_id is None:
            node_id = 'node_id'
        if volume_id == request.ROOT:
            path = self.main.root_dir
        else:
            path = os.path.join(self.main.shares_dir, 'a_share_dir')
        share = Share(path=path, volume_id=volume_id, node_id=node_id,
                      accepted=accepted, access_level=access_level,
                      subscribed=subscribed)
        return share

    def _create_udf(self, volume_id=None, node_id=None,
                    suggested_path=None, subscribed=True):
        """Create an UDF and returns it and the volume."""
        if volume_id is None:
            volume_id = 'folder_id'
        if node_id is None:
            node_id = 'node_id'
        if suggested_path is None:
            suggested_path = u'~/ñoño'
        else:
            # make sure suggested_path is unicode
            assert isinstance(suggested_path, unicode)
        path = get_udf_path(suggested_path)
        udf = UDF(
            str(volume_id), str(node_id), suggested_path, path, subscribed)
        return udf


class SyncdaemonStatusTestCase(BaseTestCase):
    """Test the SyncdaemonStatus class."""

    sd_class = SyncdaemonStatus

    def test_current_status(self):
        """Test the current_status method."""
        state = self.main.state_manager.state
        expected = dict(name=state.name, description=state.description,
                        is_error=bool_str(state.is_error),
                        is_connected=bool_str(state.is_connected),
                        is_online=bool_str(state.is_online),
                        queues=self.main.state_manager.queues.state.name,
                        connection=self.main.state_manager.connection.state)

        result = self.sd_obj.current_status()

        self.assertEqual(expected, result)

    def test_current_uploads(self):
        """Test the current_uploads method."""
        fake_upload = FakeUpload('share_id', 'node_id')
        fake_upload.deflated_size = 100
        fake_upload.n_bytes_written = 10
        fake_upload.path = "up_path"
        self.action_q.queue.waiting.append(fake_upload)

        result = self.sd_obj.current_uploads()

        self.assertEqual(1, len(result))
        self.assertEqual("up_path", str(result[0]['path']))
        self.assertEqual('100', str(result[0]['deflated_size']))
        self.assertEqual('10', str(result[0]['n_bytes_written']))

    def test_two_current_uploads(self):
        """Test the current_uploads method for two uploads."""
        fake_upload = FakeUpload('share_id', 'node_id')
        fake_upload.deflated_size = 100
        fake_upload.n_bytes_written = 10
        fake_upload.path = "up_path"
        self.action_q.queue.waiting.append(fake_upload)

        fake_upload = FakeUpload('share_id_1', 'node_id_1')
        fake_upload.deflated_size = 80
        fake_upload.n_bytes_written = 20
        fake_upload.path = "up_path_1"
        self.action_q.queue.waiting.append(fake_upload)

        result = self.sd_obj.current_uploads()

        self.assertEqual(2, len(result))
        self.assertEqual('up_path', str(result[0]['path']))
        self.assertEqual('100', str(result[0]['deflated_size']))
        self.assertEqual('10', str(result[0]['n_bytes_written']))
        self.assertEqual('up_path_1', str(result[1]['path']))
        self.assertEqual('80', str(result[1]['deflated_size']))
        self.assertEqual('20', str(result[1]['n_bytes_written']))

    def test_current_uploads_deflated_size_NA(self):
        """Test current_uploads with fake data in the AQ."""
        fake_upload = FakeUpload('share_id', 'node_id')
        fake_upload.deflated_size = None
        fake_upload.n_bytes_written = 0
        fake_upload.path = "up_path"
        self.action_q.queue.waiting.append(fake_upload)

        result = self.sd_obj.current_uploads()

        self.assertEqual(1, len(result))
        self.assertEqual("up_path", str(result[0]['path']))
        self.assertNotIn('deflated_size', result[0])
        self.assertEqual('0', str(result[0]['n_bytes_written']))

    def test_current_downloads(self):
        """Test the current_downloads method."""
        fake_download = FakeDownload('share_id', 'down_node_id')
        fake_download.deflated_size = 10
        fake_download.n_bytes_read = 1
        fake_download.path = "down_path"
        self.action_q.queue.waiting.append(fake_download)

        result = self.sd_obj.current_downloads()

        self.assertEqual(1, len(result))
        self.assertEqual("down_path", str(result[0]['path']))
        self.assertEqual('10', str(result[0]['deflated_size']))
        self.assertEqual('1', str(result[0]['n_bytes_read']))

    def test_two_current_downloads(self):
        """Test the current_downloads method for two downloads."""
        fake_download = FakeDownload('share_id', 'node_id')
        fake_download.deflated_size = 10
        fake_download.n_bytes_read = 8
        fake_download.path = "down_path"
        self.action_q.queue.waiting.append(fake_download)

        fake_download = FakeDownload('share_id_1', 'node_id_1')
        fake_download.deflated_size = 10
        fake_download.n_bytes_read = 5
        fake_download.path = "down_path_1"
        self.action_q.queue.waiting.append(fake_download)

        result = self.sd_obj.current_downloads()

        self.assertEqual(2, len(result))
        self.assertEqual('down_path', str(result[0]['path']))
        self.assertEqual('10', str(result[0]['deflated_size']))
        self.assertEqual('8', str(result[0]['n_bytes_read']))
        self.assertEqual('down_path_1', str(result[1]['path']))
        self.assertEqual('10', str(result[1]['deflated_size']))
        self.assertEqual('5', str(result[1]['n_bytes_read']))

    def test_current_downloads_deflated_size_NA(self):
        """Test current_downloads with fake data in the AQ."""
        fake_download = FakeDownload('share_id', 'down_node_id')
        fake_download.deflated_size = None
        fake_download.n_bytes_read = 0
        fake_download.path = "down_path"
        self.action_q.queue.waiting.append(fake_download)

        result = self.sd_obj.current_downloads()

        self.assertEqual(1, len(result))
        self.assertEqual('down_path', str(result[0]['path']))
        self.assertNotIn('deflated_size', result[0])
        self.assertEqual('0', str(result[0]['n_bytes_read']))

    @defer.inlineCallbacks
    def test_free_space(self):
        """Test the free_space method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        self.main.vm.update_free_space(share.volume_id, 12345)

        result = self.sd_obj.free_space(share.volume_id)

        self.assertEqual(result, 12345)

    def test_waiting(self):
        """Test the current_waiting method."""
        c1 = FakeCommand("share_id", "node_id_a", other=123)
        c2 = FakeCommand("share_id", "node_id_b", other=None)
        c2.running = False
        c3 = FakeCommand("share_id", "node_id_c", other=MDMarker('bar'))
        self.action_q.queue.waiting.extend([c1, c2, c3])

        node_a, node_b, node_c = self.sd_obj.waiting()

        should = dict(share_id='share_id', node_id='node_id_a',
                      running='True', other='123')
        self.assertEqual(node_a, ('FakeCommand', str(id(c1)), should))

        should = dict(share_id='share_id', node_id='node_id_b',
                      running='', other='None')
        self.assertEqual(node_b, ('FakeCommand', str(id(c2)), should))

        should = dict(share_id='share_id', node_id='node_id_c',
                      running='True', other='marker:bar')
        self.assertEqual(node_c, ('FakeCommand', str(id(c3)), should))

    def test_waiting_metadata(self):
        """Test the waiting_metadata method."""
        self.action_q.queue.waiting.extend([
            FakeCommand("share_id", "node_id_b", u"moño"),
            FakeCommand("share_id", "node_id_c", path='/some/path'),
            FakeCommand("share_id", "node_id_d"),
        ])

        result = self.sd_obj.waiting_metadata()

        self.assertEqual(len(result), 3)

        pl = dict(share_id='share_id', node_id='node_id_b',
                  other=u'moño', running='True')
        self.assertEqual(result[0], ('FakeCommand', pl))

        pl = dict(share_id='share_id', node_id='node_id_c',
                  other='', path='/some/path', running='True')
        self.assertEqual(result[1], ('FakeCommand', pl))

        pl = dict(share_id='share_id', node_id='node_id_d',
                  other='', running='True')
        self.assertEqual(result[2], ('FakeCommand', pl))

        self.handler.debug = True
        self.assertTrue(self.handler.check_warning('deprecated'))

    def test_waiting_content(self):
        """Test the waiting_content method."""
        self.action_q.queue.waiting.extend([
            FakeUpload("share_id", "node_id_b"),
            FakeDownload("share_id", "node_id_c"),
        ])

        result = self.sd_obj.waiting_content()

        self.assertEqual(2, len(result))
        node_b, node_c = result

        self.assertEqual('upload_path', str(node_b['path']))
        self.assertEqual('share_id', str(node_b['share']))
        self.assertEqual('node_id_b', str(node_b['node']))

        self.assertEqual('download_path', str(node_c['path']))
        self.assertEqual('share_id', str(node_c['share']))
        self.assertEqual('node_id_c', str(node_c['node']))

        self.assertTrue(self.handler.check_warning('deprecated'))


class SyncdaemonFileSystemTestCase(BaseTestCase):
    """Test the SyncdaemonFileSystem class."""

    sd_class = SyncdaemonFileSystem

    @defer.inlineCallbacks
    def test_get_metadata(self):
        """Test the get_metadata method."""
        share = yield self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, "foo")
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        result = self.sd_obj.get_metadata(path)

        self.assertEqual(path, str(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])

    @skipIfOS('win32', 'Windows symlink handling does not support resolving'
                       'symlink in between a path.')
    @defer.inlineCallbacks
    def test_get_metadata_path_symlink(self):
        """Test the get_metadata method, getting MD by path in a symlink."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, "foo")
        symlink_path = os.path.join(self.shares_dir, "share_symlink")
        share_context = self.main.fs._enable_share_write(share.volume_id,
                                                         share.path)
        with share_context:
            make_dir(share.path, recursive=True)
            make_link(share.path, symlink_path)
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        symlink_path = os.path.join(symlink_path, 'foo')
        result = self.sd_obj.get_metadata(symlink_path)

        self.assertEqual(symlink_path, str(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])

    @defer.inlineCallbacks
    def test_get_metadata_unicode(self):
        """Test the get_metadata method, getting MD by non-ascii path."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, u'ñoño'.encode('utf-8'))
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        result = self.sd_obj.get_metadata(path)

        self.assertEqual(path.decode('utf-8'), unicode(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])

    @defer.inlineCallbacks
    def test_get_metadata_by_node(self):
        """Test the get_metadata_by_node method."""
        share = self._create_share(accepted=False)
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, "foo")
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        result = self.sd_obj.get_metadata_by_node(
            share.volume_id, share.node_id)

        self.assertEqual(path, str(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])

    @defer.inlineCallbacks
    def test_get_metadata_and_quick_tree_synced(self):
        """Test the get_metadata_and_quick_tree_synced method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, u'ñoño'.encode('utf-8'))
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        # inject fake data
        self.action_q.queue.waiting.append(
            FakeCommand(share.volume_id, share.node_id))

        result = self.sd_obj.get_metadata_and_quick_tree_synced(path)

        self.assertEqual(path.decode('utf-8'), result['path'])
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])
        self.assertEqual('', result['quick_tree_synced'])

    @defer.inlineCallbacks
    def test_get_metadata_and_quick_tree_no_blow_up_kthxbye(self):
        """Test the get_metadata_and_quick_tree_synced method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, u'ñoño'.encode('utf-8'))
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        # inject fake data
        self.action_q.queue.waiting.append(
            FakeCommand("this share id no longer exists",
                        "neither does this path id"))

        result = self.sd_obj.get_metadata_and_quick_tree_synced(path)

        self.assertEqual(path.decode('utf-8'), unicode(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])
        self.assertEqual('synced', result['quick_tree_synced'])

    @defer.inlineCallbacks
    def test_get_metadata_and_quick_tree_not_synced_2(self):
        """Test the get_metadata_and_quick_tree_synced method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, u'ñoño'.encode('utf-8'))
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        # inject fake data
        self.action_q.queue.waiting.append(
            FakeCommand(share.volume_id, share.node_id))

        result = self.sd_obj.get_metadata_and_quick_tree_synced(path)

        self.assertEqual(path.decode('utf-8'), unicode(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])
        self.assertEqual('', result['quick_tree_synced'])

    @defer.inlineCallbacks
    def test_get_metadata_and_quick_tree_synced_3(self):
        """Test the get_metadata_and_quick_tree_synced method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, u'ñoño'.encode('utf-8'))
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        result = self.sd_obj.get_metadata_and_quick_tree_synced(path)

        self.assertEqual(path.decode('utf-8'), result['path'])
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])
        self.assertEqual('synced', result['quick_tree_synced'])

    @skipIfOS('win32', 'Windows symlink handling does not support resolving'
                       'symlink in between a path.')
    @defer.inlineCallbacks
    def test_get_metadata_and_quick_tree_synced_symlink(self):
        """Test the get_metadata_and_quick_tree_synced method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, u'ñoño'.encode('utf-8'))
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)
        symlink_path = os.path.join(self.shares_dir, "share_symlink")
        share_context = self.main.fs._enable_share_write(share.volume_id,
                                                         share.path)
        with share_context:
            make_dir(share.path, recursive=True)
            make_link(share.path, symlink_path)
        expected_path = os.path.join(symlink_path, os.path.basename(path))

        result = self.sd_obj.get_metadata_and_quick_tree_synced(expected_path)

        self.assertEqual(expected_path.decode('utf-8'),
                         unicode(result['path']))
        self.assertEqual(share.volume_id, result['share_id'])
        self.assertEqual(share.node_id, result['node_id'])
        self.assertEqual('synced', result['quick_tree_synced'])

    def test_get_dirty_nodes(self):
        """Test the get_dirty_nodes method."""
        # create some nodes
        path1 = os.path.join(self.root_dir, u'ñoño-1'.encode('utf-8'))
        mdid1 = self.main.fs.create(path1, "")
        path2 = os.path.join(self.root_dir, u'ñoño-2'.encode('utf-8'))
        mdid2 = self.main.fs.create(path2, "")
        path3 = os.path.join(self.root_dir, "path3")
        mdid3 = self.main.fs.create(path3, "")
        path4 = os.path.join(self.root_dir, "path4")
        mdid4 = self.main.fs.create(path4, "")

        # dirty some
        self.main.fs.set_by_mdid(mdid2, dirty=True)
        self.main.fs.set_by_mdid(mdid4, dirty=True)

        all_dirty = self.sd_obj.get_dirty_nodes()

        dirty_mdids = dict((n['mdid'], n) for n in all_dirty)
        self.assertEqual(len(all_dirty), 2)
        self.assertIn(mdid2, dirty_mdids)
        self.assertIn(mdid4, dirty_mdids)
        self.assertNotIn(mdid1, dirty_mdids)
        self.assertNotIn(mdid3, dirty_mdids)
        # check that path de/encoding is done correctly
        self.assertEqual(repr(self.main.fs.get_by_mdid(mdid2).path),
                         repr(dirty_mdids[mdid2]['path'].encode('utf-8')))


class SyncdaemonSharesTestCase(BaseTestCase):
    """Test the SyncdaemonShares class."""

    sd_class = SyncdaemonShares

    def test_get_volume(self):
        """Test the get_volume method."""
        self.patch(self.main.vm, 'get_volume', self._set_called)
        share_id = object()
        self.sd_obj.get_volume(share_id)

        self.assertEqual(self._called, ((share_id,), {}))

    @defer.inlineCallbacks
    def test_get_shares(self):
        """Test the get_shares method."""
        share = self._create_share(accepted=False)
        yield self.main.vm.add_share(share)

        shares = self.sd_obj.get_shares()

        self.assertEqual(1, len(shares))
        for info in shares:
            if info['volume_id'] == '':
                self.assertEqual('', str(info['volume_id']))
                self.assertEqual(self.root_dir, str(info['path']))
                self.assertEqual(ACCESS_LEVEL_RW,
                                 str(info['access_level']))
                self.assertEqual('False', str(info['accepted']))
            else:
                self.assertEqual(share.volume_id, str(info['volume_id']))
                self.assertEqual(share.path, str(info['path']))
                self.assertEqual(ACCESS_LEVEL_RO,
                                 str(info['access_level']))
                self.assertEqual('', str(info['accepted']))

    @defer.inlineCallbacks
    def test_accept_share(self):
        """Test the accept_share method."""
        share = self._create_share(accepted=False)
        yield self.main.vm.add_share(share)
        self.assertFalse(self.main.vm.shares[share.volume_id].accepted)

        self.sd_obj.accept_share(share.volume_id)

        self.assertTrue(self.main.vm.shares[share.volume_id].accepted)

    @defer.inlineCallbacks
    def test_reject_share(self):
        """Test the reject_share method."""
        share = self._create_share(accepted=True)
        yield self.main.vm.add_share(share)
        self.assertTrue(self.main.vm.shares[share.volume_id].accepted)

        self.sd_obj.reject_share(share.volume_id)

        self.assertFalse(self.main.vm.shares[share.volume_id].accepted)

    @defer.inlineCallbacks
    def test_delete_share(self):
        """Test the delete_share method."""
        self.patch(self.main.vm, 'delete_volume', self._set_called)
        share = self._create_share(accepted=True)
        yield self.main.vm.add_share(share)

        self.sd_obj.delete_share(share.volume_id)

        self.assertEqual(self._called, ((share.volume_id, ), {}))

    @defer.inlineCallbacks
    def test_delete_share_from_me(self):
        """Test the delete_share method with share from_me."""
        self.patch(self.main.vm, 'delete_share', self._set_called)
        share = self._create_share(accepted=True)
        yield self.main.vm.add_shared(share)

        self.assertRaises(VolumeDoesNotExist,
                          self.main.vm.get_volume, share.volume_id)

        self.sd_obj.delete_share(share.volume_id)

        self.assertEqual(self._called, ((share.volume_id, ), {}))

    def test_delete_share_doesnotexist(self):
        """Test the delete_share method with non-existent share."""
        self.patch(self.main.vm, 'delete_share', self._set_called)
        share_id = 'missing_share_id'
        self.sd_obj.delete_share(share_id)

        self.assertEqual(self._called, ((share_id, ), {}))

    def test_subscribe(self):
        """Test the subscribe method."""
        self.patch(self.main.vm, 'subscribe_share', self._set_called)
        share_id = object()
        self.sd_obj.subscribe(share_id)

        self.assertEqual(self._called, ((share_id,), {}))

    def test_unsubscribe(self):
        """Test the unsubscribe method."""
        self.patch(self.main.vm, 'unsubscribe_share', self._set_called)
        share_id = object()
        self.sd_obj.unsubscribe(share_id)

        self.assertEqual(self._called, ((share_id,), {}))

    def test_create_share(self):
        """Test the create_share method."""
        self.patch(self.main.vm, 'create_share', self._set_called)
        a_dir = os.path.join(self.root_dir, "a_dir")
        self.main.fs.create(a_dir, "", is_dir=True)
        self.main.fs.set_node_id(a_dir, "node_id")

        args = (a_dir, 'test_user', 'share_a_dir', ACCESS_LEVEL_RO)
        self.sd_obj.create_share(*args)

        self.assertEqual(self._called, (args, {}))

    def test_create_share_unicode(self):
        """Test the create_share method using a non-ascii path."""
        self.patch(self.main.vm, 'create_share', self._set_called)
        a_dir = os.path.join(self.root_dir, u'ñoño'.encode('utf-8'))
        self.main.fs.create(a_dir, "", is_dir=True)
        self.main.fs.set_node_id(a_dir, "node_id")

        args = (u'test_user', u'share_ñoño', ACCESS_LEVEL_RO)
        # ipc layer will send the path as unicode
        self.sd_obj.create_share(a_dir.decode('utf-8'), *args)

        self.assertEqual(self._called, ((a_dir,) + args, {}))

    def test_create_shares(self):
        """Test the create_shares method."""
        called = []
        self.patch(self.main.vm, 'create_share', lambda *a: called.append(a))
        a_dir = os.path.join(self.root_dir, "a_dir")
        self.main.fs.create(a_dir, "", is_dir=True)
        self.main.fs.set_node_id(a_dir, "node_id")

        usernames = ['test_user1', 'test_user2', 'test_user3']
        self.sd_obj.create_shares(a_dir, usernames, 'share_a_dir',
                                  ACCESS_LEVEL_RO)

        expected = [(a_dir, u, 'share_a_dir', ACCESS_LEVEL_RO)
                    for u in usernames]
        self.assertEqual(called, expected)

    def test_refresh_shares(self):
        """Test the refresh_shares method."""
        self.patch(self.main.vm, 'refresh_shares', self._set_called)
        self.sd_obj.refresh_shares()

        self.assertEqual(self._called, ((), {}))

    def test_get_shared(self):
        """Test the get_shared method."""
        a_dir = os.path.join(self.root_dir, "a_dir")
        self.main.fs.create(a_dir, "", is_dir=True)
        self.main.fs.set_node_id(a_dir, "node_id")

        def aq_create_share(*args):
            """Fake the action_queue's create_share."""
            self.main.event_q.push('AQ_CREATE_SHARE_OK',
                                   share_id='share_id', marker=args[-2])

        self.patch(self.main.action_q, 'create_share', aq_create_share)
        self.main.vm.create_share(a_dir, 0, 'share_a_dir', ACCESS_LEVEL_RO)

        result = self.sd_obj.get_shared()

        self.assertEqual(1, len(result))
        shared = result[0]
        self.assertEqual(a_dir, str(shared['path']))
        self.assertEqual('node_id', str(shared['node_id']))
        self.assertEqual('share_id', str(shared['volume_id']))
        self.assertEqual(ACCESS_LEVEL_RO, str(shared['access_level']))

    def test_get_shared_missing_path(self):
        """Test the get_shared method, but without having the path."""
        a_dir = os.path.join(self.root_dir, "a_dir")
        self.main.fs.create(a_dir, "", is_dir=True)
        self.main.fs.set_node_id(a_dir, "node_id")

        def aq_create_share(*args):
            """Fake the action_queue's create_share."""
            self.main.event_q.push('AQ_CREATE_SHARE_OK',
                                   share_id='share_id', marker=args[-2])

        self.patch(self.main.action_q, 'create_share', aq_create_share)
        self.main.vm.create_share(a_dir, 0, 'share_a_dir', ACCESS_LEVEL_RO)

        # remove the md of the subtree from fsm
        self.main.fs.delete_file(a_dir)
        # set the path to None
        share = self.main.vm.shared['share_id']
        share.path = None
        self.main.vm.shared['share_id'] = share

        result = self.sd_obj.get_shared()

        self.assertEqual(1, len(result))
        shared = result[0]
        self.assertEqual('', str(shared['path']))
        self.assertEqual('node_id', str(shared['node_id']))
        self.assertEqual('share_id', str(shared['volume_id']))
        self.assertEqual(ACCESS_LEVEL_RO, str(shared['access_level']))

    @defer.inlineCallbacks
    def test_get_shared_unicode(self):
        """Test the get_shared method, but with non-ascii path."""
        a_dir = os.path.join(self.root_dir, u'ñoño'.encode('utf-8'))
        self.main.fs.create(a_dir, "", is_dir=True)
        self.main.fs.set_node_id(a_dir, "node_id")
        share = Shared(path=a_dir, volume_id='shared_id', name=u'ñoño_shared',
                       access_level=ACCESS_LEVEL_RO,
                       other_username=u'test_username', node_id='node_id')
        yield self.main.vm.add_shared(share)

        result = self.sd_obj.get_shared()

        self.assertEqual(1, len(result))
        shared = result[0]
        self.assertEqual(a_dir, shared['path'].encode('utf-8'))
        self.assertEqual('node_id', str(shared['node_id']))
        self.assertEqual('shared_id', str(shared['volume_id']))
        self.assertEqual(ACCESS_LEVEL_RO, str(shared['access_level']))


class SyncdaemonConfigTestCase(BaseTestCase):
    """Test the SyncdaemonConfig class."""

    sd_class = SyncdaemonConfig

    def test_get_throttling_limits_none_set(self):
        """Test the get_throttling_limits method."""
        result = self.sd_obj.get_throttling_limits()

        self.assertEqual(-1, result['download'])
        self.assertEqual(-1, result['upload'])

    def test_get_throttling_limits_both_set(self):
        """Test the get_throttling_limits method."""
        self.main.action_q.readLimit = 100
        self.main.action_q.writeLimit = 200

        result = self.sd_obj.get_throttling_limits()

        self.assertEqual(self.main.action_q.readLimit, result['download'])
        self.assertEqual(self.main.action_q.writeLimit, result['upload'])

    def test_get_throttling_limits_only_read_set(self):
        """Test the get_throttling_limits method."""
        self.main.action_q.readLimit = 100

        result = self.sd_obj.get_throttling_limits()

        self.assertEqual(self.main.action_q.readLimit, result['download'])
        self.assertEqual(-1, result['upload'])

    def test_get_throttling_limits_only_write_set(self):
        """Test the get_throttling_limits method."""
        self.main.action_q.writeLimit = 200

        result = self.sd_obj.get_throttling_limits()

        self.assertEqual(-1, result['download'])
        self.assertEqual(self.main.action_q.writeLimit, result['upload'])

    def test_set_throttling_limits_no_limit(self):
        """Test the set_throttling_limits method."""
        download = upload = -1
        self.sd_obj.set_throttling_limits(download, upload)

        self.assertEqual(self.main.action_q.readLimit, None)
        self.assertEqual(self.main.action_q.writeLimit, None)

        user_config = config.get_user_config()
        self.assertEqual(user_config.get_throttling_read_limit(), None)
        self.assertEqual(user_config.get_throttling_write_limit(), None)

    def test_set_throttling_limits(self):
        """Test the set_throttling_limits method."""
        download = 100
        upload = 500
        self.sd_obj.set_throttling_limits(download, upload)

        self.assertEqual(self.main.action_q.readLimit, 100)
        self.assertEqual(self.main.action_q.writeLimit, 500)

        user_config = config.get_user_config()
        self.assertEqual(user_config.get_throttling_read_limit(), 100)
        self.assertEqual(user_config.get_throttling_write_limit(), 500)

    def test_enable_bandwidth_throttling(self):
        """Test the enable_bandwidth_throttling method."""
        self.main.action_q.throttling = False
        self.sd_obj.enable_bandwidth_throttling()

        self.assertTrue(self.main.action_q.throttling_enabled)
        user_config = config.get_user_config()
        self.assertEqual(user_config.get_throttling(), True)

    def test_disable_bandwidth_throttling(self):
        """Test the disable_bandwidth_throttling method."""
        self.main.action_q.throttling = True
        self.sd_obj.disable_bandwidth_throttling()

        self.assertFalse(self.main.action_q.throttling_enabled)
        user_config = config.get_user_config()
        self.assertEqual(user_config.get_throttling(), False)

    def test_bandwidth_throttling_enabled(self):
        """Test the bandwidth_throttling_enabled method."""
        self.main.action_q.throttling_enabled = False
        result = self.sd_obj.bandwidth_throttling_enabled()
        self.assertFalse(result)

        self.main.action_q.throttling_enabled = True
        result = self.sd_obj.bandwidth_throttling_enabled()
        self.assertTrue(result)

    def test_udf_autosubscribe_enabled(self):
        """Test the udf_autosubscribe_enabled method."""
        self.sd_obj.enable_udf_autosubscribe()
        result = self.sd_obj.udf_autosubscribe_enabled()
        self.assertTrue(result)

        self.sd_obj.disable_udf_autosubscribe()
        result = self.sd_obj.udf_autosubscribe_enabled()
        self.assertFalse(result)

    def test_enable_udf_autosubscribe(self):
        """Test the enable_udf_autosubscribe method."""
        self.sd_obj.enable_udf_autosubscribe()
        self.assertTrue(config.get_user_config().get_udf_autosubscribe())

    def test_disable_udf_autosubscribe(self):
        """Test the disable_udf_autosubscribe method."""
        self.sd_obj.disable_udf_autosubscribe()
        self.assertFalse(config.get_user_config().get_udf_autosubscribe())

    def test_share_autosubscribe_enabled(self):
        """Test the share_autosubscribe_enabled method."""
        self.sd_obj.enable_share_autosubscribe()
        result = self.sd_obj.share_autosubscribe_enabled()
        self.assertTrue(result)

        self.sd_obj.disable_share_autosubscribe()
        result = self.sd_obj.share_autosubscribe_enabled()
        self.assertFalse(result)

    def test_enable_share_autosubscribe(self):
        """Test the enable_share_autosubscribe method."""
        self.sd_obj.enable_share_autosubscribe()
        self.assertTrue(config.get_user_config().get_share_autosubscribe())

    def test_disable_share_autosubscribe(self):
        """Test the disable_share_autosubscribe method."""
        self.sd_obj.disable_share_autosubscribe()
        self.assertFalse(config.get_user_config().get_share_autosubscribe())

    def test_files_sync_enabled(self):
        """Test the files_sync_enabled method."""
        self.sd_obj.enable_files_sync()
        result = self.sd_obj.files_sync_enabled()
        self.assertTrue(result)

        self.sd_obj.disable_files_sync()
        result = self.sd_obj.files_sync_enabled()
        self.assertFalse(result)

    def test_enable_files_sync(self):
        """Test the enable_files_sync method."""
        self.sd_obj.enable_files_sync()
        self.assertTrue(config.get_user_config().get_files_sync_enabled())

    def test_disable_files_sync(self):
        """Test the disable_files_sync method."""
        self.sd_obj.disable_files_sync()
        self.assertFalse(config.get_user_config().get_files_sync_enabled())

    def test_autoconnect_enabled(self):
        """Test the autoconnect_enabled method."""
        self.sd_obj.enable_autoconnect()
        result = self.sd_obj.autoconnect_enabled()
        self.assertTrue(result)

        self.sd_obj.disable_autoconnect()
        result = self.sd_obj.autoconnect_enabled()
        self.assertFalse(result)

    def test_enable_autoconnect(self):
        """Test the enable_autoconnect method."""
        self.sd_obj.enable_autoconnect()
        self.assertTrue(config.get_user_config().get_autoconnect())

    def test_disable_autoconnect(self):
        """Test the disable_autoconnect method."""
        self.sd_obj.disable_autoconnect()
        self.assertFalse(config.get_user_config().get_autoconnect())


class SyncdaemonFoldersTestCase(BaseTestCase):
    """Test the SyncdaemonFolders class."""

    sd_class = SyncdaemonFolders

    def test_create(self):
        """Test the create method."""
        self.patch(self.main.vm, 'create_udf', self._set_called)
        path = u'foo/bar/ñandú'
        self.sd_obj.create(path)

        self.assertEqual(self._called, ((path.encode('utf-8'),), {}))

    def test_delete(self):
        """Test the delete method."""
        self.patch(self.main.vm, 'delete_volume', self._set_called)
        folder_id = object()
        self.sd_obj.delete(folder_id)

        self.assertEqual(self._called, ((folder_id,), {}))

    def test_validate_path(self):
        """Test the validate_path method."""
        # Use a lambda instead of _set_called since we need to return a tuple.
        self.patch(self.main.vm, 'validate_path_for_folder',
                   lambda arg: (True, arg))
        path = u'this/is/a/test'
        rv = self.sd_obj.validate_path(path)

        self.assertTrue(rv)

    @defer.inlineCallbacks
    def test_get_folders(self):
        """Test the get_folders method."""
        result = self.sd_obj.get_folders()
        self.assertEqual(result, [])

        udf1 = self._create_udf()
        yield self.main.vm.add_udf(udf1)
        udf2 = self._create_udf(volume_id='other', node_id='another',
                                suggested_path=u'~/other/location ♫ test')
        yield self.main.vm.add_udf(udf2)

        expected = sorted([get_udf_dict(udf)
                           for udf in self.main.vm.udfs.itervalues()])
        result = self.sd_obj.get_folders()
        self.assertEqual(len(result), 2)
        self.assertEqual(expected, sorted(result))

    def test_get_udf_dict(self):
        """Test for Folders.get_udf_dict."""
        udf = self._create_udf(subscribed=False)
        udf_dict = get_udf_dict(udf)
        # check the path it's unicode
        self.assertEqual(udf_dict['path'], udf.path.decode('utf-8'))
        self.assertEqual(udf_dict['volume_id'], udf.id)
        self.assertEqual(udf_dict['suggested_path'], udf.suggested_path)
        self.assertEqual(udf_dict['node_id'], udf.node_id)
        self.assertFalse(udf_dict['subscribed'])

    def test_get_udf_dict_bad_encoding(self):
        """Test for Folders.get_udf_dict."""
        suggested_path = u'~/Música'
        udf = self._create_udf(suggested_path=suggested_path, subscribed=False)
        udf.suggested_path = udf.suggested_path.encode('utf-8')
        udf_dict = get_udf_dict(udf)
        # check the path it's unicode
        self.assertEqual(udf_dict['path'], udf.path.decode('utf-8'))
        self.assertEqual(udf_dict['volume_id'], udf.id)
        self.assertEqual(repr(udf_dict['suggested_path']),
                         repr(udf.suggested_path.decode('utf-8')))
        self.assertEqual(udf_dict['node_id'], udf.node_id)
        self.assertFalse(udf_dict['subscribed'])

    def test_subscribe(self):
        """Test the subscribe method."""
        self.patch(self.main.vm, 'subscribe_udf', self._set_called)
        folder_id = object()
        self.sd_obj.subscribe(folder_id)

        self.assertEqual(self._called, ((folder_id,), {}))

    def test_unsubscribe(self):
        """Test the unsubscribe method."""
        self.patch(self.main.vm, 'unsubscribe_udf', self._set_called)
        folder_id = None
        self.sd_obj.unsubscribe(folder_id)

        self.assertEqual(self._called, ((folder_id,), {}))

    @defer.inlineCallbacks
    def test_get_info(self):
        """Test for Folders.get_info."""
        udf = self._create_udf()

        path = udf.path.decode('utf-8')
        self.assertRaises(KeyError, self.sd_obj.get_info, path)

        yield self.main.vm.add_udf(udf)

        info = self.sd_obj.get_info(path)
        udf_dict = get_udf_dict(self.main.vm.get_volume(udf.volume_id))

        self.assertEqual(info, udf_dict)

    def test_refresh_volumes(self):
        """Test the refresh_volumes method."""
        self.patch(self.main.vm, 'refresh_volumes', self._set_called)
        self.sd_obj.refresh_volumes()

        self.assertEqual(self._called, ((), {}))


class SyncdaemonPublicFilesTestCase(BaseTestCase):
    """Test the SyncdaemonPublicFiles class."""

    sd_class = SyncdaemonPublicFiles

    # XXX: change public access is the only class that expects uuid's as
    # params this may indicate that we need to refactor that class to be
    # consistent with the rest of syncdaemon where ID's are always strings

    def test_change_public_access(self):
        """Test the change_public_access method."""
        called = []
        self.patch(self.main.action_q, 'change_public_access',
                   lambda a, b, c: called.append((str(a), str(b), c)))
        share_id = '4aa0de63-b28f-43e7-98de-6ff6b8ebfdd3'
        node_id = '59809aae-9c5a-47e0-b37c-5abbfbe7c50a'
        self.sd_obj.change_public_access(share_id, node_id, True)

        self.assertEqual(called, [(share_id, node_id, True)])

    def test_change_public_access_share_id_none(self):
        """Test the change_public_access method."""
        called = []
        self.patch(self.main.action_q, 'change_public_access',
                   lambda a, b, c: called.append((a, str(b), c)))
        share_id = None
        node_id = '59809aae-9c5a-47e0-b37c-5abbfbe7c50a'
        self.sd_obj.change_public_access(share_id, node_id, True)

        self.assertEqual(called, [(share_id, node_id, True)])

    def test_get_public_files(self):
        """Test the get_public_files method."""
        self.patch(self.main.action_q, 'get_public_files', self._set_called)
        self.sd_obj.get_public_files()

        self.assertEqual(self._called, ((), {}))


class SyncdaemonEventsTestCase(BaseTestCase):
    """Test the SyncdaemonEvents class."""

    sd_class = SyncdaemonEvents

    def test_push_event(self):
        """Test the push_event method."""
        d = defer.Deferred()

        class Listener(object):
            """A basic listener to handle the pushed event."""

            def handle_FS_FILE_CREATE(innerself, path):
                """FS_FILE_CREATE handling."""
                self.assertEqual('bar', path)
                d.callback(True)

        listener = Listener()
        self.event_q.subscribe(listener)
        self.addCleanup(self.event_q.unsubscribe, listener)

        event_name = 'FS_FILE_CREATE'
        args = {'path': 'bar'}
        self.sd_obj.push_event(event_name, args)

        return d


class SyncdaemonEventListenerTestCase(BaseTestCase):
    """Test the SyncdaemonEventListener class."""

    sd_class = SyncdaemonEventListener

    @defer.inlineCallbacks
    def setUp(self):
        yield super(SyncdaemonEventListenerTestCase, self).setUp()
        self.a_dir = os.path.join(self.root_dir, u'ñoño'.encode('utf-8'))
        self.main.event_q.subscribe(self.sd_obj)
        self.addCleanup(self.main.event_q.unsubscribe, self.sd_obj)


class UploadTestCase(SyncdaemonEventListenerTestCase):
    """Test the Upload events in SyncdaemonEventListener."""

    add_fsm_key = True
    direction = 'Upload'
    bytes_key = 'n_bytes_written'
    hash_kwarg = 'hash'
    extra_finished_args = dict(new_generation='new_generation', hash='')
    finished_event = 'AQ_UPLOAD_FINISHED'

    @defer.inlineCallbacks
    def setUp(self):
        yield super(UploadTestCase, self).setUp()
        self.deferred = None
        self.signal_name = None
        if self.add_fsm_key:
            self.main.fs.create(self.a_dir, "", is_dir=False)
            self.main.fs.set_node_id(self.a_dir, "node_id")

    def error_handler(self, signal_name, args):
        """Error signal handler."""
        try:
            self.assertEqual(self.signal_name, signal_name)
            msg = 'The metadata is gone before sending %s signal'
            self.assertEqual(args['message'], msg % self.signal_name)
            self.assertEqual(args['error'], str(('', 'node_id')))
            self.assertEqual(args['node_id'], 'node_id')
            self.assertEqual(args['share_id'], '')
        except Exception, e:
            self.deferred.errback(e)
        else:
            self.deferred.callback(True)

    def test_handle_started(self):
        """Test the handle_AQ_<direction>_STARTED method."""
        self.signal_name = self.direction + 'Started'
        self.deferred = defer.Deferred()

        def handler(path):
            """Handler for the <direction>Started signal."""
            self.assertEqual(self.a_dir, path.encode('utf-8'))
            self.deferred.callback(True)

        if self.add_fsm_key:
            self.patch(self.sd_obj.interface.status, self.signal_name, handler)
        else:
            self.patch(self.sd_obj.interface.status, 'SignalError',
                       self.error_handler)

        kwargs = {'share_id': '', 'node_id': 'node_id', self.hash_kwarg: ''}
        self.main.event_q.push('AQ_%s_STARTED' % self.direction.upper(),
                               **kwargs)
        return self.deferred

    def test_handle_file_progress(self):
        """Test the handle_AQ_<direction>_FILE_PROGRESS method."""
        self.signal_name = self.direction + 'FileProgress'
        self.deferred = defer.Deferred()

        def handler(path, info):
            """Handler for <direction>FileProgress signal."""
            self.assertEqual(self.a_dir, path.encode('utf-8'))
            self.assertEqual(info, {self.bytes_key: '10',
                                    'deflated_size': '20'})
            self.deferred.callback(True)

        if self.add_fsm_key:
            self.patch(self.sd_obj.interface.status, self.signal_name, handler)
        else:
            self.patch(self.sd_obj.interface.status, 'SignalError',
                       self.error_handler)

        kwargs = {'share_id': '', 'node_id': 'node_id', self.bytes_key: 10,
                  'deflated_size': 20}
        self.main.event_q.push('AQ_%s_FILE_PROGRESS' % self.direction.upper(),
                               **kwargs)
        return self.deferred

    def test_handle_finished(self):
        """Test the handle_<finished_event> method."""
        self.signal_name = self.direction + 'Finished'
        self.deferred = defer.Deferred()

        def handler(path, info):
            """Handler for <direction>Finished signal."""
            self.assertEqual(self.a_dir, path.encode('utf-8'))
            self.assertEqual(info, {})
            self.deferred.callback(True)

        if self.add_fsm_key:
            self.patch(self.sd_obj.interface.status, self.signal_name, handler)
        else:
            self.patch(self.sd_obj.interface.status, 'SignalError',
                       self.error_handler)

        kwargs = {'share_id': '', 'node_id': 'node_id'}
        kwargs.update(self.extra_finished_args)
        self.main.event_q.push(self.finished_event, **kwargs)
        return self.deferred

    def test_handle_event_error(self):
        """Test the handle_AQ_<direction>_ERROR method."""
        self.signal_name = self.direction + 'Finished'
        self.deferred = defer.Deferred()

        def handler(path, info):
            """Handler for <direction>Finished signal."""
            self.assertEqual(self.a_dir, path.encode('utf-8'))
            self.assertEqual('AN_ERROR', info['error'])
            self.deferred.callback(True)

        if self.add_fsm_key:
            self.patch(self.sd_obj.interface.status, self.signal_name, handler)
        else:
            self.patch(self.sd_obj.interface.status, 'SignalError',
                       self.error_handler)

        kwargs = {'share_id': '', 'node_id': 'node_id', self.hash_kwarg: '',
                  'error': 'AN_ERROR'}
        self.main.event_q.push('AQ_%s_ERROR' % self.direction.upper(),
                               **kwargs)
        return self.deferred


class DownloadTestCase(UploadTestCase):
    """Test the Download events in SyncdaemonEventListener."""

    direction = 'Download'
    bytes_key = 'n_bytes_read'
    hash_kwarg = 'server_hash'
    extra_finished_args = {}
    finished_event = 'FSM_PARTIAL_COMMITED'

    # The download is special, because we don't want to throw the ipc signal on
    # AQ_DOWNLOAD_FINISHED but instead we should wait for FSM_PARTIAL_COMMITED

    def test_ignore_pre_partial_commit_event(self):
        """The AQ_DOWNLOAD_FINISHED signal is ignored."""
        self.assertNotIn("handle_AQ_DOWNLOAD_FINISHED", vars(self.sd_class))


class DownloadNoKeyTestCase(DownloadTestCase):
    """Test the Download events when there is a fsm KeyError."""

    add_fsm_key = False


class UploadNoKeyTestCase(UploadTestCase):
    """Test the Upload events when there is a fsm KeyError."""

    add_fsm_key = False


class StatusEventListenerTestCase(SyncdaemonEventListenerTestCase):
    """Test the status events in SyncdaemonEventListener."""

    @defer.inlineCallbacks
    def test_handle_SV_ACCOUNT_CHANGED(self):
        """Test the handle_SV_ACCOUNT_CHANGED method."""
        account_info = AccountInfo(purchased_bytes=12345678)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status, 'AccountChanged', d.callback)
        self.main.event_q.push('SV_ACCOUNT_CHANGED', account_info=account_info)

        info = yield d

        bytes = account_info.purchased_bytes
        self.assertEqual(info, dict(purchased_bytes=unicode(bytes)))

    @defer.inlineCallbacks
    def test_handle_FS_INVALID_NAME(self):
        """Test the handle_FS_INVALID_NAME method."""
        dirname = self.a_dir
        filename = 'testpath'
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'InvalidName', lambda *a: d.callback(a))
        self.main.event_q.push('FS_INVALID_NAME',
                               dirname=dirname, filename=filename)

        di, fi = yield d

        dirname = dirname.decode('utf-8')
        self.assertEqual(type(dirname), type(di))
        self.assertEqual(dirname, di)
        self.assertEqual(filename, fi)

    @defer.inlineCallbacks
    def test_handle_SYS_BROKEN_NODE(self):
        """Test the handle_SYS_BROKEN_NODE method with all data."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'BrokenNode', lambda *a: d.callback(a))
        self.main.event_q.push('SYS_BROKEN_NODE', volume_id='volume',
                               node_id='node', path='somepath', mdid='mdid')

        volume_id, node_id, mdid, path = yield d

        self.assertEqual(volume_id, 'volume')
        self.assertEqual(node_id, 'node')
        self.assertEqual(mdid, 'mdid')
        self.assertEqual(path, 'somepath')
        self.assertTrue(isinstance(path, unicode))

    @defer.inlineCallbacks
    def test_handle_SYS_BROKEN_NODE_partial_data(self):
        """Test the handle_SYS_BROKEN_NODE method with partial data."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'BrokenNode', lambda *a: d.callback(a))
        self.main.event_q.push('SYS_BROKEN_NODE', volume_id='volume',
                               node_id='node', path=None, mdid=None)

        volume_id, node_id, mdid, path = yield d

        self.assertEqual(volume_id, 'volume')
        self.assertEqual(node_id, 'node')
        self.assertEqual(mdid, '')
        self.assertEqual(path, u'')

    @defer.inlineCallbacks
    def test_handle_SYS_STATE_CHANGED(self):
        """Test the handle_SYS_STATE_CHANGED method."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status, 'StatusChanged', d.callback)
        self.main.event_q.push('SYS_STATE_CHANGED', state=object())

        result = yield d

        state = states.StateManager.READY
        self.assertEqual(state.name, result['name'])
        self.assertEqual(state.description, result['description'])
        self.assertEqual(state.is_error, bool(result['is_error']))
        self.assertEqual(state.is_connected, bool(result['is_connected']))
        self.assertEqual(state.is_online, bool(result['is_online']))


class SharesEventListenerTestCase(SyncdaemonEventListenerTestCase):
    """Test the shares events in SyncdaemonEventListener."""

    @defer.inlineCallbacks
    def test_handle_SV_FREE_SPACE(self):
        """Test the handle_SV_FREE_SPACE method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        free_bytes = 87654321
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'ShareChanged', d.callback)
        self.main.event_q.push('SV_FREE_SPACE',
                               share_id=share.volume_id, free_bytes=free_bytes)

        info = yield d

        expected = get_share_dict(share)
        expected['free_bytes'] = unicode(free_bytes)
        self.assertEqual(expected, info)

    @defer.inlineCallbacks
    def test_handle_AQ_CREATE_SHARE_OK(self):
        """Test the handle_AQ_CREATE_SHARE_OK method."""
        self.main.fs.create(self.a_dir, "", is_dir=True)
        self.main.fs.set_node_id(self.a_dir, "node_id")
        mdobj = self.main.fs.get_by_node_id("", "node_id")
        mdid = mdobj.mdid
        marker = MDMarker(mdid)
        share_id = 'share_id'
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'ShareCreated', d.callback)
        self.main.event_q.push('AQ_CREATE_SHARE_OK',
                               share_id=share_id, marker=marker)

        result = yield d

        self.assertEqual(str(share_id), str(result['volume_id']))

    @defer.inlineCallbacks
    def test_handle_AQ_CREATE_SHARE_ERROR(self):
        """Test the handle_AQ_CREATE_SHARE_ERROR method."""
        self.main.fs.create(self.a_dir, "", is_dir=True)
        self.main.fs.set_node_id(self.a_dir, "node_id")
        mdobj = self.main.fs.get_by_node_id("", "node_id")
        mdid = mdobj.mdid
        marker = MDMarker(mdid)
        error_msg = 'an error message'
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareCreateError', lambda *a: d.callback(a))
        self.main.event_q.push('AQ_CREATE_SHARE_ERROR',
                               marker=marker, error=error_msg)

        info, error = yield d

        self.assertEqual(str(marker), info['marker'])
        self.assertTrue(self.a_dir.decode('utf-8').endswith(info['path']))
        self.assertEqual(error, error_msg)

    @defer.inlineCallbacks
    def test_handle_AQ_ANSWER_SHARE_OK_yes(self):
        """Test the handle_AQ_ANSWER_SHARE_OK method."""
        share = self._create_share(accepted=False)
        yield self.main.vm.add_share(share)

        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareAnswerResponse', d.callback)
        self.main.vm.accept_share('share_id', True)

        result = yield d

        self.assertEqual('Yes', result['answer'])
        self.assertEqual('share_id', result['volume_id'])
        self.assertTrue(self.main.vm.shares['share_id'].accepted)

    @defer.inlineCallbacks
    def test_handle_AQ_ANSWER_SHARE_OK_no(self):
        """Test the handle_AQ_ANSWER_SHARE_OK method."""
        share = self._create_share(accepted=True)
        yield self.main.vm.add_share(share)

        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareAnswerResponse', d.callback)
        self.main.vm.accept_share('share_id', False)

        result = yield d

        self.assertEqual('No', result['answer'])
        self.assertEqual('share_id', result['volume_id'])
        self.assertFalse(self.main.vm.shares['share_id'].accepted)

    @defer.inlineCallbacks
    def test_handle_AQ_ANSWER_SHARE_ERROR(self):
        """Test the handle_AQ_ANSWER_SHARE_ERROR method."""
        share_id = 'share_id'
        answer = 'foo'
        error_msg = 'an error message'
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareAnswerResponse', d.callback)
        self.main.event_q.push('AQ_ANSWER_SHARE_ERROR', error=error_msg,
                               share_id=share_id, answer=answer)

        info = yield d

        expected = dict(volume_id=share_id, answer=answer, error=error_msg)
        self.assertEqual(expected, info)


class VolumesEventListenerTestCase(SyncdaemonEventListenerTestCase):
    """Test the shares/folders events in SyncdaemonEventListener."""

    @defer.inlineCallbacks
    def test_handle_VM_UDF_SUBSCRIBED(self):
        """Test the handle_VM_UDF_SUBSCRIBED method."""
        udf = self._create_udf(subscribed=False)
        yield self.main.vm.add_udf(udf)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders,
                   'FolderSubscribed', d.callback)
        self.main.vm.subscribe_udf(udf.volume_id)

        info = yield d

        udf.subscribed = True
        udf.local_rescanning = False
        self.assertEqual(get_udf_dict(udf), info)

    @defer.inlineCallbacks
    def test_handle_VM_UDF_SUBSCRIBE_ERROR(self):
        """Test the handle_VM_UDF_SUBSCRIBE_ERROR method."""
        udf = self._create_udf(subscribed=False)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders,
                   'FolderSubscribeError', lambda *a: d.callback(a))
        yield self.assertFailure(self.main.vm.subscribe_udf(udf.volume_id),
                                 VolumeDoesNotExist)

        info, error = yield d

        self.assertEqual(self.sd_obj._get_volume_info(udf.volume_id), info)
        self.assertEqual('DOES_NOT_EXIST', error)

    @defer.inlineCallbacks
    def test_handle_VM_UDF_UNSUBSCRIBED(self):
        """Test the handle_VM_UDF_UNSUBSCRIBED method."""
        udf = self._create_udf(subscribed=True)
        yield self.main.vm.add_udf(udf)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders,
                   'FolderUnSubscribed', d.callback)
        self.main.vm.unsubscribe_udf(udf.volume_id)

        info = yield d

        udf.subscribed = False
        udf.local_rescanning = False
        self.assertEqual(get_udf_dict(udf), info)

    @defer.inlineCallbacks
    def test_handle_VM_UDF_UNSUBSCRIBE_ERROR(self):
        """Test the handle_VM_UDF_UNSUBSCRIBE_ERROR method."""
        udf = self._create_udf(subscribed=False)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders,
                   'FolderUnSubscribeError', lambda *a: d.callback(a))
        self.main.vm.unsubscribe_udf(udf.volume_id)

        info, error = yield d

        self.assertEqual(self.sd_obj._get_volume_info(udf.volume_id), info)
        self.assertEqual('DOES_NOT_EXIST', error)

    @defer.inlineCallbacks
    def test_handle_VM_UDF_CREATED(self):
        """Test the handle_VM_UDF_CREATED method."""
        udf = self._create_udf(subscribed=True)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders,
                   'FolderCreated', d.callback)
        yield self.main.vm.add_udf(udf)

        info = yield d

        udf = self.main.vm.get_volume(udf.volume_id)
        self.assertEqual(get_udf_dict(udf), info)

    @defer.inlineCallbacks
    def test_handle_VM_UDF_CREATE_ERROR(self):
        """Test the handle_VM_UDF_CREATE_ERROR method."""
        path = self.a_dir
        error_msg = "I'm broken"
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders,
                   'FolderCreateError', lambda *a: d.callback(a))
        self.main.event_q.push('VM_UDF_CREATE_ERROR',
                               path=path, error=error_msg)

        info, error = yield d

        self.assertEqual(info['path'], path.decode('utf-8'))
        self.assertEqual(error, error_msg)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_SUBSCRIBED(self):
        """Test the handle_VM_SHARE_SUBSCRIBED method."""
        share = self._create_share(subscribed=False)
        yield self.main.vm.add_share(share)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareSubscribed', d.callback)
        self.main.vm.subscribe_share(share.volume_id)

        info = yield d

        share.subscribed = True
        share.local_rescanning = False
        self.assertEqual(get_share_dict(share), info)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_SUBSCRIBE_ERROR(self):
        """Test the handle_VM_SHARE_SUBSCRIBE_ERROR method."""
        share = self._create_share(subscribed=False)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareSubscribeError', lambda *a: d.callback(a))
        yield self.assertFailure(self.main.vm.subscribe_share(share.volume_id),
                                 VolumeDoesNotExist)

        info, error = yield d

        self.assertEqual(self.sd_obj._get_volume_info(share.volume_id), info)
        self.assertEqual('DOES_NOT_EXIST', error)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_UNSUBSCRIBED(self):
        """Test the handle_VM_SHARE_UNSUBSCRIBED method."""
        share = self._create_share(subscribed=True)
        yield self.main.vm.add_share(share)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareUnSubscribed', d.callback)
        self.main.vm.unsubscribe_share(share.volume_id)

        info = yield d

        share.subscribed = False
        share.local_rescanning = False
        self.assertEqual(get_share_dict(share), info)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_UNSUBSCRIBE_ERROR(self):
        """Test the handle_VM_SHARE_UNSUBSCRIBE_ERROR method."""
        share = self._create_share(subscribed=False)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareUnSubscribeError', lambda *a: d.callback(a))
        self.main.vm.unsubscribe_share(share.volume_id)

        info, error = yield d

        self.assertEqual(self.sd_obj._get_volume_info(share.volume_id), info)
        self.assertEqual('DOES_NOT_EXIST', error)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_CREATED(self):
        """Test the handle_VM_SHARE_CREATED method."""
        share = self._create_share(accepted=True)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'NewShare', d.callback)
        yield self.main.vm.add_share(share)

        info = yield d

        self.assertEqual(get_share_dict(share), info)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_DELETED(self):
        """Test the handle_VM_SHARE_DELETED method."""
        share = self._create_share(accepted=True)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'ShareDeleted', d.callback)
        self.main.event_q.push('VM_SHARE_DELETED', share=share)

        info = yield d

        self.assertEqual(get_share_dict(share), info)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_DELETE_ERROR(self):
        """Test the handle_VM_SHARE_DELETE_ERROR method."""
        share_id = 'share_id'
        error_msg = "I'm broken"
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares,
                   'ShareDeleteError', lambda *a: d.callback(a))
        self.main.event_q.push('VM_SHARE_DELETE_ERROR',
                               share_id=share_id, error=error_msg)

        info, error = yield d

        self.assertEqual(info['volume_id'], share_id)
        self.assertEqual(error, error_msg)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUMES_CHANGED(self):
        """Test the handle_VM_VOLUMES_CHANGED method."""
        share = self._create_share(accepted=True)
        udf = self._create_udf()
        volumes = [share, udf, self.main.vm.root]
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.sync_daemon, 'VolumesChanged',
                   d.callback)

        self.main.event_q.push('VM_VOLUMES_CHANGED', volumes=volumes)

        info = yield d

        str_volumes = sorted((get_share_dict(share), get_udf_dict(udf),
                              get_share_dict(self.main.vm.root)))
        self.assertEqual(str_volumes, sorted(info))

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETED_folder(self):
        """Test the handle_VM_VOLUME_DELETED method for a folder."""
        udf = self._create_udf()
        yield self.main.vm.add_udf(udf)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders, 'FolderDeleted', d.callback)
        self.main.event_q.push('VM_VOLUME_DELETED', volume=udf)

        info = yield d

        self.assertEqual(get_udf_dict(udf), info)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETED_share(self):
        """Test the handle_VM_VOLUME_DELETED method for a share."""
        share = self._create_share()
        yield self.main.vm.add_share(share)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'ShareDeleted', d.callback)
        self.main.event_q.push('VM_VOLUME_DELETED', volume=share)

        info = yield d

        self.assertEqual(get_share_dict(share), info)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETED_other(self):
        """Test the handle_VM_VOLUME_DELETED method for unknown volume."""
        volume = object()
        d = defer.Deferred()
        self.patch(interaction_interfaces.logger, 'error',
                   lambda *a: d.callback(a))
        self.main.event_q.push('VM_VOLUME_DELETED', volume=volume)

        msg, obj = yield d

        self.assertEqual(volume, obj)
        self.assertIn("Unable to handle VM_VOLUME_DELETED for volume", msg)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETE_ERROR_folder(self):
        """Test the handle_VM_VOLUME_DELETE_ERROR method for a folder."""
        error_msg = 'error test'
        udf = self._create_udf()
        yield self.main.vm.add_udf(udf)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.folders, 'FolderDeleteError',
                   lambda *a: d.callback(a))
        self.main.event_q.push('VM_VOLUME_DELETE_ERROR',
                               volume_id=udf.volume_id, error=error_msg)

        info, error = yield d

        udf = self.main.vm.get_volume(udf.volume_id)
        self.assertEqual(get_udf_dict(udf), info)
        self.assertEqual(error, error_msg)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETE_ERROR_share(self):
        """Test the handle_VM_VOLUME_DELETE_ERROR method for a share."""
        error_msg = 'error test'
        share = self._create_share()
        yield self.main.vm.add_share(share)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'ShareDeleteError',
                   lambda *a: d.callback(a))
        self.main.event_q.push('VM_VOLUME_DELETE_ERROR',
                               volume_id=share.volume_id, error=error_msg)

        info, error = yield d

        share = self.main.vm.get_volume(share.volume_id)
        self.assertEqual(get_share_dict(share), info)
        self.assertEqual(error, error_msg)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETE_ERROR_other(self):
        """Test the handle_VM_VOLUME_DELETE_ERROR method for unknown volume."""
        error_msg = 'error test'
        volume_id = 'test'
        volume = object()
        d = defer.Deferred()
        self.patch(self.main.vm, 'get_volume', lambda vid: volume)
        self.patch(interaction_interfaces.logger, 'error',
                   lambda *a: d.callback(a))
        self.main.event_q.push('VM_VOLUME_DELETE_ERROR',
                               volume_id=volume_id, error=error_msg)

        msg, err, obj = yield d

        self.assertEqual(volume_id, obj)
        self.assertEqual(error_msg, err)
        self.assertIn("Unable to handle VM_VOLUME_DELETE_ERROR (%r) "
                      "for volume_id=", msg)

    @defer.inlineCallbacks
    def test_handle_VM_VOLUME_DELETE_ERROR_key_error(self):
        """Test the handle_VM_VOLUME_DELETE_ERROR with VolumeDoesNotExist."""
        error_msg = 'error test'
        volume = 'foo'
        d = defer.Deferred()
        self.patch(interaction_interfaces.logger, 'error',
                   lambda *a: d.callback(a))
        self.main.event_q.push('VM_VOLUME_DELETE_ERROR',
                               volume_id=volume, error=error_msg)

        msg, obj = yield d

        self.assertEqual(volume, obj)
        self.assertIn("Unable to handle VM_VOLUME_DELETE_ERROR for volume_id",
                      msg)
        self.assertIn("no such volume", msg)

    @defer.inlineCallbacks
    def test_handle_VM_SHARE_CHANGED(self):
        """Test the handle_VM_SHARE_CHANGED method."""
        share = self._create_share(accepted=False)
        yield self.main.vm.add_share(share)
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.shares, 'ShareChanged', d.callback)
        self.main.event_q.push('VM_SHARE_CHANGED', share_id=share.volume_id)

        info = yield d

        self.assertEqual(get_share_dict(share), info)


class PublicFilesEventListenerTestCase(SyncdaemonEventListenerTestCase):
    """Test the public_files events in SyncdaemonEventListener."""

    @defer.inlineCallbacks
    def test_handle_AQ_CHANGE_PUBLIC_ACCESS_OK(self, share_id=None):
        """Test the handle_AQ_CHANGE_PUBLIC_ACCESS_OK method."""
        volume_id = request.ROOT if share_id is None else str(share_id)
        share = self._create_share(volume_id=volume_id)
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, "foo")
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        d = defer.Deferred()
        self.patch(self.sd_obj.interface.public_files,
                   'PublicAccessChanged', d.callback)

        node_id = share.node_id
        is_public = True
        public_url = 'http://example.com'
        self.event_q.push('AQ_CHANGE_PUBLIC_ACCESS_OK',
                          share_id=share_id, node_id=node_id,
                          is_public=is_public, public_url=public_url)

        info = yield d

        expected_dict = dict(share_id=volume_id, node_id=str(node_id),
                             is_public=bool_str(is_public),
                             public_url=public_url, path=path)
        self.assertEqual(expected_dict, info)

    @defer.inlineCallbacks
    def test_handle_AQ_CHANGE_PUBLIC_ACCESS_OK_share_id_not_none(self):
        """Test the handle_AQ_CHANGE_PUBLIC_ACCESS_OK method."""
        yield self.test_handle_AQ_CHANGE_PUBLIC_ACCESS_OK(share_id=12345678)

    @defer.inlineCallbacks
    def test_handle_AQ_CHANGE_PUBLIC_ACCESS_ERROR(self, share_id=None):
        """Test the handle_AQ_CHANGE_PUBLIC_ACCESS_ERROR method."""
        volume_id = request.ROOT if share_id is None else str(share_id)
        share = self._create_share(volume_id=volume_id)
        yield self.main.vm.add_share(share)
        path = os.path.join(share.path, "foo")
        self.main.fs.create(path, share.volume_id)
        self.main.fs.set_node_id(path, share.node_id)

        d = defer.Deferred()
        self.patch(self.sd_obj.interface.public_files,
                   'PublicAccessChangeError', lambda *a: d.callback(a))

        node_id = share.node_id
        error_msg = 'foo bar'
        self.event_q.push('AQ_CHANGE_PUBLIC_ACCESS_ERROR',
                          share_id=share_id, node_id=node_id, error=error_msg)

        info, error = yield d
        expected_dict = dict(share_id=volume_id, node_id=str(node_id),
                             path=path)
        self.assertEqual(expected_dict, info)
        self.assertEqual(error_msg, error)

    @defer.inlineCallbacks
    def test_handle_AQ_CHANGE_PUBLIC_ACCESS_ERROR_share_id_not_none(self):
        """Test the handle_AQ_CHANGE_PUBLIC_ACCESS_ERROR method."""
        yield self.test_handle_AQ_CHANGE_PUBLIC_ACCESS_ERROR(share_id=12345678)

    @defer.inlineCallbacks
    def test_handle_AQ_PUBLIC_FILES_LIST_OK(self):
        """Test the handle_AQ_PUBLIC_FILES_LIST_OK method."""
        udf = self._create_udf()
        yield self.main.vm.add_udf(udf)

        public_files = []
        expected = []
        for i in xrange(5):
            if i % 2:
                volume_id = udf.volume_id
                path = os.path.join(udf.path, "foo_%d" % i)
            else:
                volume_id = request.ROOT
                path = os.path.join(self.root_dir, "foo_%d" % i)

            node_id = 'node_id_%i' % i
            public_url = 'http://example.com/%d' % i
            self.main.fs.create(path, volume_id)
            self.main.fs.set_node_id(path, node_id)
            public_files.append(dict(volume_id=volume_id, node_id=node_id,
                                     public_url=public_url))
            expected.append(dict(volume_id=volume_id, node_id=node_id,
                                 public_url=public_url,
                                 path=path.decode('utf-8')))

        d = defer.Deferred()
        self.patch(self.sd_obj.interface.public_files,
                   'PublicFilesList', d.callback)
        self.main.event_q.push('AQ_PUBLIC_FILES_LIST_OK',
                               public_files=public_files)

        info = yield d

        self.assertEqual(len(public_files), len(info))
        self.assertEqual(expected, info)

    @defer.inlineCallbacks
    def test_handle_AQ_PUBLIC_FILES_LIST_ERROR(self):
        """Test the handle_AQ_PUBLIC_FILES_LIST_ERROR method."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.public_files,
                   'PublicFilesListError', d.callback)
        error_msg = 'error message'
        self.event_q.push('AQ_PUBLIC_FILES_LIST_ERROR', error=error_msg)

        error = yield d
        self.assertEqual(error_msg, error)


class SyncDaemonEventListenerTestCase(SyncdaemonEventListenerTestCase):
    """Test the sync_daemon events in SyncdaemonEventListener."""

    @defer.inlineCallbacks
    def test_handle_SYS_ROOT_MISMATCH(self):
        """Test the handle_SYS_ROOT_MISMATCH method."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.sync_daemon,
                   'RootMismatch', lambda *a: d.callback(a))
        self.main.vm._got_root('root_id')
        self.main.vm._got_root('another_root_id')

        root_id, new_root_id = yield d
        self.assertEqual('root_id', root_id)
        self.assertEqual('another_root_id', new_root_id)

    @defer.inlineCallbacks
    def assert_quota_exceeded(self, volume_id, expected_volume_dict):
        """Check correct signaling of QuotaExceeded."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.sync_daemon,
                   'QuotaExceeded', d.callback)
        self.event_q.push('SYS_QUOTA_EXCEEDED',
                          volume_id=volume_id, free_bytes=123)

        result = yield d

        # as we fix the free bytes with signal info, fix the expected dict
        expected_volume_dict['free_bytes'] = '123'
        self.assertEqual(expected_volume_dict, result)

    def test_handle_SYS_QUOTA_EXCEEDED_for_root(self):
        """Test the handle_SYS_QUOTA_EXCEEDED method."""
        root = self.main.vm.root
        return self.assert_quota_exceeded(root.volume_id, get_share_dict(root))

    @defer.inlineCallbacks
    def test_handle_SYS_QUOTA_EXCEEDED_for_share(self):
        """Test the handle_SYS_QUOTA_EXCEEDED method."""
        volume_id = 'test this please'
        share = self._create_share(volume_id=volume_id)
        yield self.main.vm.add_share(share)

        share = self.main.vm.get_volume(share.volume_id)
        yield self.assert_quota_exceeded(volume_id, get_share_dict(share))

    @defer.inlineCallbacks
    def test_handle_SYS_QUOTA_EXCEEDED_for_udf(self):
        volume_id = 'test this please'
        udf = self._create_udf(volume_id=volume_id)
        yield self.main.vm.add_udf(udf)

        udf = self.main.vm.get_volume(udf.volume_id)
        yield self.assert_quota_exceeded(volume_id, get_udf_dict(udf))


class RequestQueueEventListenerTestCase(SyncdaemonEventListenerTestCase):
    """Test the request queue events in SyncdaemonEventListener."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(RequestQueueEventListenerTestCase, self).setUp()
        self.called = []
        self.patch(self.sd_obj.interface.status, 'ContentQueueChanged',
                   lambda: self.called.append('ContentQueueChanged'))
        self.patch(self.sd_obj.interface.status, 'MetaQueueChanged',
                   lambda: self.called.append('MetaQueueChanged'))

    @defer.inlineCallbacks
    def test_handle_SYS_QUEUE_ADDED(self):
        """Test the handle_SYS_QUEUE_ADDED method."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'RequestQueueAdded', lambda *a: d.callback(a))
        cmd = FakeCommand('share', 'node', other=123)
        self.main.event_q.push('SYS_QUEUE_ADDED', command=cmd)

        op_name, op_id, data = yield d

        self.assertEqual(op_name, 'FakeCommand')
        self.assertEqual(op_id, str(id(cmd)))
        should = dict(share_id='share', node_id='node',
                      running='True', other='123')
        self.assertEqual(data, should)

        self.assertEqual(self.called, ['MetaQueueChanged'])

    @defer.inlineCallbacks
    def test_handle_SYS_QUEUE_ADDED_content_queue_changed_upload(self):
        """Test that handle_SYS_QUEUE_ADDED also calls ContentQueueChanged."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'RequestQueueAdded', lambda *a: d.callback(a))
        cmd = FakeUpload('share', 'node')
        self.main.event_q.push('SYS_QUEUE_ADDED', command=cmd)

        yield d

        self.assertEqual(self.called, ['ContentQueueChanged'])

    @defer.inlineCallbacks
    def test_handle_SYS_QUEUE_ADDED_content_queue_changed_download(self):
        """Test that handle_SYS_QUEUE_ADDED also calls ContentQueueChanged."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'RequestQueueAdded', lambda *a: d.callback(a))
        cmd = FakeDownload('share', 'node')
        self.main.event_q.push('SYS_QUEUE_ADDED', command=cmd)

        yield d

        self.assertEqual(self.called, ['ContentQueueChanged'])

    @defer.inlineCallbacks
    def test_handle_SYS_QUEUE_REMOVED(self):
        """Test the handle_SYS_QUEUE_REMOVED method."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'RequestQueueRemoved', lambda *a: d.callback(a))
        cmd = FakeCommand('share', 'node', other=MDMarker('foo'))
        self.main.event_q.push('SYS_QUEUE_REMOVED', command=cmd)

        op_name, op_id, data = yield d
        self.assertEqual(op_name, 'FakeCommand')
        self.assertEqual(op_id, str(id(cmd)))
        should = dict(share_id='share', node_id='node',
                      running='True', other='marker:foo')
        self.assertEqual(data, should)

        self.assertEqual(self.called, ['MetaQueueChanged'])

    @defer.inlineCallbacks
    def test_handle_SYS_QUEUE_REMOVED_content_queue_changed_upload(self):
        """Test handle_SYS_QUEUE_REMOVED also calls ContentQueueChanged."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'RequestQueueRemoved', lambda *a: d.callback(a))
        cmd = FakeUpload('share', 'node')
        self.main.event_q.push('SYS_QUEUE_REMOVED', command=cmd)

        yield d

        self.assertEqual(self.called, ['ContentQueueChanged'])

    @defer.inlineCallbacks
    def test_handle_SYS_QUEUE_REMOVED_content_queue_changed_download(self):
        """Test handle_SYS_QUEUE_REMOVED also calls ContentQueueChanged."""
        d = defer.Deferred()
        self.patch(self.sd_obj.interface.status,
                   'RequestQueueRemoved', lambda *a: d.callback(a))
        cmd = FakeDownload('share', 'node')
        self.main.event_q.push('SYS_QUEUE_REMOVED', command=cmd)

        yield d

        self.assertEqual(self.called, ['ContentQueueChanged'])


class SyncdaemonServiceTestCase(BaseTestCase):
    """Test the SyncdaemonService class."""

    sd_class = SyncdaemonService

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        self.patch(interaction_interfaces, 'NetworkManagerState',
                   FakeNetworkManagerState)
        yield super(SyncdaemonServiceTestCase, self).setUp()
        self.events = []
        self.sd_obj.main.event_q.push = lambda name, **kw: \
            self.events.append((name, kw))

    def test_disconnect(self):
        """Test the disconnect method."""
        self.sd_obj.disconnect()

        self.assertEqual(self.events, [('SYS_USER_DISCONNECT', {})])

    def test_get_homedir(self):
        """Test the get_homedir method."""
        result = self.sd_obj.get_homedir()
        self.assertEqual(self.main.get_homedir().decode('utf-8'), result)

    def test_get_rootdir(self):
        """Test the get_rootdir method."""
        result = self.sd_obj.get_rootdir()
        self.assertEqual(self.main.get_rootdir(), str(result))

    def test_get_sharesdir(self):
        """Test the get_sharesdir method."""
        result = self.sd_obj.get_sharesdir()
        self.assertEqual(self.main.get_sharesdir(), str(result))

    def test_get_sharesdir_link(self):
        """Test the get_sharesdir_link method."""
        result = self.sd_obj.get_sharesdir_link()
        self.assertEqual(self.main.get_sharesdir_link(), str(result))

    @defer.inlineCallbacks
    def test_wait_for_nirvana(self):
        """Test the wait_for_nirvana method."""
        self.patch(self.main, 'wait_for_nirvana', defer.succeed)
        last_event_interval = object()
        result = yield self.sd_obj.wait_for_nirvana(last_event_interval)

        self.assertEqual(result, last_event_interval)

    def test_quit(self):
        """Test the quit method."""
        self.patch(self.main, 'quit', self._set_called)
        self.sd_obj.quit()

        self.assertEqual(self._called, ((), {}))

    @defer.inlineCallbacks
    def test_rescan_from_scratch(self):
        """Test the rescan_from_scratch method."""
        share = self._create_share()
        yield self.main.vm.add_share(share)

        self.patch(self.main.action_q, 'rescan_from_scratch', self._set_called)
        self.sd_obj.rescan_from_scratch(share.volume_id)

        self.assertEqual(self._called, ((share.volume_id,), {}))

    def test_rescan_from_scratch_missing_volume(self):
        """Test for rescan_from_scratch with a non-existing volume."""
        volume_id = object()
        self.assertRaises(ValueError,
                          self.sd_obj.rescan_from_scratch, volume_id)

    def test_network_state_changed_with_connection(self):
        """Test the network_state changed method with a connection."""
        self.sd_obj.network_state_changed(ONLINE)

        self.assertEqual(self.events, [('SYS_NET_CONNECTED', {})])

    def test_network_state_changed_without_connection(self):
        """Test the network_state changed method without a connection."""
        # Sending anything instead of ONLINE should be interpreted as OFFLINE
        self.sd_obj.network_state_changed(object())

        self.assertEqual(self.events, [('SYS_NET_DISCONNECTED', {})])

    def test_network_connected(self):
        """Test the network_connected method."""
        self.sd_obj.network_connected()

        self.assertEqual(self.events, [('SYS_NET_CONNECTED', {})])

    def test_network_disconnected(self):
        """Test the network_disconnected method."""
        self.sd_obj.network_disconnected()

        self.assertEqual(self.events, [('SYS_NET_DISCONNECTED', {})])


class SyncdaemonServiceAllEventsTestCase(BaseTestCase):
    """Test the machinery to send absolutely all the events."""

    def test_not_active(self):
        """All event listener is not subscribed by default."""
        subscribed = []
        self.patch(self.main.event_q, 'subscribe',
                   lambda l: subscribed.append(l))
        obj = SyncdaemonService(self.main, send_events=False)

        # normal event listener is subscribed but not the all events one
        self.assertIn(obj.event_listener, subscribed)
        self.assertEqual(obj.all_events_sender, None)

    def test_active(self):
        """All event listener is subscribed if indicated."""
        subscribed = []
        self.patch(self.main.event_q, 'subscribe',
                   lambda l: subscribed.append(l))
        obj = SyncdaemonService(self.main, send_events=True)

        # both should be subscribed
        self.assertIn(obj.event_listener, subscribed)
        self.assertIn(obj.all_events_sender, subscribed)

    def test_events_are_sent(self):
        """Test that event information is sent to dbus."""
        obj = SyncdaemonService(self.main, send_events=True)

        # test with some method
        obj.all_events_sender.handle_default('FS_FILE_CREATE', path='x')
        expected = [((dict(event_name='FS_FILE_CREATE', path='x'),), {})]
        self.assertEqual(expected, obj.interface.events._called['Event'])


class SyncdaemonServiceConnectTestCase(BaseTestCase):
    """Tests the 'connect' method.

    Check conditions when autoconnecting is False.

    """

    sd_class = SyncdaemonService

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        self.patch(interaction_interfaces, 'NetworkManagerState',
                   FakeNetworkManagerState)
        yield super(SyncdaemonServiceConnectTestCase, self).setUp()

        self.events = []
        self.sd_obj.main.event_q.push = lambda name, **kw: \
            self.events.append((name, kw))

        self.memento = MementoHandler()
        logger.addHandler(self.memento)
        self.addCleanup(logger.removeHandler, self.memento)

    @defer.inlineCallbacks
    def test_connect_pushes_SYS_USER_CONNECT_with_token_when_autoconnect(self):
        """If autoconnecting is True, SYS_USER_CONNECT is pushed."""
        self.sd_obj.auth_credentials = FAKED_CREDENTIALS
        yield self.sd_obj.connect(autoconnecting=True)
        self.assertEqual(self.events, [('SYS_USER_CONNECT',
                                       {'access_token': FAKED_CREDENTIALS})])

    @defer.inlineCallbacks
    def test_connect_raises_exception_if_no_token_when_autoconnect(self):
        """If no credentials, NoAccessToken is raised."""
        self.sd_obj.auth_credentials = None
        yield self.assertFailure(
            self.sd_obj.connect(autoconnecting=True), NoAccessToken)

    def test_auth_credentials_are_none_at_startup(self):
        """If the auth_credentials are not passed as param, they are None."""
        self.assertTrue(self.sd_obj.auth_credentials is None)

    @defer.inlineCallbacks
    def test_auth_credentials_are_used_to_connect_when_autoconnect(self):
        """If present, the auth_credentials are used to connect."""
        expected = {'username': 'otheruser', 'password': 'otherpassword'}
        self.sd_obj.auth_credentials = expected
        yield self.sd_obj.connect(autoconnecting=True)
        self.assertEqual(self.events, [('SYS_USER_CONNECT',
                                       {'access_token': expected})])

    @defer.inlineCallbacks
    def test_connect_does_not_push_SYS_USER_CONNECT_no_autoconnect(self):
        """If autoconnecting is False, SYS_USER_CONNECT is not pushed."""
        self.sd_obj.auth_credentials = FAKED_CREDENTIALS
        assert self.events == [], self.events
        yield self.sd_obj.connect(autoconnecting=False)
        self.assertEqual(self.events, [])

    @defer.inlineCallbacks
    def test_connect_no_exception_if_no_token_and_no_autoconnect(self):
        """If no credentials, NoAccessToken is raised."""
        self.sd_obj.auth_credentials = None
        yield self.sd_obj.connect(autoconnecting=False)
