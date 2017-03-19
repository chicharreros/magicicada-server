# -*- coding: utf-8 -*-
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
"""Platform independent tests for the external interface classes."""

from twisted.internet import defer

from ubuntuone.platform.tests import (
    ConfigTestCase,
    EventsTestCase,
    FileSystemTestCase,
    FoldersTestCase,
    PublicFilesTestCase,
    SharesTestCase,
    StatusTestCase,
    SyncDaemonTestCase,
)
from ubuntuone.syncdaemon import (
    RECENT_TRANSFERS,
    UPLOADING,
)

STR = 'something'
STR_STR_DICT = {'foo': 'bar'}
STR_LST_DICT = [STR_STR_DICT]


class StatusTests(StatusTestCase):
    """Basic tests for the Status exposed object."""

    client_name = 'status'
    signal_mapping = [
        ('DownloadStarted', (STR,)),
        ('DownloadFileProgress', (STR, STR_STR_DICT)),
        ('DownloadFinished', (STR, STR_STR_DICT)),
        ('UploadStarted', (STR,)),
        ('UploadFileProgress', (STR, STR_STR_DICT)),
        ('UploadFinished', (STR, STR_STR_DICT)),
        ('InvalidName', (STR, STR)),
        ('BrokenNode', (STR, STR, STR, STR)),
        ('StatusChanged', (STR_STR_DICT,)),
        ('AccountChanged', (STR_STR_DICT,)),
        ('ContentQueueChanged', ()),
        ('MetaQueueChanged', ()),
        ('RequestQueueAdded', (STR, STR, STR_STR_DICT)),
        ('RequestQueueRemoved',  (STR, STR, STR_STR_DICT)),
    ]

    @defer.inlineCallbacks
    def test_current_status(self):
        """Test current_status."""
        result = dict(name='name', description='description',
                      is_error='', is_connected='True', is_online='')

        yield self.assert_method_called(self.service.status,
                                        'current_status', result)
        self.assert_remote_method('current_status', out_signature='a{ss}')

    @defer.inlineCallbacks
    def test_current_uploads(self):
        """Test current_uploads."""
        result = [{}, STR_STR_DICT]
        yield self.assert_method_called(self.service.status,
                                        'current_uploads', result)
        self.assert_remote_method(
            'current_uploads', in_signature=None, out_signature='aa{ss}')

    @defer.inlineCallbacks
    def test_current_downloads(self):
        """Test current_downloads."""
        result = [STR_STR_DICT, {}]
        yield self.assert_method_called(self.service.status,
                                        'current_downloads', result)
        self.assert_remote_method(
            'current_downloads', in_signature=None, out_signature='aa{ss}')

    @defer.inlineCallbacks
    def test_free_space(self):
        """Test free_space."""
        result = 963258741
        volume_id = '123-456-789'
        yield self.assert_method_called(self.service.status,
                                        'free_space', result, volume_id)
        self.assert_remote_method(
            'free_space', in_signature='s', out_signature='t')

    @defer.inlineCallbacks
    def test_waiting(self):
        """Test waiting."""
        result = [('foo', 'bar', {'command': 'test'})]
        yield self.assert_method_called(self.service.status,
                                        'waiting', result)
        self.assert_remote_method(
            'waiting', in_signature=None, out_signature='a(ssa{ss})')

    @defer.inlineCallbacks
    def test_waiting_metadata(self):
        """Test waiting_metadata. DEPRECATED."""
        result = []
        yield self.assert_method_called(self.service.status,
                                        'waiting_metadata', result)
        self.assert_remote_method(
            'waiting_metadata', in_signature=None, out_signature='a(sa{ss})')

    @defer.inlineCallbacks
    def test_waiting_content(self):
        """Test waiting_content. DEPRECATED."""
        result = []
        yield self.assert_method_called(self.service.status,
                                        'waiting_content', result)
        self.assert_remote_method(
            'waiting_metadata', in_signature=None, out_signature='a(sa{ss})')

    @defer.inlineCallbacks
    def test_sync_menu(self):
        """Test sync_menu."""
        result = {RECENT_TRANSFERS: [], UPLOADING: []}
        method = 'sync_menu'
        yield self.assert_method_called(self.service.status,
                                        method, result)
        self.assert_remote_method(
            method, in_signature=None, out_signature='a{sv}')


class EventsTests(EventsTestCase):
    """Basic tests for the Events exposed object."""

    client_name = 'events'
    signal_mapping = [('Event', (STR_STR_DICT,))]

    @defer.inlineCallbacks
    def test_push_event(self):
        """Test push_event."""
        result = None
        event_name = 'foo'
        event_args = {'param1': 'something'}
        yield self.assert_method_called(self.service.events,
                                        'push_event', result,
                                        event_name, event_args)
        self.assert_remote_method(
            'push_event', in_signature='sa{ss}', out_signature=None)


class SyncDaemonTests(SyncDaemonTestCase):
    """Basic tests for the SyncDaemon exposed object."""

    client_name = 'sync_daemon'
    signal_mapping = [
        ('RootMismatch', (STR, STR)),
        ('QuotaExceeded', (STR_STR_DICT,)),
        ('VolumesChanged', (STR_LST_DICT,)),
    ]

    @defer.inlineCallbacks
    def test_connect(self):
        """Test connect."""
        result = None
        yield self.assert_method_called(self.service.sync,
                                        'connect', result)
        self.assert_remote_method('connect')

    @defer.inlineCallbacks
    def test_disconnect(self):
        """Test disconnect."""
        result = None
        yield self.assert_method_called(self.service.sync,
                                        'disconnect', result)
        self.assert_remote_method('disconnect')

    @defer.inlineCallbacks
    def test_get_homedir(self):
        """Test get_homedir."""
        result = self.root_dir
        yield self.assert_method_called(self.service.sync,
                                        'get_homedir', result)
        self.assert_remote_method('get_homedir', out_signature='s')

    @defer.inlineCallbacks
    def test_get_rootdir(self):
        """Test get_rootdir."""
        result = self.root_dir
        yield self.assert_method_called(self.service.sync,
                                        'get_rootdir', result)
        self.assert_remote_method('get_rootdir', out_signature='s')

    @defer.inlineCallbacks
    def test_get_sharesdir(self):
        """Test get_sharesdir."""
        result = self.shares_dir
        yield self.assert_method_called(self.service.sync,
                                        'get_sharesdir', result)
        self.assert_remote_method('get_sharesdir', out_signature='s')

    @defer.inlineCallbacks
    def test_get_sharesdir_link(self):
        """Test get_sharesdir_link."""
        result = 'foo/bar/baz'
        yield self.assert_method_called(self.service.sync,
                                        'get_sharesdir_link', result)
        self.assert_remote_method('get_sharesdir_link', out_signature='s')

    @defer.inlineCallbacks
    def test_wait_for_nirvana(self):
        """Test wait_for_nirvana."""
        result = defer.succeed(True)
        last_event_interval = 4567
        yield self.assert_method_called(self.service.sync,
                                        'wait_for_nirvana', result,
                                        last_event_interval)
        async_cb = ('reply_handler', 'error_handler')
        self.assert_remote_method(
            'wait_for_nirvana', in_signature='d', out_signature='b',
            async_callbacks=async_cb)

    @defer.inlineCallbacks
    def test_quit(self):
        """Test quit."""
        result = defer.succeed(None)
        yield self.assert_method_called(self.service.sync,
                                        'quit', result)
        async_cb = ('reply_handler', 'error_handler')
        self.assert_remote_method('quit', async_callbacks=async_cb)

    @defer.inlineCallbacks
    def test_rescan_from_scratch(self):
        """Test rescan_from_scratch."""
        result = None
        volume_id = '963-852-741'
        yield self.assert_method_called(self.service.sync,
                                        'rescan_from_scratch', result,
                                        volume_id)
        self.assert_remote_method(
            'rescan_from_scratch', in_signature='s', out_signature='')


class FileSystemTests(FileSystemTestCase):
    """Basic tests for the FileSystem exposed object."""

    client_name = 'file_system'
    signal_mapping = []

    @defer.inlineCallbacks
    def test_get_metadata(self):
        """Test get_metadata."""
        result = {'node_id': 'test'}
        path = 'foo/bar'
        yield self.assert_method_called(self.service.file_system,
                                        'get_metadata', result,
                                        path)
        self.assert_remote_method(
            'get_metadata', in_signature='s', out_signature='a{ss}')

    @defer.inlineCallbacks
    def test_search_files(self):
        """Test get_metadata."""
        result = ['path']
        yield self.assert_method_called(self.service.file_system,
                                        'search_files', result, 'file')
        self.assert_remote_method(
            'search_files', in_signature='s', out_signature='as')

    @defer.inlineCallbacks
    def test_get_metadata_by_node(self):
        """Test get_metadata_by_node."""
        result = {'node_id': 'test'}
        share_id = node_id = '1234-9876'
        yield self.assert_method_called(self.service.file_system,
                                        'get_metadata_by_node', result,
                                        share_id, node_id)
        self.assert_remote_method(
            'get_metadata_by_node', in_signature='ss', out_signature='a{ss}')

    @defer.inlineCallbacks
    def test_get_metadata_and_quick_tree_synced(self):
        """Test get_metadata_and_quick_tree_synced."""
        result = {'node_id': 'test'}
        path = 'foo/bar'
        yield self.assert_method_called(self.service.file_system,
                                        'get_metadata_and_quick_tree_synced',
                                        result, path)
        self.assert_remote_method(
            'get_metadata_and_quick_tree_synced',
            in_signature='s', out_signature='a{ss}')

    @defer.inlineCallbacks
    def test_get_dirty_nodes(self):
        """Test get_dirty_nodes."""
        result = [{'node_id': 'test'}, {'node_id': 'toast'}]
        yield self.assert_method_called(self.service.file_system,
                                        'get_dirty_nodes', result)
        self.assert_remote_method(
            'get_dirty_nodes', in_signature='', out_signature='aa{ss}')


class SharesTests(SharesTestCase):
    """Basic tests for the Shares exposed object."""

    client_name = 'shares'
    signal_mapping = [
        ('ShareChanged', (STR_STR_DICT,)),
        ('ShareDeleted', (STR_STR_DICT,)),
        ('ShareDeleteError', (STR_STR_DICT, STR)),
        ('ShareCreated', (STR_STR_DICT,)),
        ('ShareCreateError', (STR_STR_DICT, STR)),
        ('ShareAnswerResponse', (STR_STR_DICT,)),
        ('NewShare', (STR_STR_DICT,)),
        ('ShareSubscribed', (STR_STR_DICT,)),
        ('ShareSubscribeError', (STR_STR_DICT, STR)),
        ('ShareUnSubscribed', (STR_STR_DICT,)),
        ('ShareUnSubscribeError', (STR_STR_DICT, STR)),
    ]

    @defer.inlineCallbacks
    def test_get_shares(self):
        """Test get_shares."""
        result = [{'share_id': '1'}, {'share_id': '2'}]
        yield self.assert_method_called(self.service.shares,
                                        'get_shares', result)
        self.assert_remote_method('get_shares', out_signature='aa{ss}')

    @defer.inlineCallbacks
    def test_accept_share(self):
        """Test accept_share."""
        result = None
        share_id = '1234'
        yield self.assert_method_called(self.service.shares,
                                        'accept_share', result, share_id)
        self.assert_remote_method('accept_share', in_signature='s')

    @defer.inlineCallbacks
    def test_reject_share(self):
        """Test reject_share."""
        result = None
        share_id = '1234'
        yield self.assert_method_called(self.service.shares,
                                        'reject_share', result, share_id)
        self.assert_remote_method('reject_share', in_signature='s')

    @defer.inlineCallbacks
    def test_delete_share(self):
        """Test delete_share."""
        result = None
        share_id = '1234'
        yield self.assert_method_called(self.service.shares,
                                        'delete_share', result, share_id)
        self.assert_remote_method('delete_share', in_signature='s')

    @defer.inlineCallbacks
    def test_subscribe(self):
        """Test subscribe."""
        result = None
        share_id = '1234'
        yield self.assert_method_called(self.service.shares,
                                        'subscribe', result, share_id)
        self.assert_remote_method(
            'subscribe', in_signature='s', out_signature=None)

    @defer.inlineCallbacks
    def test_unsubscribe(self):
        """Test unsubscribe."""
        result = None
        share_id = '1234'
        yield self.assert_method_called(self.service.shares,
                                        'unsubscribe', result, share_id)
        self.assert_remote_method(
            'unsubscribe', in_signature='s', out_signature=None)

    @defer.inlineCallbacks
    def test_create_share(self):
        """Test create_share."""
        result = None
        path = username = name = access_level = 'foo'
        yield self.assert_method_called(self.service.shares,
                                        'create_share', result,
                                        path, username, name, access_level)
        self.assert_remote_method('create_share', in_signature='ssss')

    @defer.inlineCallbacks
    def test_create_shares(self):
        """Test create_shares."""
        client = yield self.get_client()

        method = 'create_share'
        result = None
        self.patch(self.service.shares, method, lambda *a, **kw: result)

        path = 'path'
        usernames = ['pepe', 'pepito']
        name = 'name'
        access_level = 'access_level'
        actual = yield client.call_method('create_shares',
                                          path, usernames, name, access_level)
        self.assertEqual(result, actual)

        expected = [(('path', 'pepe', 'name', 'access_level',), {}),
                    (('path', 'pepito', 'name', 'access_level',), {})]
        self.assertEqual(self.service.shares._called, {method: expected})

        self.assert_remote_method('create_shares', in_signature='sasss')

    @defer.inlineCallbacks
    def test_refresh_shares(self):
        """Test refresh_shares."""
        result = None
        yield self.assert_method_called(self.service.shares,
                                        'refresh_shares', result)
        self.assert_remote_method('refresh_shares')

    @defer.inlineCallbacks
    def test_get_shared(self):
        """Test get_shared."""
        result = [{'share_id': '1'}, {'share_id': '2'}]
        yield self.assert_method_called(self.service.shares,
                                        'get_shared', result)
        self.assert_remote_method('get_shared', out_signature='aa{ss}')


class ConfigTests(ConfigTestCase):
    """Basic tests for the Config object exposed via IPC."""

    setting_name = 'files_sync'
    client_name = 'config'
    signal_mapping = []

    @defer.inlineCallbacks
    def test_enabled(self):
        """Test <setting>_enabled exposed method."""
        method = '%s_enabled' % self.setting_name
        result = False
        yield self.assert_method_called(self.service.config,
                                        method, result)
        self.assert_remote_method(method, out_signature='b')

    @defer.inlineCallbacks
    def test_disabled(self):
        """Test <setting>_enabled exposed method."""
        method = '%s_enabled' % self.setting_name
        result = True
        yield self.assert_method_called(self.service.config,
                                        method, result)
        self.assert_remote_method(method, out_signature='b')

    @defer.inlineCallbacks
    def test_enable(self):
        """Test the enable_<setting> exposed method."""
        method = 'enable_%s' % self.setting_name
        result = None
        yield self.assert_method_called(self.service.config,
                                        method, result)
        self.assert_remote_method(method)

    @defer.inlineCallbacks
    def test_disable(self):
        """Test disable_<setting> exposed method."""
        method = 'disable_%s' % self.setting_name
        result = None
        yield self.assert_method_called(self.service.config,
                                        method, result)
        self.assert_remote_method(method)


class ThrottlingConfigTests(ConfigTests):
    """Basic tests for the bandwith_enabled setting."""

    setting_name = 'bandwidth_throttling'

    @defer.inlineCallbacks
    def test_get_throttling_limits_unset(self):
        """Test get_throttling_limits exposed method."""
        result = dict(download=-1, upload=-1)
        yield self.assert_method_called(self.service.config,
                                        'get_throttling_limits', result)

    @defer.inlineCallbacks
    def test_get_throttling_limits_set(self):
        """Test get_throttling_limits exposed method."""
        result = dict(download=100, upload=200)
        yield self.assert_method_called(self.service.config,
                                        'get_throttling_limits', result)

    @defer.inlineCallbacks
    def test_set_throttling_limits(self):
        """Test set_throttling_limits exposed method."""
        result = None
        upload = 100
        download = 500
        yield self.assert_method_called(self.service.config,
                                        'set_throttling_limits', result,
                                        upload, download)


class UDFAutosubscribeConfigTests(ConfigTests):
    """Basic tests for the udf_autosubscribe setting."""

    setting_name = 'udf_autosubscribe'


class ShareAutosubscribeConfigTests(ConfigTests):
    """Basic tests for the share_autosubscribe setting."""

    setting_name = 'share_autosubscribe'


class AutoconnectConfigTests(ConfigTests):
    """Basic tests for the autoconnect setting."""

    setting_name = 'autoconnect'

    @defer.inlineCallbacks
    def test_set_autoconnect_enabled(self):
        """Test for Config.set_autoconnect_enabled.

        DEPRECATED.

        """
        client = yield self.get_client()

        yield client.call_method('set_autoconnect_enabled', True)
        called = self.service.config._called['enable_autoconnect']
        self.assertEqual(called, [((), {})])

        yield client.call_method('set_autoconnect_enabled', False)
        called = self.service.config._called['disable_autoconnect']
        self.assertEqual(called, [((), {})])


class FoldersTests(FoldersTestCase):
    """Tests for the Folder object."""

    client_name = 'folders'
    signal_mapping = [
        ('FolderCreated', (STR_STR_DICT,)),
        ('FolderCreateError', (STR_STR_DICT, STR)),
        ('FolderDeleted', (STR_STR_DICT,)),
        ('FolderDeleteError', (STR_STR_DICT, STR)),
        ('FolderSubscribed', (STR_STR_DICT,)),
        ('FolderSubscribeError', (STR_STR_DICT, STR)),
        ('FolderUnSubscribed', (STR_STR_DICT,)),
        ('FolderUnSubscribeError', (STR_STR_DICT, STR)),
    ]

    @defer.inlineCallbacks
    def test_create(self):
        """Test create."""
        result = None
        path = 'foo'
        yield self.assert_method_called(self.service.folders,
                                        'create', result, path)
        self.assert_remote_method(
            'create', in_signature='s', out_signature=None)

    @defer.inlineCallbacks
    def test_delete(self):
        """Test delete."""
        result = None
        folder_id = '1234'
        yield self.assert_method_called(self.service.folders,
                                        'delete', result, folder_id)
        self.assert_remote_method(
            'delete', in_signature='s', out_signature=None)

    @defer.inlineCallbacks
    def test_validate_path(self):
        """Test validate_path."""
        result = False
        path = 'test'
        yield self.assert_method_called(self.service.folders,
                                        'validate_path', result, path)
        self.assert_remote_method(
            'validate_path', in_signature='s', out_signature='b')

    @defer.inlineCallbacks
    def test_get_folders(self):
        """Test get_folders."""
        result = [{'folder_id': '1'}, {'folder_id': '2'}]
        yield self.assert_method_called(self.service.folders,
                                        'get_folders', result)
        self.assert_remote_method(
            'get_folders', in_signature=None, out_signature='aa{ss}')

    @defer.inlineCallbacks
    def test_subscribe(self):
        """Test subscribe."""
        result = None
        folder_id = '1234'
        yield self.assert_method_called(self.service.folders,
                                        'subscribe', result, folder_id)
        self.assert_remote_method('subscribe', in_signature='s')

    @defer.inlineCallbacks
    def test_unsubscribe(self):
        """Test unsubscribe."""
        result = None
        folder_id = '1234'
        yield self.assert_method_called(self.service.folders,
                                        'unsubscribe', result, folder_id)
        self.assert_remote_method('unsubscribe', in_signature='s')

    @defer.inlineCallbacks
    def test_get_info(self):
        """Test get_info."""
        result = {'folder_id': '1'}
        path = 'yadda'
        yield self.assert_method_called(self.service.folders,
                                        'get_info', result, path)
        self.assert_remote_method(
            'get_info', in_signature='s', out_signature='a{ss}')

    @defer.inlineCallbacks
    def test_refresh_volumes(self):
        """Test refresh_volumes."""
        result = None
        yield self.assert_method_called(self.service.folders,
                                        'refresh_volumes', result)
        self.assert_remote_method('refresh_volumes')


class PublicFilesTests(PublicFilesTestCase):
    """Basic tests for the FileSystem exposed object."""

    client_name = 'public_files'
    signal_mapping = [
        ('PublicAccessChanged', (STR_STR_DICT,)),
        ('PublicAccessChangeError', (STR_STR_DICT, STR)),
        ('PublicFilesList', ([STR_STR_DICT, STR_STR_DICT],)),
        ('PublicFilesListError', (STR,)),
    ]

    @defer.inlineCallbacks
    def test_change_public_access(self):
        """Test change_public_access."""
        result = None
        share_id = node_id = 'blah'
        is_public = False
        yield self.assert_method_called(self.service.public_files,
                                        'change_public_access', result,
                                        share_id, node_id, is_public)
        self.assert_remote_method('change_public_access', in_signature='ssb')

    @defer.inlineCallbacks
    def test_get_public_files(self):
        """Test get_public_files."""
        result = None
        yield self.assert_method_called(self.service.public_files,
                                        'get_public_files', result)
        self.assert_remote_method(
            'get_public_files', in_signature=None, out_signature=None)
