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
"""Client lib to simplify the ipc client code."""

import logging

from functools import wraps
from twisted.internet import defer
from twisted.spread.pb import Referenceable, PBClientFactory

from ubuntuone.platform.ipc.perspective_broker import (
    RemoteMeta,
    ipc_client_connect,
)

logger = logging.getLogger("ubuntuone.SyncDaemon.Client")


class SyncDaemonClientError(Exception):
    """Error ocurred when trying to be a client."""


class SyncDaemonClientConnectionError(SyncDaemonClientError):
    """Error ocurrend when trying to connect."""


def remote(function):
    """Decorate the function to make the remote call."""

    @wraps(function)
    def remote_wrapper(self, *args, **kwargs):
        """Return the deferred for the remote call."""
        fname = function.__name__
        logger.debug('Performing %s as a remote call (%r, %r).',
                     fname, args, kwargs)
        return self.remote.callRemote(fname, *args, **kwargs)

    return remote_wrapper


def signal(function):
    """Decorate a function to perform the signal callback."""

    @wraps(function)
    def callback_wrapper(self, *args, **kwargs):
        """Return the result of the callback if present."""
        fname = function.__name__
        function(self, *args, **kwargs)
        callback = getattr(self, fname + '_cb', None)
        if callback is not None:
            return callback(*args, **kwargs)

    return callback_wrapper


class RemoteClient(object):
    """Represent a client for remote calls."""

    signal_handlers = []

    def __init__(self, remote_object):
        """Create instance."""
        self.remote = remote_object

    def register_to_signals(self):
        """Register to the signals."""
        return self.remote.callRemote('register_to_signals', self,
                                      self.signal_handlers)

    def unregister_to_signals(self):
        """Register to the signals."""
        return self.remote.callRemote('unregister_to_signals', self)


class RemoteHandler(object, Referenceable):
    """A handler that can be called so that is called remotely."""

    def __init__(self, cb):
        """Create a new instance."""
        self.cb = cb

    def remote_execute(self):
        """Execute the callback."""
        if self.cb:
            self.cb()


def callbacks(callbacks_indexes=None, callbacks_names=None):
    """Ensure that the callbacks can be remotely called."""
    def decorator(function):
        """Decorate the function to make sure the callbacks can be executed."""
        @wraps(function)
        def callbacks_wrapper(*args, **kwargs):
            """Set the paths to be absolute."""
            fixed_args = list(args)
            if callbacks_indexes:
                for current_cb in callbacks_indexes:
                    fixed_args[current_cb] = RemoteHandler(args[current_cb])
                fixed_args = tuple(fixed_args)
            if callbacks_names:
                for current_key, current_index in callbacks_names:
                    try:
                        kwargs[current_key] = RemoteHandler(
                            kwargs[current_key])
                    except KeyError:
                        if len(args) >= current_index + 1:
                            fixed_args[current_index] = RemoteHandler(
                                args[current_index])
            fixed_args = tuple(fixed_args)
            return function(*fixed_args, **kwargs)
        return callbacks_wrapper
    return decorator


class StatusClient(RemoteClient, Referenceable):
    """Client used to access the status of the daemon."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    signal_handlers = [
        'on_content_queue_changed',
        'on_invalid_name',
        'on_broken_node',
        'on_status_changed',
        'on_download_started',
        'on_download_file_progress',
        'on_download_finished',
        'on_upload_started',
        'on_upload_file_progress',
        'on_upload_finished',
        'on_account_changed',
        'on_metaqueue_changed',
    ]

    @remote
    def current_status(self):
        """Return the current status of the system.

        The status can be one of: local_rescan,
        offline, trying_to_connect, server_rescan or online.
        """

    @remote
    def current_downloads(self):
        """Return a list of files with a download in progress."""

    @remote
    def free_space(self, vol_id):
        """Return the free space for the given volume."""

    @remote
    def waiting(self):
        """Return a list of the operations in action queue."""

    @remote
    def waiting_metadata(self):
        """Return a list of the operations in the meta-queue.

        As we don't have meta-queue anymore, this is faked.
        """

    @remote
    def waiting_content(self):
        """Return a list of files that are waiting to be up- or downloaded.

        As we don't have content-queue anymore, this is faked.
        """

    @remote
    def current_uploads(self):
        """Return a list of files with a upload in progress."""

    @remote
    def sync_menu(self):
        """
        This method returns a dictionary, with the following keys and values:

        Key: 'recent-transfers'
        Value: a list of strings (paths), each being the name of a file that
               was recently transferred.

        Key: 'uploading'
        Value: a list of tuples, with each tuple having the following items:
         * str: the path of a file that's currently being uploaded
         * int: size of the file
         * int: bytes written
        """

    @signal
    def on_content_queue_changed(self):
        """Emit ContentQueueChanged."""

    @signal
    def on_invalid_name(self, dirname, filename):
        """Emit InvalidName."""

    @signal
    def on_broken_node(self, volume_id, node_id, mdid, path):
        """Emit BrokenNode."""

    @signal
    def on_status_changed(self, state):
        """Emit StatusChanged."""

    @signal
    def on_download_started(self, download):
        """Emit DownloadStarted."""

    @signal
    def on_download_file_progress(self, download, info):
        """Emit DownloadFileProgress."""

    @signal
    def on_download_finished(self, download, info):
        """Emit DownloadFinished."""

    @signal
    def on_upload_started(self, upload):
        """Emit UploadStarted."""

    @signal
    def on_upload_file_progress(self, upload, info):
        """Emit UploadFileProgress."""

    @signal
    def on_upload_finished(self, upload, info):
        """Emit UploadFinished."""

    @signal
    def on_account_changed(self, account_info):
        """Emit AccountChanged."""

    @signal
    def on_metaqueue_changed(self):
        """Emit MetaQueueChanged."""

    @signal
    def on_request_queue_added(self, op_name, op_id, data):
        """Emit RequestQueueAdded."""

    @signal
    def on_request_queue_removed(self, op_name, op_id, data):
        """Emit RequestQueueRemoved."""


class EventsClient(RemoteClient, Referenceable):
    """Client use to access the status api."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    signal_handlers = ['on_event']

    @remote
    def push_event(self, event_name, args):
        """Push an event to the event queue."""

    @signal
    def on_event(self, event):
        """Emit on event."""


class SyncDaemonClient(RemoteClient, Referenceable):
    """The Daemon ipc interface client."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    signal_handlers = [
        'on_root_mismatch',
        'on_quota_exceeded',
        'on_volumes_changed',
    ]

    @remote
    def connect(self):
        """Connect to the server."""

    @remote
    def disconnect(self):
        """Disconnect from the server."""

    @remote
    def get_homedir(self):
        """Return the home dir/mount point."""

    @remote
    def get_rootdir(self):
        """Return the root dir/mount point."""

    @remote
    def get_sharesdir(self):
        """Return the shares dir/mount point."""

    @remote
    def get_sharesdir_link(self):
        """Return the shares dir/mount point. """

    @callbacks(callbacks_names=[('reply_handler', 2), ('error_handler', 3)])
    @remote
    def wait_for_nirvana(self, last_event_interval,
                         reply_handler=None, error_handler=None):
        """Call the reply handler when there are no more events/transfers."""

    @remote
    def quit(self, reply_handler=None, error_handler=None):
        """Shutdown the syncdaemon."""

    @remote
    def rescan_from_scratch(self, volume_id):
        """Request a rescan from scratch of the volume with volume_id."""

    @signal
    def on_root_mismatch(self, root_id, new_root_id):
        """Emit RootMismatch signal."""

    @signal
    def on_quota_exceeded(self, volume_dict):
        """Emit QuotaExceeded signal."""

    @signal
    def on_volumes_changed(self, volumes):
        """Emit VolumesChanged signal."""


class FileSystemClient(RemoteClient):
    """An ipc interface to the FileSystem Manager."""

    @remote
    def get_metadata(self, path):
        """Return the metadata (as a dict) for the specified path."""

    @remote
    def get_metadata_by_node(self, share_id, node_id):
        """Return the metadata (as a dict) for the specified share/node."""

    @remote
    def get_metadata_and_quick_tree_synced(self, path):
        """Return the dict with the attributes of the metadata for the path."""

    @remote
    def get_dirty_nodes(self):
        """Rerturn a list of dirty nodes."""

    @remote
    def search_files(self, pattern):
        """Returns a list of the files that matches this pattern."""


class SharesClient(RemoteClient, Referenceable):
    """A ipc interface to interact with shares."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    signal_handlers = [
        'on_share_deleted',
        'on_share_changed',
        'on_share_delete_error',
        'on_share_created',
        'on_share_create_error',
        'on_share_answer_response',
        'on_new_share',
        'on_share_subscribed',
        'on_share_subscribe_error',
        'on_share_unsubscribed',
        'on_share_unsubscribe_error',
    ]

    @remote
    def get_shares(self):
        """Return a list of dicts, each dict represents a share."""

    @remote
    def accept_share(self, share_id, reply_handler=None, error_handler=None):
        """Accept a share.

        A ShareAnswerOk|Error signal will be fired in the future as a
        success/failure indicator.

        """

    @remote
    def reject_share(self, share_id, reply_handler=None, error_handler=None):
        """Reject a share."""

    @remote
    def delete_share(self, share_id):
        """Delete a Share, both kinds: "to me" and "from me"."""

    @remote
    def subscribe(self, share_id):
        """Subscribe to the specified share."""

    @remote
    def unsubscribe(self, share_id):
        """Unsubscribe from the specified share."""

    @remote
    def create_share(self, path, username, name, access_level):
        """Share a subtree to the user identified by username.

        @param path: that path to share (the root of the subtree)
        @param username: the username to offer the share to
        @param name: the name of the share
        @param access_level: 'View' or 'Modify'
        """

    @remote
    def create_shares(self, path, usernames, name, access_level):
        """Share a subtree with several users at once.

        @param path: that path to share (the root of the subtree)
        @param usernames: the user names to offer the share to
        @param name: the name of the share
        @param access_level: 'View' or 'Modify'
        """

    @remote
    def refresh_shares(self):
        """Refresh the share list, requesting it to the server."""

    @remote
    def get_shared(self):
        """Return a list of dicts, each dict represents a shared share.

        A share might not have the path set, as we might be still fetching the
        nodes from the server. In this cases the path is ''
        """

    @signal
    def on_share_deleted(self, share_dict):
        """Emit ShareDeleted."""

    @signal
    def on_share_changed(self, share_dict):
        """Emit ShareChanged."""

    @signal
    def on_share_delete_error(self, share, error):
        """Emit ShareDeleteError signal."""

    @signal
    def on_share_created(self, share_info):
        """Emit ShareCreated signal."""

    @signal
    def on_share_create_error(self, share_info, error):
        """Emit ShareCreateError signal."""

    @signal
    def on_share_answer_response(self, answer_info):
        """Emit ShareAnswerResponse signal."""

    @signal
    def on_new_share(self, share):
        """Emit NewShare signal."""

    @signal
    def on_share_subscribed(self, share):
        """Emit the ShareSubscribed signal."""

    @signal
    def on_share_subscribe_error(self, share_id, error):
        """Emit the ShareSubscribeError signal."""

    @signal
    def on_share_unsubscribed(self, share):
        """Emit the ShareUnSubscribed signal."""

    @signal
    def on_share_unsubscribe_error(self, share_id, error):
        """Emit the ShareUnSubscribeError signal."""


class ConfigClient(RemoteClient):
    """The Syncdaemon config/settings ipc interface. """

    @remote
    def get_throttling_limits(self, reply_handler=None, error_handler=None):
        """Get the read/write limit from AQ and return a dict.

        Return a dict(download=int, upload=int), if int is -1 the value isn't
        configured.
        The values are bytes/second.
        """

    @remote
    def set_throttling_limits(self, download, upload):
        """Set the read and write limits. The expected values are bytes/sec."""

    @remote
    def enable_bandwidth_throttling(self):
        """Enable bandwidth throttling."""

    @remote
    def disable_bandwidth_throttling(self):
        """Disable bandwidth throttling."""

    @remote
    def bandwidth_throttling_enabled(self):
        """Return if the bandwidth throttling is enabled."""

    @remote
    def udf_autosubscribe_enabled(self):
        """Return the udf_autosubscribe config value."""

    @remote
    def enable_udf_autosubscribe(self):
        """Enable UDF autosubscribe."""

    @remote
    def disable_udf_autosubscribe(self):
        """Enable UDF autosubscribe."""

    @remote
    def share_autosubscribe_enabled(self):
        """Return the share_autosubscribe config value."""

    @remote
    def enable_share_autosubscribe(self):
        """Enable UDF autosubscribe."""

    @remote
    def disable_share_autosubscribe(self):
        """Enable UDF autosubscribe."""

    @remote
    def set_files_sync_enabled(self, enabled):
        """Enable/disable file sync service.

        DEPRECATED.

        """

    @remote
    def files_sync_enabled(self):
        """Return the files_sync_enabled config value."""

    @remote
    def enable_files_sync(self):
        """Enable the file sync service."""

    @remote
    def disable_files_sync(self):
        """Disable the file sync service."""

    @remote
    def autoconnect_enabled(self):
        """Return the autoconnect config value."""

    @remote
    def enable_autoconnect(self):
        """Enable the autoconnect config value."""

    @remote
    def disable_autoconnect(self):
        """Disable the autoconnect config value."""

    @remote
    def set_autoconnect_enabled(self, enabled):
        """Enable syncdaemon autoconnect.

        DEPRECATED.
        """


class FoldersClient(RemoteClient, Referenceable):
    """An interface to interact with User Defined Folders"""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    signal_handlers = [
        'on_folder_created',
        'on_folder_create_error',
        'on_folder_deleted',
        'on_folder_delete_error',
        'on_folder_subscribed',
        'on_folder_subscribe_error',
        'on_folder_unsubscribed',
        'on_folder_unsubscribe_error',
    ]

    @remote
    def create(self, path):
        """Create a user defined folder in the specified path."""

    @remote
    def delete(self, folder_id):
        """Delete the folder specified by folder_id"""

    @remote
    def validate_path(self, path):
        """Return True if the path is valid for a folder"""

    @remote
    def get_folders(self):
        """Return the list of folders (a list of dicts)"""

    @remote
    def subscribe(self, folder_id):
        """Subscribe to the specified folder"""

    @remote
    def unsubscribe(self, folder_id):
        """Unsubscribe from the specified folder"""

    @remote
    def get_info(self, path):
        """Return a dict containing the folder information."""

    @remote
    def refresh_volumes(self):
        """Refresh the volumes list, requesting it to the server."""

    @signal
    def on_folder_created(self, folder):
        """Emit the FolderCreated signal"""

    @signal
    def on_folder_create_error(self, path, error):
        """Emit the FolderCreateError signal"""

    @signal
    def on_folder_deleted(self, folder):
        """Emit the FolderCreated signal"""

    @signal
    def on_folder_delete_error(self, folder, error):
        """Emit the FolderCreateError signal"""

    @signal
    def on_folder_subscribed(self, folder):
        """Emit the FolderSubscribed signal"""

    @signal
    def on_folder_subscribe_error(self, folder_id, error):
        """Emit the FolderSubscribeError signal"""

    @signal
    def on_folder_unsubscribed(self, folder):
        """Emit the FolderUnSubscribed signal"""

    @signal
    def on_folder_unsubscribe_error(self, folder_id, error):
        """Emit the FolderUnSubscribeError signal"""


class PublicFilesClient(RemoteClient, Referenceable):
    """An IPC interface for handling public files."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    signal_handlers = [
        'on_public_access_changed',
        'on_public_access_change_error',
        'on_public_files_list',
        'on_public_files_list_error',
    ]

    @remote
    def change_public_access(self, share_id, node_id, is_public):
        """Change the public access of a file."""

    @remote
    def get_public_files(self):
        """Request the list of public files to the server.

        The result will be send in a PublicFilesList signal.
        """

    @signal
    def on_public_access_changed(self, file_info):
        """Emit the PublicAccessChanged signal."""

    @signal
    def on_public_access_change_error(self, file_info, error):
        """Emit the PublicAccessChangeError signal."""

    @signal
    def on_public_files_list(self, public_files):
        """Emit the PublicFilesList signal."""

    @signal
    def on_public_files_list_error(self, error):
        """Emit the PublicFilesListError signal."""


class UbuntuOneClient(object):
    """Root object that provides access to all the remote objects."""

    connection_lock = defer.DeferredLock()

    def __init__(self):
        """Create a new instance."""
        self.status = None
        self.events = None
        self.sync_daemon = None
        self.file_system = None
        self.shares = None
        self.config = None
        self.folders = None
        self.public_files = None
        self.factory = None
        self.client = None

    @defer.inlineCallbacks
    def _request_remote_objects(self, root):
        """Request all the diff remote objects used for the communication."""
        status = yield root.callRemote('get_status')
        self.status = StatusClient(status)

        events = yield root.callRemote('get_events')
        self.events = EventsClient(events)

        sync_daemon = yield root.callRemote('get_sync_daemon')
        self.sync_daemon = SyncDaemonClient(sync_daemon)

        file_system = yield root.callRemote('get_file_system')
        self.file_system = FileSystemClient(file_system)

        shares = yield root.callRemote('get_shares')
        self.shares = SharesClient(shares)

        config = yield root.callRemote('get_config')
        self.config = ConfigClient(config)

        folders = yield root.callRemote('get_folders')
        self.folders = FoldersClient(folders)

        public_files = yield root.callRemote('get_public_files')
        self.public_files = PublicFilesClient(public_files)

        defer.returnValue(self)

    @defer.inlineCallbacks
    def connect(self):
        """Connect to the syncdaemon service."""
        yield self.connection_lock.acquire()
        try:
            if self.client is None:
                # connect to the remote objects
                self.factory = PBClientFactory()
                self.client = yield ipc_client_connect(self.factory)
                root = yield self.factory.getRootObject()
                yield self._request_remote_objects(root)
                yield self.register_to_signals()
            defer.returnValue(self)
        except Exception as e:
            raise SyncDaemonClientConnectionError(
                'Could not connect to the syncdaemon ipc.', e)
        finally:
            self.connection_lock.release()

    @defer.inlineCallbacks
    def reconnect(self):
        """Reconnect and get the new remote objects."""
        try:
            root = yield self.factory.getRootObject()
            yield self._request_remote_objects(root)
            yield self.register_to_signals()
            defer.returnValue(self)
        except Exception as e:
            raise SyncDaemonClientConnectionError(
                'Could not reconnect to the syncdaemon ipc.', e)

    def is_connected(self):
        """Return if the client is connected."""
        return (self.client is not None)

    @defer.inlineCallbacks
    def register_to_signals(self):
        """Register the different clients to the signals."""
        for client in [self.status, self.events, self.sync_daemon, self.shares,
                       self.folders, self.public_files]:
            register = getattr(client, 'register_to_signals', None)
            if register is not None:
                yield register()
        defer.returnValue(self)

    @defer.inlineCallbacks
    def unregister_to_signals(self):
        """Unregister from the diff signals."""
        for client in [self.status, self.events, self.sync_daemon, self.shares,
                       self.folders, self.public_files]:
            unregister = getattr(client, 'unregister_to_signals', None)
            if unregister is not None:
                yield unregister()
        defer.returnValue(self)

    def disconnect(self):
        """Disconnect from the process."""
        if self.client:
            self.client.transport.loseConnection()
