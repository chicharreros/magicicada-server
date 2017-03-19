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
"""IPC implementation using perspective broker."""

import logging
import sys
import warnings

from functools import wraps
from collections import defaultdict

from twisted.internet import defer, endpoints
from twisted.spread.pb import (
    DeadReferenceError,
    NoSuchMethod,
    PBServerFactory,
    Referenceable,
    Root,
)

from ubuntuone.syncdaemon.utils import get_sd_bin_cmd
from ubuntuone.utils.tcpactivation import (
    ActivationClient,
    ActivationConfig,
    ActivationInstance,
    AlreadyStartedError,
)

# we do not do from package import as source becauser pyflakes will complain
if sys.platform == 'win32':
    from ubuntuone.platform.ipc import windows
    source = windows
else:
    from ubuntuone.platform.ipc import unix
    source = unix

DescriptionFactory = source.DescriptionFactory

logger = logging.getLogger("ubuntuone.SyncDaemon.Pb")
SD_SERVICE_NAME = "ubuntuone-syncdaemon"
CLIENT_NOT_PROCESSED = -1


def get_activation_config():
    """Get the configuration to activate the service."""
    description = DescriptionFactory()
    service_name = SD_SERVICE_NAME

    cmdline = get_sd_bin_cmd()

    return ActivationConfig(service_name, cmdline, description)


@defer.inlineCallbacks
def ipc_server_listen(server_factory, reactor=None):
    """Connect the IPC server factory."""
    description = DescriptionFactory()

    if reactor is None:
        from twisted.internet import reactor

    server = endpoints.serverFromString(reactor, description.server)
    connector = yield server.listen(server_factory)
    defer.returnValue(connector)


@defer.inlineCallbacks
def is_already_running(bus=None):
    """Return if the sd is running by trying to get the port."""
    ai = ActivationInstance(get_activation_config())
    ai_method = getattr(ai, 'get_server_description', None)
    if ai_method is None:  # backwards compatible
        ai_method = getattr(ai, 'get_port')
    try:
        yield ai_method()
        defer.returnValue(False)
    except AlreadyStartedError:
        defer.returnValue(True)


@defer.inlineCallbacks
def ipc_client_connect(client_factory, reactor=None):
    """Connect the IPC client factory."""
    ac = ActivationClient(get_activation_config())

    if reactor is None:
        from twisted.internet import reactor

    description = yield ac.get_active_client_description()
    client = endpoints.clientFromString(reactor, description)
    port = yield client.connect(client_factory)
    defer.returnValue(port)


def remote_handler(handler):
    result = handler
    if handler:
        def result(x):
            return handler.callRemote('execute', x)
    return result


class RemoteMeta(type):
    """Append remote_ to the remote methods.

    Remote has to be appended to the remote method to work over pb but this
    names cannot be used since the other platforms do not expect the remote
    prefix. This metaclass create those prefix so that the methods can be
    correctly called.
    """

    def __new__(cls, name, bases, attrs):
        remote_calls = attrs.get('remote_calls', [])
        signal_handlers = attrs.get('signal_handlers', [])
        for current in remote_calls + signal_handlers:
            attrs['remote_' + current] = attrs[current]
        return super(RemoteMeta, cls).__new__(cls, name, bases, attrs)


class SignalBroadcaster(object):
    """Object that allows to emit signals to clients over the IPC."""

    MSG_NO_SIGNAL_HANDLER = "No signal handler for %r in %r"
    MSG_COULD_NOT_EMIT_SIGNAL = "Could not emit signal %r to %r due to %r"

    def __init__(self):
        """Create a new instance."""
        self.clients_per_signal = defaultdict(set)

    def _ignore_no_such_method(self, failure, signal_name, current_client):
        """NoSuchMethod is not an error, ignore it."""
        failure.trap(NoSuchMethod)
        logger.debug(self.MSG_NO_SIGNAL_HANDLER, signal_name, current_client)

    def _other_failure(self, failure, signal_name, current_client):
        """Log the issue when emitting a signal."""
        logger.warning(self.MSG_COULD_NOT_EMIT_SIGNAL, signal_name,
                       current_client, failure.value)
        logger.warning('Traceback is:\n%s', failure.printDetailedTraceback())

    def remote_register_to_signals(self, client, signals):
        """Allow a client to register to some signals."""
        for signal in signals:
            self.clients_per_signal[signal].add(client)

    def remote_unregister_to_signals(self, client):
        """Allow a client to unregister from the signal."""
        for connected_clients in self.clients_per_signal.values():
            if client in connected_clients:
                connected_clients.remove(client)

    def emit_signal(self, signal_name, *args, **kwargs):
        """Emit the given signal to the clients."""
        logger.debug("emitting %r to all (%i) connected clients.",
                     signal_name, len(self.clients_per_signal[signal_name]))
        dead_clients = set()
        for current_client in self.clients_per_signal[signal_name]:
            try:
                d = current_client.callRemote(signal_name, *args, **kwargs)
                d.addErrback(
                    self._ignore_no_such_method, signal_name, current_client)
                d.addErrback(self._other_failure, signal_name, current_client)
            except DeadReferenceError:
                dead_clients.add(current_client)
        for client in dead_clients:
            self.remote_unregister_to_signals(client)


def signal(f):
    """Decorator to emit a signal."""

    @wraps(f)
    def inner(self, *args, **kwargs):
        """Grab the signal name from the internal mapping and emit."""
        f(self, *args, **kwargs)
        signal_name = self.signal_mapping.get(f.__name__, None)
        if signal_name:
            self.emit_signal(signal_name, *args, **kwargs)
        else:
            logger.error('Can not emit signal %r since is not in the class '
                         'mapping %r.', f.__name__, self.signal_mapping)

    return inner


class IPCExposedObject(Referenceable, SignalBroadcaster):
    """Base class that provides some helper methods to IPC exposed objects.

    @param service: the multiplatform SyncdaemonService.

    """

    def __init__(self, service):
        super(IPCExposedObject, self).__init__()
        self.service = service


class Status(IPCExposedObject):
    """Represent the status of the syncdaemon."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'current_status',
        'current_uploads',
        'current_downloads',
        'free_space',
        'waiting',
        'waiting_metadata',
        'waiting_content',
        'sync_menu',
    ]

    signal_mapping = {
        'DownloadStarted': 'on_download_started',
        'DownloadFileProgress': 'on_download_file_progress',
        'DownloadFinished': 'on_download_finished',
        'UploadStarted': 'on_upload_started',
        'UploadFileProgress': 'on_upload_file_progress',
        'UploadFinished': 'on_upload_finished',
        'InvalidName': 'on_invalid_name',
        'BrokenNode': 'on_broken_node',
        'StatusChanged': 'on_status_changed',
        'AccountChanged': 'on_account_changed',
        'ContentQueueChanged': 'on_content_queue_changed',
        'MetaQueueChanged': 'on_metaqueue_changed',
        'RequestQueueAdded': 'on_request_queue_added',
        'RequestQueueRemoved': 'on_request_queue_removed',
        'SignalError': 'on_error_signal',
    }

    def current_status(self):
        """Return the current status of the syncdaemon."""
        return self.service.status.current_status()

    def current_uploads(self):
        """Return a list of files with a upload in progress."""
        return self.service.status.current_uploads()

    def current_downloads(self):
        """Return a list of files with a download in progress."""
        return self.service.status.current_downloads()

    def free_space(self, vol_id):
        """Return the free space for the given volume."""
        return self.service.status.free_space(vol_id)

    def waiting(self):
        """Return a list of the operations in action queue."""
        return self.service.status.waiting()

    def waiting_metadata(self):
        """Return a list of the operations in the meta-queue.

        As we don't have meta-queue anymore, this is faked. This method
        is deprecated, and will go away in a near future.

        """
        warnings.warn('Use "waiting" method instead.', DeprecationWarning)
        return self.service.status.waiting_metadata()

    def waiting_content(self):
        """Return a list of files that are waiting to be up- or downloaded.

        As we don't have content-queue anymore, this is faked.  This method
        is deprecated, and will go away in a near future.

        """
        warnings.warn('Use "waiting" method instead.', DeprecationWarning)
        return self.service.status.waiting_content()

    def sync_menu(self):
        """Return the info necessary to construct the menu."""
        return self.service.status.sync_menu()

    @signal
    def DownloadStarted(self, path):
        """Fire a signal to notify that a download has started."""

    @signal
    def DownloadFileProgress(self, path, info):
        """Fire a signal to notify about a download progress."""

    @signal
    def DownloadFinished(self, path, info):
        """Fire a signal to notify that a download has finished."""

    @signal
    def UploadStarted(self, path):
        """Fire a signal to notify that an upload has started."""

    @signal
    def UploadFileProgress(self, path, info):
        """Fire a signal to notify about an upload progress."""

    @signal
    def UploadFinished(self, path, info):
        """Fire a signal to notify that an upload has finished."""

    @signal
    def InvalidName(self, dirname, filename):
        """Fire a signal to notify an invalid file or dir name."""

    @signal
    def BrokenNode(self, volume_id, node_id, mdid, path):
        """Fire a signal to notify a broken node."""

    @signal
    def StatusChanged(self, status):
        """Fire a signal to notify that the status of the system changed."""

    @signal
    def AccountChanged(self, account_info):
        """Fire a signal to notify that account information has changed."""

    @signal
    def ContentQueueChanged(self):
        """Fire a signal to notify that the content queue has changed.

        This signal is deprecated, and will go away in a near future.

        """
        msg = 'Connect to RequestQueueAdded/RequestQueueRemoved instead.'
        warnings.warn(msg, DeprecationWarning)

    @signal
    def MetaQueueChanged(self):
        """Fire a signal to notify that the meta queue has changed.

        This signal is deprecated, and will go away in a near future.

        """
        msg = 'Connect to RequestQueueAdded/RequestQueueRemoved instead.'
        warnings.warn(msg, DeprecationWarning)

    @signal
    def RequestQueueAdded(self, op_name, op_id, data):
        """Fire a signal to notify that this command was added."""

    @signal
    def RequestQueueRemoved(self, op_name, op_id, data):
        """Fire a signal to notify that this command was removed."""

    @signal
    def SignalError(self, signal, extra_args):
        """An error ocurred while trying to emit a signal."""
        # This is not implemented but is used from interaction interfaces
        # to handle KeyError from the fs_manager on:
        # handle_AQ_DOWNLOAD_STARTED, handle_AQ_DOWNLOAD_FILE_PROGRESS
        # handle_AQ_DOWNLOAD_FINISHED, handle_AQ_DOWNLOAD_ERROR
        # handle_AQ_UPLOAD_STARTED, handle_AQ_UPLOAD_FILE_PROGRESS
        # handle_AQ_UPLOAD_FINISHED, handle_AQ_UPLOAD_ERROR


class Events(IPCExposedObject):
    """The events of the system translated to signals."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'push_event',
    ]

    signal_mapping = {'Event': 'on_event'}

    @signal
    def Event(self, event_dict):
        """Fire a signal, notifying an event."""

    def push_event(self, event_name, args):
        """Push an event to the event queue."""
        self.service.events.push_event(event_name, args)


class SyncDaemon(IPCExposedObject):
    """The Syncdaemon interface."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'connect',
        'disconnect',
        'get_homedir',
        'get_rootdir',
        'get_sharesdir',
        'get_sharesdir_link',
        'wait_for_nirvana',
        'quit',
        'rescan_from_scratch',
    ]

    signal_mapping = {
        'RootMismatch': 'on_root_mismatch',
        'QuotaExceeded': 'on_quota_exceeded',
        'VolumesChanged': 'on_volumes_changed',
    }

    def connect(self):
        """Connect to the server."""
        self.service.sync.connect()

    def disconnect(self):
        """Disconnect from the server."""
        self.service.sync.disconnect()

    def get_homedir(self):
        """Return the home dir/mount point."""
        return self.service.sync.get_homedir()

    def get_rootdir(self):
        """Return the root dir/mount point."""
        return self.service.sync.get_rootdir()

    def get_sharesdir(self):
        """Return the shares dir/mount point."""
        return self.service.sync.get_sharesdir()

    def get_sharesdir_link(self):
        """Return the shares dir/mount point."""
        return self.service.sync.get_sharesdir_link()

    def wait_for_nirvana(self, last_event_interval,
                         reply_handler=None, error_handler=None):
        """Call the reply handler when there are no more events/transfers."""
        d = self.service.sync.wait_for_nirvana(last_event_interval)
        if reply_handler is not None:
            d.addCallback(remote_handler(reply_handler))
        if error_handler is not None:
            d.addErrback(remote_handler(error_handler))
        return d

    def quit(self, reply_handler=None, error_handler=None):
        """Shutdown the syncdaemon."""
        d = self.service.sync.quit()
        if reply_handler is not None:
            d.addCallback(lambda _: remote_handler(reply_handler)())
        if error_handler is not None:
            d.addErrback(remote_handler(error_handler))
        return d

    def rescan_from_scratch(self, volume_id):
        """Request a rescan from scratch of the volume with volume_id."""
        self.service.sync.rescan_from_scratch(volume_id)

    @signal
    def RootMismatch(self, root_id, new_root_id):
        """RootMismatch signal, the user connected with a different account."""

    @signal
    def QuotaExceeded(self, volume_dict):
        """QuotaExceeded signal, the user ran out of space."""

    @signal
    def VolumesChanged(self, volumes):
        """Volumes list has changed."""


class FileSystem(IPCExposedObject):
    """An interface to the FileSystem Manager."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'get_metadata',
        'get_metadata_by_node',
        'get_metadata_and_quick_tree_synced',
        'get_dirty_nodes',
        'search_files',
    ]

    def get_metadata(self, path):
        """Return the metadata (as a dict) for the specified path."""
        return self.service.file_system.get_metadata(path)

    def get_metadata_by_node(self, share_id, node_id):
        """Return the metadata (as a dict) for the specified share/node."""
        return self.service.file_system.get_metadata_by_node(share_id, node_id)

    def get_metadata_and_quick_tree_synced(self, path):
        """Return the metadata (as a dict) for the specified path.

        Include the quick subtree status.

        """
        return self.service.file_system.get_metadata_and_quick_tree_synced(
            path)

    def get_dirty_nodes(self):
        """Return a list of dirty nodes."""
        return self.service.file_system.get_dirty_nodes()

    def search_files(self, pattern):
        """Search for the occurrence of pattern in the files names."""
        return self.service.file_system.search_files(pattern)


class Shares(IPCExposedObject):
    """An interface to interact with shares."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'get_shares',
        'accept_share',
        'reject_share',
        'delete_share',
        'subscribe',
        'unsubscribe',
        'create_share',
        'create_shares',
        'refresh_shares',
        'get_shared',
    ]

    signal_mapping = {
        'ShareChanged': 'on_share_changed',
        'ShareDeleted': 'on_share_deleted',
        'ShareDeleteError': 'on_share_delete_error',
        'ShareCreated': 'on_share_created',
        'ShareCreateError': 'on_share_create_error',
        'ShareAnswerResponse': 'on_share_answer_response',
        'NewShare': 'on_new_share',
        'ShareSubscribed': 'on_share_subscribed',
        'ShareSubscribeError': 'on_share_subscribe_error',
        'ShareUnSubscribed': 'on_share_unsubscribed',
        'ShareUnSubscribeError': 'on_share_unsubscribe_error',
    }

    def get_shares(self):
        """Return a list of dicts, each dict represents a share."""
        return self.service.shares.get_shares()

    def accept_share(self, share_id):
        """Accept a share.

        A ShareAnswerOk|Error signal will be fired in the future as a
        success/failure indicator.

        """
        self.service.shares.accept_share(share_id)

    def reject_share(self, share_id):
        """Reject a share."""
        self.service.shares.reject_share(share_id)

    def delete_share(self, share_id):
        """Delete a Share, both kinds: "to me" and "from me"."""
        return self.service.shares.delete_share(share_id)

    def subscribe(self, share_id):
        """Subscribe to the specified share."""
        self.service.shares.subscribe(share_id)

    def unsubscribe(self, share_id):
        """Unsubscribe from the specified share."""
        self.service.shares.unsubscribe(share_id)

    @signal
    def ShareChanged(self, share_dict):
        """A share changed, share_dict contains all the share attributes."""

    @signal
    def ShareDeleted(self, share_dict):
        """A share was deleted, share_dict contains share details."""

    @signal
    def ShareDeleteError(self, share_dict, error):
        """An error occurred while deleting a share."""

    def create_share(self, path, username, name, access_level):
        """Share a subtree to the user identified by username.

        @param path: that path to share (the root of the subtree)
        @param username: the username to offer the share to
        @param name: the name of the share
        @param access_level: 'View' or 'Modify'
        """
        self.service.shares.create_share(path, username, name, access_level)

    def create_shares(self, path, usernames, name, access_level):
        """Share a subtree with several users at once.

        @param path: that path to share (the root of the subtree)
        @param usernames: the user names to offer the share to
        @param name: the name of the share
        @param access_level: 'View' or 'Modify'
        """
        for user in usernames:
            self.service.shares.create_share(path, user, name, access_level)

    @signal
    def ShareCreated(self, share_info):
        """The requested share was succesfully created."""

    @signal
    def ShareCreateError(self, share_info, error):
        """An error ocurred while creating the share."""

    def refresh_shares(self):
        """Refresh the share list, requesting it to the server."""
        self.service.shares.refresh_shares()

    def get_shared(self):
        """Return a list of dicts, each dict represents a shared share.

        A share might not have the path set, as we might be still fetching the
        nodes from the server. In this cases the path is ''

        """
        return self.service.shares.get_shared()

    @signal
    def ShareAnswerResponse(self, answer_info):
        """The answer to share was succesfull"""

    @signal
    def NewShare(self, share_info):
        """A new share notification."""

    @signal
    def ShareSubscribed(self, share_info):
        """Notify the subscription to a share."""

    @signal
    def ShareSubscribeError(self, share_info, error):
        """Notify an error while subscribing to a share."""

    @signal
    def ShareUnSubscribed(self, share_info):
        """Notify the unsubscription to a share."""

    @signal
    def ShareUnSubscribeError(self, share_info, error):
        """Notify an error while unsubscribing from a share."""


class Config(IPCExposedObject):
    """The Syncdaemon config/settings interface."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'get_throttling_limits',
        'set_throttling_limits',
        'bandwidth_throttling_enabled',
        'enable_bandwidth_throttling',
        'disable_bandwidth_throttling',
        'udf_autosubscribe_enabled',
        'disable_udf_autosubscribe',
        'enable_udf_autosubscribe',
        'share_autosubscribe_enabled',
        'enable_share_autosubscribe',
        'disable_share_autosubscribe',
        'files_sync_enabled',
        'enable_files_sync',
        'disable_files_sync',
        'set_files_sync_enabled',
        'autoconnect_enabled',
        'enable_autoconnect',
        'disable_autoconnect',
        'set_autoconnect_enabled',
    ]

    signal_mapping = {}

    def get_throttling_limits(self):
        """Get the read/write limit from AQ and return a dict.

        Return a dict(download=int, upload=int), if int is -1 the value isn't
        configured. The values are bytes/second.

        """
        return self.service.config.get_throttling_limits()

    def set_throttling_limits(self, download, upload):
        """Set the read and write limits. The expected values are bytes/sec."""
        self.service.config.set_throttling_limits(download, upload)

    def enable_bandwidth_throttling(self):
        """Enable bandwidth throttling."""
        self.service.config.enable_bandwidth_throttling()

    def disable_bandwidth_throttling(self):
        """Disable bandwidth throttling."""
        self.service.config.disable_bandwidth_throttling()

    def bandwidth_throttling_enabled(self):
        """Return whether the bandwidth throttling is enabled or not."""
        return self.service.config.bandwidth_throttling_enabled()

    def udf_autosubscribe_enabled(self):
        """Return the udf_autosubscribe config value."""
        return self.service.config.udf_autosubscribe_enabled()

    def enable_udf_autosubscribe(self):
        """Enable UDF autosubscribe."""
        self.service.config.enable_udf_autosubscribe()

    def disable_udf_autosubscribe(self):
        """Disable UDF autosubscribe."""
        self.service.config.disable_udf_autosubscribe()

    def share_autosubscribe_enabled(self):
        """Return the share_autosubscribe config value."""
        return self.service.config.share_autosubscribe_enabled()

    def enable_share_autosubscribe(self):
        """Enable share autosubscribe."""
        self.service.config.enable_share_autosubscribe()

    def disable_share_autosubscribe(self):
        """Disable share autosubscribe."""
        self.service.config.disable_share_autosubscribe()

    def set_files_sync_enabled(self, enabled):
        """Enable/disable file sync service.

        DEPRECATED. Use {enable/disable}_files_sync instead.

        """
        msg = 'Use enable_files_sync/disable_files_sync instead.'
        warnings.warn(msg, DeprecationWarning)
        if enabled:
            self.service.config.enable_files_sync()
        else:
            self.service.config.disable_files_sync()

    def files_sync_enabled(self):
        """Return the files_sync_enabled config value."""
        return self.service.config.files_sync_enabled()

    def enable_files_sync(self):
        """Enable file sync service."""
        self.service.config.enable_files_sync()

    def disable_files_sync(self):
        """Disable file sync service."""
        self.service.config.disable_files_sync()

    def autoconnect_enabled(self):
        """Return the autoconnect config value."""
        return self.service.config.autoconnect_enabled()

    def enable_autoconnect(self):
        """Enable syncdaemon autoconnect."""
        self.service.config.enable_autoconnect()

    def disable_autoconnect(self):
        """Disable syncdaemon autoconnect."""
        self.service.config.disable_autoconnect()

    def set_autoconnect_enabled(self, enabled):
        """Enable syncdaemon autoconnect.

        DEPRECATED. Use {enable/disable}_autoconnect instead.

        """
        msg = 'Use enable_autoconnect/disable_autoconnect instead.'
        warnings.warn(msg, DeprecationWarning)
        if enabled:
            self.service.config.enable_autoconnect()
        else:
            self.service.config.disable_autoconnect()


class Folders(IPCExposedObject):
    """An interface to interact with User Defined Folders."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'create',
        'delete',
        'validate_path',
        'get_folders',
        'subscribe',
        'unsubscribe',
        'get_info',
        'refresh_volumes',
    ]

    signal_mapping = {
        'FolderCreated': 'on_folder_created',
        'FolderCreateError': 'on_folder_create_error',
        'FolderDeleted': 'on_folder_deleted',
        'FolderDeleteError': 'on_folder_delete_error',
        'FolderSubscribed': 'on_folder_subscribed',
        'FolderSubscribeError': 'on_folder_subscribe_error',
        'FolderUnSubscribed': 'on_folder_unsubscribed',
        'FolderUnSubscribeError': 'on_folder_unsubscribe_error',
    }

    def create(self, path):
        """Create a user defined folder in the specified path."""
        return self.service.folders.create(path)

    def delete(self, folder_id):
        """Delete the folder specified by folder_id"""
        return self.service.folders.delete(folder_id)

    def validate_path(self, path):
        """Return True if the path is valid for a folder."""
        return self.service.folders.validate_path(path)

    def get_folders(self):
        """Return the list of folders (a list of dicts)"""
        return self.service.folders.get_folders()

    def subscribe(self, folder_id):
        """Subscribe to the specified folder"""
        self.service.folders.subscribe(folder_id)

    def unsubscribe(self, folder_id):
        """Unsubscribe from the specified folder"""
        self.service.folders.unsubscribe(folder_id)

    def get_info(self, path):
        """Return a dict containing the folder information."""
        return self.service.folders.get_info(path)

    def refresh_volumes(self):
        """Refresh the volumes list, requesting it to the server."""
        self.service.folders.refresh_volumes()

    @signal
    def FolderCreated(self, folder_info):
        """Notify the creation of a user defined folder."""

    @signal
    def FolderCreateError(self, folder_info, error):
        """Notify an error during the creation of a user defined folder."""

    @signal
    def FolderDeleted(self, folder_info):
        """Notify the deletion of a user defined folder."""

    @signal
    def FolderDeleteError(self, folder_info, error):
        """Notify an error during the deletion of a user defined folder."""

    @signal
    def FolderSubscribed(self, folder_info):
        """Notify the subscription to a user defined folder."""

    @signal
    def FolderSubscribeError(self, folder_info, error):
        """Notify an error while subscribing to a user defined folder."""

    @signal
    def FolderUnSubscribed(self, folder_info):
        """Notify the unsubscription to a user defined folder."""

    @signal
    def FolderUnSubscribeError(self, folder_info, error):
        """Notify an error while unsubscribing from a user defined folder."""


class PublicFiles(IPCExposedObject):
    """An interface for handling public files."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'change_public_access',
        'get_public_files',
    ]

    signal_mapping = {
        'PublicAccessChanged': 'on_public_access_changed',
        'PublicAccessChangeError': 'on_public_access_change_error',
        'PublicFilesList': 'on_public_files_list',
        'PublicFilesListError': 'on_public_files_list_error',
    }

    def change_public_access(self, share_id, node_id, is_public):
        """Change the public access of a file."""
        self.service.public_files.change_public_access(share_id, node_id,
                                                       is_public)

    def get_public_files(self):
        """Request the list of public files to the server.

        The result will be send in a PublicFilesList signal.
        """
        self.service.public_files.get_public_files()

    @signal
    def PublicAccessChanged(self, file_info):
        """Notify the new public access state of a file."""

    @signal
    def PublicAccessChangeError(self, file_info, error):
        """Report an error in changing the public access of a file."""

    @signal
    def PublicFilesList(self, files):
        """Notify the list of public files."""

    @signal
    def PublicFilesListError(self, error):
        """Report an error in geting the public files list."""


class IPCInterface(object, Root):
    """Holder of all exposed objects."""

    __metaclass__ = RemoteMeta

    # calls that will be accessible remotely
    remote_calls = [
        'get_status',
        'get_events',
        'get_sync_daemon',
        'get_file_system',
        'get_shares',
        'get_config',
        'get_folders',
        'get_public_files']

    def __init__(self, service):
        """Create the instance and add the exposed objects.

        - 'service' is the multiplatform service interface.

        """
        super(IPCInterface, self).__init__()
        self.events = Events(service)
        self.status = Status(service)
        self.sync_daemon = SyncDaemon(service)
        self.file_system = FileSystem(service)
        self.shares = Shares(service)
        self.folders = Folders(service)
        self.public_files = PublicFiles(service)
        self.config = Config(service)
        self.factory = PBServerFactory(self)

        logger.info('IPC initialized.')

    @defer.inlineCallbacks
    def start(self):
        """Start listening for ipc messages."""
        self.listener = yield ipc_server_listen(self.factory)

    def shutdown(self, with_restart=False):
        """Remove the registered objects."""
        logger.info('Shutting down IPC!')
        self.listener.stopListening()
        if with_restart:
            self.listener.startListening()

    def get_status(self):
        """Return the status remote object."""
        return self.status

    def get_events(self):
        """Return the events remote object."""
        return self.events

    def get_sync_daemon(self):
        """Return the sync daemon remote object."""
        return self.sync_daemon

    def get_file_system(self):
        """Return the file system remote object."""
        return self.file_system

    def get_shares(self):
        """Return the shares remote object."""
        return self.shares

    def get_config(self):
        """Return the config remote object."""
        return self.config

    def get_folders(self):
        """Return the folders remote object."""
        return self.folders

    def get_public_files(self):
        """Return the public files remote object."""
        return self.public_files
