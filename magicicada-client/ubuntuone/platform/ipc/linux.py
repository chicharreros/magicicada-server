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
"""IPC implementation for linux."""

import logging
import warnings

import dbus
import dbus.service

from twisted.internet import defer
from xml.etree import ElementTree

from ubuntuone.platform import launcher
from ubuntuone.syncdaemon import (
    RECENT_TRANSFERS,
    UPLOADING,
)

# Disable the "Invalid Name" check here, as we have lots of DBus style names

DBUS_IFACE_NAME = 'com.ubuntuone.SyncDaemon'
DBUS_IFACE_SYNC_NAME = DBUS_IFACE_NAME + '.SyncDaemon'
DBUS_IFACE_STATUS_NAME = DBUS_IFACE_NAME + '.Status'
DBUS_IFACE_EVENTS_NAME = DBUS_IFACE_NAME + '.Events'
DBUS_IFACE_FS_NAME = DBUS_IFACE_NAME + '.FileSystem'
DBUS_IFACE_SHARES_NAME = DBUS_IFACE_NAME + '.Shares'
DBUS_IFACE_CONFIG_NAME = DBUS_IFACE_NAME + '.Config'
DBUS_IFACE_FOLDERS_NAME = DBUS_IFACE_NAME + '.Folders'
DBUS_IFACE_PUBLIC_FILES_NAME = DBUS_IFACE_NAME + '.PublicFiles'
DBUS_IFACE_LAUNCHER_NAME = DBUS_IFACE_NAME + '.Launcher'

logger = logging.getLogger("ubuntuone.SyncDaemon.DBus")


def is_already_running(bus=None):
    """Check if there is another instance registered in DBus."""
    if bus is None:
        bus = dbus.SessionBus()
    request = bus.request_name(DBUS_IFACE_NAME,
                               dbus.bus.NAME_FLAG_DO_NOT_QUEUE)
    if request == dbus.bus.REQUEST_NAME_REPLY_EXISTS:
        return defer.succeed(True)
    else:
        return defer.succeed(False)


class DBusExposedObject(dbus.service.Object):
    """Base class that provides some helper methods to DBus exposed objects.

    @param bus_name: the BusName of this DBusExposedObject.
    @param service: the multiplatform SyncdaemonService.

    """

    path = None

    def __init__(self, bus_name, service):
        """Create the instance."""
        self.service = service
        dbus.service.Object.__init__(self, bus_name=bus_name,
                                     object_path=self.path)

    @dbus.service.signal(DBUS_IFACE_SYNC_NAME, signature='sa{ss}')
    def SignalError(self, signal, extra_args):
        """An error ocurred while trying to emit a signal."""

    @classmethod
    def _add_docstring(cls, func, reflection_data):
        """Add <docstring> tag to reflection_data if func.__doc__ isnt None."""
        # add docstring element
        if getattr(func, '__doc__', None) is not None:

            element = ElementTree.fromstring(reflection_data)
            doc = element.makeelement('docstring', dict())
            data = '<![CDATA[' + func.__doc__ + ']]>'
            doc.text = '%s'
            element.insert(0, doc)
            return ElementTree.tostring(element) % data
        else:
            return reflection_data

    @classmethod
    def _reflect_on_method(cls, func):
        """override _reflect_on_method to provide an extra <docstring> element
        in the xml.
        """
        reflection_data = dbus.service.Object._reflect_on_method(func)
        reflection_data = cls._add_docstring(func, reflection_data)
        return reflection_data

    @classmethod
    def _reflect_on_signal(cls, func):
        reflection_data = dbus.service.Object._reflect_on_signal(func)
        reflection_data = cls._add_docstring(func, reflection_data)
        return reflection_data


class Status(DBusExposedObject):
    """Represent the status of the syncdaemon."""

    path = '/status'

    @dbus.service.method(DBUS_IFACE_STATUS_NAME,
                         in_signature='', out_signature='a{ss}')
    def current_status(self):
        """Return the current status of the syncdaemon."""
        return self.service.status.current_status()

    @dbus.service.method(DBUS_IFACE_STATUS_NAME, out_signature='aa{ss}')
    def current_uploads(self):
        """Return a list of files with a upload in progress."""
        return self.service.status.current_uploads()

    @dbus.service.method(DBUS_IFACE_STATUS_NAME, out_signature='aa{ss}')
    def current_downloads(self):
        """Return a list of files with a download in progress."""
        return self.service.status.current_downloads()

    @dbus.service.method(DBUS_IFACE_STATUS_NAME,
                         in_signature='s', out_signature='t')
    def free_space(self, vol_id):
        """Return the free space for the given volume."""
        return self.service.status.free_space(vol_id)

    @dbus.service.method(DBUS_IFACE_STATUS_NAME, out_signature='a(ssa{ss})')
    def waiting(self):
        """Return a list of the operations in action queue."""
        return self.service.status.waiting()

    @dbus.service.method(DBUS_IFACE_STATUS_NAME, out_signature='a(sa{ss})')
    def waiting_metadata(self):
        """Return a list of the operations in the meta-queue.

        As we don't have meta-queue anymore, this is faked. This method
        is deprecated, and will go away in a near future.

        """
        warnings.warn('Use "waiting" method instead.', DeprecationWarning)
        return self.service.status.waiting_metadata()

    @dbus.service.method(DBUS_IFACE_STATUS_NAME, out_signature='aa{ss}')
    def waiting_content(self):
        """Return a list of files that are waiting to be up- or downloaded.

        As we don't have content-queue anymore, this is faked.  This method
        is deprecated, and will go away in a near future.

        """
        warnings.warn('Use "waiting" method instead.', DeprecationWarning)
        return self.service.status.waiting_content()

    @dbus.service.method(DBUS_IFACE_STATUS_NAME, out_signature='a{sv}')
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
        data = self.service.status.sync_menu()
        uploading = data[UPLOADING]
        transfers = data[RECENT_TRANSFERS]
        upload_data = dbus.Array(signature="(sii)")
        transfer_data = dbus.Array(signature="s")
        for up in uploading:
            upload_data.append(dbus.Struct(up, signature="sii"))
        for transfer in transfers:
            transfer_data.append(transfer)
        result = dbus.Dictionary(signature="sv")
        result[UPLOADING] = upload_data
        result[RECENT_TRANSFERS] = transfer_data
        return result

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME)
    def DownloadStarted(self, path):
        """Fire a signal to notify that a download has started."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='sa{ss}')
    def DownloadFileProgress(self, path, info):
        """Fire a signal to notify about a download progress."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='sa{ss}')
    def DownloadFinished(self, path, info):
        """Fire a signal to notify that a download has finished."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME)
    def UploadStarted(self, path):
        """Fire a signal to notify that an upload has started."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='sa{ss}')
    def UploadFileProgress(self, path, info):
        """Fire a signal to notify about an upload progress."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='sa{ss}')
    def UploadFinished(self, path, info):
        """Fire a signal to notify that an upload has finished."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='say')
    def InvalidName(self, dirname, filename):
        """Fire a signal to notify an invalid file or dir name."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='ssss')
    def BrokenNode(self, volume_id, node_id, mdid, path):
        """Fire a signal to notify a broken node."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME)
    def StatusChanged(self, status):
        """Fire a signal to notify that the status of the system changed."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='a{ss}')
    def AccountChanged(self, account_info):
        """Fire a signal to notify that account information has changed."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME)
    def ContentQueueChanged(self):
        """Fire a signal to notify that the content queue has changed.

        This signal is deprecated, and will go away in a near future.

        """
        msg = 'Connect to RequestQueueAdded/RequestQueueRemoved instead.'
        warnings.warn(msg, DeprecationWarning)

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME)
    def MetaQueueChanged(self):
        """Fire a signal to notify that the meta queue has changed.

        This signal is deprecated, and will go away in a near future.

        """
        msg = 'Connect to RequestQueueAdded/RequestQueueRemoved instead.'
        warnings.warn(msg, DeprecationWarning)

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='ssa{ss}')
    def RequestQueueAdded(self, op_name, op_id, data):
        """Fire a signal to notify that this command was added."""

    @dbus.service.signal(DBUS_IFACE_STATUS_NAME, signature='ssa{ss}')
    def RequestQueueRemoved(self, op_name, op_id, data):
        """Fire a signal to notify that this command was removed."""


class Events(DBusExposedObject):
    """The events of the system translated to signals."""

    path = '/events'

    @dbus.service.signal(DBUS_IFACE_EVENTS_NAME,
                         signature='a{ss}')
    def Event(self, event_dict):
        """Fire a signal, notifying an event."""

    @dbus.service.method(DBUS_IFACE_EVENTS_NAME, in_signature='sa{ss}')
    def push_event(self, event_name, args):
        """Push an event to the event queue."""
        self.service.events.push_event(event_name, args)


class SyncDaemon(DBusExposedObject):
    """The Syncdaemon interface."""

    path = '/'

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='')
    def connect(self):
        """Connect to the server."""
        self.service.sync.connect()

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='')
    def disconnect(self):
        """Disconnect from the server."""
        self.service.sync.disconnect()

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='s')
    def get_homedir(self):
        """Return the home dir."""
        return self.service.sync.get_homedir()

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='s')
    def get_rootdir(self):
        """Return the root dir/mount point."""
        return self.service.sync.get_rootdir()

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='s')
    def get_sharesdir(self):
        """Return the shares dir/mount point."""
        return self.service.sync.get_sharesdir()

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='s')
    def get_sharesdir_link(self):
        """Return the shares dir/mount point."""
        return self.service.sync.get_sharesdir_link()

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='d', out_signature='b',
                         async_callbacks=('reply_handler', 'error_handler'))
    def wait_for_nirvana(self, last_event_interval,
                         reply_handler=None, error_handler=None):
        """Call the reply handler when there are no more events/transfers."""
        d = self.service.sync.wait_for_nirvana(last_event_interval)
        if reply_handler is not None:
            d.addCallback(reply_handler)
        if error_handler is not None:
            d.addErrback(error_handler)

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='', out_signature='',
                         async_callbacks=('reply_handler', 'error_handler'))
    def quit(self, reply_handler=None, error_handler=None):
        """Shutdown the syncdaemon."""
        d = self.service.sync.quit()
        if reply_handler is not None:
            d.addCallback(lambda _: reply_handler())
        if error_handler is not None:
            d.addErrback(error_handler)

    @dbus.service.method(DBUS_IFACE_SYNC_NAME,
                         in_signature='s', out_signature='')
    def rescan_from_scratch(self, volume_id):
        """Request a rescan from scratch of the volume with volume_id."""
        self.service.sync.rescan_from_scratch(volume_id)

    @dbus.service.signal(DBUS_IFACE_SYNC_NAME,
                         signature='ss')
    def RootMismatch(self, root_id, new_root_id):
        """RootMismatch signal, the user connected with a different account."""

    @dbus.service.signal(DBUS_IFACE_SYNC_NAME,
                         signature='a{ss}')
    def QuotaExceeded(self, volume_dict):
        """QuotaExceeded signal, the user ran out of space."""

    @dbus.service.signal(DBUS_IFACE_SYNC_NAME, signature='aa{ss}')
    def VolumesChanged(self, volumes):
        """Volumes list changed."""


class FileSystem(DBusExposedObject):
    """An interface to the FileSystem Manager."""

    path = '/filesystem'

    @dbus.service.method(DBUS_IFACE_FS_NAME,
                         in_signature='s', out_signature='a{ss}')
    def get_metadata(self, path):
        """Return the metadata (as a dict) for the specified path."""
        return self.service.file_system.get_metadata(path)

    @dbus.service.method(DBUS_IFACE_FS_NAME,
                         in_signature='ss', out_signature='a{ss}')
    def get_metadata_by_node(self, share_id, node_id):
        """Return the metadata (as a dict) for the specified share/node."""
        return self.service.file_system.get_metadata_by_node(share_id, node_id)

    @dbus.service.method(DBUS_IFACE_FS_NAME,
                         in_signature='s', out_signature='a{ss}')
    def get_metadata_and_quick_tree_synced(self, path):
        """Return the metadata (as a dict) for the specified path.

        Include the quick subtree status.

        """
        return self.service.file_system.get_metadata_and_quick_tree_synced(
            path)

    @dbus.service.method(DBUS_IFACE_FS_NAME,
                         in_signature='', out_signature='aa{ss}')
    def get_dirty_nodes(self):
        """Return a list of dirty nodes."""
        return self.service.file_system.get_dirty_nodes()

    @dbus.service.method(DBUS_IFACE_FS_NAME,
                         in_signature='s', out_signature='as')
    def search_files(self, pattern):
        """Return the files (as a list) that contain pattern in the path."""
        return self.service.file_system.search_files(pattern)


class Shares(DBusExposedObject):
    """An interface to interact with shares."""

    path = '/shares'

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='', out_signature='aa{ss}')
    def get_shares(self):
        """Return a list of dicts, each dict represents a share."""
        return self.service.shares.get_shares()

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='s', out_signature='')
    def accept_share(self, share_id):
        """Accept a share.

        A ShareAnswerOk|Error signal will be fired in the future as a
        success/failure indicator.

        """
        self.service.shares.accept_share(share_id)

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='s', out_signature='')
    def reject_share(self, share_id):
        """Reject a share."""
        self.service.shares.reject_share(share_id)

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='s', out_signature='')
    def delete_share(self, share_id):
        """Delete a Share, both kinds: "to me" and "from me"."""
        return self.service.shares.delete_share(share_id)

    @dbus.service.method(DBUS_IFACE_SHARES_NAME, in_signature='s')
    def subscribe(self, share_id):
        """Subscribe to the specified share."""
        self.service.shares.subscribe(share_id)

    @dbus.service.method(DBUS_IFACE_SHARES_NAME, in_signature='s')
    def unsubscribe(self, share_id):
        """Unsubscribe from the specified share."""
        self.service.shares.unsubscribe(share_id)

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}')
    def ShareChanged(self, share_dict):
        """A share changed, share_dict contains all the share attributes."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}')
    def ShareDeleted(self, share_dict):
        """A share was deleted, share_dict contains share details."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}s')
    def ShareDeleteError(self, share_dict, error):
        """An error occurred while deleting a share."""

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='ssss', out_signature='')
    def create_share(self, path, username, name, access_level):
        """Share a subtree to the user identified by username.

        @param path: that path to share (the root of the subtree)
        @param username: the username to offer the share to
        @param name: the name of the share
        @param access_level: 'View' or 'Modify'
        """
        self.service.shares.create_share(path, username, name, access_level)

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='sasss', out_signature='')
    def create_shares(self, path, usernames, name, access_level):
        """Share a subtree with several users at once.

        @param path: that path to share (the root of the subtree)
        @param usernames: the user names to offer the share to
        @param name: the name of the share
        @param access_level: 'View' or 'Modify'
        """
        for user in usernames:
            self.service.shares.create_share(path, user, name, access_level)

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}')
    def ShareCreated(self, share_info):
        """The requested share was succesfully created."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}s')
    def ShareCreateError(self, share_info, error):
        """An error ocurred while creating the share."""

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='', out_signature='')
    def refresh_shares(self):
        """Refresh the share list, requesting it to the server."""
        self.service.shares.refresh_shares()

    @dbus.service.method(DBUS_IFACE_SHARES_NAME,
                         in_signature='', out_signature='aa{ss}')
    def get_shared(self):
        """Return a list of dicts, each dict represents a shared share.

        A share might not have the path set, as we might be still fetching the
        nodes from the server. In this cases the path is ''

        """
        return self.service.shares.get_shared()

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}')
    def ShareAnswerResponse(self, answer_info):
        """The answer to share was succesfull"""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME,
                         signature='a{ss}')
    def NewShare(self, share_info):
        """A new share notification."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME, signature='a{ss}')
    def ShareSubscribed(self, share_info):
        """Notify the subscription to a share."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME, signature='a{ss}s')
    def ShareSubscribeError(self, share_info, error):
        """Notify an error while subscribing to a share."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME, signature='a{ss}')
    def ShareUnSubscribed(self, share_info):
        """Notify the unsubscription to a share."""

    @dbus.service.signal(DBUS_IFACE_SHARES_NAME, signature='a{ss}s')
    def ShareUnSubscribeError(self, share_info, error):
        """Notify an error while unsubscribing from a share."""


class Config(DBusExposedObject):
    """The Syncdaemon config/settings interface."""

    path = '/config'

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='a{si}')
    def get_throttling_limits(self):
        """Get the read/write limit from AQ and return a dict.

        Return a dict(download=int, upload=int), if int is -1 the value isn't
        configured. The values are bytes/second.

        """
        return self.service.config.get_throttling_limits()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='ii', out_signature='')
    def set_throttling_limits(self, download, upload):
        """Set the read and write limits. The expected values are bytes/sec."""
        self.service.config.set_throttling_limits(download, upload)

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def enable_bandwidth_throttling(self):
        """Enable bandwidth throttling."""
        self.service.config.enable_bandwidth_throttling()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def disable_bandwidth_throttling(self):
        """Disable bandwidth throttling."""
        self.service.config.disable_bandwidth_throttling()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='b')
    def bandwidth_throttling_enabled(self):
        """Return whether the bandwidth throttling is enabled or not."""
        return self.service.config.bandwidth_throttling_enabled()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='b')
    def udf_autosubscribe_enabled(self):
        """Return the udf_autosubscribe config value."""
        return self.service.config.udf_autosubscribe_enabled()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def enable_udf_autosubscribe(self):
        """Enable UDF autosubscribe."""
        self.service.config.enable_udf_autosubscribe()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def disable_udf_autosubscribe(self):
        """Disable UDF autosubscribe."""
        self.service.config.disable_udf_autosubscribe()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='b')
    def share_autosubscribe_enabled(self):
        """Return the share_autosubscribe config value."""
        return self.service.config.share_autosubscribe_enabled()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def enable_share_autosubscribe(self):
        """Enable share autosubscribe."""
        self.service.config.enable_share_autosubscribe()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def disable_share_autosubscribe(self):
        """Disable share autosubscribe."""
        self.service.config.disable_share_autosubscribe()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='b', out_signature='')
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

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='b')
    def files_sync_enabled(self):
        """Return the files_sync_enabled config value."""
        return self.service.config.files_sync_enabled()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def enable_files_sync(self):
        """Enable file sync service."""
        self.service.config.enable_files_sync()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def disable_files_sync(self):
        """Disable file sync service."""
        self.service.config.disable_files_sync()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='b')
    def autoconnect_enabled(self):
        """Return the autoconnect config value."""
        return self.service.config.autoconnect_enabled()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def enable_autoconnect(self):
        """Enable syncdaemon autoconnect."""
        self.service.config.enable_autoconnect()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='', out_signature='')
    def disable_autoconnect(self):
        """Disable syncdaemon autoconnect."""
        self.service.config.disable_autoconnect()

    @dbus.service.method(DBUS_IFACE_CONFIG_NAME,
                         in_signature='b', out_signature='')
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


class Folders(DBusExposedObject):
    """An interface to interact with User Defined Folders."""

    path = '/folders'

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME, in_signature='s')
    def create(self, path):
        """Create a user defined folder in the specified path."""
        return self.service.folders.create(path)

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME, in_signature='s')
    def delete(self, folder_id):
        """Delete the folder specified by folder_id"""
        return self.service.folders.delete(folder_id)

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME,
                         in_signature='s', out_signature='b')
    def validate_path(self, path):
        """Return True if the path is valid for a folder"""
        return self.service.folders.validate_path(path)

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME, out_signature='aa{ss}')
    def get_folders(self):
        """Return the list of folders (a list of dicts)"""
        return self.service.folders.get_folders()

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME,
                         in_signature='s', out_signature='')
    def subscribe(self, folder_id):
        """Subscribe to the specified folder"""
        self.service.folders.subscribe(folder_id)

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME,
                         in_signature='s', out_signature='')
    def unsubscribe(self, folder_id):
        """Unsubscribe from the specified folder"""
        self.service.folders.unsubscribe(folder_id)

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME,
                         in_signature='s', out_signature='a{ss}')
    def get_info(self, path):
        """Return a dict containing the folder information."""
        return self.service.folders.get_info(path)

    @dbus.service.method(DBUS_IFACE_FOLDERS_NAME,
                         in_signature='', out_signature='')
    def refresh_volumes(self):
        """Refresh the volumes list, requesting it to the server."""
        self.service.folders.refresh_volumes()

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}')
    def FolderCreated(self, folder_info):
        """Notify the creation of a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}s')
    def FolderCreateError(self, folder_info, error):
        """Notify an error during the creation of a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}')
    def FolderDeleted(self, folder_info):
        """Notify the deletion of a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}s')
    def FolderDeleteError(self, folder_info, error):
        """Notify an error during the deletion of a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}')
    def FolderSubscribed(self, folder_info):
        """Notify the subscription to a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}s')
    def FolderSubscribeError(self, folder_info, error):
        """Notify an error while subscribing to a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}')
    def FolderUnSubscribed(self, folder_info):
        """Notify the unsubscription to a user defined folder."""

    @dbus.service.signal(DBUS_IFACE_FOLDERS_NAME,
                         signature='a{ss}s')
    def FolderUnSubscribeError(self, folder_info, error):
        """Notify an error while unsubscribing from a user defined folder."""


class Launcher(DBusExposedObject):
    """A DBus interface to interact with the launcher icon."""

    path = '/launcher'

    @dbus.service.method(DBUS_IFACE_LAUNCHER_NAME)
    def unset_urgency(self):
        """Unset urgency on the launcher."""
        result = launcher.Launcher()
        result.set_urgent(False)


class PublicFiles(DBusExposedObject):
    """An interface for handling public files."""

    path = '/publicfiles'

    @dbus.service.method(DBUS_IFACE_PUBLIC_FILES_NAME,
                         in_signature='ssb', out_signature='')
    def change_public_access(self, share_id, node_id, is_public):
        """Change the public access of a file."""
        self.service.public_files.change_public_access(share_id, node_id,
                                                       is_public)

    @dbus.service.method(DBUS_IFACE_PUBLIC_FILES_NAME)
    def get_public_files(self):
        """Request the list of public files to the server.

        The result will be send in a PublicFilesList signal.
        """
        self.service.public_files.get_public_files()

    @dbus.service.signal(DBUS_IFACE_PUBLIC_FILES_NAME,
                         signature='a{ss}')
    def PublicAccessChanged(self, file_info):
        """Notify the new public access state of a file."""

    @dbus.service.signal(DBUS_IFACE_PUBLIC_FILES_NAME,
                         signature='a{ss}s')
    def PublicAccessChangeError(self, file_info, error):
        """Report an error in changing the public access of a file."""

    @dbus.service.signal(DBUS_IFACE_PUBLIC_FILES_NAME,
                         signature='aa{ss}')
    def PublicFilesList(self, files):
        """Notify the list of public files."""

    @dbus.service.signal(DBUS_IFACE_PUBLIC_FILES_NAME,
                         signature='s')
    def PublicFilesListError(self, error):
        """Report an error in geting the public files list."""


class DBusInterface(object):
    """Holder of all DBus exposed objects."""

    def __init__(self, service, bus=None, system_bus=None):
        """Create and add the exposed object to the specified bus.

        - 'service' is the multiplatform service interface.
        - 'bus' if None will be the SessionBus.
        - 'system_bus' if None will be the SystemBus.

        """
        super(DBusInterface, self).__init__()
        if bus is None:
            logger.debug('using the real session bus')
            self.bus = dbus.SessionBus()
        else:
            self.bus = bus

        if system_bus is None:
            logger.debug('using the real system bus')
            self.system_bus = dbus.SystemBus()
        else:
            self.system_bus = system_bus

        self.busName = dbus.service.BusName(DBUS_IFACE_NAME, bus=self.bus)

        self.events = Events(self.busName, service)
        self.status = Status(self.busName, service)
        self.sync_daemon = SyncDaemon(self.busName, service)
        self.file_system = FileSystem(self.busName, service)
        self.shares = Shares(self.busName, service)
        self.folders = Folders(self.busName, service)
        self.launcher = Launcher(self.busName, service)
        self.public_files = PublicFiles(self.busName, service)
        self.config = Config(self.busName, service)
        self.service = service

        logger.info('DBusInterface initialized.')

    def start(self):
        """Start listening for ipc messages."""
        return defer.succeed(None)

    def shutdown(self, with_restart=False):
        """Remove the registered object from the bus."""
        logger.info('Shutting down DBusInterface!')
        self.status.remove_from_connection()
        self.events.remove_from_connection()
        self.sync_daemon.remove_from_connection()
        self.file_system.remove_from_connection()
        self.shares.remove_from_connection()
        self.config.remove_from_connection()
        self.folders.remove_from_connection()
        self.launcher.remove_from_connection()
        self.bus.release_name(self.busName.get_name())
        if with_restart:
            # this is what activate_name_owner boils down to, except that
            # activate_name_owner blocks, which is a luxury we can't allow
            # ourselves.
            self.bus.call_async(dbus.bus.BUS_DAEMON_NAME,
                                dbus.bus.BUS_DAEMON_PATH,
                                dbus.bus.BUS_DAEMON_IFACE,
                                'StartServiceByName', 'su',
                                (DBUS_IFACE_NAME, 0),
                                self._restart_reply_handler,
                                self._restart_error_handler)

    def _restart_reply_handler(self, *args):
        """Called by the restart async call.

        It's here to be stepped on from tests; in production we are
        going away and don't really care if the async call works or
        not: there is nothing we can do about it.
        """
    _restart_error_handler = _restart_reply_handler
