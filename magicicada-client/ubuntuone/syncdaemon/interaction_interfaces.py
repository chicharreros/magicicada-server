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
"""Interface used to interact with the syncdaemon.

ATTENTION: this is a boundary between platform dependent external interfaces
(such as the DBus interface in Linux and the perspective broker interface in
Windows) and syncdaemon.

Syncdaemon handles ONLY string volume ID's and ONLY string paths (always bytes
encoded with utf-8). We assume the external interfaces will ALWAYS handle
unicode, so ID's and paths will be encoded to bytes with utf-8 in this layer.
"""

import collections
import logging
import os
import uuid

from functools import wraps

from twisted.internet import defer

from ubuntuone.networkstate import NetworkManagerState
try:
    from ubuntuone.networkstate.networkstates import ONLINE
except ImportError:
    from ubuntuone.networkstate import ONLINE

from ubuntuone.logger import log_call
from ubuntuone.platform import ExternalInterface
from ubuntuone.storageprotocol import request
from ubuntuone.syncdaemon import config
from ubuntuone.syncdaemon.action_queue import Download, Upload
from ubuntuone.syncdaemon.interfaces import IMarker
from ubuntuone.syncdaemon.volume_manager import Share, UDF, VolumeDoesNotExist


logger = logging.getLogger("ubuntuone.SyncDaemon.InteractionInterfaces")


class NoAccessToken(Exception):
    """The access token could not be retrieved."""


def bool_str(value):
    """Return a string value that can be converted back to bool."""
    return 'True' if value else ''


def get_share_dict(share):
    """Get a dict with all the attributes of: share."""
    share_dict = share.__dict__.copy()
    if 'subscribed' not in share_dict:
        share_dict['subscribed'] = share.subscribed
    for k, v in share_dict.items():
        if v is None:
            share_dict[unicode(k)] = ''
        elif k == 'path':
            share_dict[unicode(k)] = v.decode('utf-8')
        elif k == 'accepted' or k == 'subscribed':
            share_dict[unicode(k)] = bool_str(v)
        else:
            share_dict[unicode(k)] = unicode(v)
    return share_dict


def get_udf_dict(udf):
    """Get a dict with all the attributes of: udf."""
    udf_dict = udf.__dict__.copy()
    for k, v in udf_dict.items():
        if v is None:
            udf_dict[unicode(k)] = ''
        elif k == 'subscribed':
            udf_dict[unicode(k)] = bool_str(v)
        elif k == 'path':
            udf_dict[unicode(k)] = v.decode('utf-8')
        elif k == 'suggested_path' and isinstance(v, str):
            udf_dict[unicode(k)] = v.decode('utf-8')
        else:
            udf_dict[unicode(k)] = unicode(v)
    return udf_dict


def sanitize_dict(data):
    """Sanitize *IN PLACE* a dict values to go through IPC."""
    for k, v in data.items():
        if IMarker.providedBy(v):
            # this goes first, as it also is instance of basestring
            data[k] = repr(v)
        elif isinstance(v, basestring):
            pass  # to avoid str() to already strings
        elif isinstance(v, bool):
            data[k] = bool_str(v)
        elif v is None:
            data[k] = 'None'
        else:
            data[k] = str(v)


def unicode_to_bytes(f):
    """Decorator to normalize unicode params into utf-8 bytes."""

    def handle_mapping(mapping, to_bytes):
        """Convert all the values in 'mapping' from unicode to utf-8 bytes."""
        result = {}
        for key, value in mapping.iteritems():
            result[key] = handle_item(value, to_bytes)
        return result

    def handle_sequence(sequence, to_bytes):
        """Convert all the items in 'sequence' from unicode to utf-8 bytes."""
        result = []
        for value in sequence:
            result.append(handle_item(value, to_bytes))
        return result

    def handle_item(item, to_bytes):
        """Convert any item from unicode to utf-8 bytes."""
        # Do not change the order of the guards, since str() conforms Sequence
        if isinstance(item, str):
            if not to_bytes:
                item = item.decode('utf-8')
        elif isinstance(item, unicode):
            if to_bytes:
                item = item.encode('utf-8')
        elif isinstance(item, collections.Mapping):
            item = handle_mapping(item, to_bytes)
        elif isinstance(item, collections.Sequence):
            item = handle_sequence(item, to_bytes)

        return item

    @wraps(f)
    def inner(*args, **kwargs):
        """Encode every unicode param into utf-8 bytes.

        Call 'f' with the normalized params, and decode the result, if
        possible, into a unicode.

        """
        new_args = handle_sequence(args, to_bytes=True)
        new_kwargs = handle_mapping(kwargs, to_bytes=True)

        result = f(*new_args, **new_kwargs)

        return handle_item(result, to_bytes=False)

    return inner


class SyncdaemonObject(object):
    """Represent a basic syncdaemon object."""

    def __init__(self, main, interface):
        super(SyncdaemonObject, self).__init__()
        self.main = main
        self.interface = interface

        self.action_queue = main.action_q
        self.fs_manager = main.fs
        self.vm = main.vm

    def _get_current_state(self):
        """Get the current status of the system."""
        state = self.main.state_manager.state
        connection = self.main.state_manager.connection.state
        queues = self.main.state_manager.queues.state.name
        state_dict = {
            'name': state.name,
            'description': state.description,
            'is_error': bool_str(state.is_error),
            'is_connected': bool_str(state.is_connected),
            'is_online': bool_str(state.is_online),
            'queues': queues,
            'connection': connection,
        }
        return state_dict

    def _get_volume_info(self, volume_id):
        """Build a dict to send to external interfaces with 'volume_id'."""
        # be redundant to support old APIs
        return {'volume_id': volume_id, 'id': volume_id}


class SyncdaemonStatus(SyncdaemonObject):
    """Represent the status of the syncdaemon."""

    @log_call(logger.debug)
    def current_status(self):
        """Return the current status of syncdaemon.

        The result is a dictionary with the following fields:

        - connection
        - description
        - is_connected
        - is_error
        - is_online
        - queues

        """
        return self._get_current_state()

    def current_uploads(self):
        """Return a list of files with a upload in progress."""
        current_uploads = []
        for cmd in self.action_queue.queue.waiting:
            if isinstance(cmd, Upload) and cmd.running:
                entry = {
                    'path': cmd.path,
                    'share_id': cmd.share_id,
                    'node_id': cmd.node_id,
                    'n_bytes_written': str(cmd.n_bytes_written),
                }
                if cmd.deflated_size is not None:
                    entry['deflated_size'] = str(cmd.deflated_size)
                current_uploads.append(entry)
        return current_uploads

    def current_downloads(self):
        """Return a list of files with a download in progress."""
        current_downloads = []
        for cmd in self.action_queue.queue.waiting:
            if isinstance(cmd, Download) and cmd.running:
                entry = {
                    'path': cmd.path,
                    'share_id': cmd.share_id,
                    'node_id': cmd.node_id,
                    'n_bytes_read': str(cmd.n_bytes_read),
                }
                if cmd.deflated_size is not None:
                    entry['deflated_size'] = str(cmd.deflated_size)
                current_downloads.append(entry)
        return current_downloads

    @unicode_to_bytes
    @log_call(logger.debug)
    def free_space(self, volume_id):
        """Return the free space for the given volume."""
        return self.main.vm.get_free_space(volume_id)

    def waiting(self):
        """Return a list of the operations in action queue."""
        waiting = []
        for cmd in self.action_queue.queue.waiting:
            operation = cmd.__class__.__name__
            data = cmd.to_dict()
            sanitize_dict(data)
            waiting.append((operation, str(id(cmd)), data))
        return waiting

    def waiting_metadata(self):
        """Return a list of the operations in the meta-queue.

        As we don't have meta-queue anymore, this is faked.
        """
        logger.warning('waiting_metadata is deprecated. '
                       'Use "waiting" instead.')
        waiting_metadata = []
        for cmd in self.action_queue.queue.waiting:
            if not isinstance(cmd, (Upload, Download)):
                operation = cmd.__class__.__name__
                data = cmd.to_dict()
                sanitize_dict(data)
                waiting_metadata.append((operation, data))
        return waiting_metadata

    def waiting_content(self):
        """Return a list of files that are waiting to be up- or downloaded.

        As we don't have content-queue anymore, this is faked.
        """
        logger.warning('waiting_content is deprecated. Use "waiting" instead.')
        waiting_content = []
        for cmd in self.action_queue.queue.waiting:
            if isinstance(cmd, (Upload, Download)):
                data = dict(path=cmd.path, share=cmd.share_id,
                            node=cmd.node_id, operation=cmd.__class__.__name__)
                sanitize_dict(data)
                waiting_content.append(data)
        return waiting_content

    def sync_menu(self):
        """Return the info necessary to construct the menu."""
        return self.main.status_listener.menu_data()


class SyncdaemonFileSystem(SyncdaemonObject):
    """An interface to the FileSystem Manager."""

    @unicode_to_bytes
    @log_call(logger.debug)
    def get_metadata(self, path):
        """Return the metadata (as a dict) for the specified path."""
        real_path = os.path.realpath(path)
        mdobj = self.fs_manager.get_by_path(real_path)
        md_dict = self._mdobj_dict(mdobj)
        md_dict['path'] = path
        return md_dict

    @unicode_to_bytes
    @log_call(logger.debug)
    def get_metadata_by_node(self, share_id, node_id):
        """Return the metadata (as a dict) for the specified share/node."""
        mdobj = self.fs_manager.get_by_node_id(share_id, node_id)
        md_dict = self._mdobj_dict(mdobj)
        path = self.fs_manager.get_abspath(mdobj.share_id, mdobj.path)
        md_dict['path'] = path
        return md_dict

    @unicode_to_bytes
    @log_call(logger.debug)
    def get_metadata_and_quick_tree_synced(self, path):
        """Return the metadata (as a dict) for the specified path.

        Include the quick subtree status.

        """
        real_path = os.path.realpath(path)
        mdobj = self.fs_manager.get_by_path(real_path)
        md_dict = self._mdobj_dict(mdobj)
        md_dict['path'] = path
        if self._path_in_queue(real_path):
            md_dict['quick_tree_synced'] = ''
        else:
            md_dict['quick_tree_synced'] = 'synced'
        return md_dict

    def _path_in_queue(self, path):
        """Return whether there are queued commands pertaining to the path."""
        for cmd in self.action_queue.queue.waiting:
            share_id = getattr(cmd, 'share_id', None)
            node_id = getattr(cmd, 'node_id', None)
            if share_id is not None and node_id is not None:
                # XXX: nested try/excepts in a loop are probably a
                # sign that I'm doing something wrong - or that
                # somebody is :)
                this_path = ''
                try:
                    node_md = self.fs_manager.get_by_node_id(share_id, node_id)
                except KeyError:
                    # maybe it's actually the mdid?
                    try:
                        node_md = self.fs_manager.get_by_mdid(node_id)
                    except KeyError:
                        # hm, nope. Dunno what to do then
                        pass
                    else:
                        this_path = self.fs_manager.get_abspath(share_id,
                                                                node_md.path)
                else:
                    this_path = self.fs_manager.get_abspath(share_id,
                                                            node_md.path)
                if this_path.startswith(path):
                    return True
        return False

    def _mdobj_dict(self, mdobj):
        """Return a dict from a MDObject."""
        md_dict = {}
        for k, v in mdobj.__dict__.items():
            if k == 'info':
                continue
            elif k == 'path':
                md_dict[str(k)] = v.decode('utf-8')
            else:
                md_dict[str(k)] = str(v)
        if mdobj.__dict__.get('info', None):
            for k, v in mdobj.info.__dict__.items():
                md_dict['info_' + str(k)] = str(v)
        return md_dict

    @log_call(logger.debug)
    def get_dirty_nodes(self):
        """Return a list of dirty nodes."""
        mdobjs = self.fs_manager.get_dirty_nodes()
        dirty_nodes = []
        for mdobj in mdobjs:
            dirty_nodes.append(self._mdobj_dict(mdobj))
        return dirty_nodes

    @unicode_to_bytes
    @log_call(logger.debug, with_result=False)
    def search_files(self, pattern):
        """Search for the occurrence of pattern in the files names."""
        return self.fs_manager.get_paths_by_pattern(pattern)


class SyncdaemonShares(SyncdaemonObject):
    """An interface to interact with shares."""

    @unicode_to_bytes
    @log_call(logger.debug)
    def get_volume(self, share_id):
        """Return the volume for the given share."""
        return self.vm.get_volume(share_id)

    @log_call(logger.debug)
    def get_shares(self):
        """Return a list of dicts, each dict represents a share."""
        shares = []
        for share_id, share in self.vm.shares.items():
            if share_id == request.ROOT:
                continue
            info = get_share_dict(share)
            shares.append(info)
        return shares

    @unicode_to_bytes
    @log_call(logger.debug)
    def accept_share(self, share_id):
        """Accept a share.

        A ShareAnswerOk|Error signal will be fired in the future as a
        success/failure indicator.

        """
        self.vm.accept_share(share_id, True)

    @unicode_to_bytes
    @log_call(logger.debug)
    def reject_share(self, share_id):
        """Reject a share."""
        self.vm.accept_share(share_id, False)

    @unicode_to_bytes
    @log_call(logger.debug)
    def delete_share(self, share_id):
        """Delete a Share, both kinds: "to me" and "from me"."""
        try:
            self.vm.delete_volume(share_id)
        except VolumeDoesNotExist:
            # isn't a volume! it might be a "share from me (a.k.a shared)"
            self.vm.delete_share(share_id)

    @unicode_to_bytes
    @log_call(logger.debug)
    def subscribe(self, share_id):
        """Subscribe to the specified share."""
        self.vm.subscribe_share(share_id)

    @unicode_to_bytes
    @log_call(logger.debug)
    def unsubscribe(self, share_id):
        """Unsubscribe from the specified share."""
        self.vm.unsubscribe_share(share_id)

    @log_call(logger.debug)
    def create_share(self, path, username, name, access_level):
        """Share a subtree to the user identified by username.

        @param path: that path to share (the root of the subtree)
        @param username: the username to offer the share to
        @param name: the name of the share
        @param access_level: ACCESS_LEVEL_RO or ACCESS_LEVEL_RW
        """
        path = path.encode("utf-8")
        username = unicode(username)
        name = unicode(name)
        try:
            self.fs_manager.get_by_path(path)
        except KeyError:
            raise ValueError("path '%r' does not exist" % path)
        self.vm.create_share(path, username, name, access_level)

    @log_call(logger.debug)
    def create_shares(self, path, usernames, name, access_level):
        """Share a subtree with several users at once.

        @param path: that path to share (the root of the subtree)
        @param usernames: the user names to offer the share to
        @param name: the name of the share
        @param access_level: ACCESS_LEVEL_RO or ACCESS_LEVEL_RW
        """
        for user in usernames:
            self.create_share(path, user, name, access_level)

    @log_call(logger.debug)
    def refresh_shares(self):
        """Refresh the share list, requesting it to the server."""
        self.vm.refresh_shares()

    @log_call(logger.debug)
    def get_shared(self):
        """Return a list of dicts, each dict represents a shared share.

        A share might not have the path set, as we might be still fetching the
        nodes from the server. In these cases the path is ''.

        """
        shares = []
        for share_id, share in self.vm.shared.items():
            if share_id == request.ROOT:
                continue
            info = get_share_dict(share)
            shares.append(info)
        return shares


class SyncdaemonConfig(SyncdaemonObject):
    """The Syncdaemon config/settings interface."""

    @log_call(logger.debug)
    def get_throttling_limits(self):
        """Get the read/write limit from AQ and return a dict.

        Return a dict(download=int, upload=int), if int is -1 the value isn't
        configured. The values are bytes/second.

        """
        download = -1
        upload = -1
        if self.action_queue.readLimit is not None:
            download = self.action_queue.readLimit
        if self.action_queue.writeLimit is not None:
            upload = self.action_queue.writeLimit
        info = dict(download=download, upload=upload)
        return info

    @log_call(logger.debug)
    def set_throttling_limits(self, download, upload):
        """Set the read and write limits. The expected values are bytes/sec."""
        # modify and save the config file
        user_config = config.get_user_config()
        user_config.set_throttling_read_limit(download)
        user_config.set_throttling_write_limit(upload)
        user_config.save()

        # modify AQ settings
        if download == -1:
            download = None
        if upload == -1:
            upload = None
        self.action_queue.readLimit = download
        self.action_queue.writeLimit = upload

    @log_call(logger.debug)
    def enable_bandwidth_throttling(self):
        """Enable bandwidth throttling."""
        self._set_throttling_enabled(True)

    @log_call(logger.debug)
    def disable_bandwidth_throttling(self):
        """Disable bandwidth throttling."""
        self._set_throttling_enabled(False)

    def _set_throttling_enabled(self, enabled):
        """Set throttling enabled value and save the config."""
        # modify and save the config file
        user_config = config.get_user_config()
        user_config.set_throttling(enabled)
        user_config.save()
        # modify AQ settings
        if enabled:
            self.action_queue.enable_throttling()
        else:
            self.action_queue.disable_throttling()

    @log_call(logger.debug)
    def bandwidth_throttling_enabled(self):
        """Return whether the bandwidth throttling is enabled."""
        return self.action_queue.throttling_enabled

    @log_call(logger.debug)
    def udf_autosubscribe_enabled(self):
        """Return the udf_autosubscribe config value."""
        return config.get_user_config().get_udf_autosubscribe()

    @log_call(logger.debug)
    def enable_udf_autosubscribe(self):
        """Enable UDF autosubscribe."""
        user_config = config.get_user_config()
        user_config.set_udf_autosubscribe(True)
        user_config.save()

    @log_call(logger.debug)
    def disable_udf_autosubscribe(self):
        """Enable UDF autosubscribe."""
        user_config = config.get_user_config()
        user_config.set_udf_autosubscribe(False)
        user_config.save()

    @log_call(logger.debug)
    def share_autosubscribe_enabled(self):
        """Return the share_autosubscribe config value."""
        return config.get_user_config().get_share_autosubscribe()

    @log_call(logger.debug)
    def enable_share_autosubscribe(self):
        """Enable UDF autosubscribe."""
        user_config = config.get_user_config()
        user_config.set_share_autosubscribe(True)
        user_config.save()

    @log_call(logger.debug)
    def disable_share_autosubscribe(self):
        """Enable UDF autosubscribe."""
        user_config = config.get_user_config()
        user_config.set_share_autosubscribe(False)
        user_config.save()

    @log_call(logger.debug)
    def files_sync_enabled(self):
        """Return the files_sync_enabled config value."""
        return config.get_user_config().get_files_sync_enabled()

    @log_call(logger.debug)
    def enable_files_sync(self):
        """Enable file sync service."""
        user_config = config.get_user_config()
        user_config.set_files_sync_enabled(True)
        user_config.save()

    @log_call(logger.debug)
    def disable_files_sync(self):
        """Disable file sync service."""
        user_config = config.get_user_config()
        user_config.set_files_sync_enabled(False)
        user_config.save()

    @log_call(logger.debug)
    def autoconnect_enabled(self):
        """Return the autoconnect config value."""
        return config.get_user_config().get_autoconnect()

    @log_call(logger.debug)
    def enable_autoconnect(self):
        """Enable syncdaemon autoconnect."""
        user_config = config.get_user_config()
        user_config.set_autoconnect(True)
        user_config.save()

    @log_call(logger.debug)
    def disable_autoconnect(self):
        """Disable syncdaemon autoconnect."""
        user_config = config.get_user_config()
        user_config.set_autoconnect(False)
        user_config.save()


class SyncdaemonFolders(SyncdaemonObject):
    """A interface to interact with User Defined Folders"""

    @unicode_to_bytes
    @log_call(logger.debug)
    def create(self, path):
        """Create a user defined folder in the specified path."""
        self.vm.create_udf(path)

    @unicode_to_bytes
    @log_call(logger.info)
    def delete(self, folder_id):
        """Delete the folder specified by folder_id."""
        self.vm.delete_volume(folder_id)

    @unicode_to_bytes
    @log_call(logger.debug)
    def validate_path(self, path):
        """Return True if the path is valid for a folder."""
        # Returns (bool, str), but we only care about the bool from here on.
        return self.vm.validate_path_for_folder(path)[0]

    @log_call(logger.debug)
    def get_folders(self):
        """Return the list of folders (a list of dicts)."""
        return [get_udf_dict(udf) for udf in self.vm.udfs.values()]

    @unicode_to_bytes
    @log_call(logger.debug)
    def subscribe(self, folder_id):
        """Subscribe to the specified folder."""
        self.vm.subscribe_udf(folder_id)

    @unicode_to_bytes
    @log_call(logger.debug)
    def unsubscribe(self, folder_id):
        """Unsubscribe from the specified folder."""
        self.vm.unsubscribe_udf(folder_id)

    @unicode_to_bytes
    @log_call(logger.debug)
    def get_info(self, path):
        """Return a dict containing the folder information."""
        mdobj = self.fs_manager.get_by_path(path)
        udf = self.vm.udfs.get(mdobj.share_id, None)
        if udf is None:
            return dict()
        else:
            return get_udf_dict(udf)

    @log_call(logger.debug)
    def refresh_volumes(self):
        """Refresh the volumes list, requesting it to the server."""
        self.vm.refresh_volumes()


class SyncdaemonPublicFiles(SyncdaemonObject):
    """A interface for handling public files."""

    @log_call(logger.debug)
    def change_public_access(self, share_id, node_id, is_public):
        """Change the public access of a file."""
        if share_id:
            share_id = uuid.UUID(share_id)
        else:
            share_id = None
        node_id = uuid.UUID(node_id)
        self.action_queue.change_public_access(share_id, node_id, is_public)

    @log_call(logger.debug)
    def get_public_files(self):
        """Request the list of public files to the server.

        The result will be send in a PublicFilesList signal.
        """
        self.action_queue.get_public_files()


class SyncdaemonEvents(SyncdaemonObject):
    """The events of the system translated to IPC signals."""

    @unicode_to_bytes
    @log_call(logger.debug)
    def push_event(self, event_name, args):
        """Push an event to the event queue."""
        self.main.event_q.push(event_name, **args)


class SyncdaemonEventListener(SyncdaemonObject):
    """An Event Queue Listener."""

    @unicode_to_bytes
    def _get_path(self, share_id, node_id):
        """Get the path from the given ids.

        This is an unicode boundary, so return an unicode path.

        """
        try:
            relpath = self.fs_manager.get_by_node_id(share_id, node_id).path
        except KeyError:
            path = ''
        else:
            path = self.fs_manager.get_abspath(share_id, relpath)
        return path

    def _path_from_ids(self, share_id, node_id, signal_name,
                       info=None, error_info=None):
        """Return the path for the entry (share_id, node_id)."""
        path = None
        try:
            mdobj = self.fs_manager.get_by_node_id(share_id, node_id)
            if not mdobj.is_dir:
                path = self.fs_manager.get_abspath(share_id, mdobj.path)
        except KeyError as e:
            msg = 'The metadata is gone before sending %s signal' % signal_name
            args = dict(message=msg, error=str(e),
                        share_id=share_id, node_id=node_id)
            if error_info is not None:
                args.update(error_info)
            self.interface.status.SignalError(signal_name, args)

        if path is not None:
            # unicode boundary! external interfaces expect unicode paths
            path = path.decode('utf-8')
            signal = getattr(self.interface.status, signal_name)
            if info is None:
                signal(path)
            else:
                signal(path, info)

    @log_call(logger.debug)
    def handle_AQ_DOWNLOAD_STARTED(self, share_id, node_id, server_hash):
        """Handle AQ_DOWNLOAD_STARTED."""
        self._path_from_ids(share_id, node_id, 'DownloadStarted')

    @log_call(logger.trace)
    def handle_AQ_DOWNLOAD_FILE_PROGRESS(self, share_id, node_id,
                                         n_bytes_read, deflated_size):
        """Handle AQ_DOWNLOAD_FILE_PROGRESS."""
        info = dict(n_bytes_read=str(n_bytes_read),
                    deflated_size=str(deflated_size))
        self._path_from_ids(share_id, node_id, 'DownloadFileProgress', info)

    @log_call(logger.debug)
    def handle_FSM_PARTIAL_COMMITED(self, share_id, node_id):
        """Handle FSM_PARTIAL_COMMITED."""
        self._path_from_ids(share_id, node_id, 'DownloadFinished', info={})

    @log_call(logger.debug)
    def handle_AQ_DOWNLOAD_ERROR(self, share_id, node_id, server_hash, error):
        """Handle AQ_DOWNLOAD_ERROR."""
        self._path_from_ids(share_id, node_id, 'DownloadFinished',
                            info=dict(error=str(error)),
                            error_info=dict(download_error=str(error)))

    @log_call(logger.debug)
    def handle_AQ_UPLOAD_STARTED(self, share_id, node_id, hash):
        """Handle AQ_UPLOAD_STARTED."""
        self._path_from_ids(share_id, node_id, 'UploadStarted')

    @log_call(logger.trace)
    def handle_AQ_UPLOAD_FILE_PROGRESS(self, share_id, node_id,
                                       n_bytes_written, deflated_size):
        """Handle AQ_UPLOAD_FILE_PROGRESS."""
        info = dict(n_bytes_written=str(n_bytes_written),
                    deflated_size=str(deflated_size))
        self._path_from_ids(share_id, node_id, 'UploadFileProgress', info)

    @log_call(logger.debug)
    def handle_AQ_UPLOAD_FINISHED(self, share_id, node_id, hash,
                                  new_generation):
        """Handle AQ_UPLOAD_FINISHED."""
        self._path_from_ids(share_id, node_id, 'UploadFinished', info={})

    @log_call(logger.debug)
    def handle_AQ_UPLOAD_ERROR(self, share_id, node_id, error, hash):
        """Handle AQ_UPLOAD_ERROR."""
        self._path_from_ids(share_id, node_id, 'UploadFinished',
                            info=dict(error=str(error)),
                            error_info=dict(upoad_error=str(error)))

    @log_call(logger.debug)
    def handle_SV_ACCOUNT_CHANGED(self, account_info):
        """Handle SV_ACCOUNT_CHANGED."""
        info = dict(purchased_bytes=unicode(account_info.purchased_bytes))
        self.interface.status.AccountChanged(info)

    @log_call(logger.debug)
    def handle_FS_INVALID_NAME(self, dirname, filename):
        """Handle FS_INVALID_NAME."""
        # unicode boundary! external interfaces expect unicode paths
        dirname = dirname.decode('utf-8')
        self.interface.status.InvalidName(dirname, str(filename))

    @log_call(logger.debug)
    def handle_SYS_BROKEN_NODE(self, volume_id, node_id, mdid, path):
        """Handle SYS_BROKEN_NODE."""
        if mdid is None:
            mdid = ''
        if path is None:
            path = ''
        # unicode boundary! external interfaces expect unicode paths
        path = path.decode('utf-8')
        self.interface.status.BrokenNode(volume_id, node_id, mdid, path)

    @log_call(logger.debug)
    def handle_SYS_STATE_CHANGED(self, state):
        """Handle SYS_STATE_CHANGED."""
        info = self._get_current_state()
        self.interface.status.StatusChanged(info)

    @log_call(logger.debug)
    def handle_SV_FREE_SPACE(self, share_id, free_bytes):
        """Handle SV_FREE_SPACE event, emit ShareChanged signal."""
        share = self.vm.shares.get(share_id)
        if share is not None:
            info = get_share_dict(share)
            info['free_bytes'] = unicode(free_bytes)
            self.interface.shares.ShareChanged(info)

    @log_call(logger.debug)
    def handle_AQ_CREATE_SHARE_OK(self, share_id, marker):
        """Handle AQ_CREATE_SHARE_OK event, emit ShareCreated signal."""
        share = self.vm.shared.get(share_id)
        if share:
            info = get_share_dict(share)
        else:
            info = self._get_volume_info(share_id)
        self.interface.shares.ShareCreated(info)

    @log_call(logger.debug)
    def handle_AQ_CREATE_SHARE_ERROR(self, marker, error):
        """Handle AQ_CREATE_SHARE_ERROR event, emit ShareCreateError signal."""
        path = self.fs_manager.get_by_mdid(marker).path
        # unicode boundary! external interfaces expect unicode paths
        path = path.decode('utf-8')
        info = dict(path=path, marker=marker)
        self.interface.shares.ShareCreateError(info, error)

    @log_call(logger.debug)
    def handle_AQ_ANSWER_SHARE_OK(self, share_id, answer):
        """Handle AQ_ANSWER_SHARE_OK event, emit ShareAnswerOk signal."""
        answer_info = dict(volume_id=share_id, answer=answer)
        self.interface.shares.ShareAnswerResponse(answer_info)

    @log_call(logger.debug)
    def handle_AQ_ANSWER_SHARE_ERROR(self, share_id, answer, error):
        """Handle AQ_ANSWER_SHARE_ERROR event, emit ShareAnswerResponse signal.

        The info dict sent will contain a 'error' keyword with the string
        representantion of the error.

        """
        answer_info = dict(volume_id=share_id, answer=answer, error=error)
        self.interface.shares.ShareAnswerResponse(answer_info)

    @log_call(logger.debug)
    def handle_VM_UDF_SUBSCRIBED(self, udf):
        """Handle VM_UDF_SUBSCRIBED event, emit FolderSubscribed signal."""
        info = get_udf_dict(udf)
        self.interface.folders.FolderSubscribed(info)

    @log_call(logger.debug)
    def handle_VM_UDF_SUBSCRIBE_ERROR(self, udf_id, error):
        """Handle VM_UDF_SUBSCRIBE_ERROR, emit FolderSubscribeError signal."""
        info = self._get_volume_info(udf_id)
        self.interface.folders.FolderSubscribeError(info, str(error))

    @log_call(logger.debug)
    def handle_VM_UDF_UNSUBSCRIBED(self, udf):
        """Handle VM_UDF_UNSUBSCRIBED event, emit FolderUnSubscribed signal."""
        info = get_udf_dict(udf)
        self.interface.folders.FolderUnSubscribed(info)

    @log_call(logger.debug)
    def handle_VM_UDF_UNSUBSCRIBE_ERROR(self, udf_id, error):
        """Handle VM_UDF_UNSUBSCRIBE_ERROR, emit FolderUnSubscribeError."""
        info = self._get_volume_info(udf_id)
        self.interface.folders.FolderUnSubscribeError(info, str(error))

    @log_call(logger.debug)
    def handle_VM_UDF_CREATED(self, udf):
        """Handle VM_UDF_CREATED event, emit FolderCreated signal."""
        info = get_udf_dict(udf)
        self.interface.folders.FolderCreated(info)

    @log_call(logger.debug)
    def handle_VM_UDF_CREATE_ERROR(self, path, error):
        """Handle VM_UDF_CREATE_ERROR event, emit FolderCreateError signal."""
        # unicode boundary! external interfaces expect unicode paths
        path = path.decode('utf-8')
        self.interface.folders.FolderCreateError(dict(path=path), str(error))

    @log_call(logger.debug)
    def handle_VM_SHARE_SUBSCRIBED(self, share):
        """Handle VM_SHARE_SUBSCRIBED event, emit ShareSubscribed signal."""
        info = get_share_dict(share)
        self.interface.shares.ShareSubscribed(info)

    @log_call(logger.debug)
    def handle_VM_SHARE_SUBSCRIBE_ERROR(self, share_id, error):
        """Handle VM_SHARE_SUBSCRIBE_ERROR, emit ShareSubscribeError signal."""
        info = self._get_volume_info(share_id)
        self.interface.shares.ShareSubscribeError(info, str(error))

    @log_call(logger.debug)
    def handle_VM_SHARE_UNSUBSCRIBED(self, share):
        """Handle VM_SHARE_UNSUBSCRIBED event, emit ShareUnSubscribed."""
        info = get_share_dict(share)
        self.interface.shares.ShareUnSubscribed(info)

    @log_call(logger.debug)
    def handle_VM_SHARE_UNSUBSCRIBE_ERROR(self, share_id, error):
        """Handle VM_SHARE_UNSUBSCRIBE_ERROR, emit ShareUnSubscribeError."""
        info = self._get_volume_info(share_id)
        self.interface.shares.ShareUnSubscribeError(info, str(error))

    @log_call(logger.debug)
    def handle_VM_SHARE_CREATED(self, share_id):
        """Handle VM_SHARE_CREATED event, emit NewShare event."""
        share = self.vm.get_volume(share_id)
        self.interface.shares.NewShare(get_share_dict(share))

    @log_call(logger.debug)
    def handle_VM_SHARE_DELETED(self, share):
        """Handle VM_SHARE_DELETED event, emit ShareDeleted event."""
        self.interface.shares.ShareDeleted(get_share_dict(share))

    @log_call(logger.debug)
    def handle_VM_SHARE_DELETE_ERROR(self, share_id, error):
        """Handle VM_DELETE_SHARE_ERROR event, emit ShareCreateError signal."""
        info = self._get_volume_info(share_id)
        self.interface.shares.ShareDeleteError(info, error)

    @log_call(logger.debug)
    def handle_VM_VOLUME_DELETED(self, volume):
        """Handle VM_VOLUME_DELETED event.

        Emits FolderDeleted or ShareChanged signal.

        """
        if isinstance(volume, Share):
            self.interface.shares.ShareDeleted(get_share_dict(volume))
        elif isinstance(volume, UDF):
            self.interface.folders.FolderDeleted(get_udf_dict(volume))
        else:
            logger.error("Unable to handle VM_VOLUME_DELETED for "
                         "volume=%r as it's not a Share or UDF", volume)

    @log_call(logger.debug)
    def handle_VM_VOLUME_DELETE_ERROR(self, volume_id, error):
        """Handle VM_VOLUME_DELETE_ERROR event, emit ShareDeleted event."""
        try:
            volume = self.vm.get_volume(volume_id)
        except VolumeDoesNotExist:
            logger.error("Unable to handle VM_VOLUME_DELETE_ERROR for "
                         "volume_id=%r, no such volume.", volume_id)
        else:
            error = str(error)
            if isinstance(volume, Share):
                self.interface.shares.ShareDeleteError(get_share_dict(volume),
                                                       error)
            elif isinstance(volume, UDF):
                self.interface.folders.FolderDeleteError(get_udf_dict(volume),
                                                         error)
            else:
                logger.error("Unable to handle VM_VOLUME_DELETE_ERROR (%r) "
                             "for volume_id=%r as it's not a Share or UDF",
                             error, volume_id)

    @log_call(logger.debug)
    def handle_VM_SHARE_CHANGED(self, share_id):
        """Handle VM_SHARE_CHANGED event, emit's ShareChanged signal."""
        share = self.vm.shares.get(share_id)
        self.interface.shares.ShareChanged(get_share_dict(share))

    @log_call(logger.debug)
    def handle_VM_VOLUMES_CHANGED(self, volumes):
        """Handle VM_VOLUMES_CHANGED event, emit VolumeChanged signal."""
        str_volumes = []
        for volume in volumes:
            if isinstance(volume, UDF):
                str_volumes.append(get_udf_dict(volume))
            else:
                str_volumes.append(get_share_dict(volume))
        self.interface.sync_daemon.VolumesChanged(str_volumes)

    @log_call(logger.debug)
    def handle_AQ_CHANGE_PUBLIC_ACCESS_OK(self, share_id, node_id,
                                          is_public, public_url):
        """Handle the AQ_CHANGE_PUBLIC_ACCESS_OK event."""
        if share_id is None:
            share_id = ''
        share_id = str(share_id)
        node_id = str(node_id)
        path = self._get_path(share_id, node_id)
        info = dict(share_id=share_id, node_id=node_id,
                    is_public=bool_str(is_public),
                    public_url=public_url, path=path)
        self.interface.public_files.PublicAccessChanged(info)

    @log_call(logger.debug)
    def handle_AQ_CHANGE_PUBLIC_ACCESS_ERROR(self, share_id, node_id, error):
        """Handle the AQ_CHANGE_PUBLIC_ACCESS_ERROR event."""
        if share_id is None:
            share_id = ''
        share_id = str(share_id)
        node_id = str(node_id)
        path = self._get_path(share_id, node_id)
        info = dict(share_id=share_id, node_id=node_id, path=path)
        self.interface.public_files.PublicAccessChangeError(info, str(error))

    @log_call(logger.debug)
    def handle_AQ_PUBLIC_FILES_LIST_OK(self, public_files):
        """Handle the AQ_PUBLIC_FILES_LIST_OK event."""
        files = []
        for pf in public_files:
            volume_id = pf['volume_id']
            node_id = pf['node_id']
            public_url = pf['public_url']
            path = self._get_path(volume_id, node_id)
            files.append(dict(volume_id=volume_id, node_id=node_id,
                              public_url=public_url, path=path))
        self.interface.public_files.PublicFilesList(files)

    @log_call(logger.debug)
    def handle_AQ_PUBLIC_FILES_LIST_ERROR(self, error):
        """Handle the AQ_PUBLIC_FILES_LIST_ERROR event."""
        self.interface.public_files.PublicFilesListError(str(error))

    @log_call(logger.debug)
    def handle_SYS_ROOT_MISMATCH(self, root_id, new_root_id):
        """Handle the SYS_ROOT_MISMATCH event."""
        self.interface.sync_daemon.RootMismatch(root_id, new_root_id)

    @log_call(logger.debug)
    def handle_SYS_QUOTA_EXCEEDED(self, volume_id, free_bytes):
        """Handle the SYS_QUOTA_EXCEEDED event."""
        volume = self.vm.get_volume(volume_id)

        volume_dict = {}
        if isinstance(volume, UDF):
            volume_dict = get_udf_dict(volume)
        else:
            # either a Share or Root
            volume_dict = get_share_dict(volume)

        # be sure that the volume has the most updated free bytes info
        volume_dict['free_bytes'] = unicode(free_bytes)

        self.interface.sync_daemon.QuotaExceeded(volume_dict)

    def handle_SYS_QUEUE_ADDED(self, command):
        """Handle SYS_QUEUE_ADDED.

        The content and meta queue changed signals are deprecacted and
        will go away in a near future.
        """
        if isinstance(command, (Upload, Download)):
            self.interface.status.ContentQueueChanged()
        else:
            self.interface.status.MetaQueueChanged()

        data = command.to_dict()
        op_name = command.__class__.__name__
        op_id = id(command)
        sanitize_dict(data)
        self.interface.status.RequestQueueAdded(op_name, str(op_id), data)

    def handle_SYS_QUEUE_REMOVED(self, command):
        """Handle SYS_QUEUE_REMOVED.

        The content and meta queue changed signals are deprecacted and
        will go away in a near future.
        """
        if isinstance(command, (Upload, Download)):
            self.interface.status.ContentQueueChanged()
        else:
            self.interface.status.MetaQueueChanged()

        data = command.to_dict()
        op_name = command.__class__.__name__
        op_id = id(command)
        sanitize_dict(data)
        self.interface.status.RequestQueueRemoved(op_name, str(op_id), data)


class AllEventsSender(object):
    """Event listener that sends all of them through IPC."""

    def __init__(self, events):
        self.events = events

    def handle_default(self, event_name, **kwargs):
        """Handle all events."""
        event_dict = {'event_name': event_name}
        for key, value in kwargs.iteritems():
            event_dict[str(key)] = str(value)
        self.events.Event(event_dict)


class SyncdaemonService(SyncdaemonObject):
    """The main service."""

    def __init__(self, main, send_events=False, interface=None):
        super(SyncdaemonService, self).__init__(main, interface)

        self.send_events = send_events
        self.network_manager = NetworkManagerState(
            result_cb=self.network_state_changed)
        self.network_manager.find_online_state()

        if interface is None:
            self.interface = ExternalInterface(service=self)
        else:
            self.interface = interface

        self._create_children()

        self.main.event_q.subscribe(self.event_listener)
        self.all_events_sender = None
        if self.send_events:
            self.all_events_sender = AllEventsSender(self.interface.events)
            self.main.event_q.subscribe(self.all_events_sender)

        self.auth_credentials = None

    def _create_children(self):
        """Create the specific syncdaemon objects."""
        self.status = SyncdaemonStatus(self.main, self.interface)
        self.file_system = SyncdaemonFileSystem(self.main, self.interface)
        self.shares = SyncdaemonShares(self.main, self.interface)
        self.config = SyncdaemonConfig(self.main, self.interface)
        self.folders = SyncdaemonFolders(self.main, self.interface)
        self.public_files = SyncdaemonPublicFiles(self.main, self.interface)
        self.events = SyncdaemonEvents(self.main, self.interface)
        self.event_listener = SyncdaemonEventListener(self.main,
                                                      self.interface)
        self.sync = self  # for API compatibility

    @log_call(logger.info)
    def start(self):
        """Start listening for ipc messages."""
        return self.interface.start()

    @log_call(logger.info)
    def shutdown(self, with_restart=False):
        """Shutdown the interface and unsubscribe from the event queue."""
        self.main.event_q.unsubscribe(self.event_listener)
        if self.send_events:
            self.main.event_q.unsubscribe(self.all_events_sender)

        self.interface.shutdown(with_restart=with_restart)

    @log_call(logger.info)
    def connect(self, autoconnecting=True):
        """Push the SYS_USER_CONNECT event with the stored credentials.

        If 'autoconnecting' is False, nothing will be done.

        """
        d = defer.succeed(None)

        if not autoconnecting:
            logger.info('connect: autoconnecting not set, doing nothing.')
            return d

        if self.auth_credentials is None:
            logger.error('connect: autoconnecting set but no credentials.')
            return defer.fail(NoAccessToken("got empty credentials."))

        logger.debug('connect: auth credentials were given by parameter.')
        self.main.event_q.push(
            'SYS_USER_CONNECT', access_token=self.auth_credentials)

        return d

    @log_call(logger.debug)
    def disconnect(self):
        """Disconnect from the server."""
        self.main.event_q.push('SYS_USER_DISCONNECT')

    @log_call(logger.debug)
    def get_homedir(self):
        """Return the home dir point."""
        return self.main.get_homedir().decode('utf-8')

    @log_call(logger.debug)
    def get_rootdir(self):
        """Return the root dir/mount point."""
        return self.main.get_rootdir().decode('utf-8')

    @log_call(logger.debug)
    def get_sharesdir(self):
        """Return the shares dir/mount point."""
        return self.main.get_sharesdir().decode('utf-8')

    @log_call(logger.debug)
    def get_sharesdir_link(self):
        """Return the shares dir/mount point."""
        return self.main.get_sharesdir_link().decode('utf-8')

    @log_call(logger.debug)
    def wait_for_nirvana(self, last_event_interval):
        """Return a deferred that will be fired when nirvana is reached.

        Nirvana means there are no more events/transfers.

        """
        return self.main.wait_for_nirvana(last_event_interval)

    @log_call(logger.debug)
    def quit(self):
        """Shutdown the syncdaemon."""
        return self.main.quit()

    @unicode_to_bytes
    @log_call(logger.debug)
    def rescan_from_scratch(self, volume_id):
        """Request a rescan from scratch of the volume with volume_id."""
        # check that the volume exists
        volume = self.main.vm.get_volume(volume_id)
        self.main.action_q.rescan_from_scratch(volume.volume_id)

    @log_call(logger.debug)
    def network_state_changed(self, state):
        """Receive the connection state and call the proper function."""
        if state == ONLINE:
            self.network_connected()
        else:
            self.network_disconnected()

    @log_call(logger.debug)
    def network_connected(self):
        """Push the connected event."""
        self.main.event_q.push('SYS_NET_CONNECTED')

    @log_call(logger.debug)
    def network_disconnected(self):
        """Push the disconnected event."""
        self.main.event_q.push('SYS_NET_DISCONNECTED')
