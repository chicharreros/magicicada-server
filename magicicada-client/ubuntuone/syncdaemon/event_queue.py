# Copyright 2009-2012 Canonical Ltd.
# Copyright 2016-2017 Chicharreros
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
"""Module that implements the Event Queue machinery."""

import collections
import functools
import logging

from twisted.internet import defer

from ubuntuone.platform.os_helper import access
from ubuntuone.platform.filesystem_notifications.monitor import (
    FilesystemMonitor,
)

# these are our internal events, what is inserted into the whole system
EVENTS = {
    'FS_FILE_OPEN': ('path',),
    'FS_FILE_CLOSE_NOWRITE': ('path',),
    'FS_FILE_CLOSE_WRITE': ('path',),
    'FS_FILE_CREATE': ('path',),
    'FS_DIR_CREATE': ('path',),
    'FS_FILE_DELETE': ('path',),
    'FS_DIR_DELETE': ('path',),
    'FS_FILE_MOVE': ('path_from', 'path_to',),
    'FS_DIR_MOVE': ('path_from', 'path_to',),
    'FS_INVALID_NAME': ('dirname', 'filename',),

    'AQ_FILE_NEW_OK': ('volume_id', 'marker', 'new_id', 'new_generation'),
    'AQ_FILE_NEW_ERROR': ('marker', 'failure'),
    'AQ_DIR_NEW_OK': ('volume_id', 'marker', 'new_id', 'new_generation'),
    'AQ_DIR_NEW_ERROR': ('marker', 'failure'),
    'AQ_MOVE_OK': ('share_id', 'node_id', 'new_generation'),
    'AQ_MOVE_ERROR': ('share_id', 'node_id',
                      'old_parent_id', 'new_parent_id', 'new_name', 'error'),
    'AQ_UNLINK_OK': ('share_id', 'parent_id', 'node_id', 'new_generation',
                     'was_dir', 'old_path'),
    'AQ_UNLINK_ERROR': ('share_id', 'parent_id', 'node_id', 'error'),
    'AQ_DOWNLOAD_STARTED': ('share_id', 'node_id', 'server_hash'),
    'AQ_DOWNLOAD_FILE_PROGRESS': ('share_id', 'node_id',
                                  'n_bytes_read', 'deflated_size'),
    'AQ_DOWNLOAD_COMMIT': ('share_id', 'node_id', 'server_hash'),
    'AQ_DOWNLOAD_FINISHED': ('share_id', 'node_id', 'server_hash'),
    'AQ_DOWNLOAD_ERROR': ('share_id', 'node_id', 'server_hash', 'error'),
    'AQ_DOWNLOAD_DOES_NOT_EXIST': ('share_id', 'node_id'),
    'AQ_UPLOAD_STARTED': ('share_id', 'node_id', 'hash'),
    'AQ_UPLOAD_FILE_PROGRESS': ('share_id', 'node_id',
                                'n_bytes_written', 'deflated_size'),
    'AQ_UPLOAD_FINISHED': ('share_id', 'node_id', 'hash', 'new_generation'),
    'AQ_UPLOAD_ERROR': ('share_id', 'node_id', 'error', 'hash'),
    'AQ_SHARES_LIST': ('shares_list',),
    'AQ_LIST_SHARES_ERROR': ('error',),
    'AQ_CREATE_SHARE_OK': ('share_id', 'marker'),
    'AQ_CREATE_SHARE_ERROR': ('marker', 'error'),
    'AQ_DELETE_SHARE_OK': ('share_id',),
    'AQ_DELETE_SHARE_ERROR': ('share_id', 'error'),
    'AQ_QUERY_ERROR': ('item', 'error'),
    'AQ_ANSWER_SHARE_OK': ('share_id', 'answer'),
    'AQ_ANSWER_SHARE_ERROR': ('share_id', 'answer', 'error'),
    'AQ_FREE_SPACE_ERROR': ('error',),
    'AQ_ACCOUNT_ERROR': ('error',),
    'AQ_CREATE_UDF_OK': ('volume_id', 'node_id', 'marker'),
    'AQ_CREATE_UDF_ERROR': ('error', 'marker'),
    'AQ_LIST_VOLUMES': ('volumes',),
    'AQ_LIST_VOLUMES_ERROR': ('error',),
    'AQ_DELETE_VOLUME_OK': ('volume_id',),
    'AQ_DELETE_VOLUME_ERROR': ('volume_id', 'error'),
    'AQ_CHANGE_PUBLIC_ACCESS_OK': ('share_id', 'node_id', 'is_public',
                                   'public_url'),
    'AQ_CHANGE_PUBLIC_ACCESS_ERROR': ('share_id', 'node_id', 'error'),
    'AQ_PUBLIC_FILES_LIST_OK': ('public_files',),
    'AQ_PUBLIC_FILES_LIST_ERROR': ('error',),
    'AQ_DELTA_OK': ('volume_id', 'delta_content', 'end_generation',
                    'full', 'free_bytes'),
    'AQ_DELTA_ERROR': ('volume_id', 'error'),
    'AQ_DELTA_NOT_POSSIBLE': ('volume_id',),
    'AQ_RESCAN_FROM_SCRATCH_OK': ('volume_id', 'delta_content',
                                  'end_generation', 'free_bytes'),
    'AQ_RESCAN_FROM_SCRATCH_ERROR': ('volume_id', 'error'),

    'SV_SHARE_CHANGED': ('info',),
    'SV_SHARE_DELETED': ('share_id',),
    'SV_SHARE_ANSWERED': ('share_id', 'answer'),
    'SV_FREE_SPACE': ('share_id', 'free_bytes'),
    'SV_ACCOUNT_CHANGED': ('account_info',),
    'SV_VOLUME_CREATED': ('volume',),
    'SV_VOLUME_DELETED': ('volume_id',),
    'SV_VOLUME_NEW_GENERATION': ('volume_id', 'generation'),
    'SV_FILE_NEW': ('volume_id', 'node_id', 'parent_id', 'name'),
    'SV_DIR_NEW': ('volume_id', 'node_id', 'parent_id', 'name'),
    'SV_FILE_DELETED': ('volume_id', 'node_id', 'was_dir', 'old_path'),

    'HQ_HASH_NEW': ('path', 'hash', 'crc32', 'size', 'stat'),
    'HQ_HASH_ERROR': ('mdid',),

    'LR_SCAN_ERROR': ('mdid', 'udfmode'),

    'SYS_USER_CONNECT': ('access_token',),
    'SYS_USER_DISCONNECT': (),
    'SYS_STATE_CHANGED': ('state',),
    'SYS_NET_CONNECTED': (),
    'SYS_NET_DISCONNECTED': (),
    'SYS_INIT_DONE': (),
    'SYS_LOCAL_RESCAN_DONE': (),
    'SYS_CONNECTION_MADE': (),
    'SYS_CONNECTION_FAILED': (),
    'SYS_CONNECTION_LOST': (),
    'SYS_CONNECTION_RETRY': (),
    'SYS_PROTOCOL_VERSION_ERROR': ('error',),
    'SYS_PROTOCOL_VERSION_OK': (),
    'SYS_SET_CAPABILITIES_ERROR': ('error',),
    'SYS_SET_CAPABILITIES_OK': (),
    'SYS_AUTH_ERROR': ('error',),
    'SYS_AUTH_OK': (),
    'SYS_SERVER_RESCAN_DONE': (),
    'SYS_SERVER_RESCAN_ERROR': ('error',),
    'SYS_QUEUE_WAITING': (),
    'SYS_QUEUE_DONE': (),
    'SYS_QUEUE_ADDED': ('command',),
    'SYS_QUEUE_REMOVED': ('command',),
    'SYS_UNKNOWN_ERROR': (),
    'SYS_HANDSHAKE_TIMEOUT': (),
    'SYS_ROOT_RECEIVED': ('root_id', 'mdid'),
    'SYS_ROOT_MISMATCH': ('root_id', 'new_root_id'),
    'SYS_SERVER_ERROR': ('error',),
    'SYS_QUOTA_EXCEEDED': ('volume_id', 'free_bytes'),
    'SYS_BROKEN_NODE': ('volume_id', 'node_id', 'path', 'mdid'),
    'SYS_QUIT': (),

    'FSM_FILE_CONFLICT': ('old_name', 'new_name'),
    'FSM_DIR_CONFLICT': ('old_name', 'new_name'),
    'FSM_PARTIAL_COMMITED': ('share_id', 'node_id'),

    'VM_UDF_SUBSCRIBED': ('udf',),
    'VM_UDF_SUBSCRIBE_ERROR': ('udf_id', 'error'),
    'VM_UDF_UNSUBSCRIBED': ('udf',),
    'VM_UDF_UNSUBSCRIBE_ERROR': ('udf_id', 'error'),
    'VM_UDF_CREATED': ('udf',),
    'VM_UDF_CREATE_ERROR': ('path', 'error'),
    'VM_SHARE_SUBSCRIBED': ('share',),
    'VM_SHARE_SUBSCRIBE_ERROR': ('share_id', 'error'),
    'VM_SHARE_UNSUBSCRIBED': ('share',),
    'VM_SHARE_UNSUBSCRIBE_ERROR': ('share_id', 'error'),
    'VM_SHARE_CREATED': ('share_id',),
    'VM_SHARE_DELETED': ('share',),
    'VM_SHARE_DELETE_ERROR': ('share_id', 'error'),
    'VM_VOLUME_DELETED': ('volume',),
    'VM_VOLUME_DELETE_ERROR': ('volume_id', 'error'),
    'VM_SHARE_CHANGED': ('share_id',),
    'VM_VOLUMES_CHANGED': ('volumes',),
}

DEFAULT_HANDLER = "handle_default"  # receives (event_name, **kwargs)


class EventQueue(object):
    """Manages the events from different sources and distributes them."""

    def __init__(self, fs, ignore_config=None, monitor_class=None):
        self.listener_map = {}

        self.log = logging.getLogger('ubuntuone.SyncDaemon.EQ')
        self.fs = fs

        if monitor_class is None:
            # use the default class returned by platform
            self.monitor = FilesystemMonitor(self, fs, ignore_config)
        else:
            self.monitor = monitor_class(self, fs, ignore_config)

        self.dispatching = False
        self.dispatch_queue = collections.deque()
        self._have_empty_eq_cback = False
        self.empty_event_queue_callbacks = set()
        self.ignored_base_exception = Exception

    def add_to_mute_filter(self, event, **info):
        """Add info to mute filter in the processor."""
        self.monitor.add_to_mute_filter(event, **info)

    def rm_from_mute_filter(self, event, **info):
        """Remove info to mute filter in the processor."""
        self.monitor.rm_from_mute_filter(event, **info)

    def add_empty_event_queue_callback(self, callback):
        """Add a callback for when the even queue has no more events."""
        self._have_empty_eq_cback = True
        self.empty_event_queue_callbacks.add(callback)
        if not self.dispatching and not self.dispatch_queue:
            if callable(callback):
                callback()

    def remove_empty_event_queue_callback(self, callback):
        """Remove the callback."""
        self.empty_event_queue_callbacks.remove(callback)
        if not self.empty_event_queue_callbacks:
            self._have_empty_eq_cback = False

    @defer.inlineCallbacks
    def shutdown(self):
        """Make the monitor shutdown."""
        yield self.monitor.shutdown()
        # clean up all registered listeners
        if len(self.listener_map.items()) > 0:
            for k, v in self.listener_map.items():
                v.clear()
                del self.listener_map[k]

    def rm_watch(self, dirpath):
        """Remove watch from a dir."""
        self.monitor.rm_watch(dirpath)

    def add_watch(self, dirpath):
        """Add watch to a dir."""
        return self.monitor.add_watch(dirpath)

    def add_watches_to_udf_ancestors(self, volume):
        """Add a inotify watch to volume's ancestors if it's an UDF."""
        # This is a platform dependent operation since there are cases in
        # which the watches do not have to be added (On windows we do not
        # have to add them since we have an opened handle.)
        # finally, check that UDF is ok in disk
        if not access(volume.path):
            # if we cannot access the UDF lets return false and do
            # nothing
            return defer.succeed(False)
        return self.monitor.add_watches_to_udf_ancestors(volume)

    def unsubscribe(self, obj):
        """Remove the callback object from the listener queue.

        @param obj: the callback object to remove from the queue.
        """
        for k, v in self.listener_map.items():
            v.pop(obj, None)
            if not v:
                del self.listener_map[k]

    def subscribe(self, obj):
        """Store the callback object to whom push the events when received.

        @param obj: the callback object to add to the listener queue.

        These objects should provide a 'handle_FOO' to receive the FOO
        events (replace FOO with the desired event).
        """
        for event_name in EVENTS.keys():
            meth_name = "handle_" + event_name
            method = self._get_listener_method(obj, meth_name, event_name)
            if method is not None:
                self.listener_map.setdefault(event_name, {})[obj] = method

    def push(self, event_name, **kwargs):
        """Receives a push for all events.

        The signature for each event is forced on each method, not in this
        'push' arguments.
        """
        log_msg = "push_event: %s, kwargs: %s"
        if event_name.endswith('DELETE'):
            # log every DELETE in INFO level
            self.log.info(log_msg, event_name, kwargs)
        elif event_name == 'SYS_USER_CONNECT':
            self.log.debug(log_msg, event_name, '*')
        else:
            self.log.debug(log_msg, event_name, kwargs)

        # check if we are currently dispatching an event
        self.dispatch_queue.append((event_name, kwargs))
        if not self.dispatching:
            self.dispatching = True
            while True:
                try:
                    event_name, kwargs = self.dispatch_queue.popleft()
                    self._dispatch(event_name, **kwargs)
                except IndexError:
                    self.dispatching = False
                    if self._have_empty_eq_cback:
                        for cback in self.empty_event_queue_callbacks.copy():
                            cback()
                    break

    def _dispatch(self, event_name, **kwargs):
        """ push the event to all listeners. """
        try:
            listeners = self.listener_map[event_name]
        except KeyError:
            # no listener for this
            return

        # check listeners to see if have the proper method, and call it
        for listener, method in listeners.items():
            try:
                method(**kwargs)
            except self.ignored_base_exception:
                self.log.exception("Error encountered while handling: %s "
                                   "in %s", event_name, listener)

    def _get_listener_method(self, listener, method_name, event_name):
        """ returns the method named method_name or hanlde_default from the
        listener. Or None if the methods are not defined in the listener.
        """
        method = getattr(listener, method_name, None)
        if method is None:
            method = getattr(listener, DEFAULT_HANDLER, None)
            if method is not None:
                method = functools.partial(method, event_name)
        return method

    def is_frozen(self):
        """Checks if there's something frozen."""
        return self.monitor.is_frozen()

    def freeze_begin(self, path):
        """Puts in hold all the events for this path."""
        self.monitor.freeze_begin(path)

    def freeze_rollback(self):
        """Unfreezes the frozen path, reseting to idle state."""
        self.monitor.freeze_rollback()

    def freeze_commit(self, events):
        """Unfreezes the frozen path, sending received events if not dirty.

        If events for that path happened:
            - return True
        else:
            - push the here received events, return False
        """
        return self.monitor.freeze_commit(events)
