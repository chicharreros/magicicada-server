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
"""SyncDaemon Tools."""

import logging
import subprocess
from collections import defaultdict

from twisted.internet import defer
from twisted.spread.pb import (DeadReferenceError, RemoteError)

from ubuntuone.platform.ipc.perspective_broker import is_already_running
from ubuntuone.platform.ipc.ipc_client import UbuntuOneClient
from ubuntuone.syncdaemon.utils import get_sd_bin_cmd


# make pyflakes happy since we can't disable the warning
is_already_running = is_already_running


class IPCError(Exception):
    """An IPC specific error signal."""

    def __init__(self, name, info, details=None):
        super(IPCError, self).__init__()
        self.name = name
        self.info = info
        self.details = details


class SyncDaemonToolProxy(object):
    """Platform dependent proxy to syncdaemon.

    Please note that most of the methods of this class are "pre-processed"
    by overriding __getattribute__, in a way where _call_after_connection
    is called before the method itself, so every public method will return
    a deferred that will be fired when this client is connected.

    """

    _SIGNAL_MAPPING = {
        'Event': ('events', 'on_event_cb'),
        'FolderCreated': ('folders', 'on_folder_created_cb'),
        'FolderCreateError': ('folders', 'on_folder_create_error_cb'),
        'FolderDeleted': ('folders', 'on_folder_deleted_cb'),
        'FolderDeleteError': ('folders', 'on_folder_delete_error_cb'),
        'FolderSubscribed': ('folders', 'on_folder_subscribed_cb'),
        'FolderSubscribeError': ('folders', 'on_folder_subscribe_error_cb'),
        'FolderUnSubscribed': ('folders', 'on_folder_unsubscribed_cb'),
        'FolderUnSubscribeError': ('folders',
                                   'on_folder_unsubscribe_error_cb'),
        'NewShare': ('shares', 'on_new_share_cb'),
        'PublicAccessChanged': ('public_files', 'on_public_access_changed_cb'),
        'PublicAccessChangeError': ('public_files',
                                    'on_public_access_change_error_cb'),
        'PublicFilesList': ('public_files', 'on_public_files_list_cb'),
        'PublicFilesListError': ('public_files',
                                 'on_public_files_list_error_cb'),
        'ShareAnswerResponse': ('shares', 'on_share_answer_response_cb'),
        'ShareChanges': ('shares', 'on_share_changed_cb'),
        'ShareCreated': ('shares', 'on_share_created_cb'),
        'ShareCreateError': ('shares', 'on_share_create_error_cb'),
        'ShareDeleted': ('shares', 'on_share_deleted_cb'),
        'ShareDeleteError': ('shares', 'on_share_delete_error_cb'),
        'ShareSubscribed': ('shares', 'on_share_subscribed_cb'),
        'ShareSubscribeError': ('shares', 'on_share_subscribe_error_cb'),
        'ShareUnSubscribed': ('shares', 'on_share_unsubscribed_cb'),
        'ShareUnSubscribeError': ('shares', 'on_share_unsubscribe_error_cb'),
        'StatusChanged': ('status', 'on_status_changed_cb'),
        'VolumesChanged': ('sync_daemon', 'on_volumes_changed_cb'),
    }

    # All methods and instance variables that should not be handled by
    # _call_after_connection  should be put in the list below (or start with _)

    _DONT_VERIFY_CONNECTED = [
        "wait_connected",
        "client", "last_event", "delayed_call", "log", "connected",
        "connected_signals"
    ]

    def _should_wrap(self, attr_name):
        """Check if this attribute should be wrapped."""
        return not (attr_name in SyncDaemonToolProxy._DONT_VERIFY_CONNECTED or
                    attr_name.startswith("_"))

    def __getattribute__(self, attr_name):
        """If the attribute is not special, verify the ipc connection."""
        attr = super(SyncDaemonToolProxy, self).__getattribute__(attr_name)
        if SyncDaemonToolProxy._should_wrap(self, attr_name):
            return self._call_after_connection(attr)
        else:
            return attr

    def __init__(self, bus=None):
        self.log = logging.getLogger(
            'ubuntuone.platform.tools.perspective_broker')
        self.client = UbuntuOneClient()
        self.connected = None
        self.connected_signals = defaultdict(set)

    def _call_after_connection(self, method):
        """Make sure Perspective Broker is connected before calling."""
        if not self.client.is_connected():
            self.connected = self.client.connect()

        @defer.inlineCallbacks
        def call_after_connection_inner(*args, **kwargs):
            """Call the given method after the connection to pb is made."""
            yield self.connected
            try:
                retval = yield method(*args, **kwargs)
            except DeadReferenceError:
                self.log.debug('Got stale broker, atempting reconnect.')
                # might be the case where we have a stale broker
                yield self._reconnect_client()
                retval = yield method(*args, **kwargs)
            defer.returnValue(retval)

        return call_after_connection_inner

    @defer.inlineCallbacks
    def _reconnect_client(self):
        """Reconnect the client."""
        self.connected = False
        yield self.client.reconnect()
        # do connect all the signals again
        for signal_name, handlers in self.connected_signals.items():
            for handler in handlers:
                self.connect_signal(signal_name, handler)

    @defer.inlineCallbacks
    def call_method(self, client_kind, method_name, *args, **kwargs):
        """Call the 'method_name' passing 'args' and 'kwargs'."""
        client = getattr(self.client, client_kind)
        method = getattr(client, method_name)
        try:
            result = yield method(*args, **kwargs)
        except DeadReferenceError:
            self.log.debug('Got stale broker, atempting reconnect.')
            # may happen in the case we reconnected and the server side objects
            # for gc
            yield self._reconnect_client()
            result = yield self.call_method(
                client_kind, method_name, *args, **kwargs)
        except RemoteError as e:
            # Wrap RemoteErrors in IPCError to match DBus interface's
            # behavior:
            raise IPCError(name=e.remoteType,
                           info=[e.args],
                           details=e.message)
        defer.returnValue(result)

    def shutdown(self):
        """Close connections."""
        return self.client.disconnect()

    def _handler(self, signal_name, *args, **kwargs):
        """Call all the handlers connected to signal_name."""
        for cb_handler in self.connected_signals[signal_name]:
            cb_handler(*args, **kwargs)

    def connect_signal(self, signal_name, handler):
        """Connect 'handler' with 'signal_name'."""
        client_kind, callback = self._SIGNAL_MAPPING[signal_name]
        client = getattr(self.client, client_kind)
        if len(self.connected_signals[signal_name]) == 0:
            setattr(
                client, callback,
                lambda *args, **kw: self._handler(signal_name, *args, **kw))
        # do remember the connected signal in case we need to reconnect
        self.connected_signals[signal_name].add(handler)
        return handler

    def disconnect_signal(self, signal_name, handler_or_match):
        """Disconnect 'handler_or_match' from 'signal_name'."""
        client_kind, callback = self._SIGNAL_MAPPING[signal_name]
        client = getattr(self.client, client_kind)
        setattr(client, callback, None)
        # forget that the connection was made in case we need to reconnect
        del self.connected_signals[signal_name]
        return handler_or_match

    def wait_connected(self):
        """Wait until syncdaemon is connected to the server."""
        return self.connected

    def start(self):
        """Start syncdaemon, should *not* be running."""
        try:
            cmd = get_sd_bin_cmd()
        except Exception, e:
            defer.fail(e)
        p = subprocess.Popen(cmd)
        return defer.succeed(p)
