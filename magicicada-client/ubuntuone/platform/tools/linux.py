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
"""SyncDaemon Tools."""

import dbus

from dbus.lowlevel import SignalMessage, MethodCallMessage, ErrorMessage
from dbus.exceptions import DBusException
from twisted.internet import defer

from ubuntuone.platform.ipc.linux import (
    is_already_running,
    DBUS_IFACE_NAME,
    DBUS_IFACE_STATUS_NAME,
    DBUS_IFACE_SHARES_NAME,
    DBUS_IFACE_FOLDERS_NAME,
    DBUS_IFACE_SYNC_NAME,
    DBUS_IFACE_FS_NAME,
    DBUS_IFACE_PUBLIC_FILES_NAME,
    DBUS_IFACE_CONFIG_NAME,
)


# make pyflakes happy since we can't disable the warning
is_already_running = is_already_running


class IPCError(DBusException):
    """An IPC specific error signal."""

    def __init__(self, name, info, details=None):
        super(IPCError, self).__init__(name=name)
        self.name = name
        self.info = info
        self.details = details


class DBusClient(object):
    """Low level dbus client. To help testing the DBus interface."""

    def __init__(self, bus, path, interface, destination=DBUS_IFACE_NAME):
        """Create the instance."""
        self.bus = bus
        self.path = path
        self.interface = interface
        self.destination = destination

    def send_signal(self, signal, *args):
        """Send method with *args."""
        msg = SignalMessage(self.path, self.interface, signal)
        msg.set_no_reply(True)
        msg.append(*args)
        self.bus.send_message(msg)

    def call_method(self, method, *args, **kwargs):
        """Call method with *args and **kwargs over dbus."""
        msg = MethodCallMessage(self.destination, self.path, self.interface,
                                method)
        msg.set_no_reply(True)
        # get the signature
        signature = kwargs.get('signature', None)
        if signature is not None:
            msg.append(signature=signature, *args)
        else:
            msg.append(*args)

        d = defer.Deferred()

        def reply_handler(result):
            """Callback the returned deferred and call 'reply_handler'."""
            kwargs.get('reply_handler', lambda _: None)(result)
            d.callback(result)

        def error_handler(error):
            """Errback the returned deferred and call 'error_handler'."""
            kwargs.get('error_handler', lambda _: None)(error)
            d.errback(error)

        def parse_reply(message):
            """Handle the reply message."""
            if isinstance(message, ErrorMessage):
                exc = IPCError(name=message.get_error_name(),
                               info=message.get_args_list())
                return error_handler(exc)
            args_list = message.get_args_list(utf8_strings=False,
                                              byte_arrays=False)
            if len(args_list) == 0:
                reply_handler(None)
            elif len(args_list) == 1:
                reply_handler(args_list[0])
            else:
                reply_handler(tuple(args_list))

        self.bus.send_message_with_reply(msg, reply_handler=parse_reply)

        return d


class SyncDaemonToolProxy(object):
    """Platform dependent proxy to syncdaemon."""

    def __init__(self, bus=None):
        if bus is None:
            bus = dbus.SessionBus()
        self.bus = bus

        self.config = DBusClient(self.bus, '/config', DBUS_IFACE_CONFIG_NAME)
        self.file_system = DBusClient(self.bus, '/filesystem',
                                      DBUS_IFACE_FS_NAME)
        self.folders = DBusClient(self.bus, '/folders',
                                  DBUS_IFACE_FOLDERS_NAME)
        self.public_files = DBusClient(self.bus, '/publicfiles',
                                       DBUS_IFACE_PUBLIC_FILES_NAME)
        self.shares = DBusClient(self.bus, '/shares', DBUS_IFACE_SHARES_NAME)
        self.status = DBusClient(self.bus, '/status', DBUS_IFACE_STATUS_NAME)
        self.sync_daemon = DBusClient(self.bus, '/', DBUS_IFACE_SYNC_NAME)

    def call_method(self, client_kind, method_name, *args, **kwargs):
        """Call the 'method_name' passing 'args' and 'kwargs'."""
        client = getattr(self, client_kind)
        result = client.call_method(method_name, *args, **kwargs)
        return result

    def shutdown(self):
        """Close connections."""
        # do something here?

    def connect_signal(self, signal_name, handler):
        """Connect 'handler' with 'signal_name'."""
        match = self.bus.add_signal_receiver(handler, signal_name=signal_name)
        return match

    def disconnect_signal(self, signal_name, handler_or_match):
        """Disconnect 'handler_or_match' from 'signal_name'."""
        return self.bus.remove_signal_receiver(handler_or_match,
                                               signal_name=signal_name)

    def wait_connected(self):
        """Wait until syncdaemon is connected to the server."""
        self.bus.get_object(DBUS_IFACE_NAME, '/',
                            follow_name_owner_changes=True)

    def start(self):
        """Start syncdaemon, should *not* be running."""
        if DBUS_IFACE_NAME in self.bus.list_names():
            self.bus.release_name(DBUS_IFACE_NAME)
        _, result = self.bus.start_service_by_name(DBUS_IFACE_NAME, 0)
        return defer.succeed(result == dbus.bus.DBUS_START_REPLY_SUCCESS)
