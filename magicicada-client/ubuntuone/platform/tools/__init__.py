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

import logging
import sys
import warnings

from twisted.internet import defer
from ubuntuone.logger import log_call

if sys.platform in ('win32', 'darwin'):
    from ubuntuone.platform.tools import perspective_broker
    source = perspective_broker
else:
    from ubuntuone.platform.tools import linux
    source = linux


logger = logging.getLogger('ubuntuone.SyncDaemon.SDTool')
is_already_running = source.is_already_running
IPCError = source.IPCError


def is_running(bus=None):
    """Check if syncdaemon is running, without strating it.

    This method is DEPRECATED, please use is_already_running instead.

    """
    warnings.warn('Use is_already_running instead.', DeprecationWarning)
    return is_already_running(bus=bus)


class SyncDaemonTool(object):
    """Various utility methods to test/play with the SyncDaemon."""

    def __init__(self, bus=None):
        self.bus = bus
        self.last_event = 0
        self.delayed_call = None
        self.log = logger
        self.proxy = source.SyncDaemonToolProxy(bus=bus)

    def _get_dict(self, a_dict):
        """Converts a dict returned by the IPC client to a dict of strings."""
        str_dict = {}
        for key in a_dict:
            str_dict[unicode(key)] = unicode(a_dict[key])
        return str_dict

    def shutdown(self):
        """Close connections."""
        return self.proxy.shutdown()

    def connect_signal(self, signal_name, handler):
        """Connect 'handler' with 'signal_name'."""
        return self.proxy.connect_signal(signal_name=signal_name,
                                         handler=handler)

    def disconnect_signal(self, signal_name, handler_or_match):
        """Disconnect 'handler_or_match' from 'signal_name'."""
        return self.proxy.disconnect_signal(signal_name=signal_name,
                                            handler_or_match=handler_or_match)

    @log_call(logger.debug)
    def wait_connected(self):
        """Wait until syncdaemon is connected to the server."""
        d = defer.Deferred()

        # check if the syncdaemon is running
        try:
            self.proxy.wait_connected()
            self.log.debug('wait_connected: Done!')
            d.callback(True)
        except Exception as e:
            self.log.debug('Not connected: %s', e)
            d.errback()

        return d

    @log_call(logger.debug)
    def wait_all_downloads(self, verbose=False):
        """Wait until there is no more pending downloads."""
        d = self.get_current_downloads()

        def reply_handler(downloads):
            """Check if there are downloads in progress.

            If so, reschedule a new check if there is at least one.

            """
            if verbose:
                sys.stdout.write(', %s' % str(len(downloads)))
                sys.stdout.flush()
            if len(downloads) > 0:
                self.log.debug('wait_all_downloads: %d', len(downloads))
                return self.get_current_downloads()
            else:
                self.log.debug('wait_all_downloads: No more downloads')
                return True

        if verbose:
            sys.stdout.write('\nchecking current downloads')
            sys.stdout.flush()
        d.addCallback(reply_handler)
        return d

    @log_call(logger.debug)
    def wait_all_uploads(self, verbose=False):
        """Wait until there is no more pending uploads."""
        d = self.get_current_uploads()

        def reply_handler(uploads):
            """Check if there are uploads in progress.

            If so, reschedule a new check if there is at least one.

            """
            if verbose:
                sys.stdout.write(', %s' % str(len(uploads)))
                sys.stdout.flush()
            if len(uploads) > 0:
                self.log.debug('wait_all_uploads: %d', len(uploads))
                return self.get_current_uploads()
            else:
                self.log.debug('wait_all_uploads: No more uploads')
                return True

        if verbose:
            sys.stdout.write('\nchecking current uploads')
            sys.stdout.flush()

        d.addCallback(reply_handler)
        return d

    @log_call(logger.debug)
    def wait_for_nirvana(self, last_event_interval=5, verbose=False):
        """Wait until the syncdaemon reachs nirvana.

        This is when there are:
            - the syncdaemon is connected
            - 0 transfers inprogress
            - no more events are fired in the event queue

        @param last_event_interval: the seconds to wait to determine that there
        is no more events in the queue and the daemon reached nirvana

        """
        return self.proxy.call_method('sync_daemon', 'wait_for_nirvana',
                                      last_event_interval)

    @log_call(logger.debug)
    def wait_for_signals(self, signal_ok, signal_error=None,
                         success_filter=lambda *a: True,
                         error_filter=lambda *a: True, **kwargs):
        """Wait for one of the specified signals, return a deferred.

        @param signal_ok: this will fire the deferred's callback

        @param signal_error: the will fire the deferred's errback

        @param success_filter: callable to filter the signal_ok, must return
        True or False. If True is returned, the returned deferred is fired.

        @param error_filter: callable to filter the signal_error, must return
        True or False. If True is returned, the returned deferred is errback'd.

        Other params will be ignored.

        """
        d = defer.Deferred()

        def _success_handler(*args):
            """Callback 'd' only if the success_filter returns True."""
            try:
                if success_filter(*args):
                    d.callback(args)
            except Exception as e:
                logger.exception('wait_for_signals: success_handler failed:')
                d.errback(IPCError(e.__class__.__name__, args, e.message))

        def _error_handler(*args):
            """Errback 'd' only if the error_filter returns True."""
            try:
                if error_filter(*args):
                    d.errback(IPCError(signal_error, args))
            except Exception as e:
                logger.exception('wait_for_signals: error_handler failed:')
                d.errback(IPCError(e.__class__.__name__, args, e.message))

        # register signal handlers for success/error
        match_ok = self.connect_signal(signal_name=signal_ok,
                                       handler=_success_handler)

        if signal_error is not None:
            match_error = self.connect_signal(signal_name=signal_error,
                                              handler=_error_handler)

        def remove_signal_receiver(r):
            """Cleanup the signal receivers."""
            self.disconnect_signal(signal_name=signal_ok,
                                   handler_or_match=match_ok)
            if signal_error is not None:
                self.disconnect_signal(signal_name=signal_error,
                                       handler_or_match=match_error)
            return r

        d.addBoth(remove_signal_receiver)
        return d

    @log_call(logger.debug)
    def wait_for_signal(self, signal_name, filter):
        """Wait for the specified signal (the first received).

        @param signal_name: the signal name
        @param filter: a callable to filter signal, must return True, and is
        used to fire the deferred callback.

        DEPRECATED. Use wait_for_signals instead.

        """
        return self.wait_for_signals(signal_ok=signal_name,
                                     success_filter=filter)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def get_current_downloads(self):
        """Return a deferred that will be fired with the current downloads."""
        results = yield self.proxy.call_method('status', 'current_downloads')
        downloads = [self._get_dict(r) for r in results]
        self.log.debug('downloads: %r', downloads)
        defer.returnValue(downloads)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def get_current_uploads(self):
        """Return a deferred that will be fired with the current uploads."""
        results = yield self.proxy.call_method('status', 'current_uploads')
        uploads = [self._get_dict(r) for r in results]
        self.log.debug('uploads: %r', uploads)
        defer.returnValue(uploads)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def sync_menu(self):
        """Return a deferred that will be fired with the sync menu data."""
        results = yield self.proxy.call_method('status', 'sync_menu')
        defer.returnValue(results)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def accept_share(self, share_id):
        """Accept the share with id: share_id."""
        d = self.wait_for_signals(
            signal_ok='ShareAnswerResponse',
            success_filter=lambda info: info['volume_id'] == share_id)
        self.proxy.call_method('shares', 'accept_share', share_id)
        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def reject_share(self, share_id):
        """Reject the share with id: share_id."""
        d = self.wait_for_signals(
            signal_ok='ShareAnswerResponse',
            success_filter=lambda info: info['volume_id'] == share_id)
        self.proxy.call_method('shares', 'reject_share', share_id)
        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def subscribe_share(self, share_id):
        """Subscribe to a share given its id."""
        d = self.wait_for_signals(
            'ShareSubscribed', 'ShareSubscribeError',
            success_filter=lambda info: info['volume_id'] == share_id,
            error_filter=lambda info, _: info['volume_id'] == share_id)
        self.proxy.call_method('shares', 'subscribe', share_id)
        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def unsubscribe_share(self, share_id):
        """Unsubscribe from a share given its id."""
        d = self.wait_for_signals(
            'ShareUnSubscribed', 'ShareUnSubscribeError',
            success_filter=lambda info: info['volume_id'] == share_id,
            error_filter=lambda info, _: info['volume_id'] == share_id)
        self.proxy.call_method('shares', 'unsubscribe', share_id)
        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def get_shares(self):
        """Get the list of shares (accepted or not)."""
        results = yield self.proxy.call_method('shares', 'get_shares')
        shares = [self._get_dict(r) for r in results]
        self.log.debug('shares: %r', shares)
        defer.returnValue(shares)

    @log_call(logger.debug)
    def refresh_shares(self):
        """Request a refresh of share list to the server."""
        return self.proxy.call_method('shares', 'refresh_shares')

    @log_call(logger.debug)
    def offer_share(self, path, username, name, access_level):
        """Offer a share at the specified path to user with id: username."""
        return self.proxy.call_method(
            'shares', 'create_share', path, username, name, access_level)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def list_shared(self):
        """Get the list of the shares "shared"/created/offered."""
        results = yield self.proxy.call_method('shares', 'get_shared')
        shares = [self._get_dict(r) for r in results]
        self.log.debug('shared: %r', shares)
        defer.returnValue(shares)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def create_folder(self, path):
        """Create a user defined folder in the specified path."""
        d = self.wait_for_signals(
            'FolderCreated', 'FolderCreateError',
            success_filter=lambda info: info['path'] == path,
            error_filter=lambda info, _: info['path'] == path)

        self.proxy.call_method('folders', 'create', path)

        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.info)
    def delete_folder(self, folder_id):
        """Delete a user defined folder given its id."""
        d = self.wait_for_signals(
            'FolderDeleted', 'FolderDeleteError',
            success_filter=lambda info: info['volume_id'] == folder_id,
            error_filter=lambda info, _: info['volume_id'] == folder_id)

        self.proxy.call_method('folders', 'delete', folder_id)

        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def subscribe_folder(self, folder_id):
        """Subscribe to a user defined folder given its id."""
        d = self.wait_for_signals(
            'FolderSubscribed', 'FolderSubscribeError',
            success_filter=lambda info: info['volume_id'] == folder_id,
            error_filter=lambda info, _: info['volume_id'] == folder_id)

        self.proxy.call_method('folders', 'subscribe', folder_id)

        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def unsubscribe_folder(self, folder_id):
        """Unsubscribe from a user defined folder given its id."""
        d = self.wait_for_signals(
            'FolderUnSubscribed', 'FolderUnSubscribeError',
            success_filter=lambda info: info['volume_id'] == folder_id,
            error_filter=lambda info, _: info['volume_id'] == folder_id)

        self.proxy.call_method('folders', 'unsubscribe', folder_id)

        result, = yield d
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def validate_path(self, path):
        """Return True if the path is valid for a folder."""
        result = yield self.proxy.call_method('folders', 'validate_path', path)
        self.log.debug('valid: %r', result)
        defer.returnValue(result)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def get_folders(self):
        """Return the list of folders (a list of dicts)."""
        results = yield self.proxy.call_method('folders', 'get_folders')
        folders = [self._get_dict(r) for r in results]
        self.log.debug('folders: %r', folders)
        defer.returnValue(folders)

    @log_call(logger.debug)
    def get_folder_info(self, path):
        """Call the get_info method for a UDF path."""
        return self.proxy.call_method('folders', 'get_folder_info', path)

    @log_call(logger.debug)
    def get_metadata(self, path):
        """Get metadata for 'path'."""
        return self.proxy.call_method('file_system', 'get_metadata', path)

    @log_call(logger.debug)
    def search_files(self, pattern):
        """Get the files that matches the pattern."""
        return self.proxy.call_method('file_system', 'search_files', pattern)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def change_public_access(self, path, is_public):
        """Change the public access for a given path."""
        d = self.wait_for_signals(
            'PublicAccessChanged', 'PublicAccessChangeError',
            success_filter=lambda info: info['path'] == path.decode('utf-8'),
            error_filter=lambda info, _: info['path'] == path.decode('utf-8'))

        metadata = yield self.get_metadata(path)
        args = (metadata['share_id'], metadata['node_id'], is_public)
        self.proxy.call_method('public_files', 'change_public_access', *args)

        (file_info,) = yield d
        defer.returnValue(file_info)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def get_public_files(self):
        """Get the public files list."""
        d = self.wait_for_signals('PublicFilesList', 'PublicFilesListError')
        self.proxy.call_method('public_files', 'get_public_files')
        response, = yield d  # unpacking single element tuple
        defer.returnValue(response)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def quit(self):
        """Quit the syncdaemon."""
        result = None
        running = yield is_already_running(bus=self.bus)
        if running:
            result = yield self.proxy.call_method('sync_daemon', 'quit')
        defer.returnValue(result)

    @log_call(logger.debug)
    def connect(self):
        """Connect syncdaemon."""
        return self.proxy.call_method('sync_daemon', 'connect')

    @log_call(logger.debug)
    def disconnect(self):
        """Disconnect syncdaemon."""
        return self.proxy.call_method('sync_daemon', 'disconnect')

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def get_status(self):
        """Get the current_status dict."""
        status = yield self.proxy.call_method('status', 'current_status')
        state_dict = self._get_dict(status)
        state_dict['is_connected'] = bool(state_dict['is_connected'])
        state_dict['is_online'] = bool(state_dict['is_online'])
        state_dict['is_error'] = bool(state_dict['is_error'])
        defer.returnValue(state_dict)

    @log_call(logger.debug)
    def free_space(self, vol_id):
        """Return the free space of the given volume."""
        return self.proxy.call_method('status', 'free_space', vol_id)

    @log_call(logger.debug)
    def waiting(self):
        """Return a description of the waiting queue elements."""
        return self.proxy.call_method('status', 'waiting')

    @log_call(logger.debug)
    def waiting_metadata(self):
        """Return a description of the waiting metadata queue elements."""
        return self.proxy.call_method('status', 'waiting_metadata')

    @log_call(logger.debug)
    def waiting_content(self):
        """Return the waiting content queue elements."""
        return self.proxy.call_method('status', 'waiting_content')

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def start(self):
        """Start syncdaemon if it's not running."""
        running = yield is_already_running(bus=self.bus)
        if not running:
            wait_d = self.wait_for_signals('StatusChanged')
            yield self.proxy.start()
            yield wait_d

    @log_call(logger.debug)
    def get_throttling_limits(self):
        """Return a dict with the read and write limits."""
        return self.proxy.call_method('config', 'get_throttling_limits')

    @log_call(logger.debug)
    def set_throttling_limits(self, read_limit, write_limit):
        """Set the read and write limits."""
        return self.proxy.call_method(
            'config', 'set_throttling_limits', read_limit, write_limit)

    def is_setting_enabled(self, setting_name):
        """Return whether 'setting_name' is enabled."""
        return self.proxy.call_method('config', '%s_enabled' % setting_name)

    def enable_setting(self, setting_name, enabled):
        """Enable/disable 'setting_name'."""
        if enabled:
            method = 'enable_%s'
        else:
            method = 'disable_%s'
        return self.proxy.call_method('config', method % setting_name)

    @log_call(logger.debug)
    def is_throttling_enabled(self):
        """Check if throttling is enabled."""
        return self.is_setting_enabled('bandwidth_throttling')

    @log_call(logger.debug)
    def enable_throttling(self, enabled=True):
        """Enable/disablew throttling."""
        return self.enable_setting('bandwidth_throttling', enabled)

    @log_call(logger.debug)
    def is_files_sync_enabled(self):
        """Check if files sync is enabled."""
        return self.is_setting_enabled('files_sync')

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def enable_files_sync(self, enabled):
        """Enable/disable files sync."""
        yield self.enable_setting('files_sync', enabled)
        if not enabled:
            # User requested the service to be disabled
            yield self.quit()
        else:
            # User requested the service to be enabled
            yield self.start()

    @log_call(logger.debug)
    def is_autoconnect_enabled(self):
        """Check if autoconnect is enabled."""
        return self.is_setting_enabled('autoconnect')

    @log_call(logger.debug)
    def enable_autoconnect(self, enabled):
        """Enable/disable autoconnect."""
        return self.enable_setting('autoconnect', enabled)

    @log_call(logger.debug)
    def is_share_autosubscribe_enabled(self):
        """Check if share_autosubscribe is enabled."""
        return self.is_setting_enabled('share_autosubscribe')

    @log_call(logger.debug)
    def enable_share_autosubscribe(self, enabled):
        """Enable/disable share_autosubscribe."""
        return self.enable_setting('share_autosubscribe', enabled)

    @log_call(logger.debug)
    def is_udf_autosubscribe_enabled(self):
        """Check if udf_autosubscribe is enabled."""
        return self.is_setting_enabled('udf_autosubscribe')

    @log_call(logger.debug)
    def enable_udf_autosubscribe(self, enabled):
        """Enable/disable udf_autosubscribe."""
        return self.enable_setting('udf_autosubscribe', enabled)

    @defer.inlineCallbacks
    @log_call(logger.debug)
    def refresh_volumes(self):
        """Request the volumes list to the server."""
        d = self.wait_for_signals('VolumesChanged')
        self.proxy.call_method('folders', 'refresh_volumes')

        (results,) = yield d

        volumes_info = [self._get_dict(r) for r in results]
        defer.returnValue(volumes_info)

    @log_call(logger.debug)
    def rescan_from_scratch(self, volume_id):
        """Request a rescan from scratch for volume_id."""
        return self.proxy.call_method('sync_daemon', 'rescan_from_scratch',
                                      volume_id)

    @log_call(logger.debug)
    def get_dirty_nodes(self):
        """Return the list of dirty nodes."""
        return self.proxy.call_method('file_system', 'get_dirty_nodes')

    @log_call(logger.debug)
    def get_home_dir(self):
        """Return the home directory."""
        return self.proxy.call_method('sync_daemon', 'get_homedir')

    @log_call(logger.debug)
    def get_root_dir(self):
        """Return the root directory."""
        return self.proxy.call_method('sync_daemon', 'get_rootdir')

    @log_call(logger.debug)
    def get_shares_dir(self):
        """Return the shares directory."""
        return self.proxy.call_method('sync_daemon', 'get_sharesdir')

    @log_call(logger.debug)
    def get_shares_dir_link(self):
        """Return the shares link directory."""
        return self.proxy.call_method('sync_daemon', 'get_sharesdir_link')

    @log_call(logger.debug)
    def set_status_changed_handler(self, handler):
        """Set the status changed handler."""
        return self.connect_signal(signal_name='StatusChanged',
                                   handler=handler)


# callbacks used by u1sdtool script

def show_shared(shares, out):
    """Print the list of shared shares."""
    if len(shares) == 0:
        out.write("No shared\n")
    else:
        out.write("Shared list:\n")
    for share in shares:
        msg_template = (
            '  id=%s name=%s accepted=%s access_level=%s to=%s path=%s\n')
        out.write(msg_template % (share['volume_id'], share['name'],
                                  bool(share['accepted']),
                                  share['access_level'],
                                  share['other_username'],
                                  share['path']))


def show_folders(folders, out):
    """Print the list of user defined folders."""
    if len(folders) == 0:
        out.write("No folders\n")
    else:
        out.write("Folder list:\n")
    for folder in folders:
        msg_template = '  id=%s subscribed=%s path=%s\n'
        out.write(msg_template % (folder['volume_id'],
                                  bool(folder['subscribed']),
                                  folder['path']))


def show_error(error, out):
    """Format an error when things go wrong"""
    try:
        raise error.value
    except:
        signal, (args, retval) = error.value.args
        msg_template = u"%s: %s (%s)\n"
        fmtd_args = u", ".join("%s=%s" % (k, v) for k, v in args.items())
        out.write(msg_template % (signal, retval, fmtd_args))


def show_shares(shares, out):
    """Print the list of shares."""
    if len(shares) == 0:
        out.write("No shares\n")
    else:
        out.write("Shares list:\n")
    for share in shares:
        out.write(' id=%s name=%s accepted=%s subscribed=%s access_level=%s '
                  'from=%s\n' %
                  (share['volume_id'], share['name'], bool(share['accepted']),
                   bool(share['subscribed']), share['access_level'],
                   share['other_username']))


def show_path_info(result, path, out):
    """Print the path info to stdout."""
    assert isinstance(path, unicode)
    out.write(" File: %s\n" % path)
    keys = list(result.keys())
    keys.sort()
    for key in keys:
        out.write("  %s: %s\n" % (key, result[key]))


def show_uploads(uploads, out):
    """Print the uploads to stdout."""
    if uploads:
        out.write("Current uploads:\n")
    else:
        out.write("Current uploads: 0\n")
    for upload in uploads:
        out.write("  path: %s\n" % upload['path'])
        out.write(
            "    deflated size: %s\n" % upload.get('deflated_size', 'N/A'))
        out.write("    bytes written: %s\n" % upload['n_bytes_written'])


def show_downloads(downloads, out):
    """Print the downloads to stdout."""
    if downloads:
        out.write("Current downloads:\n")
    else:
        out.write("Current downloads: 0\n")
    for download in downloads:
        out.write("  path: %s\n" % download['path'])
        out.write(
            "    deflated size: %s\n" % download.get('deflated_size', 'N/A'))
        out.write("    bytes read: %s\n" % download['n_bytes_read'])


def show_state(state_dict, out):
    """Print the state to out."""
    out.write("State: %s\n" % state_dict.pop('name'))
    for k, v in sorted(state_dict.items()):
        out.write("    %s: %s\n" % (k, v))
    out.write("\n")


def show_free_space(free_space, out):
    """Print the free_space result."""
    out.write("Free space: %d bytes\n" % (free_space,))


def show_waiting(waiting_ops, out):
    """Print the waiting result.

    We receive an unordered dict, but always try to show first the command
    name, if it's running or not, the share_id, then the node_id, then the
    path, and the rest in alphabetical order.
    """
    for op_name, op_id, op_data in waiting_ops:
        # running
        attributes = []
        running = op_data.pop('running', None)
        if running is not None:
            bool_text = u'True' if running else u'False'
            attributes.append(u"running=%s" % (bool_text,))

        # custom
        for attr in ('share_id', 'node_id', 'path'):
            if attr in op_data:
                attributes.append(u"%s='%s'" % (attr, op_data.pop(attr)))

        # the rest, ordered
        for attr in sorted(op_data):
            attributes.append(u"%s='%s'" % (attr, op_data[attr]))

        out.write("  %s(%s)\n" % (op_name, u', '.join(attributes)))


def show_waiting_metadata(waiting_ops, out):
    """Print the waiting_metadata result.

    We receive an unordered dict, but always try to show first the
    share_id, then the node_id, then the path, and the rest in
    alphabetical order.
    """
    out.write("Warning: this option is deprecated! Use '--waiting' instead\n")
    return show_waiting(((x[0], None, x[1]) for x in waiting_ops), out)


def show_waiting_content(waiting_ops, out):
    """Print the waiting_content result."""
    out.write("Warning: this option is deprecated! Use '--waiting' instead\n")
    value_tpl = (
        "operation='%(operation)s' node_id='%(node)s' share_id='%(share)s' "
        "path='%(path)s'")
    for value in waiting_ops:
        str_value = value_tpl % value
        out.write("%s\n" % str_value)


def show_public_file_info(file_info, out):
    """Print the public access information for a file."""
    if file_info['is_public']:
        out.write("File is published at %s\n" % file_info['public_url'])
    else:
        out.write("File is not published\n")


def show_dirty_nodes(nodes, out):
    """Print the list of dirty nodes."""
    if not nodes:
        out.write(" No dirty nodes.\n")
        return
    node_line_tpl = (
        "mdid: %(mdid)s volume_id: %(share_id)s node_id: %(node_id)s "
        "is_dir: %(is_dir)s path: %(path)s\n")
    out.write(" Dirty nodes:\n")
    for node in nodes:
        assert isinstance(node['path'], unicode)
        out.write(node_line_tpl % node)
