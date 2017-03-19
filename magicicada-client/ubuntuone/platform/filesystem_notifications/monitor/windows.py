# -*- coding: utf-8 *-*
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
"""File notifications on windows."""

import logging
import os

from uuid import uuid4

from twisted.internet import defer, reactor
from twisted.python.failure import Failure

from pywintypes import OVERLAPPED
from win32api import CloseHandle
from win32con import (
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_FLAG_BACKUP_SEMANTICS,
    FILE_NOTIFY_CHANGE_FILE_NAME,
    FILE_NOTIFY_CHANGE_DIR_NAME,
    FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_SIZE,
    FILE_NOTIFY_CHANGE_LAST_WRITE,
    FILE_NOTIFY_CHANGE_SECURITY,
    OPEN_EXISTING)
from win32file import (
    AllocateReadBuffer,
    CreateFileW,
    GetOverlappedResult,
    ReadDirectoryChangesW,
    FILE_FLAG_OVERLAPPED,
    FILE_NOTIFY_INFORMATION)
from win32event import (
    CreateEvent,
    INFINITE,
    SetEvent,
    WaitForMultipleObjects,
    WAIT_OBJECT_0)

from ubuntuone.platform.os_helper.windows import (
    get_syncdaemon_valid_path,
)

from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    IN_CREATE,
    IN_DELETE,
    IN_MODIFY,
    IN_MOVED_FROM,
    IN_MOVED_TO,
)


# map between windows events and pyinotify
ACTIONS = {
    1: IN_CREATE,
    2: IN_DELETE,
    3: IN_MODIFY,
    4: IN_MOVED_FROM,
    5: IN_MOVED_TO,
}

# a map of the actions to names so that we have better logs.
ACTIONS_NAMES = {
    1: 'IN_CREATE',
    2: 'IN_DELETE',
    3: 'IN_MODIFY',
    4: 'IN_MOVED_FROM',
    5: 'IN_MOVED_TO',
}


# constant found in the msdn documentation:
# http://msdn.microsoft.com/en-us/library/ff538834(v=vs.85).aspx
FILE_LIST_DIRECTORY = 0x0001
FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020
FILE_NOTIFY_CHANGE_CREATION = 0x00000040

THREADPOOL_MAX = 20

FILESYSTEM_MONITOR_MASK = FILE_NOTIFY_CHANGE_FILE_NAME | \
    FILE_NOTIFY_CHANGE_DIR_NAME | \
    FILE_NOTIFY_CHANGE_ATTRIBUTES | \
    FILE_NOTIFY_CHANGE_SIZE | \
    FILE_NOTIFY_CHANGE_LAST_WRITE | \
    FILE_NOTIFY_CHANGE_SECURITY | \
    FILE_NOTIFY_CHANGE_LAST_ACCESS


class Watch(object):
    """Implement the same functions as pyinotify.Watch."""

    def __init__(self, path, process_events, mask=FILESYSTEM_MONITOR_MASK,
                 buf_size=8192):
        self.path = os.path.abspath(path)
        self.process_events = process_events
        self.watching = False
        self.log = logging.getLogger(
            'ubuntuone.SyncDaemon.platform.windows.filesystem_notifications.'
            'Watch')
        self.log.setLevel(logging.DEBUG)
        self._buf_size = buf_size
        self._mask = mask
        self.ignore_paths = []
        self._watch_handle = None

        self._wait_stop = CreateEvent(None, 0, 0, None)
        self._overlapped = OVERLAPPED()
        self._overlapped.hEvent = CreateEvent(None, 0, 0, None)
        # this deferred is fired when the watch has started monitoring
        # a directory from a thread
        self._watch_started_deferred = defer.Deferred()
        # and this one is fired when the watch has stopped
        self._watch_stopped_deferred = defer.Deferred()

    def _process_events(self, events):
        """Process the events from the queue."""
        # we transform the events to be the same as the one in pyinotify
        # and then use the proc_fun
        for action, file_name in events:
            syncdaemon_path = get_syncdaemon_valid_path(
                os.path.join(self.path, file_name))
            self.process_events(
                action, file_name, str(uuid4()), syncdaemon_path)

    def _call_deferred(self, f, *args):
        """Executes the deferred call avoiding possible race conditions."""
        if not self._watch_started_deferred.called:
            f(*args)

    def _watch_wrapper(self):
        """Wrap _watch, and errback on any unhandled error."""
        try:
            self._watch()
        except Exception as e:
            reactor.callFromThread(
                self._call_deferred, self._watch_started_deferred.errback,
                Failure(e))

    def _watch(self):
        """Watch a path that is a directory."""
        self.log.debug('Adding watch for %r (exists? %r is dir? %r).',
                       self.path,
                       os.path.exists(self.path), os.path.isdir(self.path))
        # we are going to be using the ReadDirectoryChangesW whihc requires
        # a directory handle and the mask to be used.
        self._watch_handle = CreateFileW(
            self.path,
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            None)

        try:
            self._watch_loop(self._watch_handle)
        finally:
            CloseHandle(self._watch_handle)
            self._watch_handle = None
            reactor.callFromThread(self.stopped.callback, True)

    def _watch_loop(self, handle):
        """The loop where we watch the directory."""
        while True:
            # important information to know about the parameters:
            # param 1: the handle to the dir
            # param 2: the size to be used in the kernel to store events
            # that might be lost while the call is being performed. This
            # is complicated to fine tune since if you make lots of watcher
            # you migh used too much memory and make your OS to BSOD
            buf = AllocateReadBuffer(self._buf_size)
            ReadDirectoryChangesW(
                handle,
                buf,
                True,  # Always watch children
                self._mask,
                self._overlapped,
            )
            if not self._watch_started_deferred.called:
                reactor.callFromThread(
                    self._call_deferred, self._watch_started_deferred.callback,
                    True)
            # wait for an event and ensure that we either stop or read the
            # data
            rc = WaitForMultipleObjects(
                (self._wait_stop, self._overlapped.hEvent), 0, INFINITE)
            if rc == WAIT_OBJECT_0:
                # Stop event
                break
            # if we continue, it means that we got some data, lets read it
            data = GetOverlappedResult(handle, self._overlapped, True)
            # lets ead the data and store it in the results
            events = FILE_NOTIFY_INFORMATION(buf, data)
            self.log.debug(
                'Got from ReadDirectoryChangesW %r.',
                [(ACTIONS_NAMES[action], path) for action, path in events])
            reactor.callFromThread(self._process_events, events)

    def start_watching(self):
        """Tell the watch to start processing events."""
        self.watching = True
        reactor.callInThread(self._watch_wrapper)
        return self._watch_started_deferred

    def stop_watching(self):
        """Tell the watch to stop processing events."""
        SetEvent(self._wait_stop)
        self.watching = False
        return self.stopped

    @property
    def started(self):
        """A deferred that will be called when the watch is running."""
        return self._watch_started_deferred

    @property
    def stopped(self):
        """A deferred fired when the watch thread has finished."""
        return self._watch_stopped_deferred


class WatchManager(object):
    """Implement the same functions as pyinotify.WatchManager.

    All paths passed to methods in this class should be windows paths.

    """

    def __init__(self, log):
        """Create a new instance."""
        self.log = log
        self._wd_count = 0

    def stop_watch(self, watch):
        """Stop a watch."""
        # decrease the number of watches
        self._wd_count -= 1
        return watch.stop_watching()

    def stop(self):
        """Close the manager and stop all watches."""
        self.log.debug('Stopping watches.')
        return defer.succeed(True)

    def rm_watch(self, watch):
        """Stop the Watch."""
        self._wd_count -= 1
        return defer.succeed(True)

    def add_watch(self, watch):
        # adjust the number of threads based on the UDFs watched
        self._wd_count += 1
        reactor.suggestThreadPoolSize(THREADPOOL_MAX + self._wd_count + 1)
        return True
