# -*- coding: utf-8 *-*
#
# Copyright 2012 Canonical Ltd.
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
"""Filesystem Notifications module for MAC OS."""

import os

import fsevents
from twisted.internet import defer, reactor

from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    IN_DELETE,
    IN_CREATE,
    IN_MODIFY,
    IN_MOVED_FROM,
    IN_MOVED_TO,
)

# a map between the few events that we have on common platforms and those
# found in pyinotify
ACTIONS = {
    fsevents.IN_CREATE: IN_CREATE,
    fsevents.IN_DELETE: IN_DELETE,
    fsevents.IN_ATTRIB: IN_MODIFY,
    fsevents.IN_MODIFY: IN_MODIFY,
    fsevents.IN_MOVED_FROM: IN_MOVED_FROM,
    fsevents.IN_MOVED_TO: IN_MOVED_TO,
}

# a map of the actions to names so that we have better logs.
ACTIONS_NAMES = {
    fsevents.IN_CREATE: 'IN_CREATE',
    fsevents.IN_DELETE: 'IN_DELETE',
    fsevents.IN_MODIFY: 'IN_MODIFY',
    fsevents.IN_MOVED_FROM: 'IN_MOVED_FROM',
    fsevents.IN_MOVED_TO: 'IN_MOVED_TO',
}


# The implementation of the code that is provided as the pyinotify substitute
class Watch(object):
    """Implement the same functions as pyinotify.Watch."""

    def __init__(self, path, process_events):
        """Create a new instance for the given path.

        The process_events parameter is a callback to be executed in the main
        reactor thread to convert events in pyinotify events and add them to
        the state machine.
        """
        self.path = os.path.abspath(path)
        self.process_events = process_events
        self.watching = False
        self.ignore_paths = []
        # Create stream with folder to watch
        self.stream = fsevents.Stream(
            self._process_events, path, file_events=True)

    def _process_events(self, event):
        """Receive the filesystem event and move it to the main thread."""
        reactor.callFromThread(self._process_events_in_main_thread, event)

    def _process_events_in_main_thread(self, event):
        """Process the events from the queue."""
        action, cookie, file_name = (event.mask, event.cookie, event.name)

        syncdaemon_path = os.path.join(self.path, file_name)
        self.process_events(
            action, file_name, cookie, syncdaemon_path)

    def start_watching(self):
        """Start watching."""
        self.watching = True
        return defer.succeed(self.watching)

    def stop_watching(self):
        """Stop watching."""
        self.watching = False
        return defer.succeed(self.watching)

    # For API compatibility
    @property
    def started(self):
        """A deferred that will be called when the watch is running."""
        return defer.succeed(self.watching)

    @property
    def stopped(self):
        """A deferred fired when the watch thread has finished."""
        return defer.succeed(self.watching)


class WatchManager(object):
    """Implement the same functions as pyinotify.WatchManager.

    All paths passed to methods in this class should be darwin paths.

    """

    def __init__(self, log):
        """Init the manager to keep track of the different watches."""
        self.log = log
        self.observer = fsevents.Observer(latency=0, process_asap=True)
        self.observer.start()

    def stop_watch(self, watch):
        """Unschedule an observer stream."""
        watch.stop_watching()
        self.observer.unschedule(watch.platform_watch.stream)
        return defer.succeed(True)

    def stop(self):
        """Stop the manager."""
        self.observer.stop()
        self.observer.join()

    def add_watch(self, watch):
        """This method perform actually the action of registering the watch."""
        self.observer.schedule(watch.platform_watch.stream)
        return True

    def rm_watch(self, watch):
        """Remove the the watch with the given wd."""
        self.observer.unschedule(watch.platform_watch.stream)
