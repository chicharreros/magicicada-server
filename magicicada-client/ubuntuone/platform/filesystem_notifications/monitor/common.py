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
"""Generic File notifications."""

import logging
import os
import sys

from twisted.internet import defer

from ubuntuone.platform.filesystem_notifications import notify_processor
from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    Event,
    WatchManagerError,
    IN_CREATE,
    IN_ISDIR,
    IN_DELETE,
    IN_MOVED_FROM,
    IN_MOVED_TO,
)

from ubuntuone import logger

from ubuntuone.platform.os_helper import (
    is_valid_syncdaemon_path,
    is_valid_os_path,
    os_path,
)


if sys.platform == 'darwin':
    from ubuntuone.platform.filesystem_notifications.monitor.darwin import (
        fsevents_client,
    )
    source = fsevents_client
elif sys.platform == 'win32':
    from ubuntuone.platform.filesystem_notifications.monitor import windows
    source = windows
else:
    raise ImportError('Not supported platform')


# a map between the few events that we have on common platforms and those
# found in pyinotify
ACTIONS = source.ACTIONS

# a map of the actions to names so that we have better logs.
ACTIONS_NAMES = source.ACTIONS_NAMES

# the base class to be use for a platform
PlatformWatch = source.Watch
PlatformWatchManager = source.WatchManager

# our logging level
TRACE = logger.TRACE


# The implementation of the code that is provided as the pyinotify substitute
class Watch(object):
    """Implement the same functions as pyinotify.Watch."""

    def __init__(self, watch_descriptor, path, processor):
        """Create a new watch."""

        # do ensure that we provide a os.path.sep
        if not path.endswith(os.path.sep):
            path += os.path.sep
        self.path = path
        self.ignore_paths = []
        self._processor = processor
        self._descriptor = watch_descriptor
        self._cookie = None
        self._source_pathname = None
        # remember the subdirs we have so that when we have a delete we can
        # check if it was a remove
        self._subdirs = set()

        # platform watch used to deal with the platform details
        self.platform_watch = PlatformWatch(self.path, self.process_events)

        self.log = logging.getLogger(
            'ubuntuone.SyncDaemon.platform.common.filesystem_notifications.'
            'Watch')
        self.log.setLevel(TRACE)

    def process_events(self, action, file_name, cookie, syncdaemon_path):
        """Process the events from the queue."""
        # do not process events when the watch was stopped
        if not self.platform_watch.watching:
            return

        # do not process those events that should be ignored
        if any([file_name.startswith(path)
                for path in self.ignore_paths]):
            return

        # map the filesystem events to the pyinotify ones, tis is dirty but
        # makes the multiplatform better, linux was first :P
        full_dir_path = os.path.join(self.path, file_name)
        is_dir = self._path_is_dir(full_dir_path)

        if is_dir:
            # we need to update the list of subdirs that we have
            self._update_subdirs(full_dir_path, action)

        mask = ACTIONS[action]
        head, tail = os.path.split(file_name)
        if is_dir:
            mask |= IN_ISDIR
        event_raw_data = {
            'wd': self._descriptor,
            'dir': is_dir,
            'mask': mask,
            'name': tail,
            'path': '.'}
        # by the way in which the api fires the events we know for
        # sure that no move events will be added in the wrong order, this
        # is kind of hacky, I dont like it too much
        if ACTIONS[action] == IN_MOVED_FROM:
            self._cookie = cookie
            self._source_pathname = tail
            event_raw_data['cookie'] = self._cookie
        if ACTIONS[action] == IN_MOVED_TO:
            event_raw_data['src_pathname'] = self._source_pathname
            event_raw_data['cookie'] = self._cookie
        event = Event(event_raw_data)
        # FIXME: event deduces the pathname wrong and we need to manually
        # set it
        event.pathname = syncdaemon_path
        # add the event only if we do not have an exclude filter or
        # the exclude filter returns False, that is, the event will not
        # be excluded
        self.log.debug('Pushing event %r to processor.', event)
        self._processor(event)

    @is_valid_os_path(path_indexes=[1])
    def _update_subdirs(self, path, event):
        """Adds the path to the internal subdirs.

        The given path is considered to be a path and therefore this
        will not be checked.
        """
        if ACTIONS[event] == IN_CREATE:
            self._subdirs.add(path)
        elif ACTIONS[event] == IN_DELETE and path in self._subdirs:
            self._subdirs.remove(path)

    @is_valid_os_path(path_indexes=[1])
    def _path_is_dir(self, path):
        """Check if the path is a dir."""

        # We need to manually check if the path is a folder, because
        # neither ReadDirectoryChangesW nor the FSEvents API tell us

        is_dir = False
        if os.path.exists(path):
            is_dir = os.path.isdir(path)
        else:
            # path does not exists, was it in the internal list?
            is_dir = path in self._subdirs
        self.log.debug('Is path %r a dir? %s', path, is_dir)
        return is_dir

    @is_valid_os_path(path_indexes=[1])
    def ignore_path(self, path):
        """Add the path of the events to ignore."""
        if not path.endswith(os.path.sep):
            path += os.path.sep
        if path.startswith(self.path):
            path = path[len(self.path):]
            self.ignore_paths.append(path)

    @is_valid_os_path(path_indexes=[1])
    def remove_ignored_path(self, path):
        """Reaccept path."""
        if not path.endswith(os.path.sep):
            path += os.path.sep
        if path.startswith(self.path):
            path = path[len(self.path):]
            if path in self.ignore_paths:
                self.ignore_paths.remove(path)

    @defer.inlineCallbacks
    def start_watching(self):
        """Tell the watch to start processing events."""
        for current_child in os.listdir(self.path):
            full_child_path = os.path.join(self.path, current_child)
            if os.path.isdir(full_child_path):
                self._subdirs.add(full_child_path)
        # start to diff threads, one to watch the path, the other to
        # process the events.
        self.log.debug('Start watching path.')
        yield self.platform_watch.start_watching()

    def stop_watching(self):
        """Tell the watch to stop processing events."""
        self.log.info('Stop watching %s', self.path)
        self.platform_watch.watching = False
        self._subdirs = set()
        return self.platform_watch.stop_watching()

    @property
    def watching(self):
        """Return if we are watching."""
        return self.platform_watch.watching

    @property
    def started(self):
        """A deferred that will be called when the watch is running."""
        return self.platform_watch.started

    @property
    def stopped(self):
        """A deferred fired when the watch thread has finished."""
        return self.platform_watch.stopped


class WatchManager(object):
    """Implement the same functions as pyinotify.WatchManager.

    All paths passed to methods in this class should be proper os paths.

    """

    def __init__(self, processor):
        """Init the manager to keep trak of the different watches."""
        self.log = logging.getLogger(
            'ubuntuone.SyncDaemon.platform.common.filesystem_notifications.'
            'WatchManager')
        self.log.setLevel(TRACE)
        self._processor = processor
        # use the platform manager to perform the actual actions
        self.platform_manager = PlatformWatchManager(self.log)
        self._wdm = {}
        self._ignored_paths = []

    @defer.inlineCallbacks
    def _add_single_watch(self, path, mask, quiet=True):
        """A just one watch."""
        if path in self._ignored_paths:
            # simply removed it from the filter
            self._ignored_paths.remove(path)
            return

        # we need to add a new watch
        self.log.debug('add_single_watch(%s, %s, %s)', path, mask, quiet)

        # common code that will ensure that we keep track of the watches
        watch = Watch(len(self._wdm), path, self._processor)
        self._wdm[len(self._wdm)] = watch
        yield watch.start_watching()

        # trust that the platform watch manager to do the rest of the start
        # operations
        defer.returnValue(self.platform_manager.add_watch(watch))

    @is_valid_os_path(path_indexes=[1])
    def add_watch(self, path, mask, quiet=True):
        """Add a new path to be watched.

        The method will ensure that the path is not already present.
        """
        wd = self.get_wd(path)
        if wd is None:
            self.log.debug('Adding single watch on %r', path)
            return self._add_single_watch(path, mask, quiet)
        else:
            self.log.debug('Watch already exists on %r', path)
            return self._wdm[wd].started

    def get_watch(self, wd):
        """Return the watch with the given descriptor."""
        return self._wdm[wd]

    @is_valid_os_path(path_indexes=[1])
    def get_wd(self, path):
        """Return the watcher that is used to watch the given path."""
        if not path[-1] == os.path.sep:
            path += os.path.sep
        for current_wd in self._wdm:
            watch_path = self._wdm[current_wd].path
            if ((watch_path == path or watch_path in path) and
                    path not in self._ignored_paths):
                return current_wd

    def get_path(self, wd):
        """Return the path watched by the watch with the given wd."""
        watch = self._wdm.get(wd)
        if watch:
            return watch.path

    @defer.inlineCallbacks
    def rm_watch(self, wd, rec=False, quiet=True):
        """Remove the the watch with the given wd."""
        try:
            watch = self._wdm[wd]
            yield watch.stop_watching()
            del self._wdm[wd]
            # trust that the platform watch manager will do the rest of the
            # operations needed to delete a watch
            self.platform_manager.rm_watch(watch)
        except KeyError, err:
            self.log.error(str(err))
            if not quiet:
                raise WatchManagerError('Watch %s was not found' % wd, {})

    @is_valid_os_path(path_indexes=[1])
    def rm_path(self, path):
        """Remove a watch to the given path."""
        wd = self.get_wd(path)
        if wd is not None:
            self.log.debug('Adding exclude filter for %r', path)
            self._wdm[wd].ignore_path(path)

    @defer.inlineCallbacks
    def stop(self):
        """Close the manager and stop all watches."""
        self.log.debug('Stopping watches.')
        for current_wd in self._wdm:
            watch = self._wdm[current_wd]
            yield self.platform_manager.stop_watch(watch)
            self.log.debug('Stopping Watch on %r.', watch.path)
        yield self.platform_manager.stop()


class FilesystemMonitor(object):
    """Manages the signals from filesystem."""

    def __init__(self, eq, fs, ignore_config=None, timeout=1):
        self.log = logging.getLogger('ubuntuone.SyncDaemon.FSMonitor')
        self.filesystem_monitor_mask = None
        self.log.setLevel(TRACE)
        self.fs = fs
        self.eq = eq
        self._processor = notify_processor.NotifyProcessor(self, ignore_config)
        self._watch_manager = WatchManager(self._processor)

    @classmethod
    def is_available_monitor(cls):
        """Return if the monitor can be used in the platform."""
        # we can always use this monitor
        return defer.succeed(True)

    def add_to_mute_filter(self, event, **info):
        """Add info to mute filter in the processor."""
        self._processor.add_to_mute_filter(event, info)

    def rm_from_mute_filter(self, event, **info):
        """Remove info to mute filter in the processor."""
        self._processor.rm_from_mute_filter(event, info)

    def shutdown(self):
        """Prepares the EQ to be closed."""
        return self._watch_manager.stop()

    @os_path(path_indexes=[1])
    def rm_watch(self, dirpath):
        """Remove watch from a dir."""
        # trust the implementation of the manager
        self._watch_manager.rm_path(dirpath)

    @os_path(path_indexes=[1])
    def add_watch(self, dirpath):
        """Add watch to a dir."""
        # the logic to check if the watch is already set
        # is all in WatchManager.add_watch
        return self._watch_manager.add_watch(
            dirpath, self.filesystem_monitor_mask)

    def add_watches_to_udf_ancestors(self, volume):
        """Add a inotify watch to volume's ancestors if it's an UDF."""
        return defer.succeed(True)

    def is_frozen(self):
        """Checks if there's something frozen."""
        return self._processor.frozen_path is not None

    @is_valid_syncdaemon_path(path_indexes=[1])
    def freeze_begin(self, path):
        """Puts in hold all the events for this path."""
        if self._processor.frozen_path is not None:
            raise ValueError("There's something already frozen!")
        self._processor.freeze_begin(path)

    def freeze_rollback(self):
        """Unfreezes the frozen path, reseting to idle state."""
        if self._processor.frozen_path is None:
            raise ValueError("Rolling back with nothing frozen!")
        self._processor.freeze_rollback()

    def freeze_commit(self, events):
        """Unfreezes the frozen path, sending received events if not dirty.

        If events for that path happened:
            - return True
        else:
            - push the here received events, return False
        """
        if self._processor.frozen_path is None:
            raise ValueError("Commiting with nothing frozen!")

        d = defer.execute(self._processor.freeze_commit, events)
        return d
