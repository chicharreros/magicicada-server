# -*- coding: utf-8 *-*
# ubuntuone.syncdaemon.event_queue - Event queuing
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
"""Module that implements the Filesystem Monitor machinery."""

import logging
import os

import pyinotify
from twisted.internet import abstract, reactor,  defer

from ubuntuone.platform.os_helper import access
from ubuntuone.platform.filesystem_notifications import notify_processor


# translates quickly the event and it's is_dir state to our standard events
NAME_TRANSLATIONS = {
    pyinotify.IN_OPEN: 'FS_FILE_OPEN',
    pyinotify.IN_CLOSE_NOWRITE: 'FS_FILE_CLOSE_NOWRITE',
    pyinotify.IN_CLOSE_WRITE: 'FS_FILE_CLOSE_WRITE',
    pyinotify.IN_CREATE: 'FS_FILE_CREATE',
    pyinotify.IN_CREATE | pyinotify.IN_ISDIR: 'FS_DIR_CREATE',
    pyinotify.IN_DELETE: 'FS_FILE_DELETE',
    pyinotify.IN_DELETE | pyinotify.IN_ISDIR: 'FS_DIR_DELETE',
    pyinotify.IN_MOVED_FROM: 'FS_FILE_DELETE',
    pyinotify.IN_MOVED_FROM | pyinotify.IN_ISDIR: 'FS_DIR_DELETE',
    pyinotify.IN_MOVED_TO: 'FS_FILE_CREATE',
    pyinotify.IN_MOVED_TO | pyinotify.IN_ISDIR: 'FS_DIR_CREATE',
}

# these are the events that will listen from inotify
INOTIFY_EVENTS_GENERAL = (
    pyinotify.IN_OPEN |
    pyinotify.IN_CLOSE_NOWRITE |
    pyinotify.IN_CLOSE_WRITE |
    pyinotify.IN_CREATE |
    pyinotify.IN_DELETE |
    pyinotify.IN_MOVED_FROM |
    pyinotify.IN_MOVED_TO |
    pyinotify.IN_MOVE_SELF)

INOTIFY_EVENTS_ANCESTORS = (
    pyinotify.IN_DELETE |
    pyinotify.IN_MOVED_FROM |
    pyinotify.IN_MOVED_TO |
    pyinotify.IN_MOVE_SELF)


class _AncestorsINotifyProcessor(pyinotify.ProcessEvent):
    """inotify's processor when an event happens on an UDFs ancestor."""
    def __init__(self, monitor):
        self.log = logging.getLogger('ubuntuone.SyncDaemon.AncestorsINotProc')
        self.monitor = monitor

    def _get_udfs(self, path):
        """Yield all the subscribed udfs under a specific path."""
        pathsep = path + os.path.sep
        for udf in self.monitor.fs.vm.udfs.itervalues():
            udfpath = udf.path + os.path.sep
            if udfpath.startswith(pathsep) and udf.subscribed:
                yield udf

    def process_IN_MOVE_SELF(self, event):
        """Don't do anything here.

        We just turned this event on because pyinotify does some
        path-fixing in its internal processing when this happens.
        """
    process_IN_MOVED_TO = process_IN_MOVE_SELF

    def process_IN_MOVED_FROM(self, event):
        """Getting it out or renaming means unsuscribe."""
        if event.mask & pyinotify.IN_ISDIR:
            unsubscribed_udfs = set()
            for udf in self._get_udfs(event.pathname):
                self.log.info(
                    "Got MOVED_FROM on path %r, unsubscribing udf %s",
                    event.pathname, udf)
                self.monitor.fs.vm.unsubscribe_udf(udf.volume_id)
                unsubscribed_udfs.add(udf)
            self._unwatch_ancestors(unsubscribed_udfs)

    def process_IN_DELETE(self, event):
        """Check to see if the UDF was deleted."""
        if event.mask & pyinotify.IN_ISDIR:
            deleted_udfs = set()
            for udf in self._get_udfs(event.pathname):
                self.log.info(
                    "Got DELETE on path %r, deleting udf %s",
                    event.pathname, udf)
                self.monitor.fs.vm.delete_volume(udf.volume_id)
                deleted_udfs.add(udf)
            self._unwatch_ancestors(deleted_udfs)

    def _unwatch_ancestors(self, udfs):
        """Unwatch the ancestors of the recevied udfs only."""
        # collect all the ancestors of the received udfs
        ancestors_to_unwatch = set()
        for udf in udfs:
            ancestors_to_unwatch.update(set(udf.ancestors))

        # collect the ancestors of all the still subscribed UDFs except
        # the received ones
        sub_udfs = (
            u for u in self.monitor.fs.vm.udfs.itervalues() if u.subscribed)
        udf_remain = set(sub_udfs) - udfs
        ancestors_to_keep = set()
        for udf in udf_remain:
            ancestors_to_keep.update(set(udf.ancestors))

        # unwatch only the ancestors of the received udfs
        only_these = ancestors_to_unwatch - ancestors_to_keep
        for ancestor in only_these:
            self.monitor.rm_watch(ancestor)


class FilesystemMonitor(object):
    """Manages the signals from filesystem."""

    def __init__(self, eq, fs, ignore_config=None):
        self.log = logging.getLogger('ubuntuone.SyncDaemon.FSMonitor')
        self.fs = fs
        self.eq = eq

        # general inotify
        self._inotify_general_wm = wm = pyinotify.WatchManager()
        self._processor = notify_processor.NotifyProcessor(self, ignore_config)
        self._inotify_notifier_gral = pyinotify.Notifier(wm, self._processor)
        self._inotify_reader_gral = self._hook_inotify_to_twisted(
            wm, self._inotify_notifier_gral)
        self._general_watchs = {}

        # ancestors inotify
        self._inotify_ancestors_wm = wm = pyinotify.WatchManager()
        antr_processor = _AncestorsINotifyProcessor(self)
        self._inotify_notifier_antr = pyinotify.Notifier(wm, antr_processor)
        self._inotify_reader_antr = self._hook_inotify_to_twisted(
            wm, self._inotify_notifier_antr)
        self._ancestors_watchs = {}

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

    def _hook_inotify_to_twisted(self, wm, notifier):
        """This will hook inotify to twisted."""

        class MyReader(abstract.FileDescriptor):
            """Chain between inotify and twisted."""
            # will never pass a fd to write

            def fileno(self):
                """Returns the fileno to select()."""
                return wm._fd

            def doRead(self):
                """Called when twisted says there's something to read."""
                notifier.read_events()
                notifier.process_events()

        reader = MyReader()
        reactor.addReader(reader)
        return reader

    def shutdown(self):
        """Prepares the EQ to be closed."""
        self._inotify_notifier_gral.stop()
        self._inotify_notifier_antr.stop()
        reactor.removeReader(self._inotify_reader_gral)
        reactor.removeReader(self._inotify_reader_antr)
        self._processor.shutdown()

    def rm_watch(self, dirpath):
        """Remove watch from a dir."""
        if dirpath in self._general_watchs:
            w_dict = self._general_watchs
            w_manager = self._inotify_general_wm
        elif dirpath in self._ancestors_watchs:
            w_dict = self._ancestors_watchs
            w_manager = self._inotify_ancestors_wm
        else:
            self.log.warning("Tried to remove a nonexistent watch on %r",
                             dirpath)
            return

        wd = w_dict.pop(dirpath)
        w_manager.rm_watch(wd)

    def add_watch(self, dirpath):
        """Add watch to a dir."""
        # see where to add it
        if self._is_udf_ancestor(dirpath):
            w_type = "ancestors"
            w_manager = self._inotify_ancestors_wm
            w_dict = self._ancestors_watchs
            events = INOTIFY_EVENTS_ANCESTORS
        else:
            w_type = "general"
            w_manager = self._inotify_general_wm
            w_dict = self._general_watchs
            events = INOTIFY_EVENTS_GENERAL

        # not add it if already there
        if dirpath in w_dict:
            self.log.debug("Watch already there for %r", dirpath)
            return defer.succeed(False)

        # add the watch!
        self.log.debug("Adding %s inotify watch to %r", w_type, dirpath)
        result = w_manager.add_watch(dirpath, events)
        w_dict[dirpath] = result[dirpath]
        return defer.succeed(True)

    @defer.inlineCallbacks
    def add_watches_to_udf_ancestors(self, volume):
        """Add a inotify watch to volume's ancestors if it's an UDF."""
        added_watches = []

        def revert_watches():
            """Restore the just added watches and unsubscribe volume."""
            for path in added_watches:
                self.eq.rm_watch(path)

        for ancestor in volume.ancestors:
            # check that ancestor is still there
            if not access(ancestor):
                self.log.info("Tree broken at path: %r", volume.path)
                revert_watches()
                defer.returnValue(False)

            self.log.debug("Adding watch to UDF's ancestor %r", ancestor)
            really_added = yield self.eq.add_watch(ancestor)
            # only note it for the revert if the watch was not there before
            if really_added:
                added_watches.append(ancestor)

        # all is ok
        defer.returnValue(True)

    def inotify_watch_fix(self, pathfrom, pathto):
        """Fix the path in inotify structures."""
        if pathfrom in self._general_watchs:
            wdict = self._general_watchs
        elif pathfrom in self._ancestors_watchs:
            wdict = self._ancestors_watchs
        else:
            m = "Tried to fix nonexistent path %r in watches (to %r)"
            self.log.warning(m, pathfrom, pathto)
            return

        # fix
        wdict[pathto] = wdict.pop(pathfrom)

    def _is_udf_ancestor(self, path):
        """Decide if path is an UDF ancestor or not."""
        for udf in self.fs.vm.udfs.itervalues():
            parent = os.path.dirname(udf.path) + os.path.sep
            if parent.startswith(path + os.path.sep):
                return True
        return False

    def is_frozen(self):
        """Checks if there's something frozen."""
        return self._processor.frozen_path is not None

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
