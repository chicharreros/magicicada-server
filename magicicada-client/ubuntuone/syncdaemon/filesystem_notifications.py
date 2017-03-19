# Author: Manuel de la Pena <manuel@canonical.com>
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
"""Platfrom independent filesystem notifications code."""

import logging
import os
import re

from ubuntuone.platform import access, path_exists
from ubuntuone.syncdaemon.mute_filter import MuteFilter
from ubuntuone import logger
# our logging level
TRACE = logger.TRACE


class GeneralINotifyProcessor(object):
    """Processor that takes care of dealing with the events."""

    def __init__(self, monitor, handle_dir_delete, name_translations,
                 platform_is_ignored, ignore_mask, ignore_config=None):
        self.log = logging.getLogger(
            'ubuntuone.SyncDaemon.filesystem_notifications.GeneralProcessor')
        self.log.setLevel(TRACE)
        self.invnames_log = logging.getLogger(
            'ubuntuone.SyncDaemon.InvalidNames')
        self.monitor = monitor
        self.handle_dir_delete = handle_dir_delete
        self.name_translations = name_translations
        self.platform_is_ignored = platform_is_ignored
        self.ignore_mask = ignore_mask
        self.frozen_path = None
        self.frozen_evts = False
        self._to_mute = MuteFilter()
        self.conflict_RE = re.compile(r"\.u1conflict(?:\.\d+)?$")

        if ignore_config is not None:
            self.log.info("Ignoring files: %s", ignore_config)
            # thanks Chipaca for the following "regex composing"
            complex = '|'.join('(?:' + r + ')' for r in ignore_config)
            self.ignore_RE = re.compile(complex)
        else:
            self.ignore_RE = None

    def mute_filter(self, action, event, paths):
        """Really touches the mute filter."""
        # all events have one path except the MOVEs
        if event in ("FS_FILE_MOVE", "FS_DIR_MOVE"):
            f_path, t_path = paths['path_from'], paths['path_to']
            is_from_forreal = not self.is_ignored(f_path)
            is_to_forreal = not self.is_ignored(t_path)
            if is_from_forreal and is_to_forreal:
                action(event, **paths)
            elif is_to_forreal:
                action('FS_FILE_CREATE', path=t_path)
                action('FS_FILE_CLOSE_WRITE', path=t_path)
        else:
            path = paths['path']
            if not self.is_ignored(path):
                action(event, **paths)

    def rm_from_mute_filter(self, event, paths):
        self.mute_filter(self._to_mute.rm, event, paths)

    def add_to_mute_filter(self, event, paths):
        """Add an event and path(s) to the mute filter."""
        self.mute_filter(self._to_mute.add, event, paths)

    def get_path_share_id(self, path):
        """Return the id of the given path."""
        return self.monitor.fs.get_by_path(path).share_id

    def get_paths_starting_with(self, path, include_base=True):
        """Return all the paths that start with the given one."""
        return self.monitor.fs.get_paths_starting_with(
            path, include_base=False)

    def rm_watch(self, path):
        """Remove the watch for the given path."""
        self.monitor.rm_watch(path)

    def is_ignored(self, path):
        """should we ignore this path?"""
        # check first if the platform code knows hat to do with it
        if not self.platform_is_ignored(path):
            # check if we can read
            if path_exists(path) and not access(path):
                self.log.warning("Ignoring path as we don't have enough "
                                 "permissions to track it: %r", path)
                return True

            is_conflict = self.conflict_RE.search
            dirname, filename = os.path.split(path)
            # ignore conflicts
            if is_conflict(filename):
                return True
            # ignore partial downloads
            if filename == '.u1partial' or filename.startswith('.u1partial.'):
                return True

            # and ignore paths that are inside conflicts (why are we even
            # getting the event?)
            if any(part.endswith('.u1partial') or is_conflict(part)
                   for part in dirname.split(os.path.sep)):
                return True

            if self.ignore_RE is not None and self.ignore_RE.match(filename):
                return True

            return False
        return True

    def eq_push(self, event_name, **event_data):
        """Sends to EQ the event data, maybe filtering it."""
        if event_name == 'FS_DIR_DELETE':
            self.handle_dir_delete(event_data['path'])
        if not self._to_mute.pop(event_name, **event_data):
            self.monitor.eq.push(event_name, **event_data)

    def push_event(self, event):
        """Push the event to the EQ."""
        # ignore this trash
        if event.mask == self.ignore_mask:
            return

        # change the pattern IN_CREATE to FS_FILE_CREATE or FS_DIR_CREATE
        try:
            evt_name = self.name_translations[event.mask]
        except:
            self.log.error("Unhandled Event in INotify: %s", event)
            raise KeyError("Unhandled Event in INotify: %s" % event)
        # check if the path is not frozen
        if self.frozen_path is not None:
            if event.path == self.frozen_path:
                # this will at least store the last one, for debug
                # purposses
                self.frozen_evts = (evt_name, event.pathname)
                return

        if not self.is_ignored(event.pathname):
            self.eq_push(evt_name, path=event.pathname)

    def freeze_begin(self, path):
        """Puts in hold all the events for this path."""
        self.log.trace("Freeze begin: %r", path)
        self.frozen_path = path
        self.frozen_evts = False

    def freeze_rollback(self):
        """Unfreezes the frozen path, reseting to idle state."""
        self.log.debug("Freeze rollback: %r", self.frozen_path)
        self.frozen_path = None
        self.frozen_evts = False

    def freeze_commit(self, events):
        """Unfreezes the frozen path, sending received events if not dirty.

        If events for that path happened:
            - return True
        else:
            - push the here received events, return False
        """
        self.log.trace(
            "Freeze commit: %r (%d events)", self.frozen_path, len(events))
        if self.frozen_evts:
            # ouch! we're dirty!
            self.log.debug("Dirty by %s", self.frozen_evts)
            self.frozen_evts = False
            return True

        # push the received events
        for evt_name, path in events:
            if not self.is_ignored(path):
                self.eq_push(evt_name, path=path)

        self.frozen_path = None
        self.frozen_evts = False
        return False

    @property
    def filter(self):
        """Return the mute filter used by the processor."""
        return self._to_mute
