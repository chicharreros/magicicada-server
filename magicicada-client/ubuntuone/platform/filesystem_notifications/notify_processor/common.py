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
"""Win and darwin implementation."""

import os
import sys

from ubuntuone.syncdaemon.filesystem_notifications import (
    GeneralINotifyProcessor,
)
from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    Event,
    ProcessEvent,
    IN_OPEN,
    IN_CLOSE_NOWRITE,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_IGNORED,
    IN_ISDIR,
    IN_DELETE,
    IN_MOVED_FROM,
    IN_MOVED_TO,
)

from ubuntuone.platform.os_helper import (
    is_valid_syncdaemon_path,
)

if sys.platform == 'win32':

    @is_valid_syncdaemon_path()
    def win_is_ignored(path):
        """Should we ignore this path in the current platform.?"""
        # don't support links yet
        if path.endswith('.lnk'):
            return True
        return False

    # work around for pyflakes :(
    path_is_ignored = win_is_ignored
else:

    def unix_is_ignored(path):
        """Should we ignore this path in the current platform.?"""
        # don't support links yet
        if os.path.islink(path):
            return True
        return False

    # work around for pyflakes :(
    path_is_ignored = unix_is_ignored

# translates quickly the event and it's is_dir state to our standard events
NAME_TRANSLATIONS = {
    IN_OPEN: 'FS_FILE_OPEN',
    IN_CLOSE_NOWRITE: 'FS_FILE_CLOSE_NOWRITE',
    IN_CLOSE_WRITE: 'FS_FILE_CLOSE_WRITE',
    IN_CREATE: 'FS_FILE_CREATE',
    IN_CREATE | IN_ISDIR: 'FS_DIR_CREATE',
    IN_DELETE: 'FS_FILE_DELETE',
    IN_DELETE | IN_ISDIR: 'FS_DIR_DELETE',
    IN_MOVED_FROM: 'FS_FILE_DELETE',
    IN_MOVED_FROM | IN_ISDIR: 'FS_DIR_DELETE',
    IN_MOVED_TO: 'FS_FILE_CREATE',
    IN_MOVED_TO | IN_ISDIR: 'FS_DIR_CREATE'}


class NotifyProcessor(ProcessEvent):
    """Processor that takes care of dealing with the events.

    This interface will be exposed to syncdaemon, ergo all passed
    and returned paths must be a sequence of BYTES encoded with utf8.
    """

    def __init__(self, monitor, ignore_config=None):
        self.general_processor = GeneralINotifyProcessor(
            monitor, self.handle_dir_delete, NAME_TRANSLATIONS,
            path_is_ignored, IN_IGNORED, ignore_config=ignore_config)
        self.held_event = None

    def rm_from_mute_filter(self, event, paths):
        """Remove event from the mute filter."""
        self.general_processor.rm_from_mute_filter(event, paths)

    def add_to_mute_filter(self, event, paths):
        """Add an event and path(s) to the mute filter."""
        self.general_processor.add_to_mute_filter(event, paths)

    @is_valid_syncdaemon_path(path_indexes=[1])
    def is_ignored(self, path):
        """Should we ignore this path?"""
        return self.general_processor.is_ignored(path)

    def release_held_event(self, timed_out=False):
        """Release the event on hold to fulfill its destiny."""
        self.general_processor.push_event(self.held_event)
        self.held_event = None

    def process_IN_MODIFY(self, event):
        """Capture a modify event and fake an open ^ close write events."""
        # lets ignore dir changes
        if event.dir:
            return
        # on someplatforms we just get IN_MODIFY, lets always fake
        # an OPEN & CLOSE_WRITE couple
        raw_open = raw_close = {
            'wd': event.wd,
            'dir': event.dir,
            'name': event.name,
            'path': event.path}
        # caculate the open mask
        raw_open['mask'] = IN_OPEN
        # create the event using the raw data, then fix the pathname param
        open_event = Event(raw_open)
        open_event.pathname = event.pathname
        # push the open
        self.general_processor.push_event(open_event)
        raw_close['mask'] = IN_CLOSE_WRITE
        close_event = Event(raw_close)
        close_event.pathname = event.pathname
        # push the close event
        self.general_processor.push_event(close_event)

    def process_IN_MOVED_FROM(self, event):
        """Capture the MOVED_FROM to maybe syntethize FILE_MOVED."""
        if self.held_event is not None:
            self.general_processor.log.warn('Lost pair event of %s',
                                            self.held_event)
        self.held_event = event

    def _fake_create_event(self, event):
        """Fake the creation of an event."""
        # this is the case of a MOVE from an ignored path (links for example)
        # to a valid path
        if event.dir:
            evtname = "FS_DIR_"
        else:
            evtname = "FS_FILE_"
        self.general_processor.eq_push(evtname + "CREATE", path=event.pathname)
        if not event.dir:
            self.general_processor.eq_push('FS_FILE_CLOSE_WRITE',
                                           path=event.pathname)

    def _fake_delete_create_event(self, event):
        """Fake the deletion and the creation."""
        # this is the case of a MOVE from a watch UDF to a diff UDF which
        # means that we have to copy the way linux works.
        if event.dir:
            evtname = "FS_DIR_"
        else:
            evtname = "FS_FILE_"
        m = "Delete because of different shares: %r"
        self.log.info(m, self.held_event.pathname)
        self.general_processor.eq_push(evtname + "DELETE",
                                       path=self.held_event.pathname)
        self.general_processor.eq_push(evtname + "CREATE", path=event.pathname)
        if not event.dir:
            self.general_processor.eq_push('FS_FILE_CLOSE_WRITE',
                                           path=event.pathname)

    def process_IN_MOVED_TO(self, event):
        """Capture the MOVED_TO to maybe syntethize FILE_MOVED."""
        if self.held_event is not None:
            if event.cookie == self.held_event.cookie:
                f_path_dir = os.path.split(self.held_event.pathname)[0]
                t_path_dir = os.path.split(event.pathname)[0]

                is_from_forreal = not self.is_ignored(self.held_event.pathname)
                is_to_forreal = not self.is_ignored(event.pathname)
                if is_from_forreal and is_to_forreal:
                    f_share_id = self.general_processor.get_path_share_id(
                        f_path_dir)
                    t_share_id = self.general_processor.get_path_share_id(
                        t_path_dir)
                    if f_share_id != t_share_id:
                        # if the share_id are != push a delete/create
                        self._fake_delete_create_event(event)
                    else:
                        if event.dir:
                            evtname = "FS_DIR_"
                        else:
                            evtname = "FS_FILE_"
                        self.general_processor.eq_push(
                            evtname + "MOVE",
                            path_from=self.held_event.pathname,
                            path_to=event.pathname)
                elif is_to_forreal:
                    # this is the case of a MOVE from something ignored
                    # to a valid filename
                    self._fake_create_event(event)

                self.held_event = None
                return
            else:
                self.release_held_event()
                self.general_processor.push_event(event)
        else:
            # We should never get here, I really do not know how we
            # got here
            self.general_processor.log.warn(
                'Cookie does not match the previoues held event!')
            self.general_processor.log.warn('Ignoring %s', event)

    def process_default(self, event):
        """Push the event into the EventQueue."""
        if self.held_event is not None:
            self.release_held_event()
        self.general_processor.push_event(event)

    @is_valid_syncdaemon_path(path_indexes=[1])
    def handle_dir_delete(self, fullpath):
        """Some special work when a directory is deleted."""
        # remove the watch on that dir from our structures, this mainly tells
        # the monitor to remove the watch which is fowaded to a watch manager.
        self.general_processor.rm_watch(fullpath)

        # handle the case of move a dir to a non-watched directory
        paths = self.general_processor.get_paths_starting_with(
            fullpath, include_base=False)

        paths.sort(reverse=True)
        for path, is_dir in paths:
            m = "Pushing deletion because of parent dir move: (is_dir=%s) %r"
            self.general_processor.log.info(m, is_dir, path)
            if is_dir:
                # same as the above remove
                self.general_processor.rm_watch(path)
                self.general_processor.eq_push('FS_DIR_DELETE', path=path)
            else:
                self.general_processor.eq_push('FS_FILE_DELETE', path=path)

    @is_valid_syncdaemon_path(path_indexes=[1])
    def freeze_begin(self, path):
        """Puts in hold all the events for this path."""
        self.general_processor.freeze_begin(path)

    def freeze_rollback(self):
        """Unfreezes the frozen path, reseting to idle state."""
        self.general_processor.freeze_rollback()

    def freeze_commit(self, events):
        """Unfreezes the frozen path, sending received events if not dirty.

        If events for that path happened:
            - return True
        else:
            - push the here received events, return False
        """
        return self.general_processor.freeze_commit(events)

    @property
    def mute_filter(self):
        """Return the mute filter used by the processor."""
        return self.general_processor.filter

    @property
    def frozen_path(self):
        """Return the frozen path."""
        return self.general_processor.frozen_path

    @property
    def log(self):
        """Return the logger of the instance."""
        return self.general_processor.log
