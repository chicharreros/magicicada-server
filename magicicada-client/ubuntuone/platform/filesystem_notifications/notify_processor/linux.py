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
"""Linux implementation."""

import os

import pyinotify
from twisted.internet import reactor, error

from ubuntuone.syncdaemon.filesystem_notifications import (
    GeneralINotifyProcessor,
)

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


def validate_filename(real_func):
    """Decorator that validates the filename."""
    def func(self, event):
        """If valid, executes original function."""
        try:
            # validate UTF-8
            event.name.decode("utf8")
        except UnicodeDecodeError:
            dirname = event.path.decode("utf8")
            self.general_processor.invnames_log.info(
                "%s in %r: path %r", event.maskname, dirname, event.name)
            self.general_processor.monitor.eq.push(
                'FS_INVALID_NAME', dirname=dirname, filename=event.name)
        else:
            real_func(self, event)
    return func


class NotifyProcessor(pyinotify.ProcessEvent):
    """inotify's processor when a general event happens.

    This class also catchs the MOVEs events, and synthetises a new
    FS_(DIR|FILE)_MOVE event when possible.
    """
    def __init__(self, monitor, ignore_config=None):
        self.general_processor = GeneralINotifyProcessor(
            monitor, self.handle_dir_delete, NAME_TRANSLATIONS,
            self.platform_is_ignored, pyinotify.IN_IGNORED,
            ignore_config=ignore_config)
        self.held_event = None
        self.timer = None

    def shutdown(self):
        """Shut down the processor."""
        if self.timer is not None and self.timer.active():
            self.timer.cancel()

    def rm_from_mute_filter(self, event, paths):
        """Remove an event and path(s) from the mute filter."""
        self.general_processor.rm_from_mute_filter(event, paths)

    def add_to_mute_filter(self, event, paths):
        """Add an event and path(s) to the mute filter."""
        self.general_processor.add_to_mute_filter(event, paths)

    def on_timeout(self):
        """Called on timeout."""
        if self.held_event is not None:
            self.release_held_event(True)

    def release_held_event(self, timed_out=False):
        """Release the event on hold to fulfill its destiny."""
        if not timed_out:
            try:
                self.timer.cancel()
            except error.AlreadyCalled:
                # self.timeout() was *just* called, do nothing here
                return
        self.general_processor.push_event(self.held_event)
        self.held_event = None

    @validate_filename
    def process_IN_OPEN(self, event):
        """Filter IN_OPEN to make it happen only in files."""
        if not (event.mask & pyinotify.IN_ISDIR):
            self.general_processor.push_event(event)

    @validate_filename
    def process_IN_CLOSE_NOWRITE(self, event):
        """Filter IN_CLOSE_NOWRITE to make it happen only in files."""
        if not (event.mask & pyinotify.IN_ISDIR):
            self.general_processor.push_event(event)

    @validate_filename
    def process_IN_CLOSE_WRITE(self, event):
        """Filter IN_CLOSE_WRITE to make it happen only in files.

        eCryptFS sends IN_CLOSE_WRITE event for lower directories.

        """
        if not (event.mask & pyinotify.IN_ISDIR):
            self.general_processor.push_event(event)

    def process_IN_MOVE_SELF(self, event):
        """Don't do anything here.

        We just turned this event on because pyinotify does some
        path-fixing in its internal processing when this happens.

        """

    @validate_filename
    def process_IN_MOVED_FROM(self, event):
        """Capture the MOVED_FROM to maybe syntethize FILE_MOVED."""
        if self.held_event is not None:
            self.release_held_event()

        self.held_event = event
        self.timer = reactor.callLater(1, self.on_timeout)

    def platform_is_ignored(self, path):
        """Should we ignore this path in the current platform.?"""
        # don't support links yet
        if os.path.islink(path):
            return True
        return False

    def is_ignored(self, path):
        """Should we ignore this path?"""
        return self.general_processor.is_ignored(path)

    @validate_filename
    def process_IN_MOVED_TO(self, event):
        """Capture the MOVED_TO to maybe syntethize FILE_MOVED."""
        if self.held_event is not None:
            if event.cookie == self.held_event.cookie:
                try:
                    self.timer.cancel()
                except error.AlreadyCalled:
                    # self.timeout() was *just* called, do nothing here
                    pass
                else:
                    f_path_dir = self.held_event.path
                    f_path = os.path.join(f_path_dir, self.held_event.name)
                    t_path_dir = event.path
                    t_path = os.path.join(t_path_dir, event.name)

                    is_from_forreal = not self.is_ignored(f_path)
                    is_to_forreal = not self.is_ignored(t_path)
                    if is_from_forreal and is_to_forreal:
                        f_share_id = self.general_processor.get_path_share_id(
                            f_path_dir)
                        t_share_id = self.general_processor.get_path_share_id(
                            t_path_dir)
                        if event.dir:
                            evtname = "FS_DIR_"
                        else:
                            evtname = "FS_FILE_"
                        if f_share_id != t_share_id:
                            # if the share_id are != push a delete/create
                            m = "Delete because of different shares: %r"
                            self.general_processor.log.info(m, f_path)
                            self.general_processor.eq_push(evtname + "DELETE",
                                                           path=f_path)
                            self.general_processor.eq_push(evtname + "CREATE",
                                                           path=t_path)
                            if not event.dir:
                                self.general_processor.eq_push(
                                    'FS_FILE_CLOSE_WRITE', path=t_path)
                        else:
                            self.general_processor.monitor.inotify_watch_fix(
                                f_path, t_path)
                            self.general_processor.eq_push(
                                evtname + "MOVE", path_from=f_path,
                                path_to=t_path)
                    elif is_to_forreal:
                        # this is the case of a MOVE from something ignored
                        # to a valid filename
                        if event.dir:
                            evtname = "FS_DIR_"
                        else:
                            evtname = "FS_FILE_"
                        self.general_processor.eq_push(evtname + "CREATE",
                                                       path=t_path)
                        if not event.dir:
                            self.general_processor.eq_push(
                                'FS_FILE_CLOSE_WRITE', path=t_path)

                    else:
                        # this is the case of a MOVE from something valid
                        # to an ignored filename
                        if event.dir:
                            evtname = "FS_DIR_"
                        else:
                            evtname = "FS_FILE_"
                        self.general_processor.eq_push(evtname + "DELETE",
                                                       path=f_path)

                    self.held_event = None
                return
            else:
                self.release_held_event()
                self.general_processor.push_event(event)
        else:
            # we don't have a held_event so this is a move from outside.
            # if it's a file move it's atomic on POSIX, so we aren't going to
            # receive a IN_CLOSE_WRITE, so let's fake it for files
            self.general_processor.push_event(event)
            if not event.dir:
                t_path = os.path.join(event.path, event.name)
                self.general_processor.eq_push(
                    'FS_FILE_CLOSE_WRITE', path=t_path)

    @validate_filename
    def process_default(self, event):
        """Push the event into the EventQueue."""
        if self.held_event is not None:
            self.release_held_event()
        self.general_processor.push_event(event)

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

    def handle_dir_delete(self, fullpath):
        """Some special work when a directory is deleted."""
        # remove the watch on that dir from our structures
        self.general_processor.rm_watch(fullpath)

        # handle the case of move a dir to a non-watched directory
        paths = self.general_processor.get_paths_starting_with(
            fullpath, include_base=False)

        paths.sort(reverse=True)
        for path, is_dir in paths:
            m = "Pushing deletion because of parent dir move: (is_dir=%s) %r"
            self.general_processor.log.info(m, is_dir, path)
            if is_dir:
                self.general_processor.rm_watch(path)
                self.general_processor.eq_push('FS_DIR_DELETE', path=path)
            else:
                self.general_processor.eq_push('FS_FILE_DELETE', path=path)

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
