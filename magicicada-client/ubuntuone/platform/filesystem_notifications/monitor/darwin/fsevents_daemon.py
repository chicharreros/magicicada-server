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
"""Filesystem notifications based on the fseventsd daemon.."""

import logging
import os
import unicodedata

from uuid import uuid4

from twisted.internet import defer, endpoints, reactor

from ubuntuone import logger
from ubuntuone import fseventsd
from ubuntuone.platform.filesystem_notifications.notify_processor import (
    NotifyProcessor,
)
from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    Event,
    IN_OPEN,
    IN_CLOSE_NOWRITE,
    IN_CLOSE_WRITE,
    IN_CREATE,
    IN_ISDIR,
    IN_DELETE,
    IN_MOVED_FROM,
    IN_MOVED_TO,
    IN_MODIFY,
)
from ubuntuone.utils.tcpactivation import (
    ActivationConfig,
    ActivationInstance,
    AlreadyStartedError,
)

TRACE = logger.TRACE

# map the fseventsd actions to those from pyinotify
DARWIN_ACTIONS = {
    fseventsd.FSE_CREATE_FILE: IN_CREATE,
    fseventsd.FSE_DELETE: IN_DELETE,
    fseventsd.FSE_STAT_CHANGED: IN_MODIFY,
    fseventsd.FSE_CONTENT_MODIFIED: IN_MODIFY,
    fseventsd.FSE_CREATE_DIR: IN_CREATE,
}

# list of those events from which we do not care
DARWIN_IGNORED_ACTIONS = (
    fseventsd.FSE_UNKNOWN,
    fseventsd.FSE_INVALID,
    fseventsd.FSE_EXCHANGE,
    fseventsd.FSE_FINDER_INFO_CHANGED,
    fseventsd.FSE_CHOWN,
    fseventsd.FSE_XATTR_MODIFIED,
    fseventsd.FSE_XATTR_REMOVED,
)

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

# TODO: This should be in fseventsd to be imported!
# Path to the socket used by the daemon
DAEMON_SOCKET = '/var/run/com.ubuntu.one.fsevents.sock'


class DescriptionFactory(object):
    """Factory that provides the server and client descriptions."""

    client_description_pattern = 'unix:path=%s'
    server_description_pattern = 'unix:%s'

    def __init__(self):
        """Create a new instance."""
        self.server = self.server_description_pattern % DAEMON_SOCKET
        self.client = self.client_description_pattern % DAEMON_SOCKET


def get_activation_config():
    """Get the configuration to activate the service."""
    description = DescriptionFactory()
    return ActivationConfig(None, None, description)


@defer.inlineCallbacks
def is_daemon_running():
    """Return if the sd is running by trying to get the port."""
    ai = ActivationInstance(get_activation_config())
    ai_method = getattr(ai, 'get_server_description', None)
    if ai_method is None:  # backwards compatible
        ai_method = getattr(ai, 'get_port')
    try:
        yield ai_method()
        defer.returnValue(False)
    except AlreadyStartedError:
        defer.returnValue(True)


def get_syncdaemon_valid_path(path):
    """Return a valid encoded path."""
    return unicodedata.normalize('NFC', path).encode('utf-8')


class PyInotifyEventsFactory(fseventsd.FsEventsFactory):
    """Factory that process events and converts them in pyinotify ones."""

    def __init__(self, processor, ignored_events=DARWIN_IGNORED_ACTIONS):
        """Create a new instance."""
        # old style class
        fseventsd.FsEventsFactory.__init__(self)
        self._processor = processor
        self._ignored_events = ignored_events
        self.watched_paths = []
        self.ignored_paths = []

        self.log = logging.getLogger('ubuntuone.SyncDaemon.EventsFactory')
        self.log.setLevel(TRACE)

    def events_dropper(self):
        """Deal with the fact that the daemon dropped events."""
        self.log.error("Event received with dropped flag set, not handled.")

    def path_is_not_interesting(self, path):
        """Return if the factory is interested in the path."""
        is_watched = any(path.startswith(watched_path)
                         for watched_path in self.watched_paths)
        is_ignored = any(path.startswith(ignored_path)
                         for ignored_path in self.ignored_paths)
        return not is_watched or (is_watched and is_ignored)

    def is_create(self, event):
        """Decide if a rename event should be considered a create."""
        # is a create if the creation path (first path) is either not
        # watched or in the ignored paths
        source_path = get_syncdaemon_valid_path(event.event_paths[0])
        return self.path_is_not_interesting(source_path)

    def is_delete(self, event):
        """Decide if a rename event should be considered a delete."""
        # is a delete if the destination path (second path) is either not
        # watched or in the ignored paths
        dest_path = get_syncdaemon_valid_path(event.event_paths[1])
        return self.path_is_not_interesting(dest_path)

    def generate_from_event(self, event, cookie):
        """Return a fake from event from a rename one."""
        source_path = get_syncdaemon_valid_path(event.event_paths[0])
        mask = IN_MOVED_FROM
        if event.is_directory:
            mask |= IN_ISDIR
        head, tail = os.path.split(source_path)
        event_raw_data = {
            'wd': 0,  # we only have one factory
            'dir': event.is_directory,
            'mask': mask,
            'name': tail,
            'cookie': cookie,
            'path': '.'}
        move_from_event = Event(event_raw_data)
        move_from_event.pathname = source_path
        return move_from_event

    def generate_to_event(self, event, cookie):
        """Return a fake to event from a rename one."""
        source_path = get_syncdaemon_valid_path(event.event_paths[0])
        destination_path = get_syncdaemon_valid_path(event.event_paths[1])
        mask = IN_MOVED_TO
        if event.is_directory:
            mask |= IN_ISDIR
        source_head, source_tail = os.path.split(source_path)
        head, tail = os.path.split(destination_path)
        event_raw_data = {
            'wd': 0,  # we only have one factory
            'dir': event.is_directory,
            'mask': mask,
            'name': tail,
            'cookie': cookie,
            'src_pathname': source_tail,
            'path': '.'}
        move_to_event = Event(event_raw_data)
        move_to_event.pathname = destination_path
        return move_to_event

    def convert_in_pyinotify_event(self, event):
        """Get an event from the daemon and convert it in a pyinotify one."""
        # the rename is a special type of event because it has to be either
        # converted is a pair of events or in a single one (CREATE or DELETE)
        if event.event_type == fseventsd.FSE_RENAME:

            is_create = self.is_create(event)
            is_delete = self.is_delete(event)

            if is_create or is_delete:
                mask = IN_CREATE if is_create else IN_DELETE
                if event.is_directory:
                    mask |= IN_ISDIR
                # a create means that we moved from a not watched path to a
                # watched one and therefore we are interested in the SECOND
                # path of the event. A delete means that we moved from a
                # watched path for a not watched one and we care about the
                # FIRST path of the event
                path = (
                    event.event_paths[1] if is_create else event.event_paths[0]
                )
                path = get_syncdaemon_valid_path(path)
                head, tail = os.path.split(path)
                event_raw_data = {
                    'wd': 0,  # we only have one factory
                    'dir': event.is_directory,
                    'mask': mask,
                    'name': tail,
                    'path': '.'}
                orig_event = Event(event_raw_data)
                orig_event.pathname = path
                events = [orig_event]

                if is_create:
                    mod_event = Event(event_raw_data)
                    mod_event.pathname = path
                    mod_event.mask = IN_MODIFY
                    if event.is_directory:
                        mod_event.mask |= IN_ISDIR
                    events.append(mod_event)

                return events
            else:
                # we have a rename within watched paths, so let's
                # generate two fake events
                cookie = str(uuid4())
                return [self.generate_from_event(event, cookie),
                        self.generate_to_event(event, cookie)]
        else:
            mask = DARWIN_ACTIONS[event.event_type]
            if event.is_directory:
                mask |= IN_ISDIR
            # we do know that we are not dealing with a move which are the only
            # events that have more than one path
            path = get_syncdaemon_valid_path(event.event_paths[0])
            head, tail = os.path.split(path)
            event_raw_data = {
                'wd': 0,  # we only have one factory
                'dir': event.is_directory,
                'mask': mask,
                'name': tail,
                'path': '.'}
            pyinotify_event = Event(event_raw_data)
            # FIXME: event deduces the pathname wrong and we need to manually
            # set it
            pyinotify_event.pathname = path
            return [pyinotify_event]

    def _is_ignored_path(self, path):
        """Returns if the path is ignored."""
        if not path[-1] == os.path.sep:
            path += os.path.sep

        is_ignored_child = any(
            ignored in path for ignored in self.ignored_paths)
        return path in self.ignored_paths or is_ignored_child

    def process_event(self, event):
        """Process an event from the fsevent daemon."""
        if event.event_type in self._ignored_events:
            # Do nothing because sd does not care about such info
            return
        if event.event_type == fseventsd.FSE_EVENTS_DROPPED:
            # this should not be very common but we have to deal with it
            return self.events_dropper()
        events = self.convert_in_pyinotify_event(event)
        self.log.debug("process_event : %r => %r" % (event, events))
        for pyinotify_event in events:
            # assert that the path name is valid
            if not any([pyinotify_event.pathname.startswith(path)
                        for path in self.ignored_paths]):
                # by definition we are being callFromThread so we do know that
                # the  events are executed in the right order \o/
                if not self._is_ignored_path(pyinotify_event.pathname):
                    self._processor(pyinotify_event)


class FilesystemMonitor(object):
    """Implementation that allows to receive events from the system."""

    def __init__(self, eq, fs, ignore_config=None, timeout=1):
        self.log = logging.getLogger('ubuntuone.SyncDaemon.FSMonitor')
        self.log.setLevel(TRACE)
        self._processor = NotifyProcessor(self, ignore_config)
        self.fs = fs
        self.eq = eq
        self._factory = PyInotifyEventsFactory(self._processor)
        self._protocol = None

    @classmethod
    def is_available_monitor(cls):
        """Return if the monitor can be used in the platform."""
        # can only be used if the daemon is running
        return is_daemon_running()

    @defer.inlineCallbacks
    def _connect_to_daemon(self):
        """Connect to the daemon so that we can receive events."""
        description = 'unix:path=%s' % DAEMON_SOCKET
        client = endpoints.clientFromString(reactor, description)
        self._protocol = yield client.connect(self._factory)
        # add the user with no paths
        yield self._protocol.add_user([])

    def add_to_mute_filter(self, event, **info):
        """Add info to mute filter in the processor."""
        self._processor.add_to_mute_filter(event, info)

    def rm_from_mute_filter(self, event, **info):
        """Remove info to mute filter in the processor."""
        self._processor.rm_from_mute_filter(event, info)

    def shutdown(self):
        """Prepares the EQ to be closed."""
        if self._protocol is not None:

            def on_user_removed(data):
                """We managed to remove the user."""
                self._protocol.transport.loseConnection()
                self._protocol = None
                return True

            def on_user_not_removed(reason):
                """We did not manage to remove the user."""
                return True

            d = self._protocol.remove_user()
            d.addCallback(on_user_removed)
            d.addErrback(on_user_not_removed)
            return d
        return defer.succeed(True)

    @defer.inlineCallbacks
    def rm_watch(self, dirpath):
        """Remove watch from a dir."""
        # in mac os x we are only watching the parent watches, this is an
        # important details because we will only send a real remove_path to the
        # daemon if the path is the parent path else we will filter it in the
        # factory level

        if not dirpath[-1] == os.path.sep:
            dirpath += os.path.sep

        if dirpath not in self._factory.watched_paths:
            # we are watching a parent path but we are not a root one
            # therefore we are going to add it as an ignored path and
            # return
            self._factory.ignored_paths.append(dirpath)
            defer.returnValue(None)

        # if we got to this point we want to remove a root dir, this is an
        # important detail to take care of. Connect if needed and tell the
        # daemon to remove the path
        if self._protocol is None:
            # we have not yet connected, lets do it!
            yield self._connect_to_daemon()
        was_removed = yield self._protocol.remove_path(dirpath)
        # only remove it if we really removed it
        if was_removed:
            self._factory.watched_paths.remove(dirpath)

    @defer.inlineCallbacks
    def add_watch(self, dirpath):
        """Add watch to a dir."""
        if not dirpath[-1] == os.path.sep:
            dirpath = dirpath + os.path.sep

        # if we are watching a parent dir we can just ensure that it is not
        # ignored
        parent_watched = any(dirpath.startswith(watched_path)
                             for watched_path in self._factory.watched_paths)
        if parent_watched:
            if dirpath in self._factory.ignored_paths:
                self._factory.ignored_paths.remove(dirpath)
            defer.returnValue(True)

        if dirpath in self._factory.ignored_paths:
            self._factory.ignored_paths.remove(dirpath)
            defer.returnValue(True)

        if self._protocol is None:
            # we have not yet connected, lets do it!
            yield self._connect_to_daemon()

        was_added = yield self._protocol.add_path(dirpath)
        if was_added:
            self._factory.watched_paths.append(dirpath)
            defer.returnValue(True)

    def add_watches_to_udf_ancestors(self, volume):
        """Add a inotify watch to volume's ancestors if it's an UDF."""
        # On Mac OS X we do no need to add watches to the ancestors because we
        # will get the events from them with no problem.
        return defer.succeed(True)

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
            raise ValueError("Committing with nothing frozen!")

        d = defer.execute(self._processor.freeze_commit, events)
        return d
