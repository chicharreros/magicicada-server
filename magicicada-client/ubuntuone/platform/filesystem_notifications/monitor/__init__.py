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
"""Filesystem monitors per platform."""

import logging
import sys

from twisted.internet import defer

DEFAULT_MONITOR = 'default'
logger = logging.getLogger(
    'ubuntuone.SyncDaemon.platform.filesystem_notifications.monitor')


class NoAvailableMonitorError(Exception):
    """Raised if there are no available monitors in the system."""


if sys.platform == 'win32':
    from ubuntuone.platform.filesystem_notifications.monitor import (
        common,
        windows,
    )

    FILEMONITOR_IDS = {
        DEFAULT_MONITOR: common.FilesystemMonitor,
    }
    ACTIONS = windows.ACTIONS

elif sys.platform == 'darwin':
    from ubuntuone.platform.filesystem_notifications.monitor import darwin
    from ubuntuone.platform.filesystem_notifications.monitor import (
        common,
    )

    FILEMONITOR_IDS = {
        DEFAULT_MONITOR: darwin.fsevents_daemon.FilesystemMonitor,
        'macfsevents': common.FilesystemMonitor,
    }
    ACTIONS = darwin.fsevents_client.ACTIONS
else:
    from ubuntuone.platform.filesystem_notifications.monitor import (
        linux,
    )

    FILEMONITOR_IDS = {
        DEFAULT_MONITOR: linux.FilesystemMonitor,
    }


# mantain old API
FilesystemMonitor = FILEMONITOR_IDS[DEFAULT_MONITOR]


@defer.inlineCallbacks
def get_filemonitor_class(monitor_id=None):
    """Return the class to be used."""
    logger.debug('File monitor ids for platform "%s" are "%s"', sys.platform,
                 FILEMONITOR_IDS)

    if monitor_id is None:
        logger.debug('monitor_id is None, using default.')
        monitor_id = 'default'

    if monitor_id not in FILEMONITOR_IDS:
        msg = 'No available monitor with id %r could be found.'
        raise NoAvailableMonitorError(msg % monitor_id)

    # retrieve the correct class and assert it can be used
    cls = FILEMONITOR_IDS[monitor_id]
    logger.debug('Checking availability of monitor class %s', cls)
    is_available = yield cls.is_available_monitor()

    if is_available:
        logger.debug('Monitor is available, returning monitor with id "%s"',
                     monitor_id)
        defer.returnValue(cls)
    elif not is_available and monitor_id != DEFAULT_MONITOR:
        logger.debug('Monitor is NOT available, returning default monitor.')
        cls = yield get_filemonitor_class(DEFAULT_MONITOR)
        defer.returnValue(cls)
    else:
        raise NoAvailableMonitorError('No available monitor could be found.')
