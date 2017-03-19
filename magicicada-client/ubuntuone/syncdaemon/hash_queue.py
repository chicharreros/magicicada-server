# ubuntuone.syncdaemon.hash_queue - hash queues
#
# Authors: Facundo Batista <facundo@canonical.com>
#          Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
#          Alejandro J. Cura <alecu@canonical.com>
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
"""Module that implements the Hash Queue machinery."""

from __future__ import with_statement

import logging
import threading
import Queue
import time

from collections import OrderedDict

from twisted.internet import reactor

from ubuntuone.storageprotocol.content_hash import \
    content_hash_factory, crc32

from ubuntuone.platform import (
    open_file,
    stat_path,
)
from ubuntuone.platform.constants import HASHQUEUE_DELAY


NO_TIMESTAMP = None


class StopHashing(Exception):
    """The current hash was cancelled."""


class _Hasher(threading.Thread):
    """Class that lives in another thread, hashing all night long."""

    def __init__(self, queue, end_mark, event_queue):
        self.logger = logging.getLogger('ubuntuone.SyncDaemon.HQ.hasher')
        self.end_mark = end_mark
        self.queue = queue
        self.eq = event_queue
        # mutex to access _should_cancel and _hashing attributes
        self.mutex = threading.Lock()
        self._should_cancel = None
        self._stopped = True  # start stopped
        self.chunk_size = 2 ** 16
        self.hashing = None
        threading.Thread.__init__(self)

    def run(self):
        """Run the thread."""
        self._stopped = False
        while True:
            if self._stopped:
                break
            info, timestamp = self.queue.get()
            if info is self.end_mark:
                self._stopped = True
                self.queue.task_done()
                break

            path, mdid = info
            with self.mutex:
                self.hashing = path
            m = "Hasher: got file to hash: path %r  mdid %s"
            self.logger.debug(m, path, mdid)

            now = time.time()
            delta = timestamp - now
            if delta > 0:
                self.logger.trace("Waiting %f before starting hash", delta)
                time.sleep(delta)

            try:
                result = self._hash(path)
            except (IOError, OSError), e:
                m = "Hasher: hash error %s  (path %r  mdid %s)"
                self.logger.debug(m, e, path, mdid)
                reactor.callLater(
                    .1, reactor.callFromThread, self.eq.push,
                    "HQ_HASH_ERROR", mdid=mdid)
            except StopHashing, e:
                self.logger.debug(str(e))
            else:
                hashdata, crc, size, stat = result
                self.logger.debug("Hasher: path hash pushed:  path=%r  hash=%s"
                                  "  crc=%s  size=%d  st_ino=%d  st_size=%d"
                                  "  st_mtime=%r", path, hashdata, crc, size,
                                  stat.st_ino, stat.st_size, stat.st_mtime)
                reactor.callFromThread(self.eq.push, "HQ_HASH_NEW", path=path,
                                                     hash=hashdata, crc32=crc,
                                                     size=size, stat=stat)
            finally:
                with self.mutex:
                    self.hashing = None

            self.queue.task_done()

    def stop(self):
        """Stop the hasher.

        Will be effective in the next loop if a hash is in progress.

        """
        # clear the queue to push a end_mark, just to unblok if we are waiting
        # for a new item
        self.queue.clear()
        # set the end_mark in case we are waiting a path
        item = (self.end_mark, NO_TIMESTAMP)
        self.queue.put(item)
        self._stopped = True

    def _hash(self, path):
        """Actually hashes a file."""
        hasher = content_hash_factory()
        crc = 0
        size = 0
        try:
            initial_stat = stat_path(path)
            with open_file(path, 'rb') as fh:
                while True:
                    # stop hashing if path_to_cancel = path or _stopped is True
                    with self.mutex:
                        path_to_cancel = self._should_cancel
                    if path_to_cancel == path or self._stopped:
                        raise StopHashing('hashing of %r was cancelled' % path)
                    cont = fh.read(self.chunk_size)
                    if not cont:
                        break
                    hasher.update(cont)
                    crc = crc32(cont, crc)
                    size += len(cont)
        finally:
            with self.mutex:
                self._should_cancel = None

        return hasher.content_hash(), crc, size, initial_stat

    def busy(self):
        """Return whether we are busy."""
        with self.mutex:
            return self.hashing

    def cancel_if_running(self, path):
        """Request a cancel/stop of the current hash, if it's == path."""
        with self.mutex:
            if self.hashing == path:
                self._should_cancel = path


class HashQueue(object):
    """Interface between the real Hasher and the rest of the world."""

    def __init__(self, event_queue):
        self.logger = logging.getLogger('ubuntuone.SyncDaemon.HQ')
        self._stopped = False
        self._queue = UniqueQueue()
        self._end_mark = object()
        self.hasher = _Hasher(self._queue, self._end_mark, event_queue)
        self.hasher.setDaemon(True)
        self.hasher.start()
        self.logger.info("HashQueue: _hasher started")

    def _timestamp(self):
        """A timestamp with a small delay into the future."""
        return time.time() + HASHQUEUE_DELAY

    def insert(self, path, mdid):
        """Insert the path of a file to be hashed."""
        if self._stopped:
            self.logger.warning("HashQueue: already stopped when received "
                                "path %r  mdid %s", path, mdid)
            return
        self.logger.debug("HashQueue: inserting path %r  mdid %s", path, mdid)
        self.hasher.cancel_if_running(path)
        item = ((path, mdid), self._timestamp())
        self._queue.put(item)

    def shutdown(self):
        """Shutdown all resources and clear the queue"""
        # clear the queue
        self._queue.clear()
        # stop the hasher
        self.hasher.stop()
        self._stopped = True
        self.logger.info("HashQueue: _hasher stopped")

    def empty(self):
        """Return whether we are empty or not"""
        return self._queue.empty() and not self.hasher.busy()

    def __len__(self):
        """Return the length of the queue (not reliable!)"""
        return self._queue.qsize()

    def is_hashing(self, path, mdid):
        """Return if the path is being hashed or in the queue."""
        if self.hasher.hashing == path:
            return True
        if (path, mdid) in self._queue:
            return True
        return False


class UniqueQueue(Queue.Queue):
    """Variant of Queue that only inserts unique items in the Queue."""

    def __init__(self, *args, **kwargs):
        """create the instance"""
        Queue.Queue.__init__(self, *args, **kwargs)
        self.logger = logging.getLogger('ubuntuone.SyncDaemon.HQ.Queue')

    def _init(self, maxsize):
        """Override the underlaying data initialization."""
        self.queue = OrderedDict()

    def _qsize(self, len=len):
        """The size of the queue."""
        return len(self.queue)

    def _put(self, item):
        """Custom _put that removes previous instances of this item."""
        key, value = item
        if key in self.queue:
            # we must delete it first, so the new one is added to the end
            del(self.queue[key])
            self.logger.debug('Previous item removed from the queue: %r', key)
        self.queue[key] = value

    def _get(self):
        """Custom _get that returns the first (key, value) pair."""
        return self.queue.popitem(last=False)

    def clear(self):
        """clear the internal queue and notify all blocked threads"""
        self.queue.clear()
        with self.all_tasks_done:
            self.unfinished_tasks = 0
            self.all_tasks_done.notifyAll()

    def __contains__(self, key):
        """Tell if a key is in the queue."""
        return key in self.queue
