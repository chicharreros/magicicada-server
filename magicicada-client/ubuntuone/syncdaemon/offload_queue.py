# -*- coding: utf-8 -*-
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
"""An offloaded (to disk) FIFO queue."""

import cPickle as pickle
import cStringIO
import logging
import os
import struct
import tempfile

STRUCT_FMT = 'h'
STRUCT_SIZE = struct.calcsize(STRUCT_FMT)


class OffloadQueue(object):
    """A FIFO queue that stores items in disk."""

    # limits for file rotation...
    # after the soft limit, we'll rotate if queue is short enough
    _rotation_soft_limit = 2 * 1024 ** 3
    # if the queue is shorter than this, we'll rotate after the soft limit
    _rotation_too_big_size = 50 * 1024 ** 2
    # rotate if file gets larger than this, no matter the queue size
    _rotation_hard_limit = 10 * 1024 ** 3

    def __init__(self):
        # create the temp file
        fd, self._tempfile_name = tempfile.mkstemp()
        self._tempfile = os.fdopen(fd, 'w+b')
        self.log = logging.getLogger('ubuntuone.SyncDaemon.OffloadQueue')
        self.log.debug("Using temporary file: %r", self._tempfile_name)

        # position to read in the file
        self._pos = 0

        # queue length (in items)
        self._len = 0

        # file size
        self._tempfile_size = 0

        # fallback to memory if something goes wrong when using disk
        self._in_memory = False

    def __len__(self):
        return self._len

    def push(self, item):
        """Push some data to the queue."""
        data = pickle.dumps(item, pickle.HIGHEST_PROTOCOL)
        packed_size = struct.pack(STRUCT_FMT, len(data))

        self._tempfile.seek(0, os.SEEK_END)
        try:
            self._tempfile.write(packed_size)
        except Exception:
            self._handle_bad_write(packed_size)
        try:
            self._tempfile.write(data)
        except Exception:
            self._handle_bad_write(data)

        self._len += 1
        self._tempfile_size += len(data) + STRUCT_SIZE
        self._rotate()

    def _handle_bad_write(self, data):
        """Support a bad write, go to memory and continue."""
        self.log.exception("Crashed while writing")

        # rotate to memory
        self._tempfile.seek(self._pos)
        data_to_rotate = self._tempfile.read()
        new_file = cStringIO.StringIO()
        new_file.write(data_to_rotate)
        new_file.write(data)
        self._tempfile_name = None
        self._tempfile = new_file
        self._in_memory = True

        # set internal state
        self._pos = 0
        self._tempfile_size = new_file.tell()

    def pop(self):
        """Pop the oldest item of the queue."""
        self._tempfile.seek(self._pos)
        data_len, = struct.unpack(STRUCT_FMT, self._tempfile.read(STRUCT_SIZE))
        data = self._tempfile.read(data_len)
        item = pickle.loads(data)
        self._pos = self._tempfile.tell()
        self._len -= 1
        self._rotate()
        return item

    def _rotate(self):
        """Rotate temporary files if it's needed."""
        if self._in_memory:
            return

        filesize = self._tempfile_size
        queuesize = filesize - self._pos

        # don't rotate if small file size or no space saved on rotation
        if filesize < self._rotation_soft_limit or self._pos == 0:
            return

        # the file is big, let's check if we would need to copy too much data
        if queuesize > self._rotation_too_big_size:
            # avoid rotation only if file size is still below the hard limit
            if filesize < self._rotation_hard_limit:
                return

        # rotate to a new file
        self._tempfile.seek(self._pos)
        data_to_rotate = self._tempfile.read()
        self._tempfile.close()
        try:
            os.unlink(self._tempfile_name)
        except Exception, err:
            self.log.warning("Error when removing old tempfile: %r", err)

        try:
            fd, new_name = tempfile.mkstemp()
            self.log.debug("Rotation into %r (moving %d bytes)",
                           new_name, queuesize)
            new_file = os.fdopen(fd, 'w+b')
        except Exception:
            self.log.exception("Crashed while getting new file to rotate")
            new_file = cStringIO.StringIO()
            new_name = None
            self._in_memory = True

        new_file.write(data_to_rotate)

        # set internal state
        self._tempfile_name = new_name
        self._tempfile = new_file
        self._pos = 0
        self._tempfile_size = new_file.tell()
