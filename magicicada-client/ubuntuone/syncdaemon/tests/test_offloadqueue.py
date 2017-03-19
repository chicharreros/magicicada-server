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
"""Tests for the Offload Queue."""

import StringIO
import logging
import os
import pickle
import tempfile

from twisted.trial.unittest import TestCase as TwistedTestCase

from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.syncdaemon.offload_queue import OffloadQueue, STRUCT_SIZE
from ubuntuone.syncdaemon.interfaces import IMarker
from ubuntuone.syncdaemon.marker import MDMarker


class OffloadQueueTestCase(TwistedTestCase):
    """Tests the OffloadQueue class."""

    def setUp(self):
        """Set up."""
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        logger = logging.getLogger('ubuntuone.SyncDaemon.OffloadQueue')
        logger.setLevel(logging.DEBUG)
        logger.addHandler(self.handler)
        self.addCleanup(logger.removeHandler, self.handler)
        self.oq = OffloadQueue()
        self.addCleanup(self.oq._tempfile.close)
        return super(OffloadQueueTestCase, self).setUp()

    def test_serialization_tuple(self):
        """Check that it can store tuples of strings."""
        data = ('foo', 'bar')
        self.oq.push(data)
        retrieved = self.oq.pop()
        self.assertEqual(data, retrieved)

    def test_serialization_markers(self):
        """Check that it can store markers."""
        marker = MDMarker('foo')
        self.oq.push(marker)
        retrieved = self.oq.pop()
        self.assertTrue(IMarker.providedBy(retrieved))

    def test_fifo_simple(self):
        """Check FIFO queue with one silly value."""
        data = 'data'
        self.oq.push(data)
        self.assertEqual(len(self.oq), 1)
        retrieved = self.oq.pop()
        self.assertEqual(data, retrieved)
        self.assertEqual(len(self.oq), 0)

    def test_fifo_double(self):
        """Check FIFO queue with two values."""
        data1, data2 = 'data1', 'data2'
        self.oq.push(data1)
        self.oq.push(data2)
        self.assertEqual(len(self.oq), 2)
        retrieved = self.oq.pop()
        self.assertEqual(data1, retrieved)
        self.assertEqual(len(self.oq), 1)
        retrieved = self.oq.pop()
        self.assertEqual(data2, retrieved)
        self.assertEqual(len(self.oq), 0)

    def test_fifo_mixed(self):
        """Check FIFO queue with more values."""
        data1, data2, data3 = 'data1', 'data2', 'data3'
        self.oq.push(data1)
        self.oq.push(data2)
        self.assertEqual(data1, self.oq.pop())
        self.oq.push(data3)
        self.assertEqual(data2, self.oq.pop())
        self.assertEqual(data3, self.oq.pop())

    def test_rotate_limit_not_reached(self):
        """File does not rotate if limits are not reached."""
        orig_temp = self.oq._tempfile
        self.oq.push('data')
        self.assertEqual(self.oq._tempfile, orig_temp)
        self.oq.pop()
        self.assertEqual(self.oq._tempfile, orig_temp)

    def _get_data(self, data='data'):
        """Return data to store and it's item size in disk."""
        pickled = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
        item_size = len(pickled) + STRUCT_SIZE
        return data, item_size

    def test_rotate_soft_limit_on_push(self):
        """Rotation happens with soft limit on push."""
        # set and check rotation limits
        data, item_size = self._get_data()
        self.oq._rotation_soft_limit = item_size * 2.5
        assert self.oq._rotation_too_big_size > item_size * 10
        assert self.oq._rotation_hard_limit > item_size * 10

        # put two items, removing one so we can save space on rotation
        orig_temp = self.oq._tempfile
        self.oq.push(data)
        self.oq.pop()
        self.oq.push(data)
        self.assertEqual(self.oq._tempfile, orig_temp)

        # push another, now we're over again, but now we can save space
        self.oq.push(data)
        self.assertNotEqual(self.oq._tempfile, orig_temp)

    def test_rotate_soft_limit_on_pop(self):
        """Rotation happens with soft limit on pop."""
        # set and check rotation limits
        data, item_size = self._get_data()
        self.oq._rotation_soft_limit = item_size * 2.5
        assert self.oq._rotation_too_big_size > item_size * 10
        assert self.oq._rotation_hard_limit > item_size * 10

        # put four items
        orig_temp = self.oq._tempfile
        self.oq.push(data)
        self.oq.push(data)
        self.oq.push(data)
        self.oq.push(data)
        self.assertEqual(self.oq._tempfile, orig_temp)

        # pop the first one, we make room and still have more than soft limit
        # and min size, so we rotate
        self.oq.pop()
        self.assertNotEqual(self.oq._tempfile, orig_temp)

    def test_rotate_too_much_data(self):
        """Soft rotation doesn't happen if we have more than the max size."""
        # set and check rotation limits
        data, item_size = self._get_data()
        self.oq._rotation_soft_limit = item_size * 2.5
        self.oq._rotation_too_big_size = item_size
        assert self.oq._rotation_hard_limit > item_size * 10

        # put two items, removing one so we can save space on rotation
        orig_temp = self.oq._tempfile
        self.oq.push(data)
        self.oq.pop()
        self.oq.push(data)
        self.assertEqual(self.oq._tempfile, orig_temp)

        # push another, now we're over but we have too much data to move,
        # so rotation should not happen
        self.oq.push(data)
        self.assertEqual(self.oq._tempfile, orig_temp)

    def test_rotate_hard_limit(self):
        """We rotate on hard limit, no matter what."""
        # set and check rotation limits
        data, item_size = self._get_data()
        self.oq._rotation_soft_limit = item_size * 2.5
        self.oq._rotation_too_big_size = item_size
        self.oq._rotation_hard_limit = item_size * 3.5

        # put two items, removing one so we can save space on rotation
        orig_temp = self.oq._tempfile
        self.oq.push(data)
        self.oq.pop()
        self.oq.push(data)
        self.assertEqual(self.oq._tempfile, orig_temp)

        # push another, now we're over but we have too much data to move,
        # so rotation should not happen
        self.oq.push(data)
        self.assertEqual(self.oq._tempfile, orig_temp)

        # push another one, and check that after going over the hard limit
        # it will rotate no matter what
        self.oq.push(data)
        self.assertNotEqual(self.oq._tempfile, orig_temp)

    def test_rotate_keep_working(self):
        """Just check that all is normal after rotation."""
        data = []
        size = 0
        for i in xrange(10):
            d, s = self._get_data('data' + str(i))
            data.append(d)
            size += s
        self.oq._rotation_soft_limit = size * 0.7
        orig_temp = self.oq._tempfile

        # put one item and remove just to make it rotable
        results = []
        self.oq.push(data[0])
        results.append(self.oq.pop())

        # push the rest of the data, it should rotate at some point
        for d in data[1:]:
            self.oq.push(d)
        assert self.oq._tempfile != orig_temp

        # pop everything and compare
        while len(self.oq):
            results.append(self.oq.pop())
        self.assertEqual(data, results)

    def test_rotate_removes_old_file(self):
        """Rotation should start a new file and remove the previous one."""
        data, item_size = self._get_data()
        self.oq._rotation_soft_limit = item_size * 2.5
        orig_fname = self.oq._tempfile_name

        self.oq.push(data)
        self.oq.pop()
        self.oq.push(data)
        self.oq.push(data)

        self.assertFalse(os.path.exists(orig_fname))

    def test_log_init_tempfile(self):
        """Log the initial temp file used."""
        self.assertTrue(self.handler.check_debug("Using temporary file",
                                                 repr(self.oq._tempfile_name)))

    def test_log_rotate(self):
        """Log new file in rotation."""
        data, item_size = self._get_data()
        self.oq._rotation_soft_limit = item_size * 2.5

        self.oq.push(data)
        self.oq.pop()
        self.oq.push(data)
        self.oq.push(data)

        self.assertTrue(self.handler.check_debug("Rotation into", "moving",
                                                 repr(self.oq._tempfile_name)))

    def test_safe_rotate_crash(self):
        """All is ok even after rotation crashes when getting temp file."""
        def crash(*a):
            """Will crash."""
            raise NameError("ugly")
        self.patch(tempfile, 'mkstemp', crash)

        # do a lot of things, rotating in the middle, checking all is ok
        self.test_rotate_keep_working()
        self.assertTrue(self.handler.check_exception(NameError))
        self.assertTrue(self.oq._in_memory)

    def test_safe_rotate_unlink(self):
        """All is ok after failing to unlink old file."""
        def crash(*a):
            """Will crash."""
            raise NameError("ugly")
        self.patch(os, 'unlink', crash)

        # do a lot of things, rotating in the middle, checking all is ok
        self.test_rotate_keep_working()
        self.assertTrue(self.handler.check_warning(
                        "Error when removing old tempfile", "NameError"))

    def _test_safe_push_write(self, count):
        """Fail when pushing an item will leave it all ok."""
        class CrashingFile(StringIO.StringIO):
            """File-like object that crashes in second write."""
            def __init__(self):
                self._fail_counter = 0
                StringIO.StringIO.__init__(self)

            def write(self, *a):
                """Crashing write."""
                self._fail_counter += 1
                if self._fail_counter == count:
                    raise ValueError("broken")
                else:
                    StringIO.StringIO.write(self, *a)

        self.oq._tempfile = CrashingFile()

        # will try three items, checking all is ok
        self.test_fifo_mixed()
        self.assertTrue(self.handler.check_exception(ValueError))
        self.assertTrue(self.oq._in_memory)

    def test_safe_push_write_first(self):
        """Fail when pushing an item, on first write."""
        self._test_safe_push_write(1)

    def test_safe_push_write_second(self):
        """Fail when pushing an item, on second write."""
        self._test_safe_push_write(2)
