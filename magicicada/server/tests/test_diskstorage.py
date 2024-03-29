# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/magicicada-server

"""Test Disk Storage backend."""

import os
import shutil
import io

from twisted.internet import defer
from twisted.trial.unittest import TestCase as TwistedTestCase

from magicicada.server.diskstorage import DiskStorage, DIRS_LEVELS


class BaseTestCase(TwistedTestCase):
    """Test the disk storage basic functionality."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(BaseTestCase, self).setUp()

        self.tmpdir = os.getcwd() + "/tmp/diskstorage_tests"
        os.makedirs(self.tmpdir)
        self.addCleanup(shutil.rmtree, self.tmpdir)

    def test_treepath_simple(self):
        t = DiskStorage("foo")._get_treepath("simple")
        self.assertEqual(t, "foo/s/i/m")

    def test_treepath_invalid(self):
        self.assertRaises(
            ValueError, DiskStorage("foo")._get_treepath, "s/mple"
        )

    def test_treepath_short(self):
        for n in range(DIRS_LEVELS):
            fname = "x" * n
            self.assertRaises(
                ValueError, DiskStorage("foo")._get_treepath, fname
            )

    @defer.inlineCallbacks
    def test_get_node_ok(self):
        # write a fake file
        node_id = "dinw78cdync8"
        path = DiskStorage(self.tmpdir)._get_treepath(node_id)
        os.makedirs(path)
        data = b'test content'
        with open(os.path.join(path, node_id), 'wb') as fh:
            fh.write(data)

        # get it
        ds = DiskStorage(self.tmpdir)
        producer = ds.get(node_id)
        consumer = io.BytesIO()
        yield producer.startProducing(consumer)
        self.assertEqual(consumer.getvalue(), data)

    def test_get_node_missing(self):
        ds = DiskStorage(self.tmpdir)
        self.assertRaises(IOError, ds.get, "not there")

    def test_put_node_ok(self):
        # write it
        node_id = "dinw78cdync8"
        ds = DiskStorage(self.tmpdir)
        data = b'test content to write'
        consumer = ds.put(node_id)
        consumer.write(data)
        consumer.unregisterProducer()
        consumer.commit()

        # check the file
        path = ds._get_treepath(node_id)
        with open(os.path.join(path, node_id), 'rb') as fh:
            written = fh.read()
        self.assertEqual(written, data)

    def test_put_node_twice_similar_name(self):
        node_id_1 = "abcJJJJJJJJJ"
        node_id_2 = "abcYYYYYYYYY"
        ds = DiskStorage(self.tmpdir)
        ds.put(node_id_1)
        ds.put(node_id_2)

    def test_put_node_resumed(self):
        # write some
        node_id = "dinw78cdync8"
        ds = DiskStorage(self.tmpdir)
        data1 = b'test content to write part 1'
        consumer = ds.put(node_id)
        consumer.write(data1)
        consumer.unregisterProducer()

        # write more and finish
        data2 = b' and part 2'
        consumer = ds.put(node_id, len(data1))
        consumer.write(data2)
        consumer.unregisterProducer()
        consumer.commit()

        # check the file
        path = ds._get_treepath(node_id)
        with open(os.path.join(path, node_id), 'rb') as fh:
            written = fh.read()
        self.assertEqual(written, data1 + data2)

    def test_put_node_resumed_on_weird_file(self):
        # write some
        node_id = "dinw78cdync8"
        ds = DiskStorage(self.tmpdir)
        data1 = b'test content to write part 1'
        consumer = ds.put(node_id)
        consumer.write(data1)
        consumer.unregisterProducer()

        # modify the file
        path = ds._get_treepath(node_id)
        temppath = os.path.join(path, node_id) + ".temp"
        with open(temppath, 'ab') as fh:
            fh.write(b"garbage")

        # try to write more
        self.assertRaises(ValueError, ds.put, node_id, len(data1))

    def test_put_node_flushing(self):
        # write some
        node_id = "dinw78cdync8"
        ds = DiskStorage(self.tmpdir)
        data = b'test content to write part 1'
        consumer = ds.put(node_id)
        consumer.write(data)

        # even if not finished, disk should have written content
        path = ds._get_treepath(node_id)
        temppath = os.path.join(path, node_id) + ".temp"
        with open(temppath, 'rb') as fh:
            written = fh.read()
        self.assertEqual(written, data)

    def test_put_node_rename_on_commit(self):
        # write it
        node_id = "dinw78cdync8"
        ds = DiskStorage(self.tmpdir)
        data = b'test content to write'
        consumer = ds.put(node_id)
        consumer.write(data)
        path = ds._get_treepath(node_id)

        # at this point, it's all written in a temp file, check it (however,
        # manually flush as we still didn't close it)
        consumer.fh.flush()
        with open(consumer.temppath, 'rb') as fh:
            written = fh.read()
        self.assertEqual(written, data)

        # now let it know it's all done
        consumer.commit()

        # check the final file is there and the temp is gone
        with open(os.path.join(path, node_id), 'rb') as fh:
            written = fh.read()
        self.assertEqual(written, data)
        self.assertFalse(os.path.exists(consumer.temppath))
