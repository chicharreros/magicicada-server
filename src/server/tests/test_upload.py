# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Tests for ubuntuone.storage.server.upload."""

import os
import shutil
import zlib

from twisted.internet import defer, reactor, task

from ubuntuone.storage.server import upload, diskstorage
from ubuntuone.storage.server.auth import DummyAuthProvider
from ubuntuone.storage.server.testing import testcase
from ubuntuone.storageprotocol.content_hash import (
    content_hash_factory,
    crc32,
    magic_hash_factory,
)


class UploadTestCase(testcase.BaseProtocolTestCase):
    """Base test case for upload stuff."""
    auth_provider_class = DummyAuthProvider

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(UploadTestCase, self).setUp()

        self.tmpdir = os.getcwd() + "/tmp/diskstorage_tests"
        os.makedirs(self.tmpdir)
        self.addCleanup(shutil.rmtree, self.tmpdir)

        def slowScheduler(x):
            """A slower scheduler for our cooperator."""
            return reactor.callLater(0.1, x)
        self._cooperator = task.Cooperator(scheduler=slowScheduler)

    @defer.inlineCallbacks
    def tearDown(self):
        """Tear down."""
        self._cooperator.stop()
        yield super(UploadTestCase, self).tearDown()


class ProxyHashingProducerTest(UploadTestCase):
    """Tests for ProxyHashingProducer."""

    @defer.inlineCallbacks
    def test_proxy_producer_streaming(self):
        """Test ProxyHashingProducer."""
        data = os.urandom(1024 * 10)
        message = zlib.compress(data)
        ds = diskstorage.DiskStorage(os.path.join(self.tmpdir, "testfile"))
        consumer = ds.put("somenode")
        producer = upload.ProxyHashingProducer(consumer, True)

        chunk_sz = 10
        for part in xrange(0, len(message), chunk_sz):
            yield producer.dataReceived(message[part:part + chunk_sz])
        producer.stopProducing()
        yield producer.flush_decompressor()

        with open(consumer.filepath, "rb") as fh:
            self.assertEqual(fh.read(), message)
        hasher = content_hash_factory()
        hasher.update(data)
        self.assertEqual(producer.hash_object.content_hash(),
                         hasher.content_hash())
        magic_hasher = magic_hash_factory()
        magic_hasher.update(data)
        self.assertEqual(producer.magic_hash_object.content_hash()._magic_hash,
                         magic_hasher.content_hash()._magic_hash)
        self.assertEqual(producer.inflated_size, len(data))
        self.assertEqual(producer.crc32, crc32(data))

    @defer.inlineCallbacks
    def test_proxy_producer_not_streaming(self):
        """Test ProxyHashingProducer."""
        data = os.urandom(1024 * 10)
        message = zlib.compress(data)
        ds = diskstorage.DiskStorage(os.path.join(self.tmpdir, "testfile"))
        consumer = ds.put("somenode")
        producer = upload.ProxyHashingProducer(consumer, False)

        # add chunks, but see that nothing is really being calculated
        chunk_sz = 10
        for part in xrange(0, len(message), chunk_sz):
            yield producer.dataReceived(message[part:part + chunk_sz])
            self.assertEqual(producer.deflated_size, 0)
            self.assertEqual(producer.inflated_size, 0)
            self.assertEqual(producer.crc32, 0)

        # stop and re-check
        producer.stopProducing()
        yield producer.flush_decompressor()
        with open(consumer.filepath, "rb") as fh:
            self.assertEqual(fh.read(), message)
        hasher = content_hash_factory()
        hasher.update(data)
        self.assertEqual(producer.hash_object.content_hash(),
                         hasher.content_hash())
        magic_hasher = magic_hash_factory()
        magic_hasher.update(data)
        self.assertEqual(producer.magic_hash_object.content_hash()._magic_hash,
                         magic_hasher.content_hash()._magic_hash)
        self.assertEqual(producer.inflated_size, len(data))
        self.assertEqual(producer.crc32, crc32(data))

    def test_add_deflated_data(self):
        """Test that add_deflated_data decompress in chunks."""
        raw_data = os.urandom(1000)
        data = zlib.compress(raw_data)
        producer = upload.ProxyHashingProducer('consumer', False)
        called = []
        # patch add_inflated_data to check the chunks
        self.patch(producer, 'add_inflated_data', called.append)
        producer.add_deflated_data(data)
        # check that we have all the chunks
        self.assertEqual(10 + len(data) % 10, len(called))
        # check that the inflated data is equal to the raw data.
        self.assertEqual(raw_data, ''.join(called))

    def test_add_deflated_data_odd(self):
        """Test that add_deflated_data decompress in chunks."""
        raw_data = os.urandom(1333)
        data = zlib.compress(raw_data)
        producer = upload.ProxyHashingProducer('consumer', False)
        called = []
        # patch add_inflated_data to check the chunks
        self.patch(producer, 'add_inflated_data', called.append)
        producer.add_deflated_data(data)
        self.assertEqual(raw_data, ''.join(called))
        # check that we have all the chunks
        if len(data) % 10:
            self.assertEqual(11, len(called))
        else:
            self.assertEqual(10, len(called))
        # check that the inflated data is equal to the raw data.
        self.assertEqual(raw_data, ''.join(called))

    def test_add_deflated_data_zero(self):
        """Test that add_deflated_data decompress in chunks."""
        producer = upload.ProxyHashingProducer('consumer', False)
        called = []
        # patch add_inflated_data to check the chunks
        self.patch(producer, 'add_inflated_data', called.append)
        producer.add_deflated_data('')
        # check that we have all the chunks
        self.assertEqual(0, len(called))
