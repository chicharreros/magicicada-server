# Copyright 2008-2015 Canonical
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Some utilities for helping in the upload.

ProxyHashingProducer is a producer proxy that calculates the hash of the entire
produced data, doing it on the fly if streaming, else at the end, re-reading
the entire file.

The NullConsumer is just a consumer that discards whatever it gets.
"""

import zlib

from cStringIO import StringIO

from twisted.internet import defer
from ubuntuone.storageprotocol.content_hash import (
    content_hash_factory,
    crc32,
    magic_hash_factory,
)

from magicicada.server import errors
from magicicada.server.diskstorage import FileReaderProducer


class ProxyHashingProducer(object):
    """A producer that streams stuff off to the consumer.

    This producer calculates the hash, crc32 and inflated size on the fly
    if 'streaming' if True, else it calculates everything re-reading at the
    end.
    """

    chunks = 10

    def __init__(self, consumer, streaming):
        self.decompressor = zlib.decompressobj()
        self.hash_object = content_hash_factory()
        self.magic_hash_object = magic_hash_factory()
        self.crc32 = 0
        self.inflated_size = 0
        self.deflated_size = 0
        self.consumer = consumer
        self.streaming = streaming

    def stopProducing(self):
        """Tell consumer to stop."""
        if self.consumer is not None:
            self.consumer.unregisterProducer()

    def dataReceived(self, data):
        """Handle data from client."""
        self.consumer.write(data)
        if self.streaming:
            self.add_deflated_data(data)

    def add_inflated_data(self, data):
        """Process inflated data to make sure checksums match."""
        self.hash_object.update(data)
        self.magic_hash_object.update(data)
        self.crc32 = crc32(data, self.crc32)
        self.inflated_size += len(data)

    def add_deflated_data(self, data):
        """Helper to decompress, hash, etc. in smaller chunks."""
        if not data:
            # avoid any extra work, there is nothing to see here.
            return
        self.deflated_size += len(data)
        chunk_size = len(data) // self.chunks
        buf = StringIO(data)
        for i in xrange(self.chunks):  # split the data in 10 chunks
            self.add_inflated_data(self.decompress(buf.read(chunk_size)))
        if buf.tell() < len(data):
            self.add_inflated_data(self.decompress(buf.read()))

    def write(self, data):
        """Receives data from the FileReaderProducer when not streaming."""
        self.add_deflated_data(data)

    @defer.inlineCallbacks
    def flush_decompressor(self):
        """Flush the decompressor object and handle pending bytes."""
        if not self.streaming:
            frp = FileReaderProducer(self.consumer.filepath)
            frp.startProducing(self)
            yield frp.deferred

        final_data = self.decompressor.flush()
        self.add_inflated_data(final_data)

    def decompress(self, data):
        """Inflate the raw data."""
        try:
            return self.decompressor.decompress(data)
        except zlib.error as e:
            # bad data makes zlib cry
            raise errors.UploadCorrupt(str(e))


class NullConsumer(object):
    """A consumer that does nothing."""

    def __init__(self):
        self.producer = None
        self.paused = False
        self.producerStreaming = False

    def registerProducer(self, producer, streaming=True):
        """Register producer."""
        if self.producer is not None:
            raise RuntimeError(
                "Cannot register producer %s, because producer %s was not "
                "unregistered." % (producer, self.producer))
        self.producer = producer
        self.producerStreaming = streaming
        self.producer.consumer = self

    def unregisterProducer(self):
        """Unregister producer."""
        if self.producer is not None:
            self.producer.consumer = self.producer = None

    def commit(self):
        """Nothing to do in a null consumer."""

    def cancel(self):
        """Cancel this consumer."""
        self.producer = None

    def write(self, data):
        """Write into the void."""
        if self.paused:
            raise RuntimeError("Asked to write to consumer while paused")
