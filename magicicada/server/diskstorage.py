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

import os

from twisted.internet import defer, reactor

# the levels of directories for the tree where will store all nodes
DIRS_LEVELS = 3


class FileReaderProducer(object):
    """A producer starting from a filepath.

    It also exposes a deferred, triggered at the very end.
    """

    chunk = 65536

    def __init__(self, filepath):
        super(FileReaderProducer, self).__init__()
        self._fh = open(filepath, 'rb')
        self.deferred = defer.Deferred()
        self.pausing_deferred = None
        self.keep_going = True

    def startProducing(self, consumer):
        """Start a reactor-friendly loop to yield the file content."""

        def done(reason):
            self.keep_going = False
            if not self.deferred.called:
                self.deferred.callback(reason)

        flag = defer.Deferred()
        flag.addBoth(done)
        reactor.callLater(0, self._readloop, flag, consumer)
        return flag

    def _readloop(self, flag, consumer):
        """Read one chunk from the input file and to the consumer."""
        try:
            data = self._fh.read(self.chunk)
        except Exception as err:
            flag.errback(err)
            return

        if data and self.keep_going:
            consumer.write(data)
            if self.pausing_deferred is None:
                reactor.callLater(0, self._readloop, flag, consumer)
            else:
                def f(_):
                    return reactor.callLater(0, self._readloop, flag, consumer)
                self.pausing_deferred.addCallback(f)
        else:
            self._fh.close()
            if not flag.called:
                flag.callback(None)

    def pauseProducing(self):
        """Temporarily suspend moving bytes."""
        if self.pausing_deferred is None:
            self.pausing_deferred = defer.Deferred()

    def resumeProducing(self):
        """Undo the effects of a previous pausing."""
        if self.pausing_deferred is not None:
            d = self.pausing_deferred
            self.pausing_deferred = None
            d.callback(None)

    def stopProducing(self):
        """Stop writing bytes from the file to the consumer."""
        self.keep_going = False
        self.resumeProducing()


class FileWriterConsumer(object):
    """A file consumer (writes to disk) starting from a filepath."""

    def __init__(self, filepath, offset):
        self.filepath = filepath
        self.temppath = temppath = filepath + ".temp"

        if offset:
            fh = open(temppath, 'ab')
            fh.seek(offset)
        else:
            fh = open(temppath, 'wb')
        self.fh = fh

    def registerProducer(self, producer, streaming):
        self.producer = producer
        assert streaming

    def unregisterProducer(self):
        self.producer = None
        self.fh.close()

    def write(self, data):
        self.fh.write(data)

    def commit(self):
        """Commit the file."""
        self.fh.close()
        os.rename(self.temppath, self.filepath)


class DiskStorage(object):
    """Store nodes in disk.

    Read and write those nodes acting like Twisted producers/consumers.
    """
    def __init__(self, basedir):
        super(DiskStorage, self).__init__()
        self.basedir = basedir

    def _get_treepath(self, node_id):
        """Build the tree path."""
        if os.path.sep in node_id or len(node_id) < DIRS_LEVELS:
            raise ValueError("Invalid node id.")

        return os.path.join(self.basedir, os.path.join(*node_id[:DIRS_LEVELS]))

    def get(self, node_id):
        """Get a producer that will retrieve bytes from disk."""
        fpath = os.path.join(self._get_treepath(node_id), node_id)
        return FileReaderProducer(fpath)

    def put(self, node_id, offset=0):
        """Get a consumer that will store bytes in disk."""
        path = self._get_treepath(node_id)
        if not os.path.exists(path):
            os.makedirs(path)
        fpath = os.path.join(path, node_id)
        return FileWriterConsumer(fpath, offset)
