# Copyright 2009-2015 Canonical
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Pretty API for protocol client."""

from __future__ import with_statement

import logging
import os
import sys
import shutil
import time
import uuid
import zlib

from cStringIO import StringIO
from Queue import Queue
from threading import Lock

from magicicadaprotocol import request, volumes
from magicicadaprotocol.content_hash import crc32
from magicicadaprotocol.context import get_ssl_context
from magicicadaprotocol.client import (
    StorageClientFactory, StorageClient)
from magicicadaprotocol.delta import DIRECTORY as delta_DIR
from magicicadaprotocol.dircontent_pb2 import DIRECTORY, FILE
from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks, returnValue

from magicicada.u1sync.genericmerge import MergeNode
from magicicada.u1sync.utils import should_sync


timing_logger = logging.getLogger(__name__ + '.timing')


def share_str(share_uuid):
    """Converts a share UUID to a form the protocol likes."""
    return str(share_uuid) if share_uuid is not None else request.ROOT


def log_timing(func):
    def wrapper(*arg, **kwargs):
        start = time.time()
        ent = func(*arg, **kwargs)
        stop = time.time()
        timing_logger.debug(
            'for %s %0.5f ms elapsed', func.__name__, (stop-start) * 1000.0)
        return ent
    return wrapper


class ForcedShutdown(Exception):
    """Client shutdown forced."""


class Waiter(object):
    """Wait object for blocking waits."""

    def __init__(self):
        """Initializes the wait object."""
        self.queue = Queue()

    def wake(self, result):
        """Wakes the waiter with a result."""
        self.queue.put((result, None))

    def wakeAndRaise(self, exc_info):
        """Wakes the waiter, raising the given exception in it."""
        self.queue.put((None, exc_info))

    def wakeWithResult(self, func, *args, **kw):
        """Wakes the waiter with the result of the given function."""
        try:
            result = func(*args, **kw)
        except Exception:
            self.wakeAndRaise(sys.exc_info())
        else:
            self.wake(result)

    def wait(self):
        """Waits for wakeup."""
        (result, exc_info) = self.queue.get()
        if exc_info:
            try:
                raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                exc_info = None
        else:
            return result


class SyncStorageClient(StorageClient):
    """Simple client that calls a callback on connection."""

    @log_timing
    def connectionMade(self):
        """Setup and call callback."""
        StorageClient.connectionMade(self)
        if self.factory.current_protocol not in (None, self):
            self.factory.current_protocol.transport.loseConnection()
        self.factory.current_protocol = self
        self.factory.observer.connected()

    @log_timing
    def connectionLost(self, reason=None):
        """Callback for established connection lost."""
        StorageClient.connectionLost(self, reason)
        if self.factory.current_protocol is self:
            self.factory.current_protocol = None
            self.factory.observer.disconnected(reason)


class SyncClientFactory(StorageClientFactory):
    """A cmd protocol factory."""

    protocol = SyncStorageClient

    @log_timing
    def __init__(self, observer):
        """Create the factory"""
        self.observer = observer
        self.current_protocol = None

    @log_timing
    def clientConnectionFailed(self, connector, reason):
        """We failed at connecting."""
        self.current_protocol = None
        self.observer.connection_failed(reason)


class UnsupportedOperationError(Exception):
    """The operation is unsupported by the protocol version."""


class ConnectionError(Exception):
    """A connection error."""


class AuthenticationError(Exception):
    """An authentication error."""


class NoSuchShareError(Exception):
    """Error when there is no such share available."""


class CapabilitiesError(Exception):
    """A capabilities set/query related error."""


class Client(object):
    """U1 storage client facade."""
    required_caps = frozenset([
        "no-content", "account-info", "resumable-uploads",
        "fix462230", "volumes", "generations",
    ])

    def __init__(self, realm=None, reactor=reactor):
        """Create the instance.

        'realm' is no longer used, but is left as param for API compatibility.

        """
        self.reactor = reactor
        self.factory = SyncClientFactory(self)

        self._status_lock = Lock()
        self._status = "disconnected"
        self._status_reason = None
        self._status_waiting = []
        self._active_waiters = set()

    def force_shutdown(self):
        """Forces the client to shut itself down."""
        with self._status_lock:
            self._status = "forced_shutdown"
            self._reason = None
            for waiter in self._active_waiters:
                waiter.wakeAndRaise((ForcedShutdown("Forced shutdown"),
                                     None, None))
            self._active_waiters.clear()

    def _get_waiter_locked(self):
        """Gets a wait object for blocking waits.  Should be called with the
        status lock held.
        """
        waiter = Waiter()
        if self._status == "forced_shutdown":
            raise ForcedShutdown("Forced shutdown")
        self._active_waiters.add(waiter)
        return waiter

    def _get_waiter(self):
        """Get a wait object for blocking waits.  Acquires the status lock."""
        with self._status_lock:
            return self._get_waiter_locked()

    def _wait(self, waiter):
        """Waits for the waiter."""
        try:
            return waiter.wait()
        finally:
            with self._status_lock:
                if waiter in self._active_waiters:
                    self._active_waiters.remove(waiter)

    @log_timing
    def _change_status(self, status, reason=None):
        """Changes the client status.  Usually called from the reactor
        thread.

        """
        with self._status_lock:
            if self._status == "forced_shutdown":
                return
            self._status = status
            self._status_reason = reason
            waiting = self._status_waiting
            self._status_waiting = []
        for waiter in waiting:
            waiter.wake((status, reason))

    @log_timing
    def _await_status_not(self, *ignore_statuses):
        """Blocks until the client status changes, returning the new status.
        Should never be called from the reactor thread.

        """
        with self._status_lock:
            status = self._status
            reason = self._status_reason
            while status in ignore_statuses:
                waiter = self._get_waiter_locked()
                self._status_waiting.append(waiter)
                self._status_lock.release()
                try:
                    status, reason = self._wait(waiter)
                finally:
                    self._status_lock.acquire()
            if status == "forced_shutdown":
                raise ForcedShutdown("Forced shutdown.")
            return (status, reason)

    def connection_failed(self, reason):
        """Notification that connection failed."""
        self._change_status("disconnected", reason)

    def connected(self):
        """Notification that connection succeeded."""
        self._change_status("connected")

    def disconnected(self, reason):
        """Notification that we were disconnected."""
        self._change_status("disconnected", reason)

    def defer_from_thread(self, function, *args, **kwargs):
        """Do twisted defer magic to get results and show exceptions."""
        waiter = self._get_waiter()

        @log_timing
        def runner():
            """inner."""
            try:
                d = function(*args, **kwargs)
                if isinstance(d, defer.Deferred):
                    d.addCallbacks(lambda r: waiter.wake((r, None, None)),
                                   lambda f: waiter.wake((None, None, f)))
                else:
                    waiter.wake((d, None, None))
            except Exception:
                waiter.wake((None, sys.exc_info(), None))

        self.reactor.callFromThread(runner)
        result, exc_info, failure = self._wait(waiter)
        if exc_info:
            try:
                raise exc_info[0], exc_info[1], exc_info[2]
            finally:
                exc_info = None
        elif failure:
            failure.raiseException()
        else:
            return result

    @log_timing
    def connect(self, host, port):
        """Connect to host/port."""
        def _connect():
            """Deferred part."""
            self.reactor.connectTCP(host, port, self.factory)
        self._connect_inner(_connect)

    @log_timing
    def connect_ssl(self, host, port, no_verify):
        """Connect to host/port using ssl."""
        def _connect():
            """deferred part."""
            ctx = get_ssl_context(no_verify, host)
            self.reactor.connectSSL(host, port, self.factory, ctx)
        self._connect_inner(_connect)

    @log_timing
    def _connect_inner(self, _connect):
        """Helper function for connecting."""
        self._change_status("connecting")
        self.reactor.callFromThread(_connect)
        status, reason = self._await_status_not("connecting")
        if status != "connected":
            raise ConnectionError(reason.value)

    @log_timing
    def disconnect(self):
        """Disconnect."""
        if self.factory.current_protocol is not None:
            self.reactor.callFromThread(
                self.factory.current_protocol.transport.loseConnection)
        self._await_status_not("connecting", "connected", "authenticated")

    @log_timing
    def simple_auth(self, username, password):
        """Perform simple authorisation."""

        @inlineCallbacks
        def _wrapped_authenticate():
            """Wrapped authenticate."""
            try:
                yield self.factory.current_protocol.simple_authenticate(
                    username, password)
            except Exception:
                self.factory.current_protocol.transport.loseConnection()
            else:
                self._change_status("authenticated")

        try:
            self.defer_from_thread(_wrapped_authenticate)
        except request.StorageProtocolError as e:
            raise AuthenticationError(e)
        status, reason = self._await_status_not("connected")
        if status != "authenticated":
            raise AuthenticationError(reason.value)

    @log_timing
    def set_capabilities(self):
        """Set the capabilities with the server"""

        client = self.factory.current_protocol

        @log_timing
        def set_caps_callback(req):
            "Caps query succeeded"
            if not req.accepted:
                de = defer.fail("The server denied setting %s capabilities" %
                                req.caps)
                return de

        @log_timing
        def query_caps_callback(req):
            "Caps query succeeded"
            if req.accepted:
                set_d = client.set_caps(self.required_caps)
                set_d.addCallback(set_caps_callback)
                return set_d
            else:
                # the server don't have the requested capabilities.
                # return a failure for now, in the future we might want
                # to reconnect to another server
                de = defer.fail("The server don't have the requested"
                                " capabilities: %s" % str(req.caps))
                return de

        @log_timing
        def _wrapped_set_capabilities():
            """Wrapped set_capabilities """
            d = client.query_caps(self.required_caps)
            d.addCallback(query_caps_callback)
            return d

        try:
            self.defer_from_thread(_wrapped_set_capabilities)
        except request.StorageProtocolError as e:
            raise CapabilitiesError(e)

    @log_timing
    def get_root_info(self, volume_uuid):
        """Returns the UUID of the applicable share root."""
        if volume_uuid is None:
            _get_root = self.factory.current_protocol.get_root
            root = self.defer_from_thread(_get_root)
            return (uuid.UUID(root), True)
        else:
            str_volume_uuid = str(volume_uuid)
            volume = self._match_volume(
                lambda v: str(v.volume_id) == str_volume_uuid)
            if isinstance(volume, volumes.ShareVolume):
                modify = volume.access_level == "Modify"
            if isinstance(volume, volumes.UDFVolume):
                modify = True
            return (uuid.UUID(str(volume.node_id)), modify)

    @log_timing
    def resolve_path(self, share_uuid, root_uuid, path):
        """Resolve path relative to the given root node."""

        @inlineCallbacks
        def _resolve_worker():
            """Path resolution worker."""
            node_uuid = root_uuid
            local_path = path.strip('/')

            while local_path != '':
                local_path, name = os.path.split(local_path)
                hashes = yield self._get_node_hashes(share_uuid)
                content_hash = hashes.get(root_uuid, None)
                if content_hash is None:
                    raise KeyError("Content hash not available")
                entries = yield self._get_dir_entries(share_uuid, root_uuid)
                match_name = name.decode('utf-8')
                match = None
                for entry in entries:
                    if match_name == entry.name:
                        match = entry
                        break

                if match is None:
                    raise KeyError("Path not found")

                node_uuid = uuid.UUID(match.node)

            returnValue(node_uuid)

        return self.defer_from_thread(_resolve_worker)

    @log_timing
    def find_volume(self, volume_spec):
        """Finds a share matching the given UUID.  Looks at both share UUIDs
        and root node UUIDs."""

        def match(s):
            return (str(s.volume_id) == volume_spec or
                    str(s.node_id) == volume_spec)

        volume = self._match_volume(match)
        return uuid.UUID(str(volume.volume_id))

    @log_timing
    def _match_volume(self, predicate):
        """Finds a volume matching the given predicate."""
        _list_shares = self.factory.current_protocol.list_volumes
        r = self.defer_from_thread(_list_shares)
        for volume in r.volumes:
            if predicate(volume):
                return volume
        raise NoSuchShareError()

    @log_timing
    def build_tree(self, share_uuid, root_uuid):
        """Builds and returns a tree representing the metadata for the given
        subtree in the given share.

        @param share_uuid: the share UUID or None for the user's volume
        @param root_uuid: the root UUID of the subtree (must be a directory)
        @return: a MergeNode tree

        """
        root = MergeNode(node_type=DIRECTORY, uuid=root_uuid)

        @log_timing
        @inlineCallbacks
        def _get_root_content_hash():
            """Obtain the content hash for the root node."""
            result = yield self._get_node_hashes(share_uuid)
            returnValue(result.get(root_uuid, None))

        root.content_hash = self.defer_from_thread(_get_root_content_hash)
        if root.content_hash is None:
            raise ValueError("No content available for node %s" % root_uuid)

        @log_timing
        @inlineCallbacks
        def _get_children(parent_uuid, parent_content_hash):
            """Obtain a sequence of MergeNodes corresponding to a node's
            immediate children.

            """
            entries = yield self._get_dir_entries(share_uuid, parent_uuid)
            children = {}
            for entry in entries:
                if should_sync(entry.name):
                    child = MergeNode(node_type=entry.node_type,
                                      uuid=uuid.UUID(entry.node))
                    children[entry.name] = child

            content_hashes = yield self._get_node_hashes(share_uuid)
            for child in children.values():
                child.content_hash = content_hashes.get(child.uuid, None)

            returnValue(children)

        need_children = [root]
        while need_children:
            node = need_children.pop()
            if node.content_hash is not None:
                children = self.defer_from_thread(_get_children, node.uuid,
                                                  node.content_hash)
                node.children = children
                for child in children.values():
                    if child.node_type == DIRECTORY:
                        need_children.append(child)

        return root

    @log_timing
    @defer.inlineCallbacks
    def _get_dir_entries(self, share_uuid, node_uuid):
        """Get raw dir entries for the given directory."""
        result = yield self.factory.current_protocol.get_delta(
            share_str(share_uuid), from_scratch=True)
        node_uuid = share_str(node_uuid)
        children = []
        for n in result.response:
            if n.parent_id == node_uuid:
                # adapt here some attrs so we don't need to change ALL the code
                n.node_type = DIRECTORY if n.file_type == delta_DIR else FILE
                n.node = n.node_id
                children.append(n)
        defer.returnValue(children)

    @log_timing
    def download_string(self, share_uuid, node_uuid, content_hash):
        """Reads a file from the server into a string."""
        output = StringIO()
        self._download_inner(share_uuid=share_uuid, node_uuid=node_uuid,
                             content_hash=content_hash, output=output)
        return output.getValue()

    @log_timing
    def download_file(self, share_uuid, node_uuid, content_hash, filename):
        """Downloads a file from the server."""
        partial_filename = "%s.u1partial" % filename
        output = open(partial_filename, "w")

        @log_timing
        def rename_file():
            """Renames the temporary file to the final name."""
            output.close()
            os.rename(partial_filename, filename)

        @log_timing
        def delete_file():
            """Deletes the temporary file."""
            output.close()
            os.remove(partial_filename)

        self._download_inner(share_uuid=share_uuid, node_uuid=node_uuid,
                             content_hash=content_hash, output=output,
                             on_success=rename_file, on_failure=delete_file)

    @log_timing
    def _download_inner(self, share_uuid, node_uuid, content_hash, output,
                        on_success=lambda: None, on_failure=lambda: None):
        """Helper function for content downloads."""
        dec = zlib.decompressobj()

        @log_timing
        def write_data(data):
            """Helper which writes data to the output file."""
            uncompressed_data = dec.decompress(data)
            output.write(uncompressed_data)

        @log_timing
        def finish_download(value):
            """Helper which finishes the download."""
            uncompressed_data = dec.flush()
            output.write(uncompressed_data)
            on_success()
            return value

        @log_timing
        def abort_download(value):
            """Helper which aborts the download."""
            on_failure()
            return value

        @log_timing
        def _download():
            """Async helper."""
            _get_content = self.factory.current_protocol.get_content
            d = _get_content(share_str(share_uuid), str(node_uuid),
                             content_hash, callback=write_data)
            d.addCallbacks(finish_download, abort_download)
            return d

        self.defer_from_thread(_download)

    @log_timing
    def create_directory(self, share_uuid, parent_uuid, name):
        """Creates a directory on the server."""
        r = self.defer_from_thread(self.factory.current_protocol.make_dir,
                                   share_str(share_uuid), str(parent_uuid),
                                   name)
        return uuid.UUID(r.new_id)

    @log_timing
    def create_file(self, share_uuid, parent_uuid, name):
        """Creates a file on the server."""
        r = self.defer_from_thread(self.factory.current_protocol.make_file,
                                   share_str(share_uuid), str(parent_uuid),
                                   name)
        return uuid.UUID(r.new_id)

    @log_timing
    def create_symlink(self, share_uuid, parent_uuid, name, target):
        """Creates a symlink on the server."""
        raise UnsupportedOperationError("Protocol does not support symlinks")

    @log_timing
    def upload_string(self, share_uuid, node_uuid, old_content_hash,
                      content_hash, content):
        """Uploads a string to the server as file content."""
        crc = crc32(content, 0)
        compressed_content = zlib.compress(content, 9)
        compressed = StringIO(compressed_content)
        self.defer_from_thread(self.factory.current_protocol.put_content,
                               share_str(share_uuid), str(node_uuid),
                               old_content_hash, content_hash,
                               crc, len(content), len(compressed_content),
                               compressed)

    @log_timing
    def upload_file(self, share_uuid, node_uuid, old_content_hash,
                    content_hash, filename):
        """Uploads a file to the server."""
        parent_dir = os.path.split(filename)[0]
        unique_filename = os.path.join(parent_dir, "." + str(uuid.uuid4()))

        class StagingFile(object):
            """An object which tracks data being compressed for staging."""
            def __init__(self, stream):
                """Initialize a compression object."""
                self.crc32 = 0
                self.enc = zlib.compressobj(9)
                self.size = 0
                self.compressed_size = 0
                self.stream = stream

            def write(self, bytes):
                """Compress bytes, keeping track of length and crc32."""
                self.size += len(bytes)
                self.crc32 = crc32(bytes, self.crc32)
                compressed_bytes = self.enc.compress(bytes)
                self.compressed_size += len(compressed_bytes)
                self.stream.write(compressed_bytes)

            def finish(self):
                """Finish staging compressed data."""
                compressed_bytes = self.enc.flush()
                self.compressed_size += len(compressed_bytes)
                self.stream.write(compressed_bytes)

        with open(unique_filename, "w+") as compressed:
            os.remove(unique_filename)
            with open(filename, "r") as original:
                staging = StagingFile(compressed)
                shutil.copyfileobj(original, staging)
            staging.finish()
            compressed.seek(0)
            self.defer_from_thread(self.factory.current_protocol.put_content,
                                   share_str(share_uuid), str(node_uuid),
                                   old_content_hash, content_hash,
                                   staging.crc32,
                                   staging.size, staging.compressed_size,
                                   compressed)

    @log_timing
    def move(self, share_uuid, parent_uuid, name, node_uuid):
        """Moves a file on the server."""
        self.defer_from_thread(self.factory.current_protocol.move,
                               share_str(share_uuid), str(node_uuid),
                               str(parent_uuid), name)

    @log_timing
    def unlink(self, share_uuid, node_uuid):
        """Unlinks a file on the server."""
        self.defer_from_thread(self.factory.current_protocol.unlink,
                               share_str(share_uuid), str(node_uuid))

    @log_timing
    @defer.inlineCallbacks
    def _get_node_hashes(self, share_uuid):
        """Fetches hashes for the given nodes."""
        result = yield self.factory.current_protocol.get_delta(
            share_str(share_uuid), from_scratch=True)
        hashes = {}
        for fid in result.response:
            node_uuid = uuid.UUID(fid.node_id)
            hashes[node_uuid] = fid.content_hash
        defer.returnValue(hashes)

    @log_timing
    def get_incoming_shares(self):
        """Returns a list of incoming shares as (name, uuid, accepted)
        tuples.

        """
        _list_shares = self.factory.current_protocol.list_shares
        r = self.defer_from_thread(_list_shares)
        return [(s.name, s.id, s.other_visible_name,
                 s.accepted, s.access_level)
                for s in r.shares if s.direction == "to_me"]
