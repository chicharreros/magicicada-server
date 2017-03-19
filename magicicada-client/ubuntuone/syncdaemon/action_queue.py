# -*- coding: utf-8 -*-
#
# Copyright 2009-2015 Canonical Ltd.
# Copyright 2015-2017 Chicharreros (https://launchpad.net/~chicharreros)
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
"""Queue and execute operations on the server."""

import inspect
import itertools
import logging
import os
import tempfile
import traceback
import zlib

from collections import deque, defaultdict
from functools import partial

import OpenSSL.SSL

from zope.interface import implements
from twisted.internet import reactor, defer, task
from twisted.internet import error as twisted_errors
from twisted.python.failure import Failure, DefaultException

from ubuntuone import clientdefs
from ubuntuone.platform import platform, remove_file
from ubuntuone.storageprotocol import protocol_pb2, content_hash
from ubuntuone.storageprotocol import errors as protocol_errors
from ubuntuone.storageprotocol.client import (
    ThrottlingStorageClient,
    ThrottlingStorageClientFactory,
)
from ubuntuone.storageprotocol.context import get_ssl_context
from ubuntuone.syncdaemon.interfaces import IActionQueue, IMarker
from ubuntuone.syncdaemon.logger import mklog, TRACE
from ubuntuone.syncdaemon import config, offload_queue
from ubuntuone.syncdaemon import tunnel_runner

logger = logging.getLogger("ubuntuone.SyncDaemon.ActionQueue")

# I want something which repr() is "---" *without* the quotes :)
UNKNOWN = type('', (), {'__repr__': lambda _: '---'})()

# progress threshold to emit a download/upload progress event: 64Kb
TRANSFER_PROGRESS_THRESHOLD = 64 * 1024


class DeferredInterrupted(Exception):
    """To stop the run when pausing."""


class InterruptibleDeferred(defer.Deferred):
    """Receives a deferred, and wraps it, also behaving like a deferred.

    If the original deferred is triggered, that is passed, and can not be
    interrupted any more. If it's interrupted, then it silences the original
    deferred, no matter what.
    """
    def __init__(self, d):
        defer.Deferred.__init__(self)
        self.interrupted = False

        self.original_deferred = d
        d.addBoth(self.filter)

    def filter(self, result):
        """Pass the result if not interrupted."""
        if not self.interrupted:
            self.callback(result)

    def interrupt(self):
        """Interrupt only if original not called."""
        if not self.original_deferred.called:
            self.interrupted = True
            self.errback(DeferredInterrupted())


class PathLockingTree(object):
    """Tree that stores deferreds in the nodes."""

    def __init__(self):
        self.logger = logging.getLogger("ubuntuone.SyncDaemon.PathLockingTree")
        self.root = dict(children_nodes={})
        self.count = 0
        self.stored_by_id = {}
        self.stored_by_elements = {}
        self.id_stored = 0

    def acquire(self, *elements, **modifiers):
        """Acquire the lock for the elements.

        Return a deferred that will be triggered (when the lock is
        released) with a function to be called when the work is done.

        Example using inlineCallbacks syntax:

            release = yield plt.acquire(*elements)
            ...
            release()
        """
        # process the modifiers (this will not needed in Python 3, :)
        on_parent = modifiers.get('on_parent', False)
        on_children = modifiers.get('on_children', False)
        logger = modifiers.get('logger', self.logger)

        wait_for = []
        deferred = defer.Deferred()
        end_mark = len(elements) - 1
        parent_mark = len(elements) - 2
        self.count += 1
        desc = self.root
        for pos, element in enumerate(elements):
            # get previous child or create a new one just empty, not using
            # setdefault to avoid creating structures if not needed
            children_nodes = desc['children_nodes']
            if element in children_nodes:
                node = children_nodes[element]
            else:
                node = dict(node_deferreds=set(),
                            children_nodes={}, children_deferreds=set())
                children_nodes[element] = node

            # add the deferreds of the parent if asked for it
            if pos == parent_mark and on_parent:
                wait_for.extend(node['node_deferreds'])

            # add the deferred to the node only at the end of the path
            if pos == end_mark:
                wait_for.extend(node['node_deferreds'])
                node['node_deferreds'].add(deferred)

                # add the deferreds of the children, if asked for it
                if on_children:
                    wait_for.extend(node['children_deferreds'])
            else:
                node['children_deferreds'].add(deferred)

            desc = node

        logger.debug("pathlock acquiring on %s (on_parent=%s, on_children=%s);"
                     " wait for: %d", elements, on_parent,
                     on_children, len(wait_for))

        # store info for later releasing
        self.id_stored += 1
        self.stored_by_id[self.id_stored] = (deferred, elements, logger)
        self.stored_by_elements.setdefault(elements, []).append(self.id_stored)
        relfunc = partial(self._release, self.id_stored)

        if not wait_for:
            return defer.succeed(relfunc)
        if len(wait_for) == 1:
            d = defer.Deferred()
            wait_for[0].chainDeferred(d)
            d.addBoth(lambda _: relfunc)
            return d
        # we need to wait for several
        deferred_list = defer.DeferredList(wait_for)
        deferred_list.addBoth(lambda _: relfunc)
        return deferred_list

    def _release(self, stored_id):
        """Release the callback and clean the tree."""
        # get the elements from the stored id
        deferred, elements, logger = self.stored_by_id.pop(stored_id)
        stored_ids = self.stored_by_elements[elements]
        stored_ids.remove(stored_id)
        if not stored_ids:
            del self.stored_by_elements[elements]

        # clean the tree first!
        # keep here every node and its child element, to backtrack
        branch = []

        # remove the deferred from children_deferreds except in the end
        self.count -= 1
        desc = self.root
        for element in elements[:-1]:
            branch.append((desc, element))
            node = desc['children_nodes'][element]
            node['children_deferreds'].discard(deferred)
            desc = node

        # for the final node, remove it from node_deferreds
        branch.append((desc, elements[-1]))
        node = desc['children_nodes'][elements[-1]]
        node['node_deferreds'].discard(deferred)

        # backtrack
        while branch:
            if node['node_deferreds'] or node['children_nodes']:
                # node is not empty, done cleaning the branch!
                break

            # node is empty! remove it
            node, element = branch.pop()
            del node['children_nodes'][element]

        # finally, log and release the deferred
        logger.debug("pathlock releasing %s; remaining: %d",
                     elements, self.count)
        deferred.callback(True)

    def fix_path(self, from_elements, to_elements):
        """Fix the internal path."""
        self.logger.debug("Fixing path from %r to %r",
                          from_elements, to_elements)

        # fix the stored ids and elements
        something_found = False
        for key in self.stored_by_elements.keys():
            if key == from_elements:
                new_key = to_elements
            elif key[:len(from_elements)] == from_elements:
                new_key = to_elements + key[len(from_elements):]
            else:
                continue

            # fix the id/elements
            something_found = True
            stored_ids = self.stored_by_elements.pop(key)
            self.stored_by_elements.setdefault(new_key, []).extend(stored_ids)
            for stored_id in stored_ids:
                deferred, old_elements, logger = self.stored_by_id[stored_id]
                self.stored_by_id[stored_id] = deferred, new_key, logger

        # nothing to fix, really
        if not something_found:
            return

        # get the node to be moved around
        branch = []
        desc = self.root
        for element in from_elements[:-1]:
            branch.append((desc, element))
            node = desc['children_nodes'][element]
            desc = node
        node_to_move = desc['children_nodes'].pop(from_elements[-1])

        # backtrack to clean the branch
        node = desc
        while branch:
            if node['node_deferreds'] or node['children_nodes']:
                # node is not empty, done cleaning the branch!
                break

            # node is empty! remove it
            node, element = branch.pop()
            del node['children_nodes'][element]

        # keep here every node and its child element, to backtrack to add
        # children deferreds in the branch
        branch = []

        # get the final parent of the new moved node
        node = self.root
        for pos, element in enumerate(to_elements[:-1]):
            # get previous child or create a new one just empty, not using
            # setdefault to avoid creating structures if not needed
            children_nodes = node['children_nodes']
            if element in children_nodes:
                node = children_nodes[element]
            else:
                node = dict(node_deferreds=set(),
                            children_nodes={},
                            children_deferreds={})
                children_nodes[element] = node
            branch.append(node)

        node['children_nodes'][to_elements[-1]] = node_to_move

        # fix the children deferreds after the movement
        all_children_deferreds = (node_to_move['node_deferreds'] |
                                  node_to_move['children_deferreds'])
        for node in branch[::-1]:
            node['children_deferreds'] = set(all_children_deferreds)
            all_children_deferreds.update(node['node_deferreds'])


class NamedTemporaryFile(object):
    """Like tempfile.NamedTemporaryFile, but working in 2.5.

    Also WRT the delete argument. Actually, one of these
    NamedTemporaryFile()s is the same as a
    tempfile.NamedTemporaryFile(delete=False) from 2.6.

    Or so the theory goes.

    """

    def __init__(self):
        fileno, self.name = tempfile.mkstemp()

        # build a file object from the descriptor; note that this will *not*
        # create a new file descriptor at the OS level
        self._fh = os.fdopen(fileno, 'w+b')

    def __getattr__(self, attr):
        """Proxy everything else (other than .name) on to self._fh."""
        return getattr(self._fh, attr)


def sanitize_message(action, message):
    """Remove bytes and magic hash, return arguments to log()."""
    if message.type == protocol_pb2.Message.BYTES:
        return ('start - %s: id: %s, type: BYTES', action, message.id)
    elif message.type == protocol_pb2.Message.PUT_CONTENT:
        lines = [line for line in str(message).split("\n")
                 if not line.strip().startswith("magic_hash:")]
        return ('start - %s: %s', action, " ".join(lines))
    else:
        return ('start - %s: %s', action, str(message).replace("\n", " "))


class LoggingStorageClient(ThrottlingStorageClient):
    """A subclass of StorageClient that logs.

    Specifically, it adds logging to processMessage and sendMessage.
    """

    def __init__(self):
        ThrottlingStorageClient.__init__(self)
        self.log = logging.getLogger('ubuntuone.SyncDaemon.StorageClient')
        # configure the handler level to be < than DEBUG
        self.log_trace = partial(self.log.log, TRACE)

    def log_message(self, action, message):
        """Log the messages in the trace log."""
        if self.log.isEnabledFor(TRACE):
            self.log_trace(*sanitize_message(action, message))

    def processMessage(self, message):
        """Wrapper that logs the message and result."""
        self.log_message('processMessage', message)
        if message.id in self.requests:
            req = self.requests[message.id]
            req.deferred.addCallbacks(self.log_success, self.log_error)
        result = ThrottlingStorageClient.processMessage(self, message)
        self.log_trace('end - processMessage: id: %s - result: %s',
                       message.id, result)
        return result

    def log_error(self, failure):
        """Logging errback for requests."""
        self.log_trace('request error: %s', failure)
        return failure

    def log_success(self, result):
        """Logging callback for requests."""
        self.log_trace('request finished: %s', result)
        if getattr(result, '__dict__', None):
            self.log_trace('result.__dict__: %s', result.__dict__)
        return result

    def sendMessage(self, message):
        """Wrapper that logs the message and result."""
        # don't log the full message if it's of type BYTES
        self.log_message('sendMessage', message)
        result = ThrottlingStorageClient.sendMessage(self, message)
        self.log_trace('end - sendMessage: id: %s', message.id)
        return result


class PingManager(object):
    """Handle the ping/pong with the server."""

    _ping_delay = 600  # 10 minutes
    _timeout_delay = 180  # 3 minutes

    def __init__(self, client):
        self.client = client
        self._loop = task.LoopingCall(self._do_ping)
        self._loop.start(self._ping_delay, now=False)
        self._timeout_call = None
        self._running = True

    @defer.inlineCallbacks
    def _do_ping(self):
        """Ping the server just to use the network."""
        self.client.log.trace("Sending ping")
        self._timeout_call = reactor.callLater(self._timeout_delay,
                                               self._disconnect)
        req = yield self.client.ping()
        self.client.log.debug("Ping! rtt: %.3f segs", req.rtt)
        self._timeout_call.cancel()

    def _disconnect(self):
        """Never got the pong, disconnect."""
        self.stop()
        self.client.log.info("No Pong response, disconnecting the client")
        self.client.transport.loseConnection()

    def _stop(self):
        """Really stop all calls."""
        self._loop.stop()
        if self._timeout_call is not None and self._timeout_call.active():
            self._timeout_call.cancel()

    def stop(self):
        """Stop all the calls if still running."""
        if self._running:
            self._running = False
            self._stop()


class ActionQueueProtocol(LoggingStorageClient):
    """This is the Action Queue version of the StorageClient protocol."""

    factory = None

    def __init__(self):
        LoggingStorageClient.__init__(self)
        user_config = config.get_user_config()
        self.max_payload_size = user_config.get_max_payload_size()
        self.ping_manager = None

    def connectionMade(self):
        """A new connection was made."""
        self.log.info('Connection made.')
        LoggingStorageClient.connectionMade(self)
        self.factory.event_queue.push('SYS_CONNECTION_MADE')
        if self.ping_manager is not None:
            self.ping_manager.stop()
        self.ping_manager = PingManager(self)

    def connectionLost(self, reason):
        """The connection was lost."""
        self.log.info('Connection lost, reason: %s.', reason)
        if self.ping_manager is not None:
            self.ping_manager.stop()
            self.ping_manager = None
        LoggingStorageClient.connectionLost(self, reason)


class ZipQueue(object):
    """A queue of files to be compressed for upload.

    Parts of this were shamelessly copied from
    twisted.internet.defer.DeferredSemaphore.

    See bug #373984

    """

    def __init__(self):
        self.waiting = deque()
        self.tokens = self.limit = 10

    def acquire(self):
        """Return a deferred which fires on token acquisition."""
        assert self.tokens >= 0, "Tokens should never be negative"
        d = defer.Deferred()
        if not self.tokens:
            self.waiting.append(d)
        else:
            self.tokens = self.tokens - 1
            d.callback(self)
        return d

    def release(self):
        """Release the token.

        Should be called by whoever did the acquire() when the shared
        resource is free.
        """
        assert self.tokens < self.limit, "Too many tokens!"
        self.tokens = self.tokens + 1
        if self.waiting:
            # someone is waiting to acquire token
            self.tokens = self.tokens - 1
            d = self.waiting.popleft()
            d.callback(self)

    def _compress(self, deferred, upload, fileobj):
        """Compression background task.

        Here we also calculate other need values, like magic hash, to make
        the most of the file reading.
        """
        filename = getattr(fileobj, 'name', '<?>')
        tempfile = None
        failed = False

        try:
            if upload.cancelled:
                # avoid compression if command already cancelled
                return
            upload.log.debug('compressing: %r', filename)
            # we need to compress the file completely to figure out its
            # compressed size. So streaming is out :(
            tempfile = NamedTemporaryFile()
            zipper = zlib.compressobj()
            magic_hasher = content_hash.magic_hash_factory()
            while not upload.cancelled:
                data = fileobj.read(4096)
                if not data:
                    tempfile.write(zipper.flush())
                    # no flush/sync because we don't need this to persist
                    # on disk; if the machine goes down, we'll lose it
                    # anyway (being in /tmp and all)
                    break
                tempfile.write(zipper.compress(data))
                magic_hasher.update(data)
            # ensure that the contents are phisically in the file, some
            # operating systems will not ensure this, even in the same process
            tempfile.flush()
            upload.deflated_size = tempfile.tell()

            upload.magic_hash = magic_hasher.content_hash()
        except Exception as e:
            failed = True
            if tempfile is not None:
                tempfile.close()
                remove_file(tempfile.name)
            reactor.callFromThread(deferred.errback, e)
        finally:
            # avoid triggering the deferred if already failed!
            if not failed:
                upload.tempfile = tempfile
                reactor.callFromThread(deferred.callback, True)

    @defer.inlineCallbacks
    def zip(self, upload, fileobj_factory):
        """Acquire, do the compression in a thread, release."""
        deferred = defer.Deferred()

        yield self.acquire()
        try:
            try:
                fileobj = fileobj_factory()
            except StandardError as e:
                # maybe the user deleted the file before we got to upload it
                upload.log.warn("Unable to build fileobj (%s: '%s') so "
                                "cancelling the upload.", type(e), e)
                upload.cancel()
                return

            reactor.callInThread(self._compress, deferred, upload, fileobj)
        finally:
            self.release()

        # let's wait _compress to finish
        try:
            yield deferred
        finally:
            fileobj.close()


class RequestQueue(object):
    """Pool of commands being run."""

    def __init__(self, action_queue):
        self.action_queue = action_queue
        self.waiting = []
        self.hashed_waiting = {}
        self.active = False
        self.active_deferred = defer.Deferred()

        # transfers semaphore
        user_config = config.get_user_config()
        simult_transfers = user_config.get_simult_transfers()
        self.transfers_semaphore = defer.DeferredSemaphore(simult_transfers)

    def __len__(self):
        """Return the length of the waiting queue."""
        return len(self.waiting)

    def queue(self, command):
        """Add a command to the queue."""
        # check if the queue and head was empty before this command
        first_added = not self.waiting

        # puts the command where it was asked for
        self.waiting.append(command)
        self.action_queue.event_queue.push('SYS_QUEUE_ADDED',
                                           command=command)

        # add to the hashed waiting if it needs to be unique
        if command.uniqueness is not None:
            self.hashed_waiting[command.uniqueness] = command

        # if nothing running, and this command is the first in the
        # queue, send the signal
        if first_added:
            self.action_queue.event_queue.push('SYS_QUEUE_WAITING')

    def unqueue(self, command):
        """Unqueue a command."""
        self.waiting.remove(command)
        self.hashed_waiting.pop(command.uniqueness, None)
        self.action_queue.event_queue.push('SYS_QUEUE_REMOVED',
                                           command=command)
        if len(self.waiting) == 0:
            self.action_queue.event_queue.push('SYS_QUEUE_DONE')

    def run(self):
        """Go active and run all commands in the queue."""
        self.active = True
        self.active_deferred.callback(True)

    def stop(self):
        """Stop the pool and cleanup the running commands."""
        self.active = False
        self.active_deferred = defer.Deferred()
        for command in self.waiting:
            command.pause()

    def node_is_queued(self, cmdclass, share_id, node_id):
        """True if a command is queued for that node."""
        uniqueness = (cmdclass.__name__, share_id, node_id)
        return uniqueness in self.hashed_waiting

    def remove(self, command):
        """Remove a command from 'waiting', if there.

        This is a handy method for those commands with uniqueness, it should
        not be called from other commands.
        """
        if command.uniqueness in self.hashed_waiting:
            del self.hashed_waiting[command.uniqueness]
            self.waiting.remove(command)


class DeferredMap(object):
    """A mapping of deferred values.

    Return deferreds for a key that are fired (succesfully or not) later.
    """

    def __init__(self):
        self.waiting = defaultdict(list)

    def get(self, key):
        """Return a deferred for the given key."""
        d = defer.Deferred()
        self.waiting[key].append(d)
        return d

    def set(self, key, value):
        """We've got the value for a key!

        If it was waited, fire the waiting deferreds and remove the key.
        """
        if key in self.waiting:
            deferreds = self.waiting.pop(key)
            for d in deferreds:
                d.callback(value)

    def err(self, key, failure):
        """Something went terribly wrong in the process of getting a value.

        Break the news to the waiting deferreds and remove the key.
        """
        if key in self.waiting:
            deferreds = self.waiting.pop(key)
            for d in deferreds:
                d.errback(failure)


class ConditionsLocker(object):
    """Structure to hold commands waiting because of conditions.

    On each call to lock it will return a deferred for the received
    command. When check_conditions is called, it will trigger each
    command deferred if it's runnable.
    """
    def __init__(self):
        self.locked = {}

    def get_lock(self, command):
        """Return the deferred that will lock the command."""
        if command not in self.locked:
            self.locked[command] = defer.Deferred()
        return self.locked[command]

    def check_conditions(self):
        """Check for all commands' conditions, and release accordingly."""
        for cmd in self.locked.keys():
            if cmd.is_runnable:
                deferred = self.locked.pop(cmd)
                deferred.callback(True)

    def cancel_command(self, command):
        """The command was cancelled, if lock hold, release it and clean."""
        if command in self.locked:
            deferred = self.locked.pop(command)
            deferred.callback(True)


class UploadProgressWrapper(object):
    """A wrapper around the file-like object used for Uploads.

    It adjusts automatically the transfer variables in the command.

    fd is the file-like object used for uploads.
    """

    __slots__ = ('fd', 'command')

    def __init__(self, fd, command):
        self.fd = fd
        self.command = command
        self.command.n_bytes_written = 0
        self.command.n_bytes_written_last = 0

    def read(self, size=None):
        """Read at most size bytes from the file-like object.

        Keep track of the number of bytes that have been read.
        """
        data = self.fd.read(size)
        self.command.n_bytes_written += len(data)
        self.command.progress_hook()
        return data

    def seek(self, offset):
        """Move to new file position."""
        self.fd.seek(offset)
        self.command.n_bytes_written = offset
        self.command.n_bytes_written_last = offset

    def __getattr__(self, attr):
        """Proxy all the rest."""
        return getattr(self.fd, attr)


class ActionQueue(ThrottlingStorageClientFactory, object):
    """The ActionQueue itself."""

    implements(IActionQueue)
    protocol = ActionQueueProtocol

    def __init__(self, event_queue, main, connection_info,
                 read_limit=None, write_limit=None, throttling_enabled=False,
                 connection_timeout=30):
        ThrottlingStorageClientFactory.__init__(
            self, read_limit=read_limit, write_limit=write_limit,
            throttling_enabled=throttling_enabled)
        self.event_queue = event_queue
        self.main = main
        self.connection_info = itertools.cycle(connection_info)

        self.connection_timeout = connection_timeout
        self.credentials = {}

        self.client = None  # an instance of self.protocol

        # is a twisted.internet.tcp/ssl.Connector instance
        self.connector = None  # created on reactor.connectTCP/SSL
        # we need to track down if a connection is in progress
        # to avoid double connections
        self.connect_in_progress = False

        self.queue = RequestQueue(self)
        self.pathlock = PathLockingTree()
        self.uuid_map = DeferredMap()
        self.zip_queue = ZipQueue()
        self.conditions_locker = ConditionsLocker()
        self.disk_queue = offload_queue.OffloadQueue()

        self.estimated_free_space = {}
        event_queue.subscribe(self)

        # data for the offloaded queue
        user_config = config.get_user_config()
        self.memory_pool_limit = user_config.get_memory_pool_limit()
        self.commands = dict(
            (x, y) for x, y in globals().iteritems()
            if inspect.isclass(y) and issubclass(y, ActionQueueCommand))

    def check_conditions(self):
        """Check conditions in the locker, to release all the waiting ops."""
        self.conditions_locker.check_conditions()

    def have_sufficient_space_for_upload(self, share_id, upload_size):
        """Returns True if we have sufficient space for the given upload."""
        free = self.main.vm.get_free_space(share_id)
        enough = free is None or free >= upload_size
        if not enough:
            logger.info("Not enough space for upload %s bytes (available: %s)",
                        upload_size, free)
            self.event_queue.push('SYS_QUOTA_EXCEEDED', volume_id=share_id,
                                  free_bytes=free)

        return enough

    def handle_SYS_USER_CONNECT(self, access_token):
        """Stow the credentials for later use."""
        self.credentials = dict(username=access_token['username'],
                                password=access_token['password'])

    def _cleanup_connection_state(self, *args):
        """Reset connection state."""
        self.client = None
        self.connector = None
        self.connect_in_progress = False

    def _share_change_callback(self, info):
        """Called by the client when notified that a share changed."""
        self.event_queue.push('SV_SHARE_CHANGED', info=info)

    def _share_delete_callback(self, share_id):
        """Called by the client when notified that a share was deleted."""
        self.event_queue.push('SV_SHARE_DELETED', share_id=share_id)

    def _share_answer_callback(self, share_id, answer):
        """Called by the client when it gets a share answer notification."""
        self.event_queue.push('SV_SHARE_ANSWERED',
                              share_id=str(share_id), answer=answer)

    def _free_space_callback(self, share_id, free_bytes):
        """Called by the client when it gets a free space notification."""
        self.event_queue.push('SV_FREE_SPACE',
                              share_id=str(share_id), free_bytes=free_bytes)

    def _account_info_callback(self, account_info):
        """Called by the client when it gets an account info notification."""
        self.event_queue.push('SV_ACCOUNT_CHANGED',
                              account_info=account_info)

    def _volume_created_callback(self, volume):
        """Process new volumes."""
        self.event_queue.push('SV_VOLUME_CREATED', volume=volume)

    def _volume_deleted_callback(self, volume_id):
        """Process volume deletion."""
        self.event_queue.push('SV_VOLUME_DELETED', volume_id=volume_id)

    def _volume_new_generation_callback(self, volume_id, generation):
        """Process new volumes."""
        self.event_queue.push('SV_VOLUME_NEW_GENERATION',
                              volume_id=volume_id, generation=generation)

    def _get_tunnel_runner(self, host, port):
        """Build the tunnel runner."""
        return tunnel_runner.TunnelRunner(host, port)

    @defer.inlineCallbacks
    def _make_connection(self):
        """Do the real connect call."""
        connection_info = self.connection_info.next()
        logger.info("Attempting connection to %s", connection_info)
        host = connection_info['host']
        port = connection_info['port']
        tunnelrunner = self._get_tunnel_runner(host, port)
        client = yield tunnelrunner.get_client()
        if connection_info['use_ssl']:
            ssl_context = get_ssl_context(
                connection_info['disable_ssl_verify'], host)
            self.connector = client.connectSSL(
                host, port, factory=self, contextFactory=ssl_context,
                timeout=self.connection_timeout)
        else:
            self.connector = client.connectTCP(
                host, port, self, timeout=self.connection_timeout)

    def connect(self):
        """Start the circus going."""
        # avoid multiple connections
        if self.connect_in_progress:
            msg = "Discarding new connection attempt, there is a connector!"
            logger.warning(msg)
            return

        self.connect_in_progress = True
        self._make_connection()

    def buildProtocol(self, addr):
        """Build the client and store it. Connect callbacks."""
        # XXX: Very Important Note: within the storageprotocol project,
        # ThrottlingStorageClient.connectionMade sets self.factory.client
        # to self *if* self.factory.client is not None.
        # Since buildProcotol is called before connectionMade, the latter
        # does nothing (safely).
        self.client = ThrottlingStorageClientFactory.buildProtocol(self, addr)

        self.client.set_share_change_callback(self._share_change_callback)
        self.client.set_share_answer_callback(self._share_answer_callback)
        self.client.set_free_space_callback(self._free_space_callback)
        self.client.set_account_info_callback(self._account_info_callback)
        # volumes
        self.client.set_volume_created_callback(self._volume_created_callback)
        self.client.set_volume_deleted_callback(self._volume_deleted_callback)
        self.client.set_volume_new_generation_callback(
            self._volume_new_generation_callback)

        logger.info('Connection made.')
        return self.client

    def startedConnecting(self, connector):
        """Called when a connection has been started."""
        logger.info('Connection started to host %s, port %s.',
                    connector.host, connector.port)

    def disconnect(self):
        """Disconnect the client.

        This shouldn't be called if the client is already disconnected.

        """
        if self.connector is not None:
            self.connector.disconnect()
            self._cleanup_connection_state()
        else:
            msg = 'disconnect() was called when the connector was None.'
            logger.warning(msg)

        logger.debug("Disconnected.")

    def clientConnectionFailed(self, connector, reason):
        """Called when the connect() call fails."""
        self._cleanup_connection_state()
        self.event_queue.push('SYS_CONNECTION_FAILED')
        logger.info('Connection failed: %s', reason.getErrorMessage())

    def clientConnectionLost(self, connector, reason):
        """The client connection went down."""
        self._cleanup_connection_state()
        self.event_queue.push('SYS_CONNECTION_LOST')
        logger.warning('Connection lost: %s', reason.getErrorMessage())

    @defer.inlineCallbacks
    def _send_request_and_handle_errors(self, request, request_error,
                                        event_error, event_ok,
                                        handle_exception=True,
                                        args=(), kwargs={}):
        """Send 'request' to the server, using params 'args' and 'kwargs'.

        Expect 'request_error' as valid error, and push 'event_error' in that
        case. Do generic error handling for the rest of the protocol errors.

        """
        # if the client changes while we're waiting, this message is
        # old news and should be discarded (the message would
        # typically be a failure: timeout or disconnect). So keep the
        # original client around for comparison.
        client = self.client
        req_name = request.__name__
        failure = None
        event = None
        result = None
        try:
            try:
                result = yield request(*args, **kwargs)
            finally:
                # common handling for all cases
                if client is not self.client:
                    msg = "Client mismatch while processing the request '%s'" \
                          ", client (%r) is not self.client (%r)."
                    logger.warning(msg, req_name, client, self.client)
                    return
        except request_error, failure:
            event = event_error
            self.event_queue.push(event_error, error=str(failure))
        except (twisted_errors.ConnectionLost,
                twisted_errors.ConnectionDone,
                OpenSSL.SSL.Error), failure:
            # connection ended, just don't do anything: the SYS_CONNECTION_ETC
            # will be sent by normal client/protocol mechanisms, and logging
            # will be done later in this function.
            pass
        except protocol_errors.AuthenticationRequiredError, failure:
            # we need to separate this case from the rest because an
            # AuthenticationRequiredError is an StorageRequestError,
            # and we treat it differently.
            event = 'SYS_UNKNOWN_ERROR'
            self.event_queue.push(event)
        except protocol_errors.StorageRequestError, failure:
            event = 'SYS_SERVER_ERROR'
            self.event_queue.push(event, error=str(failure))
        except Exception, failure:
            if handle_exception:
                event = 'SYS_UNKNOWN_ERROR'
                self.event_queue.push(event)
            else:
                raise
        else:
            logger.info("The request '%s' finished OK.", req_name)
            if event_ok is not None:
                self.event_queue.push(event_ok)

        if failure is not None:
            if event is None:
                logger.info("The request '%s' failed with the error: %s",
                            req_name, failure)
            else:
                logger.info("The request '%s' failed with the error: %s "
                            "and was handled with the event: %s",
                            req_name, failure, event)
        else:
            defer.returnValue(result)

    def check_version(self):
        """Check if the client protocol version matches that of the server."""
        check_version_d = self._send_request_and_handle_errors(
            request=self.client.protocol_version,
            request_error=protocol_errors.UnsupportedVersionError,
            event_error='SYS_PROTOCOL_VERSION_ERROR',
            event_ok='SYS_PROTOCOL_VERSION_OK')
        return check_version_d

    @defer.inlineCallbacks
    def set_capabilities(self, caps):
        """Set the capabilities with the server."""

        @defer.inlineCallbacks
        def caps_raising_if_not_accepted(capability_method, caps, msg):
            """Discuss capabilities with the server."""
            client_caps = getattr(self.client, capability_method)
            req = yield client_caps(caps)
            if not req.accepted:
                raise StandardError(msg)
            defer.returnValue(req)

        error_msg = "The server doesn't have the requested capabilities"
        query_caps_d = self._send_request_and_handle_errors(
            request=caps_raising_if_not_accepted,
            request_error=StandardError,
            event_error='SYS_SET_CAPABILITIES_ERROR',
            event_ok=None,
            args=('query_caps', caps, error_msg))
        req = yield query_caps_d

        # req can be None if set capabilities failed, error is handled by
        # _send_request_and_handle_errors
        if not req:
            return

        error_msg = "The server denied setting '%s' capabilities" % caps
        set_caps_d = self._send_request_and_handle_errors(
            request=caps_raising_if_not_accepted,
            request_error=StandardError,
            event_error='SYS_SET_CAPABILITIES_ERROR',
            event_ok='SYS_SET_CAPABILITIES_OK',
            args=('set_caps', caps, error_msg))
        yield set_caps_d

    @defer.inlineCallbacks
    def authenticate(self):
        """Authenticate against the server using stored credentials."""
        metadata = {'version': clientdefs.VERSION,
                    'platform': platform}
        username = self.credentials.get('username')
        password = self.credentials.get('password')
        authenticate_d = self._send_request_and_handle_errors(
            request=self.client.simple_authenticate,
            request_error=protocol_errors.AuthenticationFailedError,
            event_error='SYS_AUTH_ERROR', event_ok='SYS_AUTH_OK',
            args=(username, password, metadata))
        req = yield authenticate_d

        # req can be None if the auth failed, but it's handled by
        # _send_request_and_handle_errors
        if req:
            # log the session_id
            logger.note('Session ID: %r', str(req.session_id))

    @defer.inlineCallbacks
    def query_volumes(self):
        """Get the list of volumes.

        This method will *not* queue a command, the request will be
        executed right away.
        """
        result = yield self._send_request_and_handle_errors(
            request=self.client.list_volumes,
            request_error=None, event_error=None,
            event_ok=None, handle_exception=False)
        defer.returnValue(result.volumes)

    @defer.inlineCallbacks
    def _really_execute(self, command_class, *args, **kwargs):
        """Actually queue and execute the operation."""
        cmd = command_class(self.queue, *args, **kwargs)

        # queue if should, otherwise all is done
        if cmd.should_be_queued():
            cmd.log.debug('queueing')
            self.queue.queue(cmd)
            yield cmd.go()
            self.queue.unqueue(cmd)

    @defer.inlineCallbacks
    def execute(self, command_class, *args, **kwargs):
        """Execute a command only if there's room in memory to handle it."""
        if len(self.queue) >= self.memory_pool_limit:
            # already in the limit, can't go further as we don't have
            # more room in memory, store it in the offloaded queue
            logger.debug('offload push: %s %s %s',
                         command_class.__name__, args, kwargs)
            self.disk_queue.push((command_class.__name__, args, kwargs))
            return

        # normal case, just instantiate the command and let it go
        yield self._really_execute(command_class, *args, **kwargs)

        # command just finished... check to queue more offloaded ones
        while (len(self.queue) < self.memory_pool_limit and
               len(self.disk_queue) > 0):
            command_class_name, args, kwargs = self.disk_queue.pop()
            logger.debug('offload pop: %s %s %s',
                         command_class_name, args, kwargs)
            command_class = self.commands[command_class_name]
            yield self._really_execute(command_class, *args, **kwargs)

    def make_file(self, share_id, parent_id, name, marker, mdid):
        """See .interfaces.IMetaQueue."""
        self.execute(MakeFile, share_id, parent_id, name, marker, mdid)

    def make_dir(self, share_id, parent_id, name, marker, mdid):
        """See .interfaces.IMetaQueue."""
        self.execute(MakeDir, share_id, parent_id, name, marker, mdid)

    def move(self, share_id, node_id, old_parent_id, new_parent_id,
             new_name, path_from, path_to):
        """See .interfaces.IMetaQueue."""
        self.execute(Move, share_id, node_id, old_parent_id,
                     new_parent_id, new_name, path_from, path_to)

    def unlink(self, share_id, parent_id, node_id, path, is_dir):
        """See .interfaces.IMetaQueue."""
        self.execute(Unlink, share_id, parent_id, node_id, path, is_dir)

    def inquire_free_space(self, share_id):
        """See .interfaces.IMetaQueue."""
        self.execute(FreeSpaceInquiry, share_id)

    def inquire_account_info(self):
        """See .interfaces.IMetaQueue."""
        self.execute(AccountInquiry)

    def list_shares(self):
        """See .interfaces.IMetaQueue."""
        self.execute(ListShares)

    def answer_share(self, share_id, answer):
        """See .interfaces.IMetaQueue."""
        self.execute(AnswerShare, share_id, answer)

    def create_share(self, node_id, share_to, name, access_level,
                     marker, path):
        """See .interfaces.IMetaQueue."""
        self.execute(CreateShare, node_id, share_to, name,
                     access_level, marker, path)

    def delete_share(self, share_id):
        """See .interfaces.IMetaQueue."""
        self.execute(DeleteShare, share_id)

    def create_udf(self, path, name, marker):
        """See .interfaces.IMetaQueue."""
        self.execute(CreateUDF, path, name, marker)

    def list_volumes(self):
        """See .interfaces.IMetaQueue."""
        self.execute(ListVolumes)

    def delete_volume(self, volume_id, path):
        """See .interfaces.IMetaQueue."""
        self.execute(DeleteVolume, volume_id, path)

    def change_public_access(self, share_id, node_id, is_public):
        """See .interfaces.IMetaQueue."""
        self.execute(ChangePublicAccess, share_id, node_id, is_public)

    def get_public_files(self):
        """See .interfaces.IMetaQueue."""
        self.execute(GetPublicFiles)

    def download(self, share_id, node_id, server_hash, mdid):
        """See .interfaces.IContentQueue.download."""
        self.execute(Download, share_id, node_id, server_hash, mdid)

    def upload(self, share_id, node_id, previous_hash, hash, crc32,
               size, mdid, upload_id=None):
        """See .interfaces.IContentQueue."""
        self.execute(Upload, share_id, node_id, previous_hash, hash, crc32,
                     size, mdid, upload_id=upload_id)

    def _cancel_op(self, share_id, node_id, cmdclass):
        """Generalized form of cancel_upload and cancel_download."""
        logstr = "cancel_" + cmdclass.__name__.lower()
        log = mklog(logger, logstr, share_id, node_id)
        uniqueness = (cmdclass.__name__, share_id, node_id)
        if uniqueness in self.queue.hashed_waiting:
            queued_command = self.queue.hashed_waiting[uniqueness]
            log.debug('external cancel attempt')
            queued_command.cancel()

    def cancel_upload(self, share_id, node_id):
        """See .interfaces.IContentQueue."""
        self._cancel_op(share_id, node_id, Upload)

    def cancel_download(self, share_id, node_id):
        """See .interfaces.IContentQueue."""
        self._cancel_op(share_id, node_id, Download)

    def node_is_with_queued_move(self, share_id, node_id):
        """True if a Move is queued for that node."""
        return self.queue.node_is_queued(Move, share_id, node_id)

    def get_delta(self, volume_id, generation):
        """See .interfaces.IMetaQueue."""
        self.execute(GetDelta, volume_id, generation)

    def rescan_from_scratch(self, volume_id):
        """See .interfaces.IMetaQueue."""
        self.execute(GetDeltaFromScratch, volume_id)

    def handle_SYS_ROOT_RECEIVED(self, root_id, mdid):
        """Demark the root node_id."""
        self.uuid_map.set(mdid, root_id)


class ActionQueueCommand(object):
    """Base of all the action queue commands."""

    # the info used in the protocol errors is hidden, but very useful!
    suppressed_error_messages = (
        [x for x in protocol_errors._error_mapping.values()
         if x is not protocol_errors.InternalError] +
        [protocol_errors.RequestCancelledError,
         twisted_errors.ConnectionDone, twisted_errors.ConnectionLost])

    retryable_errors = (
        protocol_errors.TryAgainError,
        protocol_errors.QuotaExceededError,
        twisted_errors.ConnectionDone,
        twisted_errors.ConnectionLost,
    )

    logged_attrs = ('running',)
    possible_markers = ()
    is_runnable = True
    uniqueness = None

    __slots__ = ('_queue', 'running', 'pathlock_release', 'pathlock_deferred',
                 'markers_resolved_deferred', 'action_queue', 'cancelled',
                 'running_deferred', 'log')

    def __init__(self, request_queue):
        """Initialize a command instance."""
        self._queue = request_queue
        self.action_queue = request_queue.action_queue
        self.running = False
        self.log = None
        self.markers_resolved_deferred = defer.Deferred()
        self.pathlock_release = None
        self.pathlock_deferred = None
        self.cancelled = False
        self.running_deferred = None

    def to_dict(self):
        """Dump logged attributes to a dict."""
        return dict((n, getattr(self, n, None)) for n in self.logged_attrs)

    def make_logger(self):
        """Create a logger for this object."""
        share_id = getattr(self, "share_id", UNKNOWN)
        node_id = getattr(self, "node_id", None) or \
            getattr(self, "marker", UNKNOWN)
        self.log = mklog(logger, self.__class__.__name__,
                         share_id, node_id, **self.to_dict())

    @defer.inlineCallbacks
    def demark(self):
        """Arrange to have maybe_markers realized."""
        # we need to issue all the DeferredMap.get's right now, to be
        # dereferenced later
        waiting_structure = []
        fsm = self.action_queue.main.fs
        for name in self.possible_markers:
            marker = getattr(self, name)

            # if a marker, get the real value; if not, it's already there, so
            # no action needed
            if IMarker.providedBy(marker):
                # we now it's a mdid, we may already have the marker
                # in the metadata
                try:
                    mdobj = fsm.get_by_mdid(str(marker))
                except KeyError:
                    # node is not longer there, we don't care
                    continue

                if mdobj.node_id is None:
                    msg = "waiting for the real value of %r"
                    d = self.action_queue.uuid_map.get(marker)
                else:
                    msg = "shortcutting the real value of %r"
                    d = defer.succeed(mdobj.node_id)
                self.log.debug(msg, marker)
                waiting_structure.append((name, marker, d))

        # now, we wait for all the dereferencings... if any
        for (name, marker, deferred) in waiting_structure:
            try:
                value = yield deferred
            except Exception as e:
                # on first failure, errback the marker resolved flag, and
                # quit waiting for other deferreds
                self.log.error("failed %r", marker)
                self.markers_resolved_deferred.errback(e)
                break
            else:
                self.log.debug("for %r got value %r", marker, value)
                old_uniqueness = self.uniqueness
                setattr(self, name, value)

                # as the attr changed (been demarked), need to reput itself
                # in the hashed_waiting, if was there before and not cancelled
                if old_uniqueness in self._queue.hashed_waiting:
                    if not self.cancelled:
                        del self._queue.hashed_waiting[old_uniqueness]
                        self._queue.hashed_waiting[self.uniqueness] = self
        else:
            # fire the deferred only if all markers finished ok
            self.markers_resolved_deferred.callback(True)

    def finish(self):
        """The command ended."""
        self.running = False

    def should_be_queued(self):
        """Check if the command should be queued."""
        # create the log
        self.make_logger()
        return self._should_be_queued()

    def _should_be_queued(self):
        """Return True if the command should be queued."""
        return True

    def cleanup(self):
        """Do whatever is needed to clean up from a failure.

        For example, stop producers and others that aren't cleaned up
        appropriately on their own.  Note that this may be called more
        than once.
        """

    def _start(self):
        """Do the specialized pre-run setup."""
        return defer.succeed(None)

    def pause(self):
        """Pause the command."""
        self.log.debug('pausing')
        if self.running_deferred is not None:
            self.running_deferred.interrupt()
        self.cleanup()

    @defer.inlineCallbacks
    def go(self):
        """Execute all the steps for a command."""
        # set up basic marker failure handler and demark
        def f(failure):
            self.log.debug("failing because marker failed: %s", failure)
            self.cancelled = True
            self.cleanup()
            self.handle_failure(failure)
            self.finish()
        self.markers_resolved_deferred.addErrback(f)
        self.demark()

        # acquire the pathlock; note that the pathlock_release may be None
        # if the command didn't need to acquire any pathlock
        self.pathlock_deferred = self._acquire_pathlock()
        self.pathlock_release = yield self.pathlock_deferred
        self.pathlock_deferred = None
        if self.cancelled:
            self.log.debug('command not run because of cancelled')
            if self.pathlock_release is not None:
                self.pathlock_release = self.pathlock_release()
            return

        try:
            yield self.run()
        except Exception, exc:
            self.log.exception("Error running the command: %s "
                               "(traceback follows)", exc)
        finally:
            if self.pathlock_release is not None:
                self.pathlock_release = self.pathlock_release()

    @defer.inlineCallbacks
    def run(self):
        """Run the command."""
        self.log.debug('starting')
        yield self._start()
        self.log.debug('started')

        while True:
            if self.cancelled:
                yield self.markers_resolved_deferred
                self.log.debug('cancelled before trying to run')
                break

            # if queue not active, wait for it and check again
            if not self._queue.active:
                self.log.debug('not running because of inactive queue')
                yield self._queue.active_deferred
                self.log.debug('unblocked: queue active')
                continue

            if not self.is_runnable:
                self.log.debug('not running because of conditions')
                yield self.action_queue.conditions_locker.get_lock(self)
                self.log.debug('unblocked: conditions ok')
                continue

            try:
                yield self.markers_resolved_deferred
                self.log.debug('running')
                self.running = True
                d = self._run()
                self.running_deferred = InterruptibleDeferred(d)
                result = yield self.running_deferred

            except DeferredInterrupted:
                self.running_deferred = None
                continue
            except Exception, exc:
                self.running_deferred = None
                if self.cancelled:
                    self.log.debug('cancelled while running')
                    break
                if exc.__class__ in self.suppressed_error_messages:
                    self.log.warn('failure: %s', exc)
                else:
                    self.log.exception('failure: %s (traceback follows)', exc)
                self.cleanup()

                if exc.__class__ in self.retryable_errors:
                    self.log.debug('retrying')
                    self.handle_retryable(Failure(exc))
                    continue
                else:
                    self.handle_failure(Failure(exc))
            else:
                if self.cancelled:
                    self.log.debug('cancelled while running')
                    break
                self.log.debug('success')
                self.handle_success(result)

            # finish the command
            self.finish()
            return

    def cancel(self):
        """Cancel the command.

        Also cancel the command in the conditions locker.

        Do nothing if already cancelled (as cancellation can come from other
        thread, it can come at any time, so we need to support double
        cancellation safely).

        Return True if the command was really cancelled.
        """
        if self.cancelled:
            return False

        self.cancelled = True
        self.log.debug('cancelled')
        self.action_queue.conditions_locker.cancel_command(self)
        if self.pathlock_deferred is not None:
            self.pathlock_deferred.cancel()
        self.cleanup()
        self.finish()
        return True

    def _get_current_path(self, mdid):
        """Get current path from FSM using the mdid."""
        fsm = self.action_queue.main.fs
        mdobj = fsm.get_by_mdid(self.mdid)
        path = fsm.get_abspath(mdobj.share_id, mdobj.path)
        return path

    def _acquire_pathlock(self):
        """Acquire pathlock; overwrite if needed."""
        return defer.succeed(None)

    def handle_success(self, success):
        """Do anthing that's needed to handle success of the operation."""

    def handle_failure(self, failure):
        """Do anthing that's needed to handle failure of the operation."""

    def handle_retryable(self, failure):
        """Had that failure, but the command will be retried."""

    def __str__(self, str_attrs=None):
        """Return a str representation of the instance."""
        if str_attrs is None:
            str_attrs = self.logged_attrs
        name = self.__class__.__name__
        if len(str_attrs) == 0:
            return name
        attrs = [str(attr) + '=' + str(getattr(self, attr, None) or 'None')
                 for attr in str_attrs]
        return ''.join([name, '(', ', '.join([attr for attr in attrs]), ')'])


class MakeThing(ActionQueueCommand):
    """Base of MakeFile and MakeDir."""

    __slots__ = ('share_id', 'parent_id', 'name', 'marker', 'mdid', 'path')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__
    possible_markers = 'parent_id',

    def __init__(self, request_queue, share_id, parent_id, name, marker, mdid):
        super(MakeThing, self).__init__(request_queue)
        self.share_id = share_id
        self.parent_id = parent_id
        # Unicode boundary! the name is Unicode in protocol and server, but
        # here we use bytes for paths
        self.name = name.decode("utf-8")
        self.marker = marker
        self.mdid = mdid
        self.path = self._get_current_path(mdid)

    def _run(self):
        """Do the actual running."""
        maker = getattr(self.action_queue.client, self.client_method)
        return maker(self.share_id, self.parent_id, self.name)

    def handle_success(self, request):
        """It worked! Push the event."""
        # note that we're not getting the new name from the answer
        # message, if we would get it, we would have another Unicode
        # boundary with it
        d = dict(marker=self.marker, new_id=request.new_id,
                 new_generation=request.new_generation,
                 volume_id=self.share_id)
        self.action_queue.event_queue.push(self.ok_event_name, **d)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push(self.error_event_name,
                                           marker=self.marker,
                                           failure=failure)

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        self.path = self._get_current_path(self.mdid)
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*self.path.split(os.path.sep),
                                on_parent=True, logger=self.log)


class MakeFile(MakeThing):
    """Make a file."""
    __slots__ = ()
    ok_event_name = 'AQ_FILE_NEW_OK'
    error_event_name = 'AQ_FILE_NEW_ERROR'
    client_method = 'make_file'


class MakeDir(MakeThing):
    """Make a directory."""
    __slots__ = ()
    ok_event_name = 'AQ_DIR_NEW_OK'
    error_event_name = 'AQ_DIR_NEW_ERROR'
    client_method = 'make_dir'


class Move(ActionQueueCommand):
    """Move a file or directory."""
    __slots__ = ('share_id', 'node_id', 'old_parent_id',
                 'new_parent_id', 'new_name', 'path_from', 'path_to')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__
    possible_markers = 'node_id', 'old_parent_id', 'new_parent_id'

    def __init__(self, request_queue, share_id, node_id, old_parent_id,
                 new_parent_id, new_name, path_from, path_to):
        super(Move, self).__init__(request_queue)
        self.share_id = share_id
        self.node_id = node_id
        self.old_parent_id = old_parent_id
        self.new_parent_id = new_parent_id
        # Unicode boundary! the name is Unicode in protocol and server, but
        # here we use bytes for paths
        self.new_name = new_name.decode("utf-8")

        # Move stores the paths and uses them to acquire the pathlock
        # later, as it is responsible of the moves and nobody else
        # will rename the files but it
        self.path_from = path_from
        self.path_to = path_to

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return (self.__class__.__name__, self.share_id, self.node_id)

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.move(self.share_id,
                                             self.node_id,
                                             self.new_parent_id,
                                             self.new_name)

    def handle_success(self, request):
        """It worked! Push the event."""
        d = dict(share_id=self.share_id, node_id=self.node_id,
                 new_generation=request.new_generation)
        self.action_queue.event_queue.push('AQ_MOVE_OK', **d)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push('AQ_MOVE_ERROR',
                                           error=failure.getErrorMessage(),
                                           share_id=self.share_id,
                                           node_id=self.node_id,
                                           old_parent_id=self.old_parent_id,
                                           new_parent_id=self.new_parent_id,
                                           new_name=self.new_name)

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        pathlock = self.action_queue.pathlock
        parts_from = self.path_from.split(os.path.sep)
        parts_to = self.path_to.split(os.path.sep)

        def multiple_release(list_result):
            """Multiple release.

            Get the result of both deferred and return one function
            to call both.
            """
            release1 = list_result[0][1]
            release2 = list_result[1][1]

            def release_them():
                """Efectively release them."""
                release1()
                release2()
            return release_them

        # get both locks and merge them
        d1 = pathlock.acquire(*parts_from, on_parent=True,
                              on_children=True, logger=self.log)
        d2 = pathlock.acquire(*parts_to, on_parent=True, logger=self.log)
        dl = defer.DeferredList([d1, d2])
        dl.addCallback(multiple_release)
        return dl


class Unlink(ActionQueueCommand):
    """Unlink a file or dir."""
    __slots__ = ('share_id', 'node_id', 'parent_id', 'path', 'is_dir')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__
    possible_markers = 'node_id', 'parent_id'

    def __init__(self, request_queue, share_id, parent_id, node_id, path,
                 is_dir):
        super(Unlink, self).__init__(request_queue)
        self.share_id = share_id
        self.node_id = node_id
        self.parent_id = parent_id
        # Unlink stores the path here for the pathlock as it will not change
        # in the future (nobody will rename a deleted file)
        self.path = path
        self.is_dir = is_dir

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.unlink(self.share_id, self.node_id)

    def handle_success(self, request):
        """It worked! Push the event."""
        d = dict(share_id=self.share_id, parent_id=self.parent_id,
                 node_id=self.node_id, new_generation=request.new_generation,
                 was_dir=self.is_dir, old_path=self.path)
        self.action_queue.event_queue.push('AQ_UNLINK_OK', **d)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push('AQ_UNLINK_ERROR',
                                           error=failure.getErrorMessage(),
                                           share_id=self.share_id,
                                           parent_id=self.parent_id,
                                           node_id=self.node_id)

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*self.path.split(os.path.sep), on_parent=True,
                                on_children=True, logger=self.log)


class ListShares(ActionQueueCommand):
    """List shares shared to me."""
    __slots__ = ()

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return self.__class__.__name__

    def _should_be_queued(self):
        """If other ListShares is queued, don't queue this one."""
        return self.uniqueness not in self._queue.hashed_waiting

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.list_shares()

    def handle_success(self, success):
        """It worked! Push the event."""
        self.action_queue.event_queue.push('AQ_SHARES_LIST',
                                           shares_list=success)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push('AQ_LIST_SHARES_ERROR',
                                           error=failure.getErrorMessage())


class FreeSpaceInquiry(ActionQueueCommand):
    """Inquire about free space."""

    __slots__ = ()

    def __init__(self, request_queue, share_id):
        """Initialize the instance."""
        super(FreeSpaceInquiry, self).__init__(request_queue)
        self.share_id = share_id

    def _run(self):
        """Do the query."""
        return self.action_queue.client.get_free_space(self.share_id)

    def handle_success(self, success):
        """Publish the free space information."""
        self.action_queue.event_queue.push('SV_FREE_SPACE',
                                           share_id=success.share_id,
                                           free_bytes=success.free_bytes)

    def handle_failure(self, failure):
        """Publish the error."""
        self.action_queue.event_queue.push('AQ_FREE_SPACE_ERROR',
                                           error=failure.getErrorMessage())


class AccountInquiry(ActionQueueCommand):
    """Query user account information."""

    __slots__ = ()

    def _run(self):
        """Make the actual request."""
        return self.action_queue.client.get_account_info()

    def handle_success(self, success):
        """Publish the account information to the event queue."""
        self.action_queue.event_queue.push('SV_ACCOUNT_CHANGED',
                                           account_info=success)

    def handle_failure(self, failure):
        """Publish the error."""
        self.action_queue.event_queue.push('AQ_ACCOUNT_ERROR',
                                           error=failure.getErrorMessage())


class AnswerShare(ActionQueueCommand):
    """Answer a share offer."""

    __slots__ = ('share_id', 'answer')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, share_id, answer):
        super(AnswerShare, self).__init__(request_queue)
        self.share_id = share_id
        self.answer = answer

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.accept_share(self.share_id,
                                                     self.answer)

    def handle_success(self, success):
        """It worked! Push the event."""
        self.action_queue.event_queue.push('AQ_ANSWER_SHARE_OK',
                                           share_id=self.share_id,
                                           answer=self.answer)

    def handle_failure(self, failure):
        """It didn't work. Push the event."""
        self.action_queue.event_queue.push('AQ_ANSWER_SHARE_ERROR',
                                           share_id=self.share_id,
                                           answer=self.answer,
                                           error=failure.getErrorMessage())


class CreateShare(ActionQueueCommand):
    """Offer a share to somebody."""

    __slots__ = ('node_id', 'share_to', 'name', 'access_level',
                 'marker', 'path')
    possible_markers = 'node_id',
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, node_id, share_to, name, access_level,
                 marker, path):
        super(CreateShare, self).__init__(request_queue)
        self.node_id = node_id
        self.share_to = share_to
        self.name = name
        self.access_level = access_level
        self.marker = marker
        self.path = path

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.create_share(
            self.node_id, self.share_to, self.name, self.access_level)

    def handle_success(self, success):
        """It worked! Push the event."""
        self.action_queue.event_queue.push(
            'AQ_CREATE_SHARE_OK', share_id=success.share_id,
            marker=self.marker)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push('AQ_CREATE_SHARE_ERROR',
                                           marker=self.marker,
                                           error=failure.getErrorMessage())

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*self.path.split(os.path.sep), logger=self.log)


class DeleteShare(ActionQueueCommand):
    """Delete a offered Share."""

    __slots__ = ('share_id',)
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, share_id):
        super(DeleteShare, self).__init__(request_queue)
        self.share_id = share_id

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.delete_share(self.share_id)

    def handle_success(self, success):
        """It worked! Push the event."""
        self.action_queue.event_queue.push('AQ_DELETE_SHARE_OK',
                                           share_id=self.share_id)

    def handle_failure(self, failure):
        """It didn't work. Push the event."""
        self.action_queue.event_queue.push('AQ_DELETE_SHARE_ERROR',
                                           share_id=self.share_id,
                                           error=failure.getErrorMessage())


class CreateUDF(ActionQueueCommand):
    """Create a new User Defined Folder."""

    __slots__ = ('path', 'name', 'marker')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, path, name, marker):
        super(CreateUDF, self).__init__(request_queue)
        self.path = path
        # XXX Unicode boundary?
        self.name = name
        self.marker = marker

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.create_udf(self.path, self.name)

    def handle_success(self, success):
        """It worked! Push the success event."""
        kwargs = dict(marker=self.marker,
                      volume_id=success.volume_id,
                      node_id=success.node_id)
        self.action_queue.event_queue.push('AQ_CREATE_UDF_OK', **kwargs)

    def handle_failure(self, failure):
        """It didn't work! Push the failure event."""
        self.action_queue.event_queue.push('AQ_CREATE_UDF_ERROR',
                                           marker=self.marker,
                                           error=failure.getErrorMessage())

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*self.path.split(os.path.sep), logger=self.log)


class ListVolumes(ActionQueueCommand):
    """List all the volumes for a given user."""

    __slots__ = ()

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return self.__class__.__name__

    def _should_be_queued(self):
        """If other ListVolumes is queued, don't queue this one."""
        return self.uniqueness not in self._queue.hashed_waiting

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.list_volumes()

    def handle_success(self, success):
        """It worked! Push the success event."""
        self.action_queue.event_queue.push('AQ_LIST_VOLUMES',
                                           volumes=success.volumes)

    def handle_failure(self, failure):
        """It didn't work! Push the failure event."""
        self.action_queue.event_queue.push('AQ_LIST_VOLUMES_ERROR',
                                           error=failure.getErrorMessage())


class DeleteVolume(ActionQueueCommand):
    """Delete an exsistent volume."""

    __slots__ = ('volume_id', 'marker', 'path')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, volume_id, path):
        super(DeleteVolume, self).__init__(request_queue)
        self.volume_id = volume_id
        self.path = path

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.delete_volume(self.volume_id)

    def handle_success(self, success):
        """It worked! Push the success event."""
        self.action_queue.event_queue.push('AQ_DELETE_VOLUME_OK',
                                           volume_id=self.volume_id)

    def handle_failure(self, failure):
        """It didn't work! Push the failure event."""
        self.action_queue.event_queue.push('AQ_DELETE_VOLUME_ERROR',
                                           volume_id=self.volume_id,
                                           error=failure.getErrorMessage())

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*self.path.split(os.path.sep), logger=self.log)


class DeltaList(list):
    """A list with a small and fixed representation.

    We use delta lists instead of regular lists when we push deltas into
    the event queue so when we log the arguments of the event that was pushed
    we dont flood the logs.
    """

    def __init__(self, source):
        super(DeltaList, self).__init__()
        self[:] = source

    def __repr__(self):
        """A short representation for the list."""
        return "<DeltaList(len=%s)>" % (len(self),)

    __str__ = __repr__


class GetDelta(ActionQueueCommand):
    """Get a delta from a generation for a volume."""

    __slots__ = ('volume_id', 'generation')
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, volume_id, generation):
        super(GetDelta, self).__init__(request_queue)
        self.volume_id = volume_id
        self.generation = generation

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.get_delta(self.volume_id,
                                                  self.generation)

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return (self.__class__.__name__, self.volume_id)

    def _should_be_queued(self):
        """Determine if the command should be queued or other removed."""
        if self.uniqueness in self._queue.hashed_waiting:
            # other GetDelta for same volume! leave the smaller one
            queued_command = self._queue.hashed_waiting[self.uniqueness]
            if queued_command.generation > self.generation:
                if not queued_command.running:
                    # don't remove anything if already running!
                    m = "removing previous command because bigger gen num: %s"
                    self.log.debug(m, queued_command)
                    self._queue.remove(queued_command)
            else:
                if not queued_command.running:
                    self.log.debug("not queueing self because there's other "
                                   "(not running) command with less or "
                                   "same gen num")
                    return False

        # no similar command, or removed the previous command (if not running)
        return True

    def handle_success(self, request):
        """It worked! Push the success event."""
        data = dict(
            volume_id=self.volume_id,
            delta_content=DeltaList(request.response),
            end_generation=request.end_generation,
            full=request.full,
            free_bytes=request.free_bytes,
        )
        self.action_queue.event_queue.push('AQ_DELTA_OK', **data)

    def handle_failure(self, failure):
        """It didn't work! Push the failure event."""
        if failure.check(protocol_errors.CannotProduceDelta):
            self.action_queue.event_queue.push('AQ_DELTA_NOT_POSSIBLE',
                                               volume_id=self.volume_id)
        else:
            self.action_queue.event_queue.push('AQ_DELTA_ERROR',
                                               volume_id=self.volume_id,
                                               error=failure.getErrorMessage())

    def make_logger(self):
        """Create a logger for this object."""
        self.log = mklog(logger, 'GetDelta', self.volume_id,
                         None, generation=self.generation)

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        pathlock = self.action_queue.pathlock
        return pathlock.acquire('GetDelta', str(self.volume_id),
                                logger=self.log)


class GetDeltaFromScratch(ActionQueueCommand):
    """Get a delta from scratch."""

    __slots__ = ('volume_id',)
    logged_attrs = ActionQueueCommand.logged_attrs + __slots__

    def __init__(self, request_queue, volume_id):
        super(GetDeltaFromScratch, self).__init__(request_queue)
        self.volume_id = volume_id

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.get_delta(self.volume_id,
                                                  from_scratch=True)

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return (self.__class__.__name__, self.volume_id)

    def _should_be_queued(self):
        """Determine if the command should be queued."""
        if self.uniqueness in self._queue.hashed_waiting:
            # other GetDeltaFromScratch for same volume! skip self
            m = "GetDeltaFromScratch already queued, not queueing self"
            self.log.debug(m)
            return False

        return True

    def handle_success(self, request):
        """It worked! Push the success event."""
        data = dict(
            volume_id=self.volume_id,
            delta_content=DeltaList(request.response),
            end_generation=request.end_generation,
            free_bytes=request.free_bytes,
        )
        self.action_queue.event_queue.push('AQ_RESCAN_FROM_SCRATCH_OK', **data)

    def handle_failure(self, failure):
        """It didn't work! Push the failure event."""
        self.action_queue.event_queue.push('AQ_RESCAN_FROM_SCRATCH_ERROR',
                                           volume_id=self.volume_id,
                                           error=failure.getErrorMessage())

    def make_logger(self):
        """Create a logger for this object."""
        self.log = mklog(logger, 'GetDeltaFromScratch', self.volume_id, None)


class ChangePublicAccess(ActionQueueCommand):
    """Change the public access of a file."""

    __slots__ = ('share_id', 'node_id', 'is_public')
    possible_markers = 'node_id',

    def __init__(self, request_queue, share_id, node_id, is_public):
        super(ChangePublicAccess, self).__init__(request_queue)
        self.share_id = share_id
        self.node_id = node_id
        self.is_public = is_public

    def _run(self):
        """Do the actual running."""
        return self.action_queue.client.change_public_access(
            self.share_id, self.node_id, self.is_public)

    def handle_success(self, request):
        """It worked! Push the event."""
        d = dict(share_id=self.share_id, node_id=self.node_id,
                 is_public=request.is_public, public_url=request.public_url)
        self.action_queue.event_queue.push('AQ_CHANGE_PUBLIC_ACCESS_OK', **d)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push(
            'AQ_CHANGE_PUBLIC_ACCESS_ERROR', share_id=self.share_id,
            node_id=self.node_id, error=failure.getErrorMessage())


class GetPublicFiles(ActionQueueCommand):
    """Get the list of public files."""

    __slots__ = ()

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return self.__class__.__name__

    def _should_be_queued(self):
        """If other ListVolumes is queued, don't queue this one."""
        return self.uniqueness not in self._queue.hashed_waiting

    def _run(self):
        """See ActionQueueCommand."""
        return self.action_queue.client.list_public_files()

    def handle_success(self, request):
        """See ActionQueueCommand."""
        self.action_queue.event_queue.push('AQ_PUBLIC_FILES_LIST_OK',
                                           public_files=request.public_files)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push('AQ_PUBLIC_FILES_LIST_ERROR',
                                           error=failure.getErrorMessage())


class Download(ActionQueueCommand):
    """Get the contents of a file."""

    __slots__ = ('share_id', 'node_id', 'server_hash',
                 'fileobj', 'gunzip', 'mdid', 'download_req', 'tx_semaphore',
                 'deflated_size', 'n_bytes_read_last', 'n_bytes_read', 'path')
    logged_attrs = ActionQueueCommand.logged_attrs + (
        'share_id', 'node_id', 'server_hash', 'mdid', 'path')
    possible_markers = 'node_id',

    def __init__(self, request_queue, share_id, node_id, server_hash, mdid):
        super(Download, self).__init__(request_queue)
        self.share_id = share_id
        self.node_id = node_id
        self.server_hash = server_hash
        self.fileobj = None
        self.gunzip = None
        self.mdid = mdid
        self.download_req = None
        self.n_bytes_read = 0
        self.n_bytes_read_last = 0
        self.deflated_size = None
        self.tx_semaphore = None
        self.path = self._get_current_path(mdid)

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return (self.__class__.__name__, self.share_id, self.node_id)

    def _should_be_queued(self):
        """Queue but keeping uniqueness."""
        for uniq in [(Upload.__name__, self.share_id, self.node_id),
                     (Download.__name__, self.share_id, self.node_id)]:
            if uniq in self._queue.hashed_waiting:
                previous_command = self._queue.hashed_waiting[uniq]
                did_cancel = previous_command.cancel()
                if did_cancel:
                    m = "Previous command cancelled because uniqueness: %s"
                else:
                    m = ("Tried to cancel other command because uniqueness, "
                         "but couldn't: %s")
                self.log.debug(m, previous_command)
        return True

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        curr_path = self._get_current_path(self.mdid)
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*curr_path.split(os.path.sep), logger=self.log)

    def cancel(self):
        """Cancel the download."""
        if self.download_req is not None:
            self.download_req.cancel()
        return super(Download, self).cancel()

    @defer.inlineCallbacks
    def _start(self):
        """Just acquire the transfers semaphore."""
        self.tx_semaphore = yield self._queue.transfers_semaphore.acquire()
        if self.cancelled:
            # release the semaphore and stop working!
            self.log.debug("semaphore released after acquiring, "
                           "command cancelled")
            self.tx_semaphore = self.tx_semaphore.release()
            return
        self.log.debug('semaphore acquired')

    def finish(self):
        """Release the semaphore if already acquired."""
        if self.tx_semaphore is not None:
            self.tx_semaphore = self.tx_semaphore.release()
            self.log.debug('semaphore released')
        super(Download, self).finish()

    def _run(self):
        """Do the actual running."""
        # start or reset the file object, and get a new decompressor
        if self.fileobj is None:
            fsm = self.action_queue.main.fs
            try:
                self.fileobj = fsm.get_partial_for_writing(self.node_id,
                                                           self.share_id)
            except StandardError:
                self.log.debug(traceback.format_exc())
                msg = DefaultException('unable to build fileobj'
                                       ' (file went away?)'
                                       ' so aborting the download.')
                return defer.fail(Failure(msg))
        else:
            self.fileobj.seek(0, 0)
            self.fileobj.truncate(0)
            self.n_bytes_read = 0
            self.n_bytes_read_last = 0
        self.gunzip = zlib.decompressobj()

        self.action_queue.event_queue.push('AQ_DOWNLOAD_STARTED',
                                           share_id=self.share_id,
                                           node_id=self.node_id,
                                           server_hash=self.server_hash)

        req = self.action_queue.client.get_content_request(
            self.share_id, self.node_id, self.server_hash,
            offset=self.n_bytes_read,
            callback=self.downloaded_cb, node_attr_callback=self.node_attr_cb)
        self.download_req = req
        return req.deferred

    def handle_success(self, _):
        """It worked! Push the event."""
        self.sync()
        # send a COMMIT, the Nanny will issue the FINISHED if it's ok
        self.action_queue.event_queue.push('AQ_DOWNLOAD_COMMIT',
                                           share_id=self.share_id,
                                           node_id=self.node_id,
                                           server_hash=self.server_hash)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        if failure.check(protocol_errors.DoesNotExistError):
            self.action_queue.event_queue.push('AQ_DOWNLOAD_DOES_NOT_EXIST',
                                               share_id=self.share_id,
                                               node_id=self.node_id)
        else:
            self.action_queue.event_queue.push('AQ_DOWNLOAD_ERROR',
                                               error=failure.getErrorMessage(),
                                               share_id=self.share_id,
                                               node_id=self.node_id,
                                               server_hash=self.server_hash)

    def downloaded_cb(self, bytes):
        """A streaming decompressor."""
        self.n_bytes_read += len(bytes)
        self.fileobj.write(self.gunzip.decompress(bytes))
        # not strictly necessary but nice to see the downloaded size
        self.fileobj.flush()
        self.progress_hook()

    def progress_hook(self):
        """Send event if accumulated enough progress."""
        read_since_last = self.n_bytes_read - self.n_bytes_read_last
        if read_since_last >= TRANSFER_PROGRESS_THRESHOLD:
            event_data = dict(share_id=self.share_id, node_id=self.node_id,
                              n_bytes_read=self.n_bytes_read,
                              deflated_size=self.deflated_size)
            self.action_queue.event_queue.push('AQ_DOWNLOAD_FILE_PROGRESS',
                                               **event_data)
            self.n_bytes_read_last = self.n_bytes_read

    def node_attr_cb(self, **kwargs):
        """Update command information with node attributes."""
        self.deflated_size = kwargs['deflated_size']

    def sync(self):
        """Flush the buffers and sync them to disk if possible."""
        remains = self.gunzip.flush()
        if remains:
            self.fileobj.write(remains)
        self.fileobj.flush()
        if getattr(self.fileobj, 'fileno', None) is not None:
            # it's a real file, with a fileno! Let's sync its data
            # out to disk
            os.fsync(self.fileobj.fileno())
        self.fileobj.close()


class Upload(ActionQueueCommand):
    """Upload stuff to a file."""

    __slots__ = ('share_id', 'node_id', 'previous_hash', 'hash', 'crc32',
                 'size', 'magic_hash', 'deflated_size', 'tempfile',
                 'tx_semaphore', 'n_bytes_written_last', 'upload_req',
                 'n_bytes_written', 'upload_id', 'mdid', 'path')

    logged_attrs = ActionQueueCommand.logged_attrs + (
        'share_id', 'node_id', 'previous_hash', 'hash', 'crc32',
        'size', 'upload_id', 'mdid', 'path')
    retryable_errors = ActionQueueCommand.retryable_errors + (
        protocol_errors.UploadInProgressError,)
    possible_markers = 'node_id',

    def __init__(self, request_queue, share_id, node_id, previous_hash, hash,
                 crc32, size, mdid, upload_id=None):
        super(Upload, self).__init__(request_queue)
        self.share_id = share_id
        self.node_id = node_id
        self.previous_hash = previous_hash
        self.hash = hash
        self.crc32 = crc32
        self.size = size
        self.upload_id = upload_id
        self.tempfile = None
        self.mdid = mdid
        self.upload_req = None
        self.n_bytes_written_last = 0
        self.n_bytes_written = 0
        self.deflated_size = None
        self.tx_semaphore = None
        self.magic_hash = None
        self.path = self._get_current_path(mdid)

    @property
    def is_runnable(self):
        """Tell if the upload is ok to be carried on.

        Return True if there is sufficient space available to complete
        the upload, or if the upload is cancelled so it can pursue
        its fate.
        """
        if self.cancelled:
            return True
        else:
            return self.action_queue.have_sufficient_space_for_upload(
                self.share_id, self.size)

    def _should_be_queued(self):
        """Queue but keeping uniqueness."""
        for uniq in [(Upload.__name__, self.share_id, self.node_id),
                     (Download.__name__, self.share_id, self.node_id)]:
            if uniq in self._queue.hashed_waiting:
                previous_command = self._queue.hashed_waiting[uniq]
                did_cancel = previous_command.cancel()
                if did_cancel:
                    m = "Previous command cancelled because uniqueness: %s"
                else:
                    m = ("Tried to cancel other command because uniqueness, "
                         "but couldn't: %s")
                self.log.debug(m, previous_command)
        return True

    @property
    def uniqueness(self):
        """Info for uniqueness."""
        return (self.__class__.__name__, self.share_id, self.node_id)

    def _acquire_pathlock(self):
        """Acquire pathlock."""
        curr_path = self._get_current_path(self.mdid)
        pathlock = self.action_queue.pathlock
        return pathlock.acquire(*curr_path.split(os.path.sep), logger=self.log)

    def cancel(self):
        """Cancel the upload."""
        if self.upload_req is not None:
            producer = self.upload_req.producer
            if producer is not None and producer.finished:
                # can not cancel if already sent the EOF
                return False

            self.upload_req.cancel()
        return super(Upload, self).cancel()

    def cleanup(self):
        """Cleanup: stop the producer."""
        self.log.debug('cleanup')
        if (self.upload_req is not None and
                self.upload_req.producer is not None):
            self.log.debug('stopping the producer')
            self.upload_req.producer.stopProducing()

    @defer.inlineCallbacks
    def _start(self):
        """Do the specialized pre-run setup."""
        self.tx_semaphore = yield self._queue.transfers_semaphore.acquire()
        if self.cancelled:
            # release the semaphore and stop working!
            self.log.debug("semaphore released after acquiring, "
                           "command cancelled")
            self.tx_semaphore = self.tx_semaphore.release()
            return
        self.log.debug('semaphore acquired')

        fsm = self.action_queue.main.fs
        yield self.action_queue.zip_queue.zip(
            self, lambda: fsm.open_file(self.mdid))

    def finish(self):
        """Release the semaphore if already acquired."""
        if self.tempfile is not None:
            # clean the temporary file
            self.tempfile.close()
            remove_file(self.tempfile.name)

        if self.tx_semaphore is not None:
            self.tx_semaphore = self.tx_semaphore.release()
            self.log.debug('semaphore released')
        super(Upload, self).finish()

    def _run(self):
        """Do the actual running."""
        self.action_queue.event_queue.push('AQ_UPLOAD_STARTED',
                                           share_id=self.share_id,
                                           node_id=self.node_id,
                                           hash=self.hash)
        self.tempfile.seek(0)
        f = UploadProgressWrapper(self.tempfile, self)

        # access here the magic hash value, don't log anywhere, and
        # just send it
        magic_hash = self.magic_hash._magic_hash
        req = self.action_queue.client.put_content_request(
            self.share_id, self.node_id, self.previous_hash, self.hash,
            self.crc32, self.size, self.deflated_size, f,
            upload_id=self.upload_id, upload_id_cb=self._upload_id_cb,
            magic_hash=magic_hash)
        self.upload_req = req
        return req.deferred

    def _upload_id_cb(self, upload_id, offset):
        """Handle the received upload_id, save it in the metadata."""
        self.log.debug("got from server: upload_id=%s offset=%s",
                       upload_id, offset)
        self.action_queue.main.fs.set_by_node_id(
            self.node_id, self.share_id, upload_id=upload_id)
        self.upload_id = upload_id

    def progress_hook(self):
        """Send event if accumulated enough progress."""
        written_since_last = self.n_bytes_written - self.n_bytes_written_last
        if written_since_last >= TRANSFER_PROGRESS_THRESHOLD:
            event_data = dict(share_id=self.share_id, node_id=self.node_id,
                              n_bytes_written=self.n_bytes_written,
                              deflated_size=self.deflated_size)
            self.action_queue.event_queue.push('AQ_UPLOAD_FILE_PROGRESS',
                                               **event_data)
            self.n_bytes_written_last = self.n_bytes_written

    def handle_success(self, request):
        """It worked! Push the event."""
        # send the event
        d = dict(share_id=self.share_id, node_id=self.node_id, hash=self.hash,
                 new_generation=request.new_generation)
        self.action_queue.event_queue.push('AQ_UPLOAD_FINISHED', **d)

    def handle_retryable(self, failure):
        """For a retryable failure."""
        if failure.check(protocol_errors.QuotaExceededError):
            error = failure.value
            self.action_queue.event_queue.push('SYS_QUOTA_EXCEEDED',
                                               volume_id=str(error.share_id),
                                               free_bytes=error.free_bytes)

    def handle_failure(self, failure):
        """It didn't work! Push the event."""
        self.action_queue.event_queue.push('AQ_UPLOAD_ERROR',
                                           error=failure.getErrorMessage(),
                                           share_id=self.share_id,
                                           node_id=self.node_id,
                                           hash=self.hash)
