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

"""Provides a layer to handle all the database objects from twisted.

This layer is the main interface to the RPC DAL.
"""

import calendar
import logging
import posixpath as pypath
import uuid
import weakref
import zlib

import twisted.internet.error
import twisted.web.error

from twisted.internet import defer

from backends.filesync import errors as dataerrors
from backends.filesync.models import Share
from magicicada import settings
from ubuntuone.storage.server import errors, upload
from ubuntuone.storageprotocol import protocol_pb2

ZERO_LENGTH_CONTENT_KEY = ""


class FalseProducer(object):
    """Not really a producer, just deliver all the data when asked to.

    It has all the methods to comply the Push or Pull Producer Interface,
    but the only one implemented is resumeProducing: sends all the data.
    """

    def __init__(self, data):
        self.data = data
        self.deferred = defer.Deferred()
        self.consumer = None

    def resumeProducing(self):
        """Resume producing, just send all the data."""
        if self.consumer:
            self.consumer.write(self.data)
        self.deferred.callback(True)

    def startProducing(self, consumer):
        """Start producing."""
        self.consumer = consumer

    def stopProducing(self):
        """Stop producing."""

    def pauseProducing(self):
        """Pause producing."""


class Node(object):
    """StorageObject proxy."""

    def __init__(self, manager, node):
        """Create a Node.

        @param manager: the ContentManager which created this object
        @param node: a dao.StorageNode
        """
        self.manager = manager
        self.id = node['id']
        self.volume_id = node['volume_id']
        self.path = node['path']
        self.name = node['name']
        self.parent_id = node['parent_id']
        self.is_file = node['is_file']
        self.content_hash = node['content_hash']
        self.size = node['size'] or 0
        self.crc32 = node['crc32'] or 0
        self.deflated_size = node['deflated_size'] or 0
        self.is_live = node['is_live']
        self.generation = node['generation']
        self.is_public = node['is_public']
        last_modif = node['last_modified']

        # special cases for no content
        if node['storage_key'] is None:
            self.has_content = False
            self.storage_key = ZERO_LENGTH_CONTENT_KEY
        else:
            self.has_content = node['has_content']
            self.storage_key = node['storage_key']

        self.last_modified = calendar.timegm(last_modif.timetuple())
        self.node = node
        self.logger = logging.getLogger('storage.server')

    def get_content(self, start=None, previous_hash=None, user=None):
        """Get the content for this node.

        @param start: the start offset
        @param previous_hash: not used for FileNode.
        @param user: the user doing the request, useful for logging.
        """
        if not self.is_file:
            raise TypeError("Content can be retrieved only on Files.")
        storage_key = self.storage_key
        if storage_key == ZERO_LENGTH_CONTENT_KEY:
            # we send the compressed empty string
            return FalseProducer(zlib.compress(""))

        # TODO: we should get bytes from a 'start' point, there are not
        # test cases for this, did this work at all or client always sent 0?
        producer = self.manager.factory.diskstorage.get(str(storage_key))
        producer.deferred.addErrback(self._handle_errors, user)
        return producer

    def _context_msg(self, user):
        """Return a string with the context."""
        if user.protocols:
            session_ids = ','.join([str(p.session_id) for p in user.protocols])
        else:
            session_ids = 'No sessions?'
        context = dict(user_id=user.id,
                       username=user.username.replace('%', '%%'),
                       session_ids=session_ids, node_id=str(self.id))
        return ("%(session_ids)s - %(username)s (%(user_id)s) - "
                "node_id=%(node_id)s" % context)

    def _handle_errors(self, failure, user):
        """Transform storage backend errors into something more appropiate."""
        ctx = self._context_msg(user)
        self.logger.warning("%s - storage backend error: %s", ctx, failure)
        raise errors.NotAvailable(failure.getErrorMessage())


class DBUploadJob(object):
    """A proxy for Upload model objects."""

    def __init__(self, user, volume_id, node_id, uploadjob_id, uploaded_bytes,
                 multipart_key, chunk_count, when_last_active):
        self.__dict__ = locals()

        # will only update the DB with parts when accumulate over a trigger
        self.unsaved_count = 0

    @classmethod
    def get(cls, user, volume_id, node_id, uploadjob_id, hash_value, crc32):
        """Get a multipart upload job."""
        data = dict(user=user, volume_id=volume_id,
                    node_id=node_id)
        kwargs = dict(user_id=user.id, volume_id=volume_id, node_id=node_id,
                      uploadjob_id=uploadjob_id,
                      hash_value=hash_value, crc32=crc32)
        d = user.rpc_dal.call('get_uploadjob', **kwargs)
        d.addCallback(lambda r: r.update(data) or r)
        d.addCallback(lambda r: cls(**r))
        return d

    @classmethod
    def make(cls, user, volume_id, node_id, previous_hash,
             hash_value, crc32, inflated_size):
        """Make an upload job."""
        multipart_key = uuid.uuid4()
        data = dict(user=user, volume_id=volume_id,
                    node_id=node_id, multipart_key=multipart_key)
        kwargs = dict(user_id=user.id, volume_id=volume_id, node_id=node_id,
                      previous_hash=previous_hash,
                      hash_value=hash_value, crc32=crc32,
                      inflated_size=inflated_size, multipart_key=multipart_key)
        d = user.rpc_dal.call('make_uploadjob', **kwargs)
        d.addCallback(lambda r: r.update(data) or r)
        d.addCallback(lambda r: cls(**r))
        return d

    def add_part(self, chunk_size):
        """Add a part to an upload job."""
        self.unsaved_count += chunk_size
        if self.unsaved_count >= settings.api_server.STORAGE_CHUNK_SIZE:
            self.unsaved_count -= settings.api_server.STORAGE_CHUNK_SIZE
            kwargs = dict(user_id=self.user.id, volume_id=self.volume_id,
                          uploadjob_id=self.uploadjob_id,
                          chunk_size=chunk_size)
            d = self.user.rpc_dal.call('add_part_to_uploadjob', **kwargs)
        else:
            d = defer.succeed(True)
        return d

    @defer.inlineCallbacks
    def delete(self):
        """Delete an upload job."""
        try:
            yield self.user.rpc_dal.call('delete_uploadjob',
                                         user_id=self.user.id,
                                         volume_id=self.volume_id,
                                         uploadjob_id=self.uploadjob_id)
        except dataerrors.DoesNotExist:
            pass

    @defer.inlineCallbacks
    def touch(self):
        """Touch an upload job."""
        r = yield self.user.rpc_dal.call('touch_uploadjob',
                                         user_id=self.user.id,
                                         volume_id=self.volume_id,
                                         uploadjob_id=self.uploadjob_id)
        self.when_last_active = r['when_last_active']


class BogusUploadJob(object):
    """A proxy for Upload that really doesn't do anything, for small files."""
    def __init__(self):
        self.multipart_key = uuid.uuid4()  # unique id for the upload
        self.uploaded_bytes = 0  # always start from 0 (non resumable)
        self._bogus_deferred = defer.succeed(True)

    def add_part(self, _):
        """Bogus add part."""
        return self._bogus_deferred

    def delete(self):
        """Bogus delete."""
        return self._bogus_deferred


class BaseUploadJob(object):
    """Main interface for Uploads."""

    _inflated_size_hint_mismatch = "Inflated size does not match hint."
    _deflated_size_hint_mismatch = "Deflated size does not match hint."
    _content_hash_hint_mismatch = "Content hash does not match hint."
    _magic_hash_hint_mismatch = "Magic hash does not match hint."
    _crc32_hint_mismatch = "Crc32 does not match hint."

    def __init__(self, user, file_node, previous_hash, hash_hint, crc32_hint,
                 inflated_size_hint, deflated_size_hint, session_id,
                 blob_exists, magic_hash):
        node_hash = file_node.content_hash
        if (node_hash or previous_hash) and \
                node_hash != previous_hash and node_hash != hash_hint:
            raise errors.ConflictError("Previous hash does not match.")

        self.user = user
        self.session_id = session_id
        self.magic_hash = magic_hash
        self.producer = None
        self.consumer = None
        self.ops = defer.succeed(None)
        self.deferred = defer.Deferred()
        self.deferred.addErrback(self._handle_errors)
        self._initial_data = True
        self.storage_key = None
        self.canceling = False
        self.logger = logging.getLogger('storage.server')

        self.original_file_hash = node_hash
        self.hash_hint = hash_hint
        self.crc32_hint = crc32_hint
        self.inflated_size_hint = inflated_size_hint
        self.deflated_size_hint = deflated_size_hint
        self.file_node = file_node
        self.blob_exists = blob_exists

    def add_operation(self, operation_func, error_handler):
        """Add an operation and error handler to ops deferred."""
        self.ops.addCallback(operation_func)
        self.ops.addErrback(error_handler)

    @property
    def upload_id(self):
        """Return the upload_id for this upload job."""
        raise NotImplementedError("subclass responsability.")

    @property
    def offset(self):
        """The offset of this upload."""
        raise NotImplementedError("subclass responsability.")

    def connect(self):
        """Setup the producer and consumer."""
        if self.blob_exists:
            # we have a storage object like this already (not magic upload
            # because other user); wrap the producer to only hash and
            # discard the bytes
            self.producer = upload.ProxyHashingProducer(self.producer, True)
            self.consumer = upload.NullConsumer()
            self.consumer.registerProducer(self.producer)
            self.deferred.callback(None)
        else:
            # we need to upload this content, get ready for it
            self._start_receiving()

    def _start_receiving(self):
        """Prepare the upload job to start receiving streaming bytes."""
        self.storage_key = self.uploadjob.multipart_key
        offset = self.uploadjob.uploaded_bytes

        self.consumer = self.user.manager.factory.diskstorage.put(
            str(self.storage_key), offset)

        streaming = offset == 0  # hash on the fly if receive from start
        self.producer = upload.ProxyHashingProducer(self.consumer, streaming)
        self.consumer.registerProducer(self.producer, True)  # push producer

    @defer.inlineCallbacks
    def add_data(self, data):
        """Add data to this upload.

        This is called by the server with the bytes that arrive in a packet.
        This is at most MAX_MESSAGE_SIZE bytes (2**16, 65k at the moment).

        zlib has a theoretical limit of compression of 1032:1, so this means
        that at most we will get a 1032*2**16 ~= 64MB, meaning that the memory
        usage for this has a maximum.

        http://zlib.net/zlib_tech.html
        """
        if self.canceling:
            return

        try:
            self.producer.dataReceived(data)
        except Exception as err:
            self.deferred.errback(err)
        else:
            yield self.uploadjob.add_part(len(data))

    def _stop_producer_and_factory(self):
        """Cancel this upload job.

        - Unregister producer.
        - Stop the producer if not yet stopped.
        - Cancel the factory if one exists.
        """
        self.canceling = True
        if self.producer is not None:
            # upload already started
            self.producer.stopProducing()
        if self.consumer is not None:
            self.consumer.unregisterProducer()
        if not self.deferred.called:
            self.deferred.callback(None)

    def cancel(self):
        """Cancel this upload job."""
        return self._stop_producer_and_factory()

    def stop(self):
        """Stop the upload and cleanup."""
        return self._stop_producer_and_factory()

    def _handle_connection_done(self, failure):
        """Process error states encountered by producers and consumers """
        if failure.check(twisted.internet.error.ConnectionDone):
            # if we're on the canceling pathway, we expect this
            if self.canceling:
                return
            raise errors.UploadCanceled("Connection closed prematurely.")
        return failure

    def _handle_errors(self, failure):
        """Handle all internal errors."""

        def context_msg():
            """Return a str with the context for this upload."""
            session_ids = ''
            if self.user.protocols:
                session_ids = ','.join([str(p.session_id)
                                        for p in self.user.protocols])
            upload_context = dict(
                user_id=self.user.id,
                username=self.user.username.replace('%', '%%'),
                session_ids=session_ids or 'No sessions?',
                volume_id=self.file_node.volume_id,
                node_id=self.file_node.id,
                bytes_sent=self.producer.deflated_size if self.producer else 0,
            )
            context_msg = ('%(session_ids)s - %(username)s (%(user_id)s) - '
                           'node=%(volume_id)s::%(node_id)s '
                           'sent=%(bytes_sent)s')
            return context_msg % upload_context

        self.logger.warning("%s - storage backend error: %s",
                            context_msg(), failure)
        if failure.check(errors.UploadCorrupt):
            return failure
        raise errors.TryAgain(failure.value)

    @defer.inlineCallbacks
    def commit(self):
        """Simple commit, overwrite for more detailed behaviour."""
        try:
            new_gen = yield self._commit()
        finally:
            try:
                yield self.uploadjob.delete()
            except Exception as exc:
                self.logger.warning("%s(%s): while deleting uploadjob",
                                    exc.__class__.__name__, exc)
        defer.returnValue(new_gen)

    @defer.inlineCallbacks
    def _commit(self):
        """Make this upload the current content for the node."""
        self.producer.stopProducing()
        self.consumer.commit()
        yield self.producer.flush_decompressor()

        # size matches hint
        if self.producer.deflated_size != self.deflated_size_hint:
            raise errors.UploadCorrupt(self._deflated_size_hint_mismatch)
        if self.producer.inflated_size != self.inflated_size_hint:
            raise errors.UploadCorrupt(self._inflated_size_hint_mismatch)

        # get the magic hash value here, don't log it, don't save it
        magic_hash = self.producer.magic_hash_object.content_hash()
        magic_hash_value = magic_hash._magic_hash
        # magic hash should match the one sent by the client
        if self.magic_hash is not None and magic_hash_value != self.magic_hash:
            raise errors.UploadCorrupt(self._magic_hash_hint_mismatch)

        # hash matches hint
        if self.producer.hash_object.content_hash() != self.hash_hint:
            raise errors.UploadCorrupt(self._content_hash_hint_mismatch)

        # crc matches hint
        if self.producer.crc32 != self.crc32_hint:
            raise errors.UploadCorrupt(self._crc32_hint_mismatch)

        storage_key = self.storage_key
        if storage_key is None:
            storage_key = self.file_node.storage_key
        if storage_key is None and self.inflated_size == 0:
            storage_key = ZERO_LENGTH_CONTENT_KEY

        new_gen = yield self._commit_content(storage_key, magic_hash_value)
        defer.returnValue(new_gen)

    @defer.inlineCallbacks
    def _commit_content(self, storage_key, magic_hash):
        """Commit the content in the DAL."""
        kwargs = dict(user_id=self.user.id, node_id=self.file_node.id,
                      volume_id=self.file_node.volume_id,
                      original_hash=self.original_file_hash,
                      hash_hint=self.hash_hint, crc32_hint=self.crc32_hint,
                      inflated_size_hint=self.inflated_size_hint,
                      deflated_size_hint=self.deflated_size_hint,
                      storage_key=storage_key, magic_hash=magic_hash,
                      session_id=self.session_id)
        try:
            r = yield self.user.rpc_dal.call('make_content', **kwargs)
        except dataerrors.ContentMissing:
            raise errors.TryAgain("Content missing on commit content.")
        except dataerrors.HashMismatch:
            raise errors.ConflictError("The File changed while uploading.")
        defer.returnValue(r['generation'])


class UploadJob(BaseUploadJob):
    """A simple upload job."""

    def __init__(self, user, file_node, previous_hash, hash_hint, crc32_hint,
                 inflated_size_hint, deflated_size_hint,
                 session_id, blob_exists, magic_hash, upload):
        super(UploadJob, self).__init__(user, file_node, previous_hash,
                                        hash_hint, crc32_hint,
                                        inflated_size_hint, deflated_size_hint,
                                        session_id, blob_exists, magic_hash)
        self.uploadjob = upload

    @property
    def upload_id(self):
        """Return the upload_id for this upload job."""
        return self.uploadjob.multipart_key

    @property
    def offset(self):
        return self.uploadjob.uploaded_bytes


class MagicUploadJob(BaseUploadJob):
    """The magic upload job.

    Its initial offset is the size itself (no data should be added), all
    that is required for the upload is known at the beginning.  The only
    real action here is the commit.
    """

    def __init__(self, user, file_node, previous_hash, hash_hint, crc32_hint,
                 inflated_size_hint, deflated_size_hint,
                 storage_key, magic_hash, session_id, blob_exists):
        super(MagicUploadJob, self).__init__(user, file_node, previous_hash,
                                             hash_hint, crc32_hint,
                                             inflated_size_hint,
                                             deflated_size_hint,
                                             session_id, blob_exists,
                                             magic_hash)
        self.storage_key = storage_key
        # all already done!
        self.deferred.callback(None)

    @property
    def upload_id(self):
        """Return the upload_id for this upload job."""
        return ''

    @property
    def offset(self):
        """The initial offset is all the file."""
        return self.deflated_size_hint

    def add_data(self, data):
        """No data should be added!"""
        raise RuntimeError("No data should be added to the MagicUploadJob!")

    def connect(self):
        """Nothing to do, as magic uploads won't push bytes to backend."""

    def commit(self):
        """Make this upload the current content for the node."""
        return self._commit_content(self.storage_key, self.magic_hash)


class User(object):
    """A proxy for User objects."""

    def __init__(self, manager, user_id,
                 root_volume_id, username, visible_name):
        self.manager = manager
        self.id = user_id
        self.root_volume_id = root_volume_id
        self.username = username
        self.visible_name = visible_name
        self.protocols = []
        self.rpc_dal = self.manager.rpc_dal

    def register_protocol(self, protocol):
        """Register protocol as a connection authenticated for this user.

        @param protocol: the Server protocol.
        """
        self.protocols.append(protocol)

    def unregister_protocol(self, protocol, cleanup=None):
        """Unregister protocol.

        @param protocol: the Server protocol.
        """
        self.protocols.remove(protocol)

    def broadcast(self, message, filter=lambda _: True):
        """Send message to all connections from this user."""
        for protocol in self.protocols:
            if not filter(protocol):
                continue
            new_message = protocol_pb2.Message()
            new_message.CopyFrom(message)
            new_message.id = protocol.get_new_request_id()
            protocol.sendMessage(new_message)
            protocol.log.trace_message("NOTIFICATION:", new_message)

    @defer.inlineCallbacks
    def get_root(self):
        """Get the root node for this user."""
        r = yield self.rpc_dal.call('get_root', user_id=self.id)
        defer.returnValue((r['root_id'], r['generation']))

    @defer.inlineCallbacks
    def get_free_bytes(self, share_id=None):
        """Returns free space for the given share or the user volume.

        @param share_id: if provided, the id of an accepted share to the user
        """
        if share_id:
            try:
                share = yield self.rpc_dal.call(
                    'get_share', user_id=self.id, share_id=share_id)
                owner_id = share['shared_by_id']
            except dataerrors.DoesNotExist:
                # There is currently a bug in the client which
                # will allow volume_id to be passed to this method. And it
                # will default to the free_bytes of the user. However, this
                # method should not accept a volume_id and share_id should
                # always be valid
                owner_id = self.id
        else:
            owner_id = self.id
        r = yield self.rpc_dal.call('get_user_quota', user_id=owner_id)
        defer.returnValue(r['free_bytes'])

    @defer.inlineCallbacks
    def get_storage_byte_quota(self):
        """Returns purchased and available space for the user."""
        r = yield self.rpc_dal.call('get_user_quota', user_id=self.id)
        defer.returnValue((r['max_storage_bytes'], r['used_storage_bytes']))

    @defer.inlineCallbacks
    def get_node(self, volume_id, node_id, content_hash):
        """Get a content.Node for this node_id.

        @param: volume_id: None for the root volume, or uuid of udf or share id
        @param node_id: an uuid object or string representing the id of the
            we are looking for
        @param content_hash: The current content hash of the node.
        """
        node = yield self.rpc_dal.call('get_node', user_id=self.id,
                                       volume_id=volume_id, node_id=node_id)
        if content_hash and content_hash != node['content_hash']:
            msg = "Node is not available due to hash mismatch."
            raise errors.NotAvailable(msg)

        if node['is_file'] and node['crc32'] is None:
            msg = "Node does not exist since it has no content."
            raise dataerrors.DoesNotExist(msg)

        defer.returnValue(Node(self.manager, node))

    @defer.inlineCallbacks
    def move(self, volume_id, node_id, new_parent_id,
             new_name, session_id=None):
        """Move a node.

        Returns a list of modified nodes.

        @param volume_id: the id of the udf or share, None for root.
        @param node_id: the id of the node to move.
        @param new_parent_id: the node id of the new parent.
        @param new_name: the new name for node_id.
        """
        args = dict(user_id=self.id, volume_id=volume_id, node_id=node_id,
                    new_name=new_name, new_parent_id=new_parent_id,
                    session_id=session_id)
        r = yield self.rpc_dal.call('move', **args)
        defer.returnValue((r['generation'], r['mimetype']))

    @defer.inlineCallbacks
    def make_dir(self, volume_id, parent_id, name, session_id=None):
        """Create a directory.

        @param: volume_id: None for the root volume, or uuid of udf or share id
        @param parent: the parent content.Node.
        @param name: the name for the directory.
        """
        args = dict(user_id=self.id, volume_id=volume_id, parent_id=parent_id,
                    name=name, session_id=session_id)
        r = yield self.rpc_dal.call('make_dir', **args)
        defer.returnValue((r['node_id'], r['generation'], r['mimetype']))

    @defer.inlineCallbacks
    def make_file(self, volume_id, parent_id, name,
                  session_id=None):
        """Create a file.

        @param: volume_id: None for the root volume, or uuid of udf or share id
        @param parent: the parent content.Node.
        @param name: the name for the file.
        """
        args = dict(user_id=self.id, volume_id=volume_id, parent_id=parent_id,
                    name=name, session_id=session_id)
        r = yield self.rpc_dal.call('make_file', **args)
        defer.returnValue((r['node_id'], r['generation'], r['mimetype']))

    @defer.inlineCallbacks
    def create_udf(self, path, name, session_id=None):
        """Creates an UDF.

        @param path: the directory of where the UDF is
        @param name: the name of the UDF
        @param session_id: id of the session where the event was generated
        """
        fullpath = pypath.join(path, name)
        r = yield self.rpc_dal.call('create_udf', user_id=self.id,
                                    path=fullpath, session_id=session_id)
        defer.returnValue((r['udf_id'], r['udf_root_id'], r['udf_path']))

    @defer.inlineCallbacks
    def delete_volume(self, volume_id, session_id=None):
        """Deletes a volume.

        @param volume_id: the id of the share or udf.
        @param session_id: id of the session where the event was generated.
        """
        yield self.rpc_dal.call('delete_volume', user_id=self.id,
                                volume_id=volume_id, session_id=session_id)

    @defer.inlineCallbacks
    def list_volumes(self):
        """List all the volumes the user is involved.

        This includes the real Root, the UDFs, and the shares that were shared.
        to her and she already accepted.
        """
        r = yield self.rpc_dal.call('list_volumes', user_id=self.id)
        root_info = r['root']
        shares = r['shares']
        udfs = r['udfs']
        free_bytes = r['free_bytes']
        defer.returnValue((root_info, shares, udfs, free_bytes))

    @defer.inlineCallbacks
    def list_shares(self):
        """List all the shares the user is involved.

        This only returns the "from me" shares, and the "to me" shares that I
        still didn't accept.
        """
        r = yield self.rpc_dal.call('list_shares', user_id=self.id,
                                    accepted=False)
        defer.returnValue((r['shared_by'], r['shared_to']))

    @defer.inlineCallbacks
    def create_share(self, node_id, shared_to_username, name, access_level):
        """Creates a share.

        @param node_id: the id of the node that will be root of the share.
        @param shared_to_username: the username of the receiving user.
        @param name: the name of the share.
        @param access_level: the permissions on the share.
        """
        readonly = access_level == Share.VIEW
        r = yield self.rpc_dal.call('create_share', user_id=self.id,
                                    node_id=node_id, share_name=name,
                                    to_username=shared_to_username,
                                    readonly=readonly)
        defer.returnValue(r['share_id'])

    @defer.inlineCallbacks
    def delete_share(self, share_id):
        """Deletes a share.

        @param share_id: the share id.
        """
        yield self.rpc_dal.call('delete_share',
                                user_id=self.id, share_id=share_id)

    @defer.inlineCallbacks
    def share_accepted(self, share_id, answer):
        """Accepts (or not) the share.

        @param share_id: the share id.
        @param answer: if it was accepted ("Yes") or not ("No").
        """
        if answer == "Yes":
            call = 'accept_share'
        elif answer == "No":
            call = 'decline_share'
        else:
            raise ValueError("Received invalid answer: %r" % answer)
        yield self.rpc_dal.call(call, user_id=self.id, share_id=share_id)

    @defer.inlineCallbacks
    def unlink_node(self, volume_id, node_id, session_id=None):
        """Unlink a node.

        @param volume_id: the id of the volume of the node.
        @param node_id: the id of the node.
        """
        r = yield self.rpc_dal.call('unlink_node', user_id=self.id,
                                    volume_id=volume_id, node_id=node_id,
                                    session_id=session_id)
        defer.returnValue((r['generation'], r['kind'],
                           r['name'], r['mimetype']))

    @defer.inlineCallbacks
    def get_upload_job(self, vol_id, node_id, previous_hash, hash_value, crc32,
                       inflated_size, deflated_size, session_id=None,
                       magic_hash=None, upload_id=None):
        """Create an upload reservation for a node.

        @param vol_id: the volume id this node belongs to.
        @param node_id: the node to upload to.
        @param previous_hash: the current hash of the node.
        @param hash_value: the hash of the new content.
        @param crc32: the crc32 of the new content.
        @param size: the uncompressed size of the new content.
        @param deflated_size: the compressed size of the new content.
        """
        if previous_hash == "":
            previous_hash = None

        # reuse the content if we can
        r = yield self.rpc_dal.call('get_reusable_content', user_id=self.id,
                                    hash_value=hash_value,
                                    magic_hash=magic_hash)
        blob_exists, storage_key = r['blob_exists'], r['storage_key']

        if storage_key is not None:
            upload_job = yield self._get_magic_upload_job(
                vol_id, node_id, previous_hash, hash_value,
                crc32, inflated_size, deflated_size,
                storage_key, magic_hash, session_id,
                blob_exists)
            defer.returnValue(upload_job)

        upload_job = yield self._get_upload_job(
            vol_id, node_id, previous_hash, hash_value, crc32, inflated_size,
            deflated_size, session_id, blob_exists, magic_hash, upload_id)
        defer.returnValue(upload_job)

    @defer.inlineCallbacks
    def _get_upload_job(self, vol_id, node_id, previous_hash, hash_value,
                        crc32, inflated_size, deflated_size,
                        session_id, blob_exists, magic_hash, upload_id):
        """Create an upload reservation for a node.

        @param vol_id: the volume id this node belongs to.
        @param node_id: the node to upload to.
        @param previous_hash: the current hash of the node.
        @param hash_value: the hash of the new content.
        @param crc32: the crc32 of the new content.
        @param size: the uncompressed size of the new content.
        @param deflated_size: the compressed size of the new content.
        """
        node = yield self.rpc_dal.call('get_node', user_id=self.id,
                                       volume_id=vol_id, node_id=node_id)
        if not node["is_file"]:
            raise dataerrors.NoPermission("Can only put content on files.")
        file_node = Node(self.manager, node)

        upload = None
        if upload_id:
            # check if there is already a job.
            try:
                uploadid = uuid.UUID(upload_id)
            except ValueError:
                # invalid upload_id, just ignore it a create a new upload.
                upload = None
            else:
                try:
                    upload = yield DBUploadJob.get(self, vol_id, node_id,
                                                   uploadid, hash_value, crc32)
                except dataerrors.DoesNotExist:
                    # there is no uploadjob with the specified id
                    upload = None

        if upload is None:
            # no uploadjob found, create a new one: if the file is small just
            # get a bo
            if deflated_size <= settings.api_server.STORAGE_CHUNK_SIZE:
                upload = BogusUploadJob()
            else:
                try:
                    upload = yield DBUploadJob.make(self, vol_id, node_id,
                                                    previous_hash, hash_value,
                                                    crc32, inflated_size)
                except dataerrors.HashMismatch:
                    raise errors.ConflictError("Previous hash does not match.")
        else:
            # update the when_last_active value.
            yield upload.touch()

        uj = UploadJob(self, file_node, previous_hash, hash_value,
                       crc32, inflated_size, deflated_size,
                       session_id, blob_exists, magic_hash, upload)

        defer.returnValue(uj)

    @defer.inlineCallbacks
    def _get_magic_upload_job(self, vol_id, node_id, previous_hash, hash_value,
                              crc32, inflated_size, deflated_size, storage_key,
                              magic_hash, session_id, blob_exists):
        """Create a magic upload reservation for a node.

        @param vol_id: the volume id this node belongs to.
        @param node_id: the node to upload to.
        @param previous_hash: the current hash of the node.
        @param hash_value: the hash of the new content.
        @param crc32: the crc32 of the new content.
        @param size: the uncompressed size of the new content.
        @param deflated_size: the compressed size of the new content.
        @param storage_key: the content's storage key
        @param magic_hash: the magic_hash from client
        """
        node = yield self.rpc_dal.call('get_node', user_id=self.id,
                                       volume_id=vol_id, node_id=node_id)
        if not node["is_file"]:
            raise dataerrors.NoPermission("Can only put content on files.")
        file_node = Node(self.manager, node)
        uj = MagicUploadJob(self, file_node, previous_hash, hash_value,
                            crc32, inflated_size, deflated_size,
                            storage_key, magic_hash, session_id, blob_exists)
        defer.returnValue(uj)

    @defer.inlineCallbacks
    def get_delta(self, volume_id, from_generation, limit=None):
        """Get the delta form generation for volume_id."""
        r = yield self.rpc_dal.call('get_delta', user_id=self.id,
                                    volume_id=volume_id, limit=limit,
                                    from_generation=from_generation)
        nodes = [Node(self.manager, n) for n in r['nodes']]
        defer.returnValue((nodes, r['vol_generation'], r['free_bytes']))

    @defer.inlineCallbacks
    def get_from_scratch(self, volume_id, start_from_path=None, limit=None,
                         max_generation=None):
        """Get the list of live nodes in volume_id."""
        r = yield self.rpc_dal.call('get_from_scratch', user_id=self.id,
                                    volume_id=volume_id,
                                    start_from_path=start_from_path,
                                    limit=limit, max_generation=max_generation)
        nodes = [Node(self.manager, n) for n in r['nodes']]
        defer.returnValue((nodes, r['vol_generation'], r['free_bytes']))

    @defer.inlineCallbacks
    def get_volume_id(self, node_id):
        """Get the (client) volume_id (UDF id or root) of this node_id.

        @param node_id: an uuid object or string representing the id of the
            we are looking for
        """
        r = yield self.rpc_dal.call('get_volume_id', user_id=self.id,
                                    node_id=node_id)
        defer.returnValue(r['volume_id'])


class ContentManager(object):
    """Manages Users."""

    def __init__(self, factory):
        """Create a ContentManager."""
        self.factory = factory
        self.users = weakref.WeakValueDictionary()

    @defer.inlineCallbacks
    def get_user_by_id(self, user_id, session_id=None, required=False):
        """Return a user by id and session id if its connected.

        If it's not cached and required, it's retrieved from the DB.
        """
        user = self.users.get(user_id, None)
        if user is None and required:
            r = yield self.rpc_dal.call(
                'get_user_data', user_id=user_id, session_id=session_id)
            # Another task may have already updated the cache, so check again
            user = self.users.get(user_id, None)
            if user is None:
                user = User(self, user_id, r['root_volume_id'],
                            r['username'], r['visible_name'])
                self.users[user_id] = user
        defer.returnValue(user)
