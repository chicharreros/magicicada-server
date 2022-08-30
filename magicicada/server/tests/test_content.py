# Copyright 2008-2015 Canonical
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

"""Test content operations."""

import logging
import os
import uuid
import zlib
from functools import partial
from unittest import mock

from magicicadaprotocol import (
    request,
    client as sp_client,
    errors as protoerrors,
    protocol_pb2,
)
from twisted.internet import defer, reactor, threads, task, address
from twisted.trial.unittest import TestCase
from twisted.test.proto_helpers import StringTransport

from magicicada import settings
from magicicada.filesync import errors
from magicicada.filesync.models import StorageObject, StorageUser
from magicicada.server import server, diskstorage
from magicicada.server.content import (
    BaseUploadJob,
    BogusUploadJob,
    DBUploadJob,
    ContentManager,
    UploadJob,
    User,
    logger,
)
from magicicada.server.testing.testcase import (
    EMPTY_HASH,
    BufferedConsumer,
    TestWithDatabase,
    get_hash,
    get_magic_hash,
    get_put_content_params,
)


class TestGetContent(TestWithDatabase):
    """Test get_content command."""

    @defer.inlineCallbacks
    def test_getcontent_unknown(self):
        """Get the content from an unknown file."""
        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        d = client.get_content(request.ROOT, root_id, request.UNKNOWN_HASH)
        yield self.assertFails(d, 'NOT_AVAILABLE')

    @defer.inlineCallbacks
    def test_getcontent_no_content(self):
        """Get the contents a file with no content"""
        file_id = self.usr0.root.make_file("file").id

        client = yield self.get_client_helper(auth_token="open sesame")
        yield client.get_root()
        d = client.get_content(request.ROOT, file_id, '')
        yield self.assertFails(d, 'DOES_NOT_EXIST')

    @defer.inlineCallbacks
    def test_getcontent_not_owned_file(self):
        """Get the contents of a directory not owned by the user."""
        # create another user
        dir_id = self.usr1.root.make_subdirectory("subdir1").id

        # try to get the content of the directory with a different user
        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        yield client.make_file(request.ROOT, root_id, "foo")
        d = client.get_content(request.ROOT, dir_id, EMPTY_HASH)
        yield self.assertFails(d, 'DOES_NOT_EXIST')

    @defer.inlineCallbacks
    def test_getcontent_empty_file(self):
        """Make sure get content of empty files work."""
        data = b""

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "foo")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)
        result = yield client.get_content(
            params['share'], params['node'], EMPTY_HASH
        )
        self.assertEqual(zlib.decompress(result.data), data)

    @defer.inlineCallbacks
    def test_getcontent_file(self, check_file_content=True):
        """Get the content from a file."""
        data = b"*" * 100000

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        req = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        if check_file_content:
            self.assertEqual(zlib.decompress(req.data), data)

    @defer.inlineCallbacks
    def test_getcontent_cancel_after_other_request(self):
        """Simulate getting the cancel after another request in the middle."""
        data = os.urandom(100000)

        # this is for the get content to send a lot of BYTES (which will leave
        # time for the cancel to arrive to the server) but not needing to
        # actually *put* a lot of content
        server.BytesMessageProducer.payload_size = 500

        # replace handle_GET_CONTENT so we can get the request reference
        def handle_get_content(s, message):
            """Handle GET_CONTENT message."""
            request = server.GetContentResponse(s, message)
            self.request = request
            request.start()

        self.patch(
            server.StorageServer, 'handle_GET_CONTENT', handle_get_content
        )

        # monkeypatching to simulate that we're not working on that request
        # at the moment the CANCEL arrives
        orig_lie_method = server.GetContentResponse.processMessage

        def lie_about_current(self, *a, **k):
            """Lie that the request is not started."""
            self.started = False
            orig_lie_method(self, *a, **k)
            self.started = True
            server.GetContentResponse.processMessage = orig_lie_method

        server.GetContentResponse.processMessage = lie_about_current

        # monkeypatching to assure that the lock is released
        orig_check_method = server.GetContentResponse._processMessage

        def middle_check(innerself, *a, **k):
            """Check that the lock is released."""
            orig_check_method(innerself, *a, **k)
            self.assertFalse(innerself.protocol.request_locked)
            server.GetContentResponse._processMessage = orig_check_method

            server.GetContentResponse._processMessage = middle_check

        d = defer.Deferred()

        def cancel(*args):
            if d.called:
                return

            d.callback(True)

            def _cancel(_):
                """Directly cancel the server request."""
                m = protocol_pb2.Message()
                m.id = self.request.id
                m.type = protocol_pb2.Message.CANCEL_REQUEST
                self.request.cancel_message = m
                self.request.processMessage(m)

            d.addCallbacks(_cancel)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        gc_request = client.get_content_request(
            params['share'],
            params['node'],
            params['new_hash'],
            offset=0,
            callback=cancel,
        )
        yield d
        yield self.assertFailure(
            gc_request.deferred, protoerrors.RequestCancelledError
        )

    @defer.inlineCallbacks
    def test_getcontent_cancel_inside_download(self):
        """Start to get the content from a file, and cancel in the middle."""
        data = os.urandom(100000)

        # this is for the get content to send a lot of BYTES (which will leave
        # time for the cancel to arrive to the server) but not needing to
        # actually *put* a lot of content
        server.BytesMessageProducer.payload_size = 500

        # replace handle_GET_CONTENT so we can get the request reference
        def handle_get_content(s, message):
            """Handle GET_CONTENT message."""
            request = server.GetContentResponse(s, message)
            self.request = request
            request.start()

        self.patch(
            server.StorageServer, 'handle_GET_CONTENT', handle_get_content
        )

        # monkeypatching to assure that the producer was cancelled
        orig_method = server.GetContentResponse.unregisterProducer

        def check(*a, **k):
            """Assure that it was effectively cancelled."""
            orig_method(*a, **k)
            server.GetContentResponse.unregisterProducer = orig_method

        server.GetContentResponse.unregisterProducer = check

        d = defer.Deferred()

        def cancel(*args):
            if d.called:
                return

            d.callback(True)

            def _cancel(_):
                """Directly cancel the server request."""
                m = protocol_pb2.Message()
                m.id = self.request.id
                m.type = protocol_pb2.Message.CANCEL_REQUEST
                self.request.cancel_message = m
                self.request.processMessage(m)

            d.addCallbacks(_cancel)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        gc_request = client.get_content_request(
            params['share'], params['node'], params['new_hash'], 0, cancel
        )
        yield d
        yield self.assertFailure(
            gc_request.deferred, protoerrors.RequestCancelledError
        )

    @defer.inlineCallbacks
    def test_getcontent_cancel_after_download(self):
        """Start to get the content from a file, and cancel in the middle"""
        data = b"*" * 100000

        client = yield self.get_client_helper(auth_token="open sesame")

        d = defer.Deferred()
        received = []

        def cancel(newdata):
            received.append(newdata)
            if zlib.decompress(b''.join(received)) != data:
                return
            # got everything, now generate the cancel
            if d.called:
                self.fail('Should not be called again, already cancelled!')
            d.callback(True)

        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        gc_request = client.get_content_request(
            params['share'], params['node'], params['new_hash'], 0, cancel
        )
        yield d
        yield gc_request.cancel()
        yield gc_request.deferred

    @defer.inlineCallbacks
    def test_getcontent_doesnt_exist(self):
        """Get the content from an unexistent node."""

        client = yield self.get_client_helper(auth_token="open sesame")
        yield client.get_root()
        d = client.get_content(request.ROOT, uuid.uuid4(), EMPTY_HASH)
        yield self.assertFails(d, 'DOES_NOT_EXIST')

    @defer.inlineCallbacks
    def test_when_to_release(self):
        """GetContent should assign resources before release."""
        storage_server = self.service.factory.buildProtocol('addr')
        producer = mock.Mock(deferred=defer.Deferred(), name='producer')
        node = mock.Mock(
            deflated_size=0, size=0, content_hash='hash', crc32=0, name='node'
        )
        node.get_content.return_value = defer.succeed(producer)

        user = mock.Mock(username='', name='user')
        user.get_node.return_value = defer.succeed(node)
        storage_server.user = user

        message = mock.Mock(name='message')
        share_id = uuid.uuid4()
        message.get_content.share = str(share_id)

        self.patch(server.GetContentResponse, 'sendMessage', lambda *a: None)
        gc = server.GetContentResponse(storage_server, message)
        gc.id = 321

        # when GetContentResponse calls protocol.release(), it already
        # must have assigned the producer
        assigned = []
        storage_server.release = lambda a: assigned.append(gc.message_producer)
        yield gc._start()

        self.assertNotEqual(assigned[0], None)
        user.get_node.assert_called_once_with(
            share_id, message.get_content.node, message.get_content.hash
        )
        node.get_content.assert_called_once_with(
            user=user,
            previous_hash=message.get_content.hash,
            start=message.get_content.offset,
        )
        producer.startProducing.assert_called_once_with(mock.ANY)


class TestPutContent(TestWithDatabase):
    """Test put_content command."""

    def setUp(self):
        """Set up."""
        d = super(TestPutContent, self).setUp()
        self.handler = self.add_memento_handler(server.logger, level=0)
        return d

    @defer.inlineCallbacks
    def test_putcontent_cancel(self):
        """Test putting content to a file and cancelling it."""
        data = os.urandom(300000)

        def test_done(request):
            d = defer.Deferred()
            if request.cancelled and request.finished:
                d.callback(True)
            else:
                reactor.callLater(0.1, test_done, request)
            return d

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        pc_request = client.put_content_request(**params)
        pc_request.cancel()
        yield self.assertFailure(
            pc_request.deferred, protoerrors.RequestCancelledError
        )

        yield test_done(pc_request)

    @defer.inlineCallbacks
    def test_putcontent_cancel_after(self):
        """Test putting content to a file and cancelling it after finished."""
        data = os.urandom(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        pc_request = client.put_content_request(**params)
        yield pc_request.deferred
        yield pc_request.cancel()

    @defer.inlineCallbacks
    def test_putcontent_cancel_middle(self):
        """Test putting content to a file and cancelling it in the middle."""
        size = int(settings.STORAGE_CHUNK_SIZE * 1.5)
        data = os.urandom(size)
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=size * 2
        )

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        real_fd_read = params['fd'].read

        notifs = []

        def cancel_and_read(request, amount):
            """If second read, cancel and trigger test."""
            notifs.append(amount)
            if len(notifs) == 2:
                request.cancel()
            if len(notifs) > 2:
                self.fail(ValueError("called beyond cancel!"))
            return real_fd_read(amount)

        pc_request = client.put_content_request(**params)
        pc_request.fd.read = partial(cancel_and_read, pc_request)
        yield self.assertFailure(
            pc_request.deferred, protoerrors.RequestCancelledError
        )

    @defer.inlineCallbacks
    def test_putcontent(self, num_files=1, size=300000):
        """Test putting content to a file."""
        data = os.urandom(size)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # hook to test stats
        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)

        for i in range(num_files):
            fname = 'hola_%d' % i
            mkfile_req = yield client.make_file(request.ROOT, root_id, fname)
            params = get_put_content_params(data, node=mkfile_req.new_id)
            yield client.put_content(**params)
            try:
                self.usr0.volume().get_content(params['new_hash'])
            except errors.DoesNotExist:
                raise ValueError("content blob is not there")

            # check upload stat and the offset sent
            self.assertTrue(('UploadJob.upload', 0) in gauge)
            self.assertTrue(('UploadJob.upload.begin', 1) in meter)
            self.handler.assert_debug("UploadJob begin content from offset 0")

    @defer.inlineCallbacks
    def test_put_content_in_not_owned_file(self):
        """Test putting content in other user file"""
        # create another user
        file_id = self.usr1.root.make_file("a_dile").id
        # try to put the content in this file, but with other user
        data = os.urandom(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        params = get_put_content_params(data, node=file_id)
        d = client.put_content(**params)
        yield self.assertFails(d, 'DOES_NOT_EXIST')

    @defer.inlineCallbacks
    def test_putcontent_duplicated(self):
        """Test putting the same content twice"""
        # check that only one object will be stored
        called = []
        ds = self.service.factory.diskstorage
        orig_put = ds.put
        ds.put = lambda *a: called.append(True) or orig_put(*a)
        yield self.test_putcontent(num_files=2)
        self.assertEqual(len(called), 1)

    @defer.inlineCallbacks
    def test_putcontent_twice_simple(self):
        """Test putting content twice."""
        data = b"*" * 100

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)
        yield client.put_content(**params)

        def check_file():
            try:
                self.usr0.volume().get_content(params['new_hash'])
            except errors.DoesNotExist:
                raise ValueError("content blob is not there")

        yield threads.deferToThread(check_file)

    @defer.inlineCallbacks
    def test_putcontent_twice_samefinal(self):
        """Test putting content twice."""
        data = b"*" * 100

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)
        # don't care about previous hash, as long the final hash is ok
        yield client.put_content(**params)

        def check_file():
            try:
                self.usr0.volume().get_content(params['new_hash'])
            except errors.DoesNotExist:
                raise ValueError("content blob is not there")

        yield threads.deferToThread(check_file)

    @defer.inlineCallbacks
    def _put_content_bad_params(self, error_class, data=None, **kwargs):
        """Base function to create tests of wrong hints."""
        if data is None:
            data = b"*" * 1000

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "foo")

        params = get_put_content_params(data, node=mkfile_req.new_id, **kwargs)
        yield self.assertFailure(client.put_content(**params), error_class)

    def test_putcontent_bad_prev_hash(self):
        """Test wrong prev hash hint."""
        return self._put_content_bad_params(
            previous_hash="sha1:wrong", error_class=protoerrors.ConflictError
        )

    def test_putcontent_bad_hash(self):
        """Test wrong hash hint."""
        return self._put_content_bad_params(
            new_hash="sha1:notthehash", error_class=protoerrors.ProtocolError
        )

    def test_putcontent_bad_c3c32(self):
        """Test wrong crc32 hint."""
        return self._put_content_bad_params(
            crc32=100, error_class=protoerrors.UploadCorruptError
        )

    def test_putcontent_bad_size(self):
        """Test wrong size hint."""
        return self._put_content_bad_params(
            size=20, error_class=protoerrors.UploadCorruptError
        )

    @defer.inlineCallbacks
    def test_putcontent_notify(self):
        """Make sure put_content generates a notification."""
        data = b"*" * 100000

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "foo")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        # XXX where is the notification???

    @defer.inlineCallbacks
    def test_putcontent_nofile(self):
        """Test putting content to an inexistent file."""

        client = yield self.get_client_helper(auth_token="open sesame")
        kwargs = get_put_content_params(
            share=request.ROOT,
            node=uuid.uuid4(),
            previous_hash='',
            new_hash='',
            crc32=0,
            size=0,
            deflated_size=0,
            fd='',
        )
        d = client.put_content(**kwargs)
        yield self.assertFails(d, 'DOES_NOT_EXIST')

    def test_remove_uploadjob_deleted_file(self):
        """Make sure we dont raise exceptions on deleted files."""
        so_file = self.usr0.root.make_file("foobar")
        upload_job = so_file.make_uploadjob(
            so_file.content_hash, "sha1:100", 0, 100
        )
        # kill file
        so_file.delete()
        upload_job.delete()

    @defer.inlineCallbacks
    def test_putcontent_conflict_middle(self):
        """Test putting content to a file and changing it in the middle."""
        data = os.urandom(3000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        real_fd_read = params['fd'].read

        def make_conflict_and_read(amount):
            """Change the file when this client starts uploading it."""
            # modify the file and cause a conflict
            hash_value = get_hash(b'randomdata')
            filenode = self.usr0.get_node(params['node'])
            filenode.make_content(
                filenode.content_hash, hash_value, 32, 1000, 1000, uuid.uuid4()
            )
            return real_fd_read(amount)

        params['fd'].read = make_conflict_and_read
        pc_request = client.put_content_request(**params)
        yield self.assertFailure(
            pc_request.deferred, protoerrors.ConflictError
        )

    @defer.inlineCallbacks
    def test_putcontent_update_used_bytes(self):
        """Putting content to a file updates user's used bytes."""
        data = os.urandom(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola_1')

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        def check_used_bytes():
            quota = StorageUser.objects.get(id=self.usr0.id)
            self.assertEqual(params['size'], quota.used_storage_bytes)

        yield threads.deferToThread(check_used_bytes)

    @defer.inlineCallbacks
    def test_putcontent_quota_exceeded(self):
        """Test the QuotaExceeded handling."""
        StorageUser.objects.filter(id=self.usr0.id).update(max_storage_bytes=1)
        e = yield self.assertFailure(
            self.test_putcontent(), protoerrors.QuotaExceededError
        )
        self.assertEqual(e.free_bytes, 1)
        self.assertEqual(e.share_id, request.ROOT)

    @defer.inlineCallbacks
    def test_putcontent_generations(self):
        """Put content on a file and receive new generation."""
        data = os.urandom(30)

        client = yield self.get_client_helper(auth_token="open sesame")
        # create the dir
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        # put content and check
        params = get_put_content_params(data, node=mkfile_req.new_id)
        putc_req = yield client.put_content(**params)
        self.assertEqual(
            putc_req.new_generation, mkfile_req.new_generation + 1
        )

    @defer.inlineCallbacks
    def test_putcontent_corrupt(self):
        """Put content on a file with corrupt data."""
        data = os.urandom(30)
        size = len(data) + 10

        client = yield self.get_client_helper(auth_token="open sesame")

        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)

        # create the dir
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        # put content and check
        params = get_put_content_params(
            data, node=mkfile_req.new_id, size=size
        )
        yield self.assertFailure(
            client.put_content(**params), protoerrors.UploadCorruptError
        )
        self.handler.assert_debug('UploadCorrupt', str(size))

    @defer.inlineCallbacks
    def test_when_to_release(self):
        """PutContent should assign resources before release."""
        storage_server = self.service.factory.buildProtocol('addr')
        upload_job = mock.Mock(
            deferred=defer.succeed(None),
            offset=0,
            upload_id="hola",
            storage_key="storage_key",
        )
        upload_job.connect.return_value = defer.succeed(None)

        user = mock.Mock(username='')
        user.get_upload_job.return_value = defer.succeed(upload_job)
        storage_server.user = user

        share_id = uuid.uuid4()
        message = mock.Mock()
        message.put_content.share = str(share_id)

        self.patch(server.PutContentResponse, 'sendMessage', lambda *r: None)
        pc = server.PutContentResponse(storage_server, message)
        pc.id = 123

        # when PutContentResponse calls protocol.release(), it already
        # must have assigned the upload job
        assigned = []
        storage_server.release = lambda r: assigned.append(pc.upload_job)

        yield pc._start()

        self.assertEqual(assigned[0], upload_job)
        user.get_upload_job.assert_called_once_with(
            share_id,
            message.put_content.node,
            message.put_content.previous_hash,
            message.put_content.hash,
            message.put_content.crc32,
            message.put_content.size,
            message.put_content.deflated_size,
            session_id=mock.ANY,
            magic_hash=message.put_content.magic_hash,
            upload_id=message.put_content.upload_id,
        )
        upload_job.connect.assert_called_once_with()

    @defer.inlineCallbacks
    def test_putcontent_bad_data(self):
        """Test putting bad data to a file."""
        data = os.urandom(300000)
        # insert bad data in the deflated_data
        deflated_data = b'break it'

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(
            request.ROOT, root_id, 'a_file.txt'
        )

        params = get_put_content_params(
            data, node=mkfile_req.new_id, deflated_data=deflated_data
        )
        d = client.put_content(**params)
        yield self.assertFails(d, 'UPLOAD_CORRUPT')

    def _get_users(self, max_storage_bytes):
        """Get both storage and content users."""
        s_user = self.make_user(max_storage_bytes=max_storage_bytes)
        c_user = User(
            self.service.factory.content,
            s_user.id,
            s_user.root_volume_id,
            s_user.username,
            s_user.visible_name,
        )
        return s_user, c_user

    @defer.inlineCallbacks
    def test_putcontent_handle_error_in_uploadjob_deferred(self):
        """PutContent should handle errors in upload_job.deferred.

        Test that a PutContent fails and is terminated as soon we get an
        error, instead of wait until the full upload is done.
        """
        chunk_size = settings.STORAGE_CHUNK_SIZE
        user, content_user = self._get_users(chunk_size**2)
        # create the file
        a_file = user.root.make_file("A new file")
        # build the upload data
        size = int(chunk_size * 1.5)
        data = os.urandom(size)
        params = get_put_content_params(data, node=str(a_file.id), size=size)

        # get a server instance
        storage_server = self.service.factory.buildProtocol('addr')
        storage_server.transport = StringTransport()
        # twisted 10.0.0 (lucid) returns an invalid peer in transport.getPeer()
        peerAddr = address.IPv4Address('TCP', '192.168.1.1', 54321)
        storage_server.transport.peerAddr = peerAddr
        storage_server.user = content_user
        storage_server.working_caps = server.PREFERRED_CAP

        message = protocol_pb2.Message()
        message.put_content.share = params['share']
        message.put_content.node = params['node']
        message.put_content.previous_hash = params['previous_hash']
        message.put_content.hash = params['new_hash']
        message.put_content.crc32 = params['crc32']
        message.put_content.size = params['size']
        message.put_content.deflated_size = params['deflated_size']
        message.id = 10
        message.type = protocol_pb2.Message.PUT_CONTENT

        begin_d = defer.Deferred()
        self.patch(
            server.PutContentResponse,
            'sendMessage',
            lambda *r: begin_d.callback(None),
        )
        error_d = defer.Deferred()
        self.patch(
            server.PutContentResponse,
            'sendError',
            lambda _, error, comment: error_d.callback((error, comment)),
        )
        pc = server.PutContentResponse(storage_server, message)
        pc.id = 123

        # make the consumer crash
        def crash(*_):
            """Make it crash."""
            raise ValueError("test problem")

        self.patch(diskstorage.FileWriterConsumer, 'write', crash)

        # start uploading
        pc.start()
        # only one packet, in order to trigger the _start_receiving code path
        yield begin_d
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.BYTES
        msg.bytes.bytes = params['fd'].read(65536)
        pc._processMessage(msg)
        # check the error
        error_type, comment = yield error_d
        self.assertEqual(error_type, protocol_pb2.Error.TRY_AGAIN)
        self.assertEqual(comment, 'TryAgain (ValueError: test problem)')
        # check that the put_content response is properly termintated
        yield pc.deferred
        self.assertTrue(pc.finished)

    @defer.inlineCallbacks
    def test_putcontent_reuse_content_different_user_no_magic(self):
        """Different user with no magic hash: upload everything again."""
        data = os.urandom(30000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # first file, it should ask for all the content not magic here
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=None
        )
        yield client.put_content(**params)

        # startup another client for a different user
        client = yield self.get_client_helper(auth_token="usr3")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'chau')

        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=None
        )
        yield client.put_content(**params)

        # the BEGIN_CONTENT should be from 0
        message = [
            m
            for m in client.messages
            if m.type == protocol_pb2.Message.BEGIN_CONTENT
        ][0]
        self.assertEqual(message.begin_content.offset, 0)

        # check all went ok by getting the content
        get_req = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        self.assertEqual(zlib.decompress(get_req.data), data)

    @defer.inlineCallbacks
    def test_putcontent_reuse_content_different_user_with_magic(self):
        """Different user but with magic hash: don't upload all again."""
        data = os.urandom(30000)
        mhash_value = get_magic_hash(data)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # first file, it should ask for all the content not magic here
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=None
        )
        yield client.put_content(**params)

        # hook to test stats
        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)

        # startup another client for a different user.
        client = yield self.get_client_helper(auth_token="usr3")
        root_id = yield client.get_root()

        mkfile_req = yield client.make_file(request.ROOT, root_id, 'chau')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=mhash_value
        )
        resp = yield client.put_content(**params)

        # the response should have the new_generation
        self.assertEqual(mkfile_req.new_generation + 1, resp.new_generation)

        # the BEGIN_CONTENT should be from the end
        message = [
            m
            for m in client.messages
            if m.type == protocol_pb2.Message.BEGIN_CONTENT
        ][0]
        self.assertEqual(message.begin_content.offset, params['deflated_size'])

        # check all went ok by getting the content
        get_req = yield client.get_content(
            params['share'], mkfile_req.new_id, params['new_hash']
        )
        self.assertEqual(zlib.decompress(get_req.data), data)
        # check reused content stat
        self.assertIn(
            ('MagicUploadJob.upload', params['deflated_size']), gauge
        )
        self.assertIn(('MagicUploadJob.upload.begin', 1), meter)

    @defer.inlineCallbacks
    def test_putcontent_reuse_content_same_user_no_magic(self):
        """Same user doesn't upload everything even with no hash."""
        data = os.urandom(30000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # first file, it should ask for all the content not magic here
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=None
        )
        yield client.put_content(**params)

        # the BEGIN_CONTENT should be from 0
        message = [
            m
            for m in client.messages
            if m.type == protocol_pb2.Message.BEGIN_CONTENT
        ][0]
        self.assertEqual(message.begin_content.offset, 0)

        # hook to test stats
        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)
        client.messages = []

        # other file but same content, still no magic
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'chau')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=None
        )
        resp = yield client.put_content(**params)

        # response has the new generation in it
        self.assertEqual(resp.new_generation, mkfile_req.new_generation + 1)

        # the BEGIN_CONTENT should be from the end
        message = [
            m
            for m in client.messages
            if m.type == protocol_pb2.Message.BEGIN_CONTENT
        ][0]
        self.assertEqual(message.begin_content.offset, params['deflated_size'])

        # check all went ok by getting the content
        get_req = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        self.assertEqual(zlib.decompress(get_req.data), data)
        # check reused content stat
        self.assertIn(
            ('MagicUploadJob.upload', params['deflated_size']), gauge
        )
        self.assertIn(('MagicUploadJob.upload.begin', 1), meter)

    @defer.inlineCallbacks
    def test_putcontent_reuse_content_same_user_with_magic(self):
        """Same user with magic hash: of course no new upload is needed."""
        data = os.urandom(30000)
        mhash_value = get_magic_hash(data)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # first file, it should ask for all the content not magic here
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=mhash_value
        )
        yield client.put_content(**params)

        # the BEGIN_CONTENT should be from 0
        message = [
            m
            for m in client.messages
            if m.type == protocol_pb2.Message.BEGIN_CONTENT
        ][0]
        self.assertEqual(message.begin_content.offset, 0)

        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)
        client.messages = []

        # another file but same content, still no upload
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'chau')
        params = get_put_content_params(
            data, node=mkfile_req.new_id, magic_hash=mhash_value
        )
        resp = yield client.put_content(**params)

        # response has the new generation in it
        self.assertEqual(resp.new_generation, mkfile_req.new_generation + 1)

        # the BEGIN_CONTENT should be from the end
        message = [
            m
            for m in client.messages
            if m.type == protocol_pb2.Message.BEGIN_CONTENT
        ][0]
        self.assertEqual(message.begin_content.offset, params['deflated_size'])

        # check all went ok by getting the content
        get_req = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        self.assertEqual(zlib.decompress(get_req.data), data)
        # check reused content stat
        self.assertIn(
            ('MagicUploadJob.upload', params['deflated_size']), gauge
        )
        self.assertIn(('MagicUploadJob.upload.begin', 1), meter)

    @defer.inlineCallbacks
    def test_putcontent_magic_hash(self):
        """Test that it calculated and stored the magic hash on put content."""
        data = os.urandom(30000)
        magic_hash_value = get_magic_hash(data)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        content_blob = self.usr0.volume().get_content(params['new_hash'])
        self.assertEqual(content_blob.magic_hash, magic_hash_value)

    @defer.inlineCallbacks
    def test_putcontent_blob_exists(self):
        """Test putting content with an existing blob (no magic)."""
        data = b"*" * 100
        params = get_put_content_params(data)
        # create the content blob without a magic hash in a different user.
        self.make_user('my_user', max_storage_bytes=2**20)
        self.usr3.make_filepath_with_content(
            settings.ROOT_USERVOLUME_PATH + "/file.txt",
            params['new_hash'],
            params['crc32'],
            params['size'],
            params['deflated_size'],
            uuid.uuid4(),
        )

        # overwrite UploadJob method to detect if it
        # uploaded stuff (it shouldn't)
        self.patch(
            BaseUploadJob,
            '_start_receiving',
            lambda s: defer.fail(Exception("This shouldn't be called")),
        )

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        # check it has content ok
        result = self.usr0.volume().get_content(params['new_hash'])
        self.assertEqual(result.hash, params['new_hash'])

    @defer.inlineCallbacks
    def test_put_content_on_a_dir_normal(self):
        """Test putting content in a dir."""
        data = os.urandom(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_dir(request.ROOT, root_id, "hola")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        d = client.put_content(**params)
        yield self.assertFailure(d, protoerrors.NoPermissionError)

    @defer.inlineCallbacks
    def test_put_content_on_a_dir_magic(self):
        """Test putting content in a dir."""
        data = os.urandom(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # create a normal file
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        # create a dir and trigger a putcontent that will use 'magic'
        mkfile_req = yield client.make_dir(request.ROOT, root_id, "chau")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        d = client.put_content(**params)
        yield self.assertFailure(d, protoerrors.NoPermissionError)


class TestMultipartPutContent(TestWithDatabase):
    """Test put_content using multipart command."""

    # override defaults set by TestWithDatabase.setUp.
    STORAGE_CHUNK_SIZE = 1024

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        self.handler = self.add_memento_handler(server.logger, level=0)
        yield super(TestMultipartPutContent, self).setUp()

    def get_data(self, size):
        """Return random data of the specified size.

        This method is overriden in the next testcase.

        """
        return os.urandom(size)

    @defer.inlineCallbacks
    def _test_putcontent(self, num_files=1, size=1024 * 1024):
        """Test putting content to a file."""
        data = self.get_data(size)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        # hook to test stats
        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)

        for i in range(num_files):
            fname = 'hola_%d' % i
            mkfile_req = yield client.make_file(request.ROOT, root_id, fname)
            params = get_put_content_params(data, node=mkfile_req.new_id)
            yield client.put_content(**params)

            self.assertRaises(
                errors.DoesNotExist,
                self.usr0.volume().get_content,
                params['new_hash'],
            )
            # check upload stat and log, with the offset sent
            self.assertIn(('UploadJob.upload', 0), gauge)
            self.assertIn(('UploadJob.upload.begin', 1), meter)
            self.handler.assert_debug("UploadJob begin content from offset 0")

    @defer.inlineCallbacks
    def test_resume_putcontent(self):
        """Test that the client can resume a putcontent request."""
        self.patch(settings, 'STORAGE_CHUNK_SIZE', 1024 * 64)
        size = 2 * 1024 * 512
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=size * 2
        )
        data = self.get_data(size)

        # setup
        client = yield self.get_client_helper(auth_token="open sesame")

        # hook to test stats
        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)

        # patch BytesMessageProducer in order to avoid sending the whole file
        orig_go = sp_client.BytesMessageProducer.go
        called = []

        def my_go(myself):
            data = myself.fh.read(request.MAX_PAYLOAD_SIZE)
            if len(called) >= 1:
                myself.request.error(EOFError("finish!"))
                myself.producing = False
                myself.finished = True
                return
            called.append(1)
            if data:
                response = protocol_pb2.Message()
                response.type = protocol_pb2.Message.BYTES
                response.bytes.bytes = data
                myself.request.sendMessage(response)
                reactor.callLater(0.1, myself.go)

        self.patch(sp_client.BytesMessageProducer, 'go', my_go)
        # we are authenticated
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola_12')
        upload_info = []
        params = get_put_content_params(
            data,
            node=mkfile_req.new_id,
            upload_id_cb=lambda *a: upload_info.append(a),
        )
        yield self.assertFailure(client.put_content(**params), EOFError)

        # check upload stat and log, with the offset sent
        self.assertTrue(('UploadJob.upload', 0) in gauge)
        self.assertTrue(('UploadJob.upload.begin', 1) in meter)
        self.handler.assert_debug("UploadJob begin content from offset 0")

        # connect a new client and try to upload again
        client = yield self.get_client_helper(auth_token="open sesame")

        # restore patched client
        self.patch(sp_client.BytesMessageProducer, 'go', orig_go)

        processMessage = sp_client.PutContent.processMessage

        begin_content_d = defer.Deferred()

        def new_processMessage(myself, message):
            if message.type == protocol_pb2.Message.BEGIN_CONTENT:
                begin_content_d.callback(message)
            # call the original processMessage method
            return processMessage(myself, message)

        self.patch(sp_client.PutContent, 'processMessage', new_processMessage)
        params = get_put_content_params(
            data, node_id=mkfile_req.new_id, upload_id=str(upload_info[0][0])
        )
        req = sp_client.PutContent(client, **params)
        req.start()
        yield req.deferred

        message = yield begin_content_d
        offset_sent = message.begin_content.offset
        try:
            node_content = self.usr0.volume().get_content(params['new_hash'])
        except errors.DoesNotExist:
            raise ValueError("content blob is not there")
        self.assertEqual(node_content.crc32, params['crc32'])
        self.assertEqual(node_content.size, params['size'])
        self.assertEqual(node_content.deflated_size, params['deflated_size'])
        self.assertEqual(node_content.hash, params['new_hash'])
        self.assertTrue(node_content.storage_key)

        # check upload stat and log, with the offset sent, second time it
        # resumes from the first chunk
        self.assertTrue(('UploadJob.upload', offset_sent) in gauge)
        self.handler.assert_debug(
            "UploadJob begin content from offset %d" % offset_sent
        )

    @defer.inlineCallbacks
    def test_resume_putcontent_invalid_upload_id(self):
        """Client try to resume with an invalid upload_id.

        It receives a new upload_id.
        """
        self.patch(settings, 'STORAGE_CHUNK_SIZE', 1024 * 32)
        size = 2 * 1024 * 128
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=size * 2
        )
        data = self.get_data(size)
        # hook to test stats
        meter = []
        self.service.factory.metrics.meter = lambda *a: meter.append(a)
        gauge = []
        self.service.factory.metrics.gauge = lambda *a: gauge.append(a)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        upload_info = []
        params = get_put_content_params(
            data,
            node=mkfile_req.new_id,
            upload_id="invalid id",
            upload_id_cb=lambda *a: upload_info.append(a),
        )
        yield client.put_content(**params)

        self.assertIn(('UploadJob.upload', 0), gauge)
        self.assertIn(('UploadJob.upload.begin', 1), meter)
        self.handler.assert_debug("UploadJob begin content from offset 0")
        self.assertEqual(len(upload_info), 1)
        upload_id, start_from = upload_info[0]
        self.assertIsInstance(uuid.UUID(upload_id), uuid.UUID)
        self.assertEqual(start_from, 0)

    @defer.inlineCallbacks
    def test_putcontent_magic_hash(self):
        """Test that it calculated and stored the magic hash on put content."""
        data = self.get_data(30000)
        magic_hash_value = get_magic_hash(data)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        content_blob = self.usr0.volume().get_content(params['new_hash'])
        self.assertEqual(content_blob.magic_hash, magic_hash_value)

    @defer.inlineCallbacks
    def test_putcontent_corrupt(self):
        """Put content on a file with corrupt data."""
        self.patch(settings, 'STORAGE_CHUNK_SIZE', 1024 * 64)
        size = 2 * 1024 * 512
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=size * 2 + 10
        )
        data = self.get_data(size)
        size = len(data) + 10

        client = yield self.get_client_helper(auth_token="open sesame")
        # create the dir
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(
            data, node=mkfile_req.new_id, size=size
        )
        # put content and check
        putc_req = client.put_content_request(**params)
        yield self.assertFailure(
            putc_req.deferred, protoerrors.UploadCorruptError
        )

        self.handler.assert_debug('UploadCorrupt', str(size))
        # check that the uploadjob was deleted.
        node = self.usr0.volume(None).get_node(params['node'])
        self.assertRaises(
            errors.DoesNotExist,
            node.get_multipart_uploadjob,
            putc_req.upload_id,
            params['new_hash'],
            params['crc32'],
        )

    @defer.inlineCallbacks
    def test_putcontent_blob_exists(self):
        """Test putting content with an existing blob (no magic)."""
        data = self.get_data(1024 * 20)
        params = get_put_content_params(data)
        # create the content blob without a magic hash in a different user.
        self.make_user('my_user', max_storage_bytes=2**20)
        self.usr3.make_filepath_with_content(
            settings.ROOT_USERVOLUME_PATH + "/file.txt",
            params['new_hash'],
            params['crc32'],
            params['size'],
            params['deflated_size'],
            uuid.uuid4(),
        )

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        def check_file():
            self.usr0.volume().get_content(params['new_hash'])

        yield threads.deferToThread(check_file)

    @defer.inlineCallbacks
    def test_put_content_on_a_dir(self):
        """Test putting content in a dir."""
        data = self.get_data(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_dir(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        d = client.put_content(**params)
        yield self.assertFailure(d, protoerrors.NoPermissionError)


class TestMultipartPutContentGoodCompression(TestMultipartPutContent):
    """TestMultipartPutContent using data with a good compression ratio."""

    def get_data(self, size):
        """Return zero data of the specified size."""
        with open('/dev/zero', 'rb') as source:
            return source.read(size) + os.urandom(size)


class TestPutContentInternalError(TestWithDatabase):
    """Test put_content command."""

    @defer.inlineCallbacks
    def test_putcontent_handle_internal_error_in_uploadjob_deferred(self):
        """PutContent should handle errors in upload_job.deferred.

        Test that a PutContent fails and is terminated as soon we get an
        error, instead of wait until the full upload is done.
        """
        chunk_size = settings.STORAGE_CHUNK_SIZE
        user = self.make_user(max_storage_bytes=chunk_size**2)
        content_user = User(
            self.service.factory.content,
            user.id,
            user.root_volume_id,
            user.username,
            user.visible_name,
        )
        # create the file
        a_file = user.root.make_file("A new file")
        # build the upload data
        data = os.urandom(int(chunk_size * 1.5))
        params = get_put_content_params(data, node=str(a_file.id))

        # get a server instance
        storage_server = self.service.factory.buildProtocol('addr')
        storage_server.transport = StringTransport()
        # twisted 10.0.0 (lucid) returns an invalid peer in transport.getPeer()
        peerAddr = address.IPv4Address('TCP', '192.168.1.1', 54321)
        storage_server.transport.peerAddr = peerAddr
        storage_server.user = content_user
        storage_server.working_caps = server.PREFERRED_CAP

        message = protocol_pb2.Message()
        message.put_content.share = params['share']
        message.put_content.node = params['node']
        message.put_content.previous_hash = params['previous_hash']
        message.put_content.hash = params['new_hash']
        message.put_content.crc32 = params['crc32']
        message.put_content.size = params['size']
        message.put_content.deflated_size = params['deflated_size']
        message.id = 10
        message.type = protocol_pb2.Message.PUT_CONTENT

        begin_d = defer.Deferred()
        self.patch(
            server.PutContentResponse,
            'sendMessage',
            lambda *r: begin_d.callback(None),
        )
        error_d = defer.Deferred()
        self.patch(
            server.PutContentResponse,
            'sendError',
            lambda _, error, comment: error_d.callback((error, comment)),
        )
        pc = server.PutContentResponse(storage_server, message)
        pc.id = 123

        # make the consumer crash
        def crash(*_):
            """Make it crash."""
            raise ValueError("Fail!")

        self.patch(BaseUploadJob, 'add_data', crash)

        # start uploading
        pc.start()
        # only one packet, in order to trigger the _start_receiving code
        # path.
        yield begin_d
        msg = protocol_pb2.Message()
        msg.type = protocol_pb2.Message.BYTES
        msg.bytes.bytes = params['fd'].read(65536)
        pc._processMessage(msg)
        # check the error
        error_type, comment = yield error_d
        self.assertEqual(error_type, protocol_pb2.Error.INTERNAL_ERROR)
        self.assertEqual(comment, "Fail!")
        # check that the put_content response is properly termintated
        # and the server is shuttdown.
        yield storage_server.wait_for_shutdown()
        self.assertTrue(pc.finished)
        self.assertTrue(storage_server.shutting_down)

    @defer.inlineCallbacks
    def test_putcontent_handle_error_in_sendok(self):
        """PutContent should handle errors in send_ok."""
        data = os.urandom(1000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        def breakit(*a):
            """Raise an exception to simulate the method call failed."""
            raise MemoryError("Simulated ME")

        self.patch(server.PutContentResponse, "_commit_uploadjob", breakit)

        params = get_put_content_params(data, node=mkfile_req.new_id)
        d = client.put_content(**params)
        yield self.assertFailure(d, protoerrors.InternalError)


class TestChunkedContent(TestWithDatabase):
    """Test operation on large data that requires multiple chunks."""

    STORAGE_CHUNK_SIZE = 1024 * 1024

    @defer.inlineCallbacks
    def test_putcontent_chunked(self, put_fail=False, get_fail=False):
        """Checks a chunked putcontent."""
        size = int(settings.STORAGE_CHUNK_SIZE * 1.5)
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=size * 2
        )
        data = os.urandom(size)

        def _put_fail():
            # this will allow the server to split the data into chunks but
            # fail to put it back together in a single blob
            if put_fail:
                # make the consumer crash
                def crash(*_):
                    """Make it crash."""
                    raise ValueError("test problem")

                self.patch(diskstorage.FileWriterConsumer, 'write', crash)

        def _get_fail():
            # this will allow the server to split the data into chunks but
            # fail to put it back together in a single blob
            if get_fail:
                # make the producer crash
                orig_func = diskstorage.FileReaderProducer.startProducing

                def mitm(*a):
                    """MITM to return a failed deferred, not real one."""
                    deferred = orig_func(*a)
                    deferred.errback(ValueError())
                    return deferred

                self.patch(
                    diskstorage.FileReaderProducer, 'startProducing', mitm
                )

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        _put_fail()
        _get_fail()

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        content = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        if not put_fail and not get_fail:
            self.assertEqual(zlib.decompress(content.data), data)

    def test_putcontent_chunked_putfail(self):
        """Assures that chunked putcontent fails with "try again"."""
        d = self.test_putcontent_chunked(put_fail=True)
        return self.assertFails(d, 'TRY_AGAIN')

    def test_putcontent_chunked_getfail(self):
        """Assures that chunked putcontent fails with "try again"."""
        d = self.test_putcontent_chunked(get_fail=True)
        return self.assertFails(d, 'NOT_AVAILABLE')

    @defer.inlineCallbacks
    def test_deferred_add_part_to_uj(self):
        """Check that parts are added to upload job only after a limit."""
        size = int(settings.STORAGE_CHUNK_SIZE * 2.5)
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=size * 2
        )
        data = os.urandom(size)

        recorded_calls = []
        orig_call = self.service.rpc_dal.call

        def recording_call(method, **parameters):
            if method == 'add_part_to_uploadjob':
                recorded_calls.append(parameters)
            return orig_call(method, **parameters)

        self.service.rpc_dal.call = recording_call

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        # check calls; there should be only 2, as size == chunk size * 2.5
        self.assertEqual(len(recorded_calls), 2)


class UserTest(TestWithDatabase):
    """Test User functionality."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(UserTest, self).setUp()

        # user and root to use in the tests
        u = self.suser = self.make_user(max_storage_bytes=64**2)
        self.user = User(
            self.service.factory.content,
            u.id,
            u.root_volume_id,
            u.username,
            u.visible_name,
        )

    @defer.inlineCallbacks
    def test_make_file_node_with_gen(self):
        """Test that make_file returns a node with generation in it."""
        root_id, root_gen = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)
        _, generation, _ = yield self.user.make_file(
            volume_id, root_id, "name", True
        )
        self.assertEqual(generation, root_gen + 1)

    @defer.inlineCallbacks
    def test_make_dir_node_with_gen(self):
        """Test that make_dir returns a node with generation in it."""
        root_id, root_gen = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)
        _, generation, _ = yield self.user.make_dir(
            volume_id, root_id, "name", True
        )
        self.assertEqual(generation, root_gen + 1)

    @defer.inlineCallbacks
    def test_unlink_node_with_gen(self):
        """Test that unlink returns a node with generation in it."""
        root_id, root_gen = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)
        node_id, generation, _ = yield self.user.make_dir(
            volume_id, root_id, "name", True
        )
        new_gen, kind, name, _ = yield self.user.unlink_node(
            volume_id, node_id
        )
        self.assertEqual(new_gen, generation + 1)
        self.assertEqual(kind, StorageObject.DIRECTORY)
        self.assertEqual(name, "name")

    @defer.inlineCallbacks
    def test_move_node_with_gen(self):
        """Test that move returns a node with generation in it."""
        root_id, _ = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)
        yield self.user.make_dir(volume_id, root_id, "name", True)
        node_id, generation, _ = yield self.user.make_dir(
            volume_id, root_id, "name", True
        )
        new_generation, _ = yield self.user.move(
            volume_id, node_id, root_id, "new_name"
        )
        self.assertEqual(new_generation, generation + 1)

    @defer.inlineCallbacks
    def test_get_upload_job(self):
        """Test for _get_upload_job."""
        root_id, _ = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)
        node_id, _, _ = yield self.user.make_file(
            volume_id, root_id, "name", True
        )
        size = 1024
        # this will create a new uploadjob
        upload_job = yield self.user.get_upload_job(
            None, node_id, '', 'foo', 10, size / 2, size / 4, True
        )
        self.assertIsInstance(upload_job, UploadJob)

    @defer.inlineCallbacks
    def test_get_free_bytes_root(self):
        """Get the user free bytes, normal case."""
        StorageUser.objects.filter(id=self.suser.id).update(
            max_storage_bytes=1000
        )
        fb = yield self.user.get_free_bytes()
        self.assertEqual(fb, 1000)

    @defer.inlineCallbacks
    def test_get_free_bytes_own_share(self):
        """Get the user free bytes asking for same user's share."""
        other_user = self.make_user(username='user2')
        share = self.suser.root.share(other_user.id, "sharename")
        StorageUser.objects.filter(id=self.suser.id).update(
            max_storage_bytes=1000
        )
        fb = yield self.user.get_free_bytes(share.id)
        self.assertEqual(fb, 1000)

    @defer.inlineCallbacks
    def test_get_free_bytes_othershare_ok(self):
        """Get the user free bytes for other user's share."""
        other_user = self.make_user(username='user2', max_storage_bytes=500)
        share = other_user.root.share(self.suser.id, "sharename")
        fb = yield self.user.get_free_bytes(share.id)
        self.assertEqual(fb, 500)

    @defer.inlineCallbacks
    def test_get_free_bytes_othershare_bad(self):
        """Get the user free bytes for a share of a user that is not valid."""
        other_user = self.make_user(username='user2', max_storage_bytes=500)
        share = other_user.root.share(self.suser.id, "sharename")
        StorageUser.objects.filter(id=other_user.id).update(is_active=False)
        d = self.user.get_free_bytes(share.id)
        yield self.assertFailure(d, errors.DoesNotExist)

    @defer.inlineCallbacks
    def test_change_public_access(self):
        """Test change public access action."""
        root_id, root_gen = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)
        node_id, generation, _ = yield self.user.make_file(
            volume_id, root_id, "name"
        )
        public_url = yield self.user.change_public_access(
            volume_id, node_id, True
        )
        self.assertTrue(public_url.startswith(settings.PUBLIC_URL_PREFIX))

    @defer.inlineCallbacks
    def test_list_public_files(self):
        """Test the public files listing."""
        root_id, _ = yield self.user.get_root()
        volume_id = yield self.user.get_volume_id(root_id)

        # create three files, make two public
        node_id_1, _, _ = yield self.user.make_file(
            volume_id, root_id, "name1"
        )
        yield self.user.make_file(volume_id, root_id, "name2")
        node_id_3, _, _ = yield self.user.make_file(
            volume_id, root_id, "name3"
        )
        yield self.user.change_public_access(volume_id, node_id_1, True)
        yield self.user.change_public_access(volume_id, node_id_3, True)

        public_files = yield self.user.list_public_files()
        self.assertEqual(
            set(node.id for node in public_files), {node_id_1, node_id_3}
        )


class TestUploadJob(TestWithDatabase):
    """Tests for UploadJob class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(TestUploadJob, self).setUp()
        self.chunk_size = settings.STORAGE_CHUNK_SIZE
        self.half_size = self.chunk_size // 2
        self.double_size = self.chunk_size * 2
        self.user = self.make_user(max_storage_bytes=self.chunk_size**2)
        self.content_user = User(
            self.service.factory.content,
            self.user.id,
            self.user.root_volume_id,
            self.user.username,
            self.user.visible_name,
        )

        def slowScheduler(x):
            """A slower scheduler for our cooperator."""
            return reactor.callLater(0.1, x)

        self._cooperator = task.Cooperator(scheduler=slowScheduler)
        self.addCleanup(self._cooperator.stop)

    def make_upload(self, size):
        """Create the storage UploadJob object.

        @param size: the size of the upload
        @return: a tuple (deflated_data, hash_value, upload_job)
        """
        return self.make_upload_job(size, self.user, self.content_user)

    @defer.inlineCallbacks
    def test_simple_upload(self):
        """Test UploadJob without scatter/gather."""
        size = self.half_size
        deflated_data, hash_value, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        yield upload_job.commit()
        node_id = upload_job.file_node.id
        node = yield self.content_user.get_node(
            self.user.root_volume_id, node_id, None
        )
        self.assertEqual(node.content_hash, hash_value)

    @defer.inlineCallbacks
    def test_chunked_upload(self):
        """Test UploadJob with chunks."""
        size = self.double_size
        deflated_data, hash_value, upload_job = yield self.make_upload(size)
        yield upload_job.connect()

        # now let's upload some data
        def data_iter(chunk_size=request.MAX_MESSAGE_SIZE):
            """Iterate over chunks."""
            for part in range(0, len(deflated_data), chunk_size):
                yield upload_job.add_data(
                    deflated_data[part : part + chunk_size]  # noqa: E203
                )

        yield self._cooperator.coiterate(data_iter())
        yield upload_job.commit()

        # verify node content
        node_id = upload_job.file_node.id
        node = yield self.content_user.get_node(
            self.user.root_volume_id, node_id, None
        )
        self.assertEqual(node.content_hash, hash_value)

    @defer.inlineCallbacks
    def test_upload_fail_with_conflict(self):
        """Test UploadJob conflict."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        # poison the upload
        upload_job.original_file_hash = "sha1:fakehash"

        e = yield self.assertFailure(
            upload_job.commit(), server.errors.ConflictError
        )
        self.assertEqual(str(e), 'The File changed while uploading.')

    @defer.inlineCallbacks
    def test_upload_corrupted_deflated(self):
        """Test corruption of deflated data in UploadJob."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        # change the deflated data to trigger a UploadCorrupt error
        yield upload_job.add_data(deflated_data + b'10')
        try:
            yield upload_job.commit()
        except server.errors.UploadCorrupt as e:
            self.assertEqual(str(e), upload_job._deflated_size_hint_mismatch)
        else:
            self.fail("Should fail with UploadCorrupt")

    @defer.inlineCallbacks
    def test_upload_corrupted_inflated(self):
        """Test corruption of inflated data in UploadJob."""
        # now test corruption of the inflated data
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        # change the inflated size hint to trigger the error
        upload_job.producer.inflated_size += 10
        try:
            yield upload_job.commit()
        except server.errors.UploadCorrupt as e:
            self.assertEqual(str(e), upload_job._inflated_size_hint_mismatch)
        else:
            self.fail("Should fail with UploadCorrupt")

    @defer.inlineCallbacks
    def test_upload_corrupted_hash(self):
        """Test corruption of hash in UploadJob."""
        # now test corruption of the content hash hint
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        upload_job.hash_hint = 'sha1:fakehash'
        yield upload_job.add_data(deflated_data)
        try:
            yield upload_job.commit()
        except server.errors.UploadCorrupt as e:
            self.assertEqual(str(e), upload_job._content_hash_hint_mismatch)
        else:
            self.fail("Should fail with UploadCorrupt")

    @defer.inlineCallbacks
    def test_upload_corrupted_magic_hash(self):
        """Test corruption of magic hash in UploadJob."""
        # now test corruption of the content hash hint
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        upload_job.magic_hash = 'sha1:fakehash'
        yield upload_job.add_data(deflated_data)
        try:
            yield upload_job.commit()
        except server.errors.UploadCorrupt as e:
            self.assertEqual(str(e), upload_job._magic_hash_hint_mismatch)
        else:
            self.fail("Should fail with UploadCorrupt")

    @defer.inlineCallbacks
    def test_upload_corrupted_crc32(self):
        """Test corruption of crc32 in UploadJob."""
        # now test corruption of the crc32 hint
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        upload_job.crc32_hint = 'bad crc32'
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        try:
            yield upload_job.commit()
        except server.errors.UploadCorrupt as e:
            self.assertEqual(str(e), upload_job._crc32_hint_mismatch)
        else:
            self.fail("Should fail with UploadCorrupt")

    @defer.inlineCallbacks
    def test_commit_return_node_with_gen(self):
        """Commit return the node with the updated generation."""
        size = self.half_size
        deflated_data, hash_value, upload_job = yield self.make_upload(size)
        previous_generation = upload_job.file_node.generation
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        new_generation = yield upload_job.commit()
        self.assertEqual(new_generation, previous_generation + 1)

    @defer.inlineCallbacks
    def test_add_bad_data(self):
        """Test UploadJob.add_data with invalid data."""
        size = self.half_size
        deflated_data, hash_value, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        self.addCleanup(upload_job.cancel)
        yield upload_job.add_data(b'Neque quisquam est qui dolorem ipsum')
        self.assertFailure(upload_job.deferred, server.errors.UploadCorrupt)

    @defer.inlineCallbacks
    def test_upload_id(self):
        """Test the upload_id generation."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        self.assertEqual(
            upload_job.upload_id, upload_job.uploadjob.multipart_key
        )

    @defer.inlineCallbacks
    def test_stop_sets_canceling(self):
        """Set canceling on stop."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        assert not upload_job.canceling
        upload_job.stop()
        self.assertTrue(upload_job.canceling)

    @defer.inlineCallbacks
    def test_unregisterProducer_on_cancel(self):
        """unregisterProducer is never called"""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        producer = mock.Mock()
        self.patch(upload_job, 'producer', producer)

        yield upload_job.cancel()

        producer.stopProducing.assert_called_once_with()

    @defer.inlineCallbacks
    def test_unregisterProducer_on_stop(self):
        """unregisterProducer isn't called."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        producer = mock.Mock()
        self.patch(upload_job, 'producer', producer)

        yield upload_job.stop()

        producer.stopProducing.assert_called_once_with()

    @defer.inlineCallbacks
    def test_commit_and_delete_fails(self):
        """Commit and delete fails, log in warning."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        # make commit fail
        self.patch(
            upload_job, "_commit", lambda: defer.fail(ValueError("boom"))
        )
        # also delete
        self.patch(
            upload_job.uploadjob,
            "delete",
            lambda: defer.fail(ValueError("delete boom")),
        )
        handler = self.add_memento_handler(logger, level=logging.WARNING)
        failure = yield self.assertFailure(upload_job.commit(), ValueError)
        self.assertEqual(str(failure), "delete boom")
        handler.assert_exception("delete boom")

    @defer.inlineCallbacks
    def test_delete_after_commit_ok(self):
        """Delete the UploadJob after succesful commit."""
        size = self.half_size
        deflated_data, _, upload_job = yield self.make_upload(size)
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        yield upload_job.commit()
        node = upload_job.file_node
        # check that the upload is no more
        d = DBUploadJob.get(
            self.content_user,
            node.volume_id,
            node.id,
            upload_job.upload_id,
            upload_job.hash_hint,
            upload_job.crc32_hint,
        )
        yield self.assertFailure(d, errors.DoesNotExist)

    @defer.inlineCallbacks
    def test_add_operation_ok(self):
        _, _, upload_job = yield self.make_upload(20)
        called = []

        def fake_operation(_):
            called.append('operation')

        def fake_error_handler(_):
            called.append('error')

        upload_job.add_operation(fake_operation, fake_error_handler)
        yield upload_job.ops
        self.assertEqual(called, ['operation'])

    @defer.inlineCallbacks
    def test_add_operation_error(self):
        _, _, upload_job = yield self.make_upload(20)
        called = []

        def crash(_):
            called.append('operation')
            raise ValueError("crash")

        def fake_error_handler(failure):
            called.append('error: ' + str(failure.value))

        upload_job.add_operation(crash, fake_error_handler)
        yield upload_job.ops
        self.assertEqual(called, ['operation', 'error: crash'])

    @defer.inlineCallbacks
    def test_add_data_after_cancel(self):
        """Data after cancellation should be just ignored."""
        deflated_data, _, upload_job = yield self.make_upload(self.half_size)
        middle = self.half_size // 2
        data1, data2 = deflated_data[:middle], deflated_data[middle:]
        yield upload_job.connect()
        yield upload_job.add_data(data1)
        yield upload_job.cancel()
        yield upload_job.add_data(data2)


class TestNode(TestWithDatabase):
    """Tests for Node class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(TestNode, self).setUp()
        self.chunk_size = settings.STORAGE_CHUNK_SIZE
        self.half_size = self.chunk_size / 2
        self.double_size = self.chunk_size * 2
        self.user = self.make_user(max_storage_bytes=self.chunk_size**2)
        self.suser = User(
            self.service.factory.content,
            self.user.id,
            self.user.root_volume_id,
            self.user.username,
            self.user.visible_name,
        )

        # add a memento handler, to check we log ok
        self.handler = self.add_memento_handler(server.logger)

    @defer.inlineCallbacks
    def _upload_a_file(self, user, content_user):
        """Upload a file.

        @param user: the storage user
        @param content: the User
        @return: a tuple (upload, deflated_data)
        """
        size = self.chunk_size / 2
        deflated_data, hash_value, upload_job = yield self.make_upload_job(
            size, user, content_user
        )
        yield upload_job.connect()
        yield upload_job.add_data(deflated_data)
        yield upload_job.commit()
        node_id = upload_job.file_node.id
        node = yield content_user.get_node(user.root_volume_id, node_id, None)
        self.assertEqual(hash_value, node.content_hash)
        defer.returnValue((node, deflated_data))

    @defer.inlineCallbacks
    def test_get_content(self):
        """Test for Node.get_content 'all good' code path."""
        node, deflated_data = yield self._upload_a_file(self.user, self.suser)
        producer = yield node.get_content(previous_hash=node.content_hash)
        consumer = BufferedConsumer(producer)
        # resume producing
        producer.startProducing(consumer)
        yield producer.deferred
        self.assertEqual(len(consumer.buffer.getvalue()), len(deflated_data))
        self.assertEqual(consumer.buffer.getvalue(), deflated_data)

    @defer.inlineCallbacks
    def _get_user_node(self):
        """Get a user and a node."""
        node, deflated_data = yield self._upload_a_file(self.user, self.suser)
        defer.returnValue((self.suser, node))

    @defer.inlineCallbacks
    def test_handles_producing_error(self):
        user, node = yield self._get_user_node()

        # make the consumer crash
        orig_func = diskstorage.FileReaderProducer.startProducing

        def mitm(*a):
            """MITM to return a failed deferred instead of real one."""
            deferred = orig_func(*a)
            deferred.errback(ValueError("crash"))
            return deferred

        self.patch(diskstorage.FileReaderProducer, 'startProducing', mitm)

        producer = yield node.get_content(
            previous_hash=node.content_hash, user=user
        )
        consumer = BufferedConsumer(producer)
        # resume producing
        producer.startProducing(consumer)
        yield self.assertFailure(producer.deferred, server.errors.NotAvailable)


class TestGenerations(TestWithDatabase):
    """Tests for generations related methods."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(TestGenerations, self).setUp()
        self.suser = u = self.make_user(max_storage_bytes=64**2)
        self.user = User(
            self.service.factory.content,
            u.id,
            u.root_volume_id,
            u.username,
            u.visible_name,
        )

    @defer.inlineCallbacks
    def test_get_delta_empty(self):
        """Test that User.get_delta works as expected."""
        delta = yield self.user.get_delta(None, 0)
        free_bytes = self.suser.free_bytes
        self.assertEqual(delta, ([], 0, free_bytes))

    @defer.inlineCallbacks
    def test_get_delta_from_0(self):
        """Test that User.get_delta works as expected."""
        nodes = [self.suser.root.make_file("name%s" % i) for i in range(5)]
        delta, end_gen, free_bytes = yield self.user.get_delta(None, 0)
        self.assertEqual(len(delta), len(nodes))
        self.assertEqual(end_gen, nodes[-1].generation)
        self.assertEqual(free_bytes, self.suser.free_bytes)

    @defer.inlineCallbacks
    def test_get_delta_from_middle(self):
        """Test that User.get_delta works as expected."""
        # create some nodes
        root = self.suser.root
        nodes = [root.make_file("name%s" % i) for i in range(5)]
        nodes += [root.make_subdirectory("dir%s" % i) for i in range(5)]
        from_generation = nodes[5].generation
        delta, end_gen, free_bytes = yield self.user.get_delta(
            None, from_generation
        )
        self.assertEqual(len(delta), len(nodes[6:]))
        self.assertEqual(end_gen, nodes[-1].generation)
        self.assertEqual(free_bytes, self.suser.free_bytes)

    @defer.inlineCallbacks
    def test_get_delta_from_last(self):
        """Test that User.get_delta works as expected."""
        # create some nodes
        root = self.suser.root
        nodes = [root.make_file("name%s" % i) for i in range(5)]
        nodes += [root.make_subdirectory("dir%s" % i) for i in range(5)]
        from_generation = nodes[-1].generation
        delta, end_gen, free_bytes = yield self.user.get_delta(
            None, from_generation
        )
        self.assertEqual(len(delta), 0)
        self.assertEqual(end_gen, nodes[-1].generation)
        self.assertEqual(free_bytes, self.suser.free_bytes)

    @defer.inlineCallbacks
    def test_get_delta_partial(self):
        """Test User.get_delta with partial delta."""
        # create some nodes
        root = self.suser.root
        nodes = [root.make_file("name%s" % i) for i in range(10)]
        nodes += [root.make_subdirectory("dir%s" % i) for i in range(10)]
        limit = 5
        delta, vol_gen, free_bytes = yield self.user.get_delta(
            None, 10, limit=limit
        )
        self.assertEqual(len(delta), limit)
        self.assertEqual(vol_gen, 20)

    @defer.inlineCallbacks
    def test_rescan_from_scratch(self):
        """Test User.rescan_from_scratch."""
        root = self.suser.root
        nodes = [root.make_file("name%s" % i) for i in range(5)]
        nodes += [root.make_subdirectory("dir%s" % i) for i in range(5)]
        for f in [root.make_file("name%s" % i) for i in range(5, 10)]:
            f.delete()
        for d in [root.make_subdirectory("dir%s" % i) for i in range(5, 10)]:
            d.delete()
        live_nodes, gen, free_bytes = yield self.user.get_from_scratch(None)
        # nodes + root
        self.assertEqual(len(nodes) + 1, len(live_nodes))
        self.assertEqual(30, gen)


class TestContentManagerTests(TestWithDatabase):
    """Test ContentManger class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(TestContentManagerTests, self).setUp()
        self.suser = self.make_user(max_storage_bytes=64**2)
        self.cm = ContentManager(self.service.factory)
        self.cm.rpc_dal = self.service.rpc_dal

    @defer.inlineCallbacks
    def test_get_user_by_id(self):
        """Test get_user_by_id."""
        # user isn't cached yet.
        u = yield self.cm.get_user_by_id(self.suser.id)
        self.assertEqual(u, None)
        u = yield self.cm.get_user_by_id(self.suser.id, required=True)
        self.assertIsInstance(u, User)
        # make sure it's in the cache
        self.assertEqual(u, self.cm.users[self.suser.id])
        # get it from the cache
        u = yield self.cm.get_user_by_id(self.suser.id)
        self.assertIsInstance(u, User)

    @defer.inlineCallbacks
    def test_get_user_by_id_race_condition(self):
        """Two requests both try to fetch and cache the user."""
        # Has to fire before first call to rpc client returns
        d = defer.Deferred()
        rpc_call = self.cm.rpc_dal.call

        @defer.inlineCallbacks
        def delayed_rpc_call(funcname, **kwargs):
            """Wait for the deferred, then make the real client call."""
            yield d
            val = yield rpc_call(funcname, **kwargs)
            defer.returnValue(val)

        self.cm.rpc_dal.call = delayed_rpc_call

        # Start the first call
        u1_deferred = self.cm.get_user_by_id(self.suser.id, required=True)
        # Start the second call
        u2_deferred = self.cm.get_user_by_id(self.suser.id, required=True)
        # Let the first continue
        d.callback(None)
        # Get the results
        u1 = yield u1_deferred
        u2 = yield u2_deferred

        self.assertIdentical(u1, u2)
        self.assertIdentical(u1, self.cm.users[self.suser.id])


class TestContent(TestWithDatabase):
    """Test the upload and download."""

    @defer.inlineCallbacks
    def test_getcontent(self):
        """Get the content from a file."""
        data = b"*" * 100000

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        req = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        self.assertEqual(zlib.decompress(req.data), data)

    @defer.inlineCallbacks
    def test_putcontent(self):
        """Test putting content to a file."""
        data = os.urandom(100000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        mkfile_req = yield client.make_file(request.ROOT, root_id, 'hola')
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        def check_file():
            try:
                self.usr0.volume().get_content(params['new_hash'])
            except errors.DoesNotExist:
                raise ValueError("content blob is not there")

        yield threads.deferToThread(check_file)


class DBUploadJobTestCase(TestCase):
    """Tests for the DBUploadJob."""

    class FakeUser(object):
        """Fake object that simulates a rpc_dal call."""

        def __init__(self, to_return):
            self.to_return = to_return
            self.recorded = None
            self.id = 'fake_user_id'

        def call(self, method, **attribs):
            """Record the call."""
            self.recorded = (method, attribs)
            return defer.succeed(self.to_return)

        rpc_dal = property(lambda self: self)

    def setUp(self):
        """Set up."""
        d = dict(
            uploadjob_id='uploadjob_id',
            uploaded_bytes='uploaded_bytes',
            multipart_key='multipart_key',
            chunk_count='chunk_count',
            when_last_active='when_last_active',
        )
        self.user = self.FakeUser(to_return=d)
        return super(DBUploadJobTestCase, self).setUp()

    @defer.inlineCallbacks
    def test_get(self):
        """Test the getter."""
        args = (
            self.user,
            'volume_id',
            'node_id',
            'uploadjob_id',
            'hash_value',
            'crc32',
        )
        dbuj = yield DBUploadJob.get(*args)

        # check it called rpc dal correctly
        method, attribs = self.user.recorded
        self.assertEqual(method, 'get_uploadjob')
        should = dict(
            user_id='fake_user_id',
            volume_id='volume_id',
            node_id='node_id',
            uploadjob_id='uploadjob_id',
            hash_value='hash_value',
            crc32='crc32',
        )
        self.assertEqual(attribs, should)

        # check it built the instance correctly
        self.assertIsInstance(dbuj, DBUploadJob)
        self.assertEqual(dbuj.user, self.user)
        self.assertEqual(dbuj.volume_id, 'volume_id')
        self.assertEqual(dbuj.node_id, 'node_id')
        self.assertEqual(dbuj.uploadjob_id, 'uploadjob_id')
        self.assertEqual(dbuj.uploaded_bytes, 'uploaded_bytes')
        self.assertEqual(dbuj.multipart_key, 'multipart_key')
        self.assertEqual(dbuj.chunk_count, 'chunk_count')
        self.assertEqual(dbuj.when_last_active, 'when_last_active')

    @defer.inlineCallbacks
    def test_make(self):
        """Test the builder."""
        args = (
            self.user,
            'volume_id',
            'node_id',
            'previous_hash',
            'hash_value',
            'crc32',
            'inflated_size',
        )
        self.patch(uuid, 'uuid4', lambda: "test unique id")
        dbuj = yield DBUploadJob.make(*args)

        # check it called rpc dal correctly
        method, attribs = self.user.recorded
        self.assertEqual(method, 'make_uploadjob')
        should = dict(
            user_id='fake_user_id',
            volume_id='volume_id',
            node_id='node_id',
            previous_hash='previous_hash',
            hash_value='hash_value',
            crc32='crc32',
            inflated_size='inflated_size',
            multipart_key='test unique id',
        )
        self.assertEqual(attribs, should)

        # check it built the instance correctly
        self.assertIsInstance(dbuj, DBUploadJob)
        self.assertEqual(dbuj.user, self.user)
        self.assertEqual(dbuj.volume_id, 'volume_id')
        self.assertEqual(dbuj.node_id, 'node_id')
        self.assertEqual(dbuj.uploadjob_id, 'uploadjob_id')
        self.assertEqual(dbuj.uploaded_bytes, 'uploaded_bytes')
        self.assertEqual(dbuj.multipart_key, 'test unique id')
        self.assertEqual(dbuj.chunk_count, 'chunk_count')
        self.assertEqual(dbuj.when_last_active, 'when_last_active')

    def _make_uj(self):
        """Helper to create the upload job."""
        args = (
            self.user,
            'volume_id',
            'node_id',
            'previous_hash',
            'hash_value',
            'crc32',
            'inflated_size',
        )
        return DBUploadJob.make(*args)

    @defer.inlineCallbacks
    def test_add_part(self):
        """Test add_part method."""
        dbuj = yield self._make_uj()
        chunk_size = int(settings.STORAGE_CHUNK_SIZE) + 1
        yield dbuj.add_part(chunk_size)

        # check it called rpc dal correctly
        method, attribs = self.user.recorded
        self.assertEqual(method, 'add_part_to_uploadjob')
        should = dict(
            user_id='fake_user_id',
            uploadjob_id='uploadjob_id',
            chunk_size=chunk_size,
            volume_id='volume_id',
        )
        self.assertEqual(attribs, should)

    @defer.inlineCallbacks
    def test_delete(self):
        """Test delete method."""
        dbuj = yield self._make_uj()
        yield dbuj.delete()

        # check it called rpc dal correctly
        method, attribs = self.user.recorded
        self.assertEqual(method, 'delete_uploadjob')
        should = dict(
            user_id='fake_user_id',
            uploadjob_id='uploadjob_id',
            volume_id='volume_id',
        )
        self.assertEqual(attribs, should)

    @defer.inlineCallbacks
    def test_touch(self):
        """Test the touch method."""
        dbuj = yield self._make_uj()
        self.user.to_return = dict(when_last_active='new_when_last_active')
        yield dbuj.touch()

        # check it called rpc dal correctly
        method, attribs = self.user.recorded
        self.assertEqual(method, 'touch_uploadjob')
        should = dict(
            user_id='fake_user_id',
            uploadjob_id='uploadjob_id',
            volume_id='volume_id',
        )
        self.assertEqual(attribs, should)

        # check updated attrib
        self.assertEqual(dbuj.when_last_active, 'new_when_last_active')

    @defer.inlineCallbacks
    def test_bogus_upload_job(self):
        """Check the not-going-to-db upload job."""
        self.patch(uuid, 'uuid4', lambda: "test unique id")
        uj = BogusUploadJob()

        # basic attributes
        self.assertEqual(uj.multipart_key, "test unique id")
        self.assertEqual(uj.uploaded_bytes, 0)

        # check methods
        yield uj.add_part(123)
        yield uj.delete()
