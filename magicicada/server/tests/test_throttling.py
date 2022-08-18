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

import os
import zlib

from django.db import transaction
from magicicadaprotocol import request, client
from twisted.internet import threads, defer
from twisted.internet.protocol import connectionDone

from magicicada.filesync import services
from magicicada.filesync.models import ContentBlob
from magicicada.server.testing.testcase import (
    ClientTestHelper,
    TestWithDatabase,
    get_put_content_params,
)

NO_CONTENT_HASH = ""


class ThrottlingTestClient(client.ThrottlingStorageClient, ClientTestHelper):
    """ThrottlingStorageClient for the tests"""

    def connectionMade(self):
        """connection!"""
        client.ThrottlingStorageClient.connectionMade(self)
        ClientTestHelper.connectionMade(self)

    def connectionLost(self, reason=connectionDone):
        """connection lost"""
        self.factory.unregisterProtocol(self)
        ClientTestHelper.connectionLost(self, reason=reason)


class ThrottlingTestFactory(client.ThrottlingStorageClientFactory):
    """ThrottlingStorageClientFactory for the tests"""
    protocol = ThrottlingTestClient


class TestThrottling(TestWithDatabase):
    """Test thorttling in get/put content"""

    factory_class = ThrottlingTestFactory

    @defer.inlineCallbacks
    def test_getcontent_file(self, check_file_content=True):
        """Get the content from a file."""
        data = os.urandom(300000)

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()
        # create a file with content
        mkfile_req = yield client.make_file(request.ROOT, root_id, "test_file")
        params = get_put_content_params(data, node=mkfile_req.new_id)
        yield client.put_content(**params)

        # get the content
        content = yield client.get_content(
            params['share'], params['node'], params['new_hash'])
        if check_file_content:
            self.assertEqual(zlib.decompress(content.data), data)

    @defer.inlineCallbacks
    def test_getcontent_file_slow(self):
        """Get content from a file with very low BW and fail with timeout."""
        data = os.urandom(300000)

        @defer.inlineCallbacks
        def auth(client):
            """Test."""
            yield client.dummy_authenticate("open sesame")
            root_id = yield client.get_root()

            # make a file and put content in it
            mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")
            params = get_put_content_params(data, node=mkfile_req.new_id)
            yield client.put_content(**params)

            # set the read limit, and get content
            client.factory.factory.readLimit = 1000
            yield client.get_content(
                params['share'], params['node'], params['new_hash'])

        # This test is buggy since the timeout occurs way before the read
        # operation, so it's not asserting what's described
        d = self.callback_test(auth, add_default_callbacks=True,
                               timeout=0.1)
        err = yield self.assertFailure(d, Exception)
        self.assertEqual(str(err), "timeout")

    @defer.inlineCallbacks
    def test_putcontent(self, num_files=1):
        """Test putting content to a file."""

        client = yield self.get_client_helper(auth_token="open sesame")
        root_id = yield client.get_root()

        def check_file(hash_value):
            return services.get_object_or_none(ContentBlob, hash=hash_value)

        for i in range(num_files):
            mkfile_req = yield client.make_file(
                request.ROOT, root_id, 'hola_%d' % i)
            data = os.urandom(300 + i)
            params = get_put_content_params(data, node=mkfile_req.new_id)
            yield client.put_content(**params)
            content_blob = yield threads.deferToThread(
                check_file, params['new_hash'])
            self.assertIsNotNone(content_blob)

    @defer.inlineCallbacks
    def test_putcontent_slow(self, num_files=1):
        """Putting content using very low bandwidth and fail with timeout."""
        data = os.urandom(30000)

        @defer.inlineCallbacks
        def auth(client):

            @transaction.atomic
            def check_file(hash_value):
                return services.get_object_or_none(
                    ContentBlob, hash=hash_value)

            yield client.dummy_authenticate("open sesame")
            root_id = yield client.get_root()

            # make a file and put content in it
            mkfile_req = yield client.make_file(request.ROOT, root_id, "hola")

            # set the read limit, and get content
            client.factory.factory.writeLimit = 100

            params = get_put_content_params(data, node=mkfile_req.new_id)
            yield client.put_content(**params)

            content_blob = yield threads.deferToThread(
                check_file, params['new_hash'])
            self.assertIsNotNone(content_blob)

        d = self.callback_test(auth, add_default_callbacks=True,
                               timeout=0.1)
        err = yield self.assertFailure(d, Exception)
        self.assertEqual(str(err), "timeout")
