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

"""Test User Defined Folder operations."""

import os
import uuid
import zlib

from magicicadaprotocol import request
from twisted.internet import reactor, defer

from magicicada.filesync.errors import DoesNotExist
from magicicada.server.testing.testcase import (
    FactoryHelper,
    TestWithDatabase,
    get_put_content_params,
)


class TestManageUDF(TestWithDatabase):
    """Test udf creation and deletion."""

    def test_create_udf_simple(self):
        """Create an UDF."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            def check_result(req):
                """Check the request result."""
                self.assertFalse(req.volume_id is None)
                self.assertFalse(req.node_id is None)

            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(check_result)
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_create_udf_same_path(self):
        """Try to create two UDFs with the same path."""
        udf = self.usr0.make_udf("~/myudf")

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            def check_result(req):
                """Check the request result."""
                self.assertEqual(req.volume_id, str(udf.id))

            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(check_result)
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_create_udf_nested_inside(self):
        """Try to create two nested UDFs, the second being inside."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            def check(failure):
                """Checks the error returned."""
                self.assertIsInstance(
                    failure.value, request.StorageRequestError
                )
                self.assertEqual(str(failure.value), 'NO_PERMISSION')
                client.test_done(True)

            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(lambda _: client.create_udf("~/myudf/foo", "bar"))
            d.addCallbacks(client.test_fail, check)

        return self.callback_test(auth)

    def test_create_udf_nested_outside(self):
        """Try to create two nested UDFs, the second being outside."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            def check(failure):
                """Checks the error returned."""
                self.assertIsInstance(
                    failure.value, request.StorageRequestError
                )
                self.assertEqual(str(failure.value), 'NO_PERMISSION')
                client.test_done(True)

            d.addCallback(lambda _: client.create_udf("~/myudf/foo", "bar"))
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallbacks(client.test_fail, check)

        return self.callback_test(auth)

    def test_create_udf_nested_overlapping(self):
        """Try to create two UDFs with overlapping names."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda _: client.create_udf("~/foob", "myudf"))
            d.addCallback(lambda _: client.create_udf("~/foobar", "myudf"))
            d.addCallback(lambda _: client.create_udf("~/fo", "myudf"))
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_delete_udf(self):
        """Delete an UDF."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(lambda r: client.delete_volume(r.volume_id))
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_delete_udf_with_file(self):
        """Delete an UDF and all the files there."""

        @defer.inlineCallbacks
        def auth(client):
            """Authenticate and test."""
            yield client.dummy_authenticate("open sesame")

            # create the udf and a file in it
            udf_req = yield client.create_udf("~", "myudf")
            mk_req = yield client.make_file(
                udf_req.volume_id, udf_req.node_id, "test_file"
            )

            # delete the udf
            yield client.delete_volume(udf_req.volume_id)

            # check that the file is gone
            user = self.service.factory.protocols[0].user
            d = user.get_node(udf_req.volume_id, mk_req.new_id, None)
            yield self.assertFailure(d, DoesNotExist)

        return self.callback_test(auth, add_default_callbacks=True)

    def test_delete_udf_with_dir(self):
        """Delete an UDF and all the dirs there."""

        @defer.inlineCallbacks
        def auth(client):
            """Authenticate and test."""
            yield client.dummy_authenticate("open sesame")

            # create the udf and a file in it
            udf_req = yield client.create_udf("~", "myudf")
            mk_req = yield client.make_dir(
                udf_req.volume_id, udf_req.node_id, "test_dir"
            )

            # delete the udf
            yield client.delete_volume(udf_req.volume_id)

            # check that the file is gone
            user = self.service.factory.protocols[0].user
            d = user.get_node(udf_req.volume_id, mk_req.new_id, None)
            yield self.assertFailure(d, DoesNotExist)

        return self.callback_test(auth, add_default_callbacks=True)

    def test_delete_nonexistant_udf(self):
        """Delete an UDF that does not exist."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            def check(failure):
                """Checks the error returned."""
                self.assertIsInstance(
                    failure.value, request.StorageRequestError
                )
                self.assertEqual(str(failure.value), 'DOES_NOT_EXIST')
                client.test_done(True)

            d.addCallback(lambda _: client.delete_volume(uuid.uuid4()))
            d.addCallbacks(client.test_fail, check)

        return self.callback_test(auth)

    def test_notification_create_udf(self):
        """Creating an UDF should generate a volume notification."""

        def login1(client):
            """First client login."""
            self._state.client1 = client
            d = client.dummy_authenticate("open sesame")
            d.addCallback(
                lambda _: reactor.connectTCP('localhost', self.port, factory2)
            )
            d.addCallback(lambda _: d2)  # will wait second connection
            d.addCallback(lambda _: client.create_udf("~", "moño"))
            d.addCallback(self.save_req, "udf")
            d.addCallback(d3.callback)

        def login2(client):
            """Second client login."""
            self._state.client2 = client
            client.set_volume_created_callback(on_notification)
            d = client.dummy_authenticate("open sesame")
            d.addCallback(d2.callback)

        def on_notification(new_udf):
            """Notification arrived."""

            def check_and_clean(_):
                """Check and cleanup."""
                # check
                self.assertEqual(
                    new_udf.volume_id, uuid.UUID(self._state.udf.volume_id)
                )
                self.assertEqual(
                    new_udf.node_id, uuid.UUID(self._state.udf.node_id)
                )
                self.assertEqual(new_udf.suggested_path, "~/moño")

                # cleanup
                factory1.timeout.cancel()
                factory2.timeout.cancel()
                timeout.cancel()
                d1.callback(True)
                self._state.client1.transport.loseConnection()
                self._state.client2.transport.loseConnection()

            # we should wait the request to finish first to be able to test
            d3.addCallback(check_and_clean)

        factory1 = FactoryHelper(login1)
        factory2 = FactoryHelper(login2)
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        d3 = defer.Deferred()
        timeout = reactor.callLater(3, d1.errback, Exception("timeout"))

        reactor.connectTCP('localhost', self.port, factory1)
        return d1

    def test_notification_delete_udf(self):
        """Deleting an UDF should generate a volume notification."""

        def login1(client):
            """First client login."""
            self._state.client1 = client
            d = client.dummy_authenticate("open sesame")
            d.addCallback(
                lambda _: reactor.connectTCP('localhost', self.port, factory2)
            )
            d.addCallback(lambda _: d2)  # will wait second connection
            d.addCallback(lambda _: client.create_udf("~", "moño"))
            d.addCallback(self.save_req, "udf")
            d.addCallback(lambda r: client.delete_volume(r.volume_id))
            d.addCallback(d3.callback)

        def login2(client):
            """Second client login."""
            self._state.client2 = client
            client.set_volume_deleted_callback(on_notification)
            d = client.dummy_authenticate("open sesame")
            d.addCallback(d2.callback)

        def on_notification(deleted_udf_id):
            """Notification arrived."""

            def check_and_clean(_):
                """Check and cleanup."""
                self.assertEqual(
                    deleted_udf_id, uuid.UUID(self._state.udf.volume_id)
                )

                # cleanup
                factory1.timeout.cancel()
                factory2.timeout.cancel()
                timeout.cancel()
                d1.callback(True)
                self._state.client1.transport.loseConnection()
                self._state.client2.transport.loseConnection()

            # we should wait the request to finish first to be able to test
            d3.addCallback(check_and_clean)

        factory1 = FactoryHelper(login1)
        factory2 = FactoryHelper(login2)
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        d3 = defer.Deferred()
        timeout = reactor.callLater(3, d1.errback, Exception("timeout"))

        reactor.connectTCP('localhost', self.port, factory1)
        return d1


class TestUDFsWithData(TestWithDatabase):
    """Tests data handling on an UDF."""

    def test_mkfile(self):
        """Create a file."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(
                lambda r: client.make_file(r.volume_id, r.node_id, "test_file")
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_mkdir(self):
        """Create a dir."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(
                lambda r: client.make_dir(r.volume_id, r.node_id, "test_dir")
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_unlink_udf_root(self):
        """Test unlinking the UDFs root."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            def check(failure):
                """Checks the error returned."""
                self.assertIsInstance(
                    failure.value, request.StorageRequestError
                )
                self.assertEqual(str(failure.value), 'NO_PERMISSION')
                client.test_done(True)

            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(lambda r: client.unlink(r.volume_id, r.node_id))
            d.addCallbacks(client.test_fail, check)

        return self.callback_test(auth)

    def test_unlink_normal_node(self):
        """Unlink a file inside the UDF."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(self.save_req, "udf")
            d.addCallback(
                lambda r: client.make_file(r.volume_id, r.node_id, "test_file")
            )
            d.addCallback(
                lambda r: client.unlink(self._state.udf.volume_id, r.new_id)
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_move_inside(self):
        """Move a file on inside the UDF."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            # create the udf and keep the request for later
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(self.save_req, "udf")

            # create a file in the udf, and also a subdir
            d.addCallback(
                lambda r: client.make_dir(r.volume_id, r.node_id, "subdir")
            )
            d.addCallback(self.save_req, "subdir")
            d.addCallback(
                lambda _: client.make_file(
                    self._state.udf.volume_id,
                    self._state.udf.node_id,
                    "test_file",
                )
            )

            # move the file from the udf's root to the subdir
            d.addCallback(
                lambda r: client.move(
                    self._state.udf.volume_id,
                    r.new_id,
                    self._state.subdir.new_id,
                    "newname",
                )
            )
            d.addCallbacks(client.test_done, client.test_fail)

        return self.callback_test(auth)

    def test_move_outside(self):
        """Make sure we cant move across roots."""

        def auth(client):
            """Authenticate and test."""
            d = client.dummy_authenticate("open sesame")

            # create the udf and keep the request for later
            d.addCallback(lambda _: client.create_udf("~", "myudf"))
            d.addCallback(self.save_req, "udf")

            # create a file in the udf
            d.addCallback(
                lambda _: client.make_file(
                    self._state.udf.volume_id,
                    self._state.udf.node_id,
                    "test_file",
                )
            )
            d.addCallback(self.save_req, "newfile")

            # get the real root and move the file from the udf to it
            d.addCallback(lambda _: client.get_root())
            d.addCallback(
                lambda root: client.move(
                    self._state.udf.volume_id,
                    self._state.newfile.new_id,
                    root,
                    "test_file",
                )
            )

            def check(failure):
                """Checks the error returned."""
                self.assertIsInstance(
                    failure.value, request.StorageRequestError
                )
                self.assertEqual(str(failure.value), 'DOES_NOT_EXIST')
                client.test_done(True)

            d.addCallbacks(client.test_fail, check)

        return self.callback_test(auth)

    @defer.inlineCallbacks
    def test_get_content(self):
        """Read a file."""
        data = os.urandom(100)

        client = yield self.get_client_helper(auth_token="open sesame")
        udf = yield client.create_udf("~", "myudf")
        # create a file with content
        mkfile_req = yield client.make_file(
            udf.volume_id, udf.node_id, "test_file"
        )
        params = get_put_content_params(
            data, share=udf.volume_id, node=mkfile_req.new_id
        )
        yield client.put_content(**params)

        # get the content
        content = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        self.assertEqual(zlib.decompress(content.data), data)

    @defer.inlineCallbacks
    def test_put_content(self):  # XXX: this is the same as test_get_content
        """Write a file."""
        data = b"*" * 10000

        client = yield self.get_client_helper(auth_token="open sesame")
        udf = yield client.create_udf("~", "myudf")
        # create a file with content
        mkfile_req = yield client.make_file(
            udf.volume_id, udf.node_id, "test_file"
        )
        params = get_put_content_params(
            data, share=udf.volume_id, node=mkfile_req.new_id
        )
        yield client.put_content(**params)

        # get the content
        content = yield client.get_content(
            params['share'], params['node'], params['new_hash']
        )
        self.assertEqual(zlib.decompress(content.data), data)

    def test_notify_multi_clients(self):
        """Node notification are sent with correct info."""

        @defer.inlineCallbacks
        def login1(client):
            """First client login."""
            self._state.client1 = client
            yield client.dummy_authenticate("open sesame")
            yield reactor.connectTCP('localhost', self.port, factory2)
            yield d2  # wait second connection
            req = yield client.create_udf("~", "moño")
            self._state.udf = req
            yield client.make_file(req.volume_id, req.node_id, "foo")
            d3.callback(True)

        @defer.inlineCallbacks
        def login2(client):
            """Second client login."""
            self._state.client2 = client
            client.set_volume_new_generation_callback(on_notification)
            yield client.dummy_authenticate("open sesame")
            d2.callback(True)

        @defer.inlineCallbacks
        def on_notification(volume, generation):
            """Notification arrived."""
            # we should wait the request to finish first to be able to test
            yield d3
            self.assertEqual(str(volume), self._state.udf.volume_id)

            # cleanup
            factory1.timeout.cancel()
            factory2.timeout.cancel()
            timeout.cancel()
            d1.callback(True)
            self._state.client1.transport.loseConnection()
            self._state.client2.transport.loseConnection()

        factory1 = FactoryHelper(login1)
        factory2 = FactoryHelper(login2)
        d1 = defer.Deferred()
        d2 = defer.Deferred()
        d3 = defer.Deferred()
        timeout = reactor.callLater(3, d1.errback, Exception("timeout"))

        reactor.connectTCP('localhost', self.port, factory1)
        return d1
