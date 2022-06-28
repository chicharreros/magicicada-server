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

"""Test authentication."""

import logging

from magicicadaprotocol import errors as protocol_errors, request
from twisted.internet import defer

from magicicada.filesync.errors import DoesNotExist
from magicicada.filesync.models import StorageUser
from magicicada.server.auth import (
    DummyAuthProvider,
    SimpleAuthProvider,
    logger as auth_logger,
)
from magicicada.server.server import logger as server_logger
from magicicada.server.testing.testcase import TestWithDatabase


class AuthenticationBaseTestCase(TestWithDatabase):

    def do_auth(self, client, credentials, **kwargs):
        if not isinstance(credentials, dict):
            auth_d = client.dummy_authenticate(credentials, **kwargs)
        else:
            username = credentials['username']
            password = credentials['password']
            auth_d = client.simple_authenticate(username, password, **kwargs)

        return auth_d

    @defer.inlineCallbacks
    def setUp(self):
        yield super(AuthenticationBaseTestCase, self).setUp()
        self.provider = self.service.factory.auth_provider


class DummyProviderTests(AuthenticationBaseTestCase):
    """Tests for the dummy authentication provider."""

    auth_provider_class = DummyAuthProvider

    @defer.inlineCallbacks
    def test_authenticate(self):
        """The dummy authentication provider succeeds with a valid token."""
        auth_params = {"dummy_token": "open sesame"}
        user = yield self.provider.authenticate(auth_params, None)
        self.assertEqual(user.id, self.usr0.id)
        # the same user is returned by repeated calls
        user2 = yield self.provider.authenticate(auth_params, None)
        self.assertEqual(user.id, user2.id)

    @defer.inlineCallbacks
    def test_authenticate_fail(self):
        """The dummy authentication provider fails with an invalid token."""
        auth_params = {"dummy_token": "wrong password"}
        user = yield self.provider.authenticate(auth_params, None)
        self.assertEqual(user, None)

    @defer.inlineCallbacks
    def test_authenticate_no_parameters(self):
        """The dummy authentication provider fails with no parameters."""
        user = yield self.provider.authenticate({}, None)
        self.assertEqual(user, None)


class SimpleAuthProviderTests(AuthenticationBaseTestCase):
    """Tests for the simple authentication provider."""

    auth_provider_class = SimpleAuthProvider

    @defer.inlineCallbacks
    def setUp(self):
        yield super(SimpleAuthProviderTests, self).setUp()
        self.creds = {
            "username": self.usr0.username,
            "password": self.usr0.password,
        }

    @defer.inlineCallbacks
    def test_authenticate(self):
        """The Auth provider succeeds with a valid password."""
        user = yield self.provider.authenticate(self.creds, None)
        self.assertEqual(user.id, self.usr0.id)

        # the same user is returned by repeated calls
        user2 = yield self.provider.authenticate(self.creds, None)
        self.assertEqual(user.id, user2.id)

    @defer.inlineCallbacks
    def test_authenticate_failure(self):
        """The Auth provider succeeds with an invalid password."""
        auth_parameters = self.creds.copy()
        auth_parameters['password'] = 'invalid'

        user = yield self.provider.authenticate(auth_parameters, None)
        self.assertEqual(user, None)

    @defer.inlineCallbacks
    def test_authenticate_no_parameters(self):
        """The Auth provider fails with no parameters."""
        user = yield self.provider.authenticate({}, None)
        self.assertEqual(user, None)


class ClientDummyAuthTests(AuthenticationBaseTestCase):
    """Client authentication tests using the dummy auth provider."""

    auth_provider_class = DummyAuthProvider

    @defer.inlineCallbacks
    def setUp(self):
        yield super(ClientDummyAuthTests, self).setUp()
        self.creds = 'open sesame'
        self.bad_creds = 'not my secret'

    def assert_auth_ok_logging(self, handler):
        handler.assert_debug("authenticated user", "OK", self.usr0.username)
        handler.assert_not_logged("missing user")

    def assert_auth_ok_missing_user(self, handler):
        handler.assert_debug("missing user", "(id=%s)" % self.usr0.id)
        handler.assert_not_logged("authenticated user")

    @defer.inlineCallbacks
    def test_auth_ok_user_ok(self):
        """Correct authentication must succeed."""
        handler = self.add_memento_handler(auth_logger, level=logging.DEBUG)
        yield self.callback_test(
            self.do_auth, credentials=self.creds, add_default_callbacks=True)
        self.assert_auth_ok_logging(handler)

    @defer.inlineCallbacks
    def test_auth_ok_bad_user(self):
        """Non existing user must fail authentication."""
        handler = self.add_memento_handler(auth_logger, level=logging.DEBUG)
        # make the user getter fail
        self.patch(self.service.factory.content, 'get_user_by_id',
                   lambda *a, **k: defer.fail(DoesNotExist()))

        d = self.callback_test(
            self.do_auth, credentials=self.creds, add_default_callbacks=True)
        yield self.assertFailure(d, protocol_errors.AuthenticationFailedError)

        self.assert_auth_ok_missing_user(handler)

    @defer.inlineCallbacks
    def test_auth_ok_with_session_id(self):
        """Correct authentication must succeed and include the session_id."""
        auth_request = yield self.callback_test(
            self.do_auth, credentials=self.creds, add_default_callbacks=True)

        protocol = self.service.factory.protocols[0]
        self.assertEqual(auth_request.session_id, str(protocol.session_id))

    @defer.inlineCallbacks
    def test_auth_ok_with_metadata(self):
        """Correct authentication must succeed and include metadata."""
        m_called = []
        self.service.factory.metrics.meter = lambda *a: m_called.append(a)
        handler = self.add_memento_handler(server_logger, level=logging.DEBUG)
        metadata = {"platform": "linux2", "version": "1.0", "foo": "bar"}
        yield self.callback_test(
            self.do_auth, credentials=self.creds, metadata=metadata,
            add_default_callbacks=True)

        handler.assert_info("Client metadata: %s" % metadata)
        self.assertIn(("client.platform.linux2", 1), m_called)
        self.assertIn(("client.version.1_0", 1), m_called)
        self.assertNotIn(("client.foo.bar", 1), m_called)

    def test_auth_fail(self):
        """Wrong secret must fail."""

        def test(client, **kwargs):
            d = self.do_auth(client, credentials=self.bad_creds)
            d.addCallbacks(
                lambda _: client.test_fail(Exception("Should not succeed.")),
                lambda _: client.test_done("ok"))

        return self.callback_test(test)

    def test_get_root(self):
        """Must receive the root after authentication."""

        @defer.inlineCallbacks
        def test(client, **kwargs):
            yield self.do_auth(client, credentials=self.creds)
            root_id = yield client.get_root()
            self.assertIsNotNone(root_id)

        return self.callback_test(test, add_default_callbacks=True)

    def test_get_root_twice(self):
        """Get root must keep the root id."""

        @defer.inlineCallbacks
        def test(client, **kwargs):
            yield self.do_auth(client, credentials=self.creds)
            root_id1 = yield client.get_root()
            root_id2 = yield client.get_root()
            self.assertEqual(root_id1, root_id2)

        return self.callback_test(test, add_default_callbacks=True)

    def test_user_becomes_inactive(self):
        """After StorageUser authentication ok it becomes inactive."""

        @defer.inlineCallbacks
        def test(client):
            """Test."""
            yield self.do_auth(client, credentials=self.creds)
            root_id = yield client.get_root()

            # create one file, should be ok
            yield client.make_file(request.ROOT, root_id, "f1")

            # cancel user subscription, so it needs
            # to get it again from the DB
            StorageUser.objects.filter(id=self.usr0.id).update(is_active=False)

            # create second file, should NOT be ok
            try:
                yield client.make_file(request.ROOT, root_id, "f2")
            except protocol_errors.DoesNotExistError:
                pass  # failed as we expected
            else:
                client.test_fail("It should have failed!")

        return self.callback_test(test, add_default_callbacks=True)


class ClientSimpleAuthTests(ClientDummyAuthTests):
    """Client authentication tests using the Auth provider."""

    auth_provider_class = SimpleAuthProvider

    @defer.inlineCallbacks
    def setUp(self):
        yield super(ClientSimpleAuthTests, self).setUp()
        self.creds = {
            "username": self.usr0.username,
            "password": self.usr0.password,
        }
        self.bad_creds = {
            "username": self.usr0.username,
            "password": 'invalid',
        }

    def assert_auth_ok_logging(self, handler):
        handler.assert_info(
            "authenticated user", "OK", self.usr0.username,
            "(id=%s)" % self.usr0.id)
        handler.assert_info("valid tokens", "(id=%s)" % self.usr0.id)
        handler.assert_not_logged("missing user")

    def assert_auth_ok_missing_user(self, handler):
        handler.assert_info("valid tokens", "(id=%s)" % self.usr0.id)
        handler.assert_warning("missing user", "(id=%s)" % self.usr0.id)
        handler.assert_not_logged("authenticated user")
