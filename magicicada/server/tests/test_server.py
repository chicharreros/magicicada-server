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

"""Test Storage Server requests/responses."""

import collections
import logging
import time
import uuid
import weakref
from unittest import mock

from django.utils.timezone import now
from magicicadaprotocol import protocol_pb2, request
from twisted.python.failure import Failure
from twisted.python import log
from twisted.internet import defer, task, error as txerror
from twisted.trial.unittest import TestCase as TwistedTestCase

from magicicada import metrics, settings
from magicicada.filesync import errors as dataerror
from magicicada.filesync.models import Share
from magicicada.server import errors
from magicicada.server.server import (
    PREFERRED_CAP,
    AccountResponse,
    Action,
    AuthenticateResponse,
    BytesMessageProducer,
    ChangePublicAccess,
    CreateShare,
    CreateUDF,
    DeleteShare,
    DeleteVolume,
    FreeSpaceResponse,
    GetContentResponse,
    GetDeltaResponse,
    ListShares,
    ListPublicFiles,
    ListVolumes,
    LoopingPing,
    MakeResponse,
    MoveResponse,
    PutContentResponse,
    QuerySetCapsResponse,
    RescanFromScratchResponse,
    ShareAccepted,
    SimpleRequestResponse,
    StorageServer,
    StorageServerFactory,
    StorageServerRequestResponse,
    Unlink,
    cancel_filter,
    logger,
)
from magicicada.server.testing import testcase
from magicicada.testing.testcase import BaseTestCase

try:
    from versioninfo import version_info
except ImportError:
    version_info = None


def noop(*args, **kwargs):
    return


class FakeNode(object):
    """A fake node."""

    id = 123
    generation = 0
    is_live = False
    is_file = False
    name = "name"
    parent_id = None
    content_hash = None
    crc32 = 12123
    size = 45325
    last_modified = 2334524
    is_public = False
    path = "path"
    volume_id = 'volumeid'
    public_url = 'public_url'


class FakeUser(object):
    """A fake user."""

    id = 42
    username = 'username'

    def get_root(self):
        return (123, 456)  # root_id, gen

    def set_client_caps(self, caps):
        return


class FakeProducer(object):
    """A fake producer."""

    def dummy(*s):
        return

    resumeProducing = stopProducing = pauseProducing = startProducing = dummy


class FakedStats(object):
    """A faked statsmeter"""

    def __init__(self):
        self.informed = []

    def hit(self, *args):
        """Inform stats."""
        self.informed.append(args)


class FakedFactory(object):
    """A faked factory."""

    def __init__(self):
        self.stats = FakedStats()
        self.metrics = metrics.get_meter('metrics')
        self.user_metrics = metrics.get_meter('user_metrics')
        self.sli_metrics = metrics.get_meter('sli_metrics')
        self.servername = "fakeservername"
        self.trace_users = []
        self.auth_provider = mock.Mock(name='factory-auth-provider')
        self.auth_provider.authenticate.return_value = FakeUser()


class FakedPeer(object):
    """A faked peer."""

    def __init__(self):
        self.host = 'localhost'
        self.port = 0


class FakedTransport(object):
    """A faked transport."""

    def __init__(self):
        self.registerProducer = noop
        self.unregisterProducer = noop
        self.loseConnection = noop
        self.getPeer = lambda *_: FakedPeer()


class BaseStorageServerTestCase(BaseTestCase, TwistedTestCase):
    """Test the StorageServer class.

    This is just a base class with a lot of functionality for other TestCases.
    """

    maxDiff = None
    session_id = '1234-567890'

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(BaseStorageServerTestCase, self).setUp()
        self.last_msg = None
        self.restore = {}
        self.server = StorageServer(session_id=self.session_id)
        self.patch(
            self.server,
            'sendMessage',
            lambda msg: setattr(self, 'last_msg', msg),
        )
        self.patch(self.server, 'factory', FakedFactory())
        self.patch(self.server, 'transport', FakedTransport())

        self.handler = self.add_memento_handler(logger, level=settings.TRACE)

    @property
    def shutdown(self):
        """Property to access self.server.shutting_down attribute."""
        return self.server.shutting_down

    @property
    def msg(self):
        """A per-test message to raise exceptions."""
        return 'Some message for a failure while executing %s.' % self.id()

    def assert_correct_comment(self, comment, msg):
        """Ckeck that error sent had `msg' as comment."""
        self.assertIsNotNone(comment)
        self.assertTrue(len(comment) > 0)
        self.assertIn(str(msg), comment)

    def fail_please(self, failure):
        """Return a function that raises 'failure'."""

        def inner(*args, **kwargs):
            """Do nothing but fail."""
            raise failure

        return inner

    def just_return(self, result):
        """Return a function that returns 'result'."""

        def inner(*args, **kwargs):
            """Do nothing but return a value."""
            return result

        return inner

    def make_protocol_message(self, msg_type=None, msg_id=None):
        message = protocol_pb2.Message()
        if msg_type is not None:
            message.type = getattr(protocol_pb2.Message, msg_type)
        if msg_id is not None:
            message.id = msg_id
        return message


class StorageServerTestCase(BaseStorageServerTestCase):
    """Test the StorageServer class.

    Here are the tests specific for the StorageServer class... other TestCase
    classes should not inherit this.
    """

    def test_log_error(self):
        """Test server._log_error."""
        req = request.Request(protocol=None)
        failure = Failure(Exception(self.msg))
        self.server._log_error(failure, req.__class__)

        self.handler.assert_error(req.__class__.__name__, str(failure))

    def test_schedule_request(self):
        """Test schedule_request adds a logging errback to the request."""
        self.patch(self.server, 'execute_next_request', lambda: None)

        req = request.Request(protocol=self.server)
        req.id = 42
        self.server.requests[req.id] = req
        self.server.schedule_request(request=req, callback=None)

        # assert proper errback was chained
        self.assertEqual(len(req.deferred.callbacks), 1)
        self.assertEqual(
            req.deferred.callbacks[0][1][0],
            self.server._log_error,
            'errback must be correct',
        )
        self.assertEqual(
            req.deferred.callbacks[0][1][1],
            (req.__class__,),
            'errback parameter is correct',
        )

        # the logging callback actually works!
        failure = Failure(Exception(self.msg))
        req.error(failure)
        self.handler.assert_error(str(failure), req.__class__.__name__)

    def test_schedule_request_head(self):
        """Test schedule_request to the left of the deque."""
        self.patch(self.server, 'execute_next_request', lambda: None)

        req1 = request.Request(protocol=self.server)
        req1.id = 42
        self.server.requests[req1.id] = req1
        self.server.schedule_request(req1, None)

        req2 = request.Request(protocol=self.server)
        req2.id = 43
        self.server.requests[req2.id] = req2
        self.server.schedule_request(req2, None, head=True)
        # check that req2 is at the head of the deque
        expected_deque = collections.deque([(req2, None), (req1, None)])
        self.assertEqual(expected_deque, self.server.pending_requests)
        self.assertEqual(req2.id, self.server.pending_requests.popleft()[0].id)

    def test_handle_PROTOCOL_VERSION_when_version_too_low(self):
        """handle_PROTOCOL_VERSION when unsupported version."""
        message = self.make_protocol_message(msg_type='PROTOCOL_VERSION')
        message.protocol.version = self.server.VERSION_REQUIRED - 1

        self.server.handle_PROTOCOL_VERSION(message)

        self.assertTrue(self.shutdown)
        self.assertTrue(self.last_msg is not None)
        self.assertEqual(protocol_pb2.Message.ERROR, self.last_msg.type)
        self.assertEqual(
            protocol_pb2.Error.UNSUPPORTED_VERSION, self.last_msg.error.type
        )
        self.assert_correct_comment(
            comment=self.last_msg.error.comment, msg=message.protocol.version
        )

    def test_handle_PROTOCOL_VERSION_when_version_too_high(self):
        """handle_PROTOCOL_VERSION when unsupported version."""
        message = self.make_protocol_message(msg_type='PROTOCOL_VERSION')
        message.protocol.version = self.server.PROTOCOL_VERSION + 1

        self.server.handle_PROTOCOL_VERSION(message)

        self.assertTrue(self.shutdown)
        self.assertTrue(self.last_msg is not None)
        self.assertEqual(protocol_pb2.Message.ERROR, self.last_msg.type)
        self.assertEqual(
            protocol_pb2.Error.UNSUPPORTED_VERSION, self.last_msg.error.type
        )

        self.assert_correct_comment(
            comment=self.last_msg.error.comment, msg=message.protocol.version
        )

    def test_data_received(self):
        """Test error handling on server.dataReceived method."""
        failure = Exception(self.msg)
        self.patch(self.server, 'buildMessage', self.fail_please(failure))
        self.server.dataReceived(data=None)
        self.handler.assert_exception(failure)

    def test_execute_next_request(self):
        """Test error handling for execute_next_request."""
        failure = Exception(self.msg)
        next_req = (request.Request(None), self.fail_please(failure))
        self.patch(
            self.server, 'pending_requests', collections.deque([next_req])
        )
        self.server.execute_next_request()

        self.handler.assert_exception(failure, next_req[0].__class__.__name__)

    def test_process_message_logs_on_error(self):
        """Test error handling for processMessage."""
        failure = Exception(self.msg)
        self.patch(
            request.RequestHandler, 'processMessage', self.fail_please(failure)
        )
        self.server.processMessage(self.make_protocol_message())
        self.handler.assert_exception(
            failure, self.server.processMessage.__name__
        )

    def test_protocol_ref_enabled(self):
        """Test that protocol weakref is disabled in tests."""
        self.patch(settings, 'PROTOCOL_WEAKREF', True)
        _server = StorageServer()
        response = StorageServerRequestResponse(
            protocol=_server, message=self.make_protocol_message()
        )
        self.assertEqual(_server, response._protocol_ref())
        self.assertEqual(weakref.ref, type(response._protocol_ref))

    def test_protocol_ref_disabled(self):
        """Test that protocol weakref is disabled in tests."""
        self.patch(settings, 'PROTOCOL_WEAKREF', False)
        _server = StorageServer()
        response = StorageServerRequestResponse(
            protocol=_server, message=self.make_protocol_message()
        )
        self.assertEqual(_server, response._protocol_ref)

    def test_looping_ping_enabled(self):
        """Test that the server instantiates the looping ping."""
        self.assertIsInstance(self.server.ping_loop, LoopingPing)

    def test_looping_ping_interval(self):
        """Test the looping ping interval set from the server."""
        self.assertEqual(self.server.ping_loop.interval, 120)

    def test_looping_ping_timeout(self):
        """Test the looping ping timeout set from the server."""
        self.assertEqual(self.server.ping_loop.timeout, 480)

    def test_setuser_set_user(self):
        """Check the user is set."""
        assert self.server.user is None
        user = FakeUser()
        self.server.set_user(user)
        self.assertEqual(self.server.user, user)

    def test_handle_PING(self):
        """Handle PING."""
        # get the response
        response = []
        self.server.sendMessage = lambda r: response.append(r)

        # build the msg
        message = self.make_protocol_message('PING')

        # try it
        self.server.handle_PING(message)

        # check response and logging
        self.assertEqual(response[0].type, protocol_pb2.Message.PONG)
        self.handler.assert_trace("ping pong")


class ActionTestCase(BaseStorageServerTestCase):
    """Test the Action class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(ActionTestCase, self).setUp()
        # create a request-response to use in the tests.
        self.response = StorageServerRequestResponse(
            protocol=self.server, message=self.make_protocol_message()
        )
        self.response.id = 42
        self.response.protocol.requests[self.response.id] = self.response
        self.callable_deferred = defer.Deferred()
        self.action = Action(self.response, self._callable)
        self.increments = []
        self.decrements = []
        self.patch(
            self.response.protocol.factory.metrics,
            'increment',
            self.increments.append,
        )
        self.patch(
            self.response.protocol.factory.metrics,
            'decrement',
            self.decrements.append,
        )

    def _callable(self):
        """Do nothing."""
        return self.callable_deferred

    def test_start(self):
        """Test the start method."""
        self.action.start()
        self.assertTrue(self.action.started)
        self.assertEqual(
            ["action_instances." + Action.__name__], self.increments
        )
        self.handler.assert_debug(
            "Action being scheduled (%s)" % self._callable
        )
        self.handler.assert_debug(
            "Action being started, working on: %s" % self._callable
        )

    def test_start_tail(self):
        """Test the start method, scheduled in the tail."""
        # get the request lock
        self.server.request_locked = self.response
        action = Action(self.response, self._callable)
        action.start()
        self.action.start(False)
        self.assertEqual(action, self.server.pending_requests.popleft()[0])
        self.assertEqual(
            self.action, self.server.pending_requests.popleft()[0]
        )

    def test_start_head(self):
        """Test the start method, scheduled in the head."""
        # get the request lock
        self.server.request_locked = self.response
        self.action.start()
        self.assertFalse(self.action.started)
        action = Action(self.response, self._callable)
        action.start()
        self.action.start()
        self.assertEqual(
            self.action, self.server.pending_requests.popleft()[0]
        )
        self.assertEqual(action, self.server.pending_requests.popleft()[0])

    def test_schedule_start(self):
        """Test the start method."""
        self.server.request_locked = self.response
        self.action.start()
        self.assertEqual(
            ["action_instances." + Action.__name__], self.increments
        )
        self.handler.assert_debug(
            "Action being scheduled (%s)" % self._callable
        )

    def test__start(self):
        """Test the _start method."""

        def _callable():
            """Do nothing."""
            self.callable_deferred.callback(None)
            return self.callable_deferred

        self.action._callable = _callable
        self.action.start()
        self.assertTrue(self.callable_deferred.called)

    def test_cleanup(self):
        """Test the cleanup method."""
        self.action.start()
        self.callable_deferred.callback(None)
        self.assertTrue(self.action.finished)
        self.assertFalse(self.action.started)
        self.assertEqual(
            ["action_instances." + Action.__name__], self.increments
        )
        self.assertEqual(
            ["action_instances." + Action.__name__], self.decrements
        )

    def test_done(self):
        """Test the done method."""
        self.action.start()
        self.callable_deferred.callback(None)
        self.handler.assert_debug("Action done (%s)" % self._callable)

    def test_done_fails(self):
        """Test that error is called if done fails."""
        # patch base class done method, and make it fail.
        exc = RuntimeError("fail!")

        def bad_cleanup(_):
            """cleanup method that always fails."""
            raise exc

        self.patch(Action, 'cleanup', bad_cleanup)
        # patch error method to know it was called
        called = []

        def error(_, e):
            """Collect the errors."""
            called.append(e)

        self.patch(Action, 'error', error)
        self.action.start()
        self.callable_deferred.callback(None)
        self.handler.assert_debug("Action done (%s)" % self._callable)
        # done was called, check if error too.
        self.assertEqual(1, len(called))
        self.assertEqual(exc, called[0].value)

    def test_action_deferred_called(self):
        """Test the action.deferred callback chain."""
        self.action.start()
        result = object()
        self.callable_deferred.callback(result)
        self.assertTrue(self.action.deferred.called)
        self.assertEqual(result, self.action.deferred.result)

    def test_action_deferred_errback_called(self):
        """Test the action.deferred errback chain."""
        self.action.start()
        failure = Failure(RuntimeError("fail!"))
        self.callable_deferred.errback(failure)
        self.assertTrue(self.action.deferred.called)

        def check(f):
            """Check the failure."""
            self.assertEqual(failure, f)

        self.action.deferred.addErrback(check)


class StorageServerRequestResponseTestCase(BaseStorageServerTestCase):
    """Test the StorageServerRequestResponse class."""

    response_class = StorageServerRequestResponse

    @defer.inlineCallbacks
    def setUp(self):
        """Init."""
        yield super(StorageServerRequestResponseTestCase, self).setUp()
        self.errors = []
        self.last_msg = None

        def sendError(myself, msg, comment=None, free_space_info=None):
            """Fake sendError."""
            self.errors.append((msg, comment, free_space_info))

        self.patch(self.response_class, 'sendError', sendError)
        self.patch(
            self.response_class,
            'sendMessage',
            lambda s, m: setattr(self, 'last_msg', m),
        )
        self.response = self.response_class(
            protocol=self.server, message=self.make_protocol_message()
        )
        self.response.id = 42
        self.response.protocol.requests[self.response.id] = self.response
        factory = self.response.protocol.factory
        self.increments = []
        self.decrements = []
        self.patch(factory.metrics, 'increment', self.increments.append)
        self.patch(factory.metrics, 'decrement', self.decrements.append)

    @property
    def last_error(self):
        """Return the last error."""
        return self.errors[-1] if self.errors else None

    def assert_comment_present(self, msg):
        """Ckeck that error sent had `msg' as comment."""
        self.assertTrue(self.last_error is not None)
        self.assertEqual(3, len(self.last_error))
        if self.last_error[2] is not None:
            free_space_info = self.last_error[2]
            self.assertEqual(dict, type(free_space_info))

        comment = self.last_error[1]
        self.assert_correct_comment(comment, msg)

    def test_error_doesnt_fail(self):
        """Test response.error doesn't fail, always log."""
        failure = Exception(self.msg)
        self.patch(request.RequestResponse, 'error', self.fail_please(failure))
        self.response.error(failure=failure)
        self.handler.assert_error(str(failure), self.response.error.__name__)

    def test_process_message_returns_result_when_started(self):
        """Test response.processMessage erturns the result."""
        expected = object()
        self.patch(
            self.response_class, '_processMessage', self.just_return(expected)
        )
        # create a new response with the patched class
        response = self.response_class(
            protocol=self.server, message=self.make_protocol_message()
        )
        response.id = 43
        response.protocol.requests[self.response.id] = self.response
        # check
        message = self.make_protocol_message()
        response.started = True
        actual = response.processMessage(message=message)
        self.assertEqual(
            expected,
            actual,
            'processMessage must return _processMessage result',
        )

    def test_protocol_gone_raise_error(self):
        """Test that ProtocolReferenceError is raised."""
        # patch _protocol_ref to return None, and fake a gc'ed protocol.
        self.patch(self.response, 'use_protocol_weakref', True)
        self.patch(self.response, '_protocol_ref', lambda: None)
        self.assertRaises(
            errors.ProtocolReferenceError, self.response._get_protocol
        )

    @defer.inlineCallbacks
    def test_queue_action(self):
        """Test queue_action"""
        result = object()

        def to_do():
            """Just succeed."""
            return defer.succeed(result)

        r = yield self.response.queue_action(to_do)
        self.assertEqual(result, r)

    def test_request_logger_id_updated(self):
        """Test that StorageRequestLogger.request_id is updated."""
        response = self.response_class(
            protocol=self.server, message=self.make_protocol_message()
        )
        self.assertEqual(None, response.id)
        self.assertEqual(None, response.log.request_id)
        response.id = 42
        self.assertEqual(42, response.id)
        self.assertEqual(42, response.log.request_id)

    def test_stop_if_started(self):
        """Cancel the request if already started."""
        called = []
        self.patch(
            self.response_class, 'cancel', lambda _: called.append(True)
        )
        self.response.started = True
        self.response.stop()
        self.assertTrue(called)

    def test_stop_if_not_started(self):
        """Log and cleanup the request if not started."""
        called = []
        self.patch(
            self.response_class, 'cleanup', lambda _: called.append(True)
        )
        assert not self.response.started
        self.response.stop()
        self.assertTrue(called)
        self.handler.assert_debug("Request being released before start")


class SSRequestResponseSpecificTestCase(StorageServerRequestResponseTestCase):
    """Test the StorageServerRequestResponse class, not all inherited ones."""

    @defer.inlineCallbacks
    def test_done_user_activity_yes(self):
        """Report the request's user activity string."""
        # put a user_activity in the class
        self.response_class.user_activity = 'test-activity'
        self.addCleanup(delattr, self.response_class, 'user_activity')

        # set a user
        self.response.protocol.user = FakeUser()

        # record what is measured
        informed = []
        self.patch(
            self.response.protocol.factory.user_metrics,
            'report',
            lambda *a: informed.extend(a),
        )

        # execute and test
        self.response.done()
        yield self.response.deferred

        self.assertEqual(informed, ['test-activity', '42'])

    @defer.inlineCallbacks
    def test_done_user_activity_no_activity(self):
        """Don't report the request's user activity, as there is no string."""
        # assure there's no activity
        assert not hasattr(self.response_class, 'user_activity')

        # record what is measured
        informed = []
        self.patch(
            self.response.protocol.factory.user_metrics,
            'report',
            lambda *a: informed.extend(a),
        )

        # execute and test
        self.response.done()
        yield self.response.deferred
        self.assertEqual(informed, [])

    @defer.inlineCallbacks
    def test_done_user_activity_no_user_name(self):
        """Report the request's user activity, but still no user."""
        # put a user_activity in the class
        self.response_class.user_activity = 'test-activity'
        self.addCleanup(delattr, self.response_class, 'user_activity')

        # assure there's no user
        assert self.response.protocol.user is None

        # record what is measured
        informed = []
        self.patch(
            self.response.protocol.factory.user_metrics,
            'report',
            lambda *a: informed.extend(a),
        )

        # execute and test
        self.response.done()
        yield self.response.deferred
        self.assertEqual(informed, ['test-activity', ''])

    def test_get_extension_valids(self):
        """Get a 2 chars extension."""
        ext = self.response._get_extension("code.c")
        self.assertEqual(ext, "c")
        ext = self.response._get_extension("binary.db")
        self.assertEqual(ext, "db")
        ext = self.response._get_extension("image.png")
        self.assertEqual(ext, "png")
        ext = self.response._get_extension("image.jpeg")
        self.assertEqual(ext, "jpeg")

    def test_get_extension_toolong(self):
        """Get an extension from something that has too long similar one."""
        ext = self.response._get_extension("document.personal")
        self.assertEqual(ext, None)

    def test_get_extension_path(self):
        """Get an extension from a big path."""
        ext = self.response._get_extension("/foo/bar/etc/image.png")
        self.assertEqual(ext, "png")

    def test_get_extension_several_dots(self):
        """Get an extension from a path with several dots."""
        ext = self.response._get_extension("/foo/bar.etc/image.stuff.png")
        self.assertEqual(ext, "png")

    def test_get_extension_small_name(self):
        """Get an extension from a small name."""
        ext = self.response._get_extension("do")
        self.assertEqual(ext, None)

    def test_get_extension_nothing(self):
        """Get an extension not finding one."""
        ext = self.response._get_extension("alltogetherjpg")
        self.assertEqual(ext, None)


class SimpleRequestResponseTestCase(StorageServerRequestResponseTestCase):
    """Test the SimpleRequestResponse class."""

    response_class = SimpleRequestResponse

    def test_retry_limit_reached_sends_try_again(self):
        """When RetryLimitReached is raised TRY_AGAIN is sent."""
        self.assertIn(
            dataerror.RetryLimitReached, self.response.try_again_errors
        )

    def test_tcp_timeout_sends_try_again(self):
        """When TCPTimedOutError is raised TRY_AGAIN is sent."""
        self.assertIn(txerror.TCPTimedOutError, self.response.try_again_errors)

    def test_translation_does_not_exist(self):
        """DoesNotExist is properly translated."""
        e = self.response.protocol_errors[dataerror.DoesNotExist]
        self.assertEqual(protocol_pb2.Error.DOES_NOT_EXIST, e)

    def test_send_protocol_error_handles_retry_limit_reached(self):
        """_send_protocol_error handles the RetryLimitReached."""
        failure = Failure(dataerror.RetryLimitReached(self.msg))
        self.response._send_protocol_error(failure=failure)
        self.assertTrue(self.last_error is not None)
        self.assertEqual(protocol_pb2.Error.TRY_AGAIN, self.last_error[0])
        self.assertEqual(
            "TryAgain (RetryLimitReached: %s)" % self.msg, self.last_error[1]
        )

    def test_tcp_timeout_handled_as_try_again(self):
        """_send_protocol_error handles TCPTimedOutError as TRY_AGAIN."""
        failure = Failure(txerror.TCPTimedOutError())
        self.response._send_protocol_error(failure=failure)
        self.assertTrue(self.last_error is not None)
        self.assertEqual(protocol_pb2.Error.TRY_AGAIN, self.last_error[0])

    def test_send_protocol_error_handles_does_not_exist(self):
        """_send_protocol_error handles the DoesNotExist."""
        failure = Failure(dataerror.DoesNotExist(self.msg))
        self.response._send_protocol_error(failure=failure)
        self.assertTrue(self.last_error is not None)
        self.assertEqual(protocol_pb2.Error.DOES_NOT_EXIST, self.last_error[0])
        self.assertEqual(self.msg, self.last_error[1])

    def test_send_protocol_error_sends_comment(self):
        """_send_protocol_error sends the optional comment on errors."""
        errors = self.response.protocol_errors
        self.response.__class__.expected_errors = errors.keys()
        for error in self.response.protocol_errors:
            msg = 'Failing with %s' % error
            if error == dataerror.QuotaExceeded:
                failure = Failure(error(msg, uuid.uuid4(), 10))
            else:
                failure = Failure(error(msg))
            self.response._send_protocol_error(failure=failure)
            self.assert_comment_present(msg)

        # any error not in protocol_errors
        msg = "ñoño message with non ascii chars"
        failure = Failure(Exception(msg))
        self.response._send_protocol_error(failure=failure)
        self.assert_comment_present(msg)

    def test_send_protocol_error_dont_shutdown(self):
        """_send_protocol_error don't shutdown the StorageServer instance."""
        failure = Failure(ValueError(self.msg))
        self.response._send_protocol_error(failure=failure)
        self.assertTrue(self.last_error is not None)
        self.assertEqual(protocol_pb2.Error.INTERNAL_ERROR, self.last_error[0])
        self.assertEqual(self.msg, self.last_error[1])
        self.assertFalse(self.shutdown)

    def test_send_protocol_error_try_again_is_metered(self):
        """_send_protocol_error sends metrics on TryAgain errors."""
        mock_metrics = mock.Mock(name='metrics')
        self.patch(self.response.protocol.factory, 'metrics', mock_metrics)

        failure = Failure(errors.TryAgain(ValueError(self.msg)))
        self.response._send_protocol_error(failure=failure)

        mock_metrics.meter.assert_called_once_with("TRY_AGAIN.ValueError", 1)

    def test_send_protocol_error_converted_try_again_is_metered(self):
        """_send_protocol_error sends metrics on convertd TryAgain errors."""
        mock_metrics = mock.Mock(metrics.FileBasedMeter)
        self.patch(self.response.protocol.factory, 'metrics', mock_metrics)
        error = self.response.try_again_errors[0]

        failure = Failure(error(self.msg))
        self.response._send_protocol_error(failure=failure)

        mock_metrics.meter.assert_called_once_with(
            "TRY_AGAIN.%s" % error.__name__, 1
        )

    def test_send_protocol_error_locked_user(self):
        """_send_protocol_error handles the LockedUserError"""
        called = []
        self.patch(
            self.response.protocol, 'shutdown', lambda: called.append(1)
        )
        failure = Failure(dataerror.LockedUserError())
        self.response._send_protocol_error(failure=failure)
        self.assertEqual(self.last_error, None)
        self.assertEqual(called, [1])

    def fake_reactor_inspector(self, last_responsive_ts):
        """Instance that fakes the last_responsive_ts attribute."""

        class FakeReactorInspector:
            """Just fakes the last_responsive_ts field."""

            def __init__(self, last_responsive_ts):
                """Pass in the fake last_responsive_ts value."""
                self.last_responsive_ts = last_responsive_ts

        return FakeReactorInspector(last_responsive_ts)

    def test_start_sends_comment_on_error(self):
        """_start sends the optional comment on errors."""
        self.patch(self.response_class, 'authentication_required', True)
        self.response.protocol.user = None
        self.response._start()
        self.assert_comment_present(self.response.auth_required_error)

    @defer.inlineCallbacks
    def test_done_never_fails_if_inner_done_fails(self):
        """_start never fails even if done() fails."""
        failure = Exception(self.msg)
        self.patch(request.RequestResponse, 'done', self.fail_please(failure))

        self.response.done()
        yield self.assertFailure(self.response.deferred, Exception)

        self.assertTrue(
            self.response.deferred.called, 'request.deferred was fired.'
        )
        self.handler.assert_exception(
            failure, self.response.__class__.__name__
        )

    def test_get_node_info(self):
        """Test the correct info generation."""
        self.response = self.response_class(
            protocol=self.server, message=self.make_protocol_message()
        )

    def test_log_working_on_nothing(self):
        """Log working on without specifications."""
        message = self.make_protocol_message()
        req = self.response_class(self.server, message)
        req.start()
        self.handler.assert_debug("Request being started")

    def test_request_instances_metric(self):
        """request_instances.<request> is updated."""
        message = self.make_protocol_message()
        req = self.response_class(self.server, message)
        req.start()
        self.assertIn(
            "request_instances." + self.response_class.__name__,
            self.increments,
        )
        self.assertIn(
            "request_instances." + self.response_class.__name__,
            self.decrements,
        )

    def test_log_working_on_something(self):
        """Log working on something."""
        message = self.make_protocol_message()
        self.patch(self.response_class, '_get_node_info', lambda _: 'FOO')
        req = self.response_class(self.server, message)
        req.start()
        self.handler.assert_debug("Request being started, working on: FOO")

    def test_log_operation_data(self):
        """Log data operation."""
        message = self.make_protocol_message()
        req = self.response_class(self.server, message)
        req.operation_data = "some=stuff bar=foo"
        req.done()
        self.handler.assert_info("Request done: some=stuff bar=foo")

    def test_log_request_process(self):
        """Log correctly the life of a request."""
        # setup the message
        message = self.make_protocol_message(msg_id=42)
        self.patch(self.response_class, '_process', lambda _: None)
        req = self.response_class(self.server, message)
        req.start()

        # assert log order
        msgs = [
            (r.levelname, r.msg)
            for r in self.handler.records
            if r.levelno >= logging.DEBUG
        ]
        prefix = '%s localhost:0 - %s 42 - ' % (
            self.session_id,
            self.response_class.__name__,
        )

        node = req._get_node_info()
        if node is None:
            working_on = ""
        else:
            working_on = ", working on: " + node
        expected = [
            ('INFO', prefix + 'Request being scheduled'),
            ('DEBUG', prefix + "Request being started" + working_on),
            ('INFO', prefix + 'Request done'),
        ]
        self.assertItemsEqual(msgs, expected)

    @defer.inlineCallbacks
    def test_internal_error(self):
        """Test for the internal_error method."""
        failure = Failure(ValueError(self.msg))
        self.response.internal_error(failure=failure)
        yield self.assertFailure(self.response.deferred, ValueError)
        self.assertTrue(self.response.finished)
        self.assertTrue(self.shutdown)

    def test_internal_error_after_shutdown(self):
        """Test for getting internal errors after shutdown."""
        # shutdown the server, just like if another request
        # failed with internal error
        self.server.shutdown()
        self.assertTrue(self.shutdown)
        self.assertTrue(self.response.finished)
        # now, make this one fail with internal error
        called = []
        self.patch(self.server, 'shutdown', lambda: called.append(1))
        failure = Failure(ValueError(self.msg))
        # the request is already finished
        self.response.internal_error(failure=failure)
        self.assertTrue(self.response.finished)
        self.assertFalse(called)

    def test_cancel_filter(self):
        """Test the cancel_filter decorator."""
        self.response_class.fakefunction = cancel_filter(lambda *a: 'hi')
        self.addCleanup(delattr, self.response_class, 'fakefunction')

        self.assertEqual(self.response.fakefunction(self.response), "hi")
        self.response.cancelled = True
        self.assertRaises(
            request.RequestCancelledError,
            self.response.fakefunction,
            self.response,
        )

    def test_requests_leak(self):
        """Test that the server shutdown remove non-started requests."""
        # remove the default request
        del self.server.requests[42]
        # set a fake user.
        self.server.user = mock.Mock(username="username", id=1)

        cleaned = []
        orig_cleanup = self.response_class.cleanup

        def fake_cleanup(response):
            """Clean up the request, but flag it here for the tests."""
            cleaned.append(response.id)
            orig_cleanup(response)

        # patch the _start method to avoid real Response execution
        start_deferred = defer.Deferred()

        @defer.inlineCallbacks
        def fake_start(r):
            """Fake start."""
            yield start_deferred

            # call done() only if it's not a PutContent response, as it handles
            # its own termination in its own _cancel() method (that is called
            # for the running instance at shutdown() time).
            if not isinstance(r, PutContentResponse):
                r.done()

        self.patch(self.response_class, 'cleanup', fake_cleanup)
        self.patch(self.response_class, '_start', fake_start)
        for i in range(5):
            response = self.response_class(
                protocol=self.server, message=self.make_protocol_message()
            )
            response.source_message.id = i
            response.start()
        self.assertTrue(self.server.pending_requests)

        # we should have 4 pending_requests
        self.assertEqual(
            len(self.server.pending_requests), 4, self.server.pending_requests
        )

        # the first request should be executing
        running_request = self.server.requests[0]
        self.assertTrue(running_request.started)

        # shutdown and check that pending_requests is clean
        self.server.shutdown()
        self.assertFalse(
            self.server.pending_requests, self.server.pending_requests
        )

        # trigger the executing request _process deferred, for
        # it to finish, the requests should be clean now
        start_deferred.callback(True)
        self.assertFalse(self.server.requests, self.server.requests)

        # verify that all the requests were properly cleaned
        self.assertEqual(sorted(cleaned), list(range(5)), cleaned)

    @defer.inlineCallbacks
    def test_sli_informed_on_done_default(self):
        """The SLI is informed when all ok."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'sli_metrics', mock_metrics)
        self.response.start_time = time.time()

        self.response.done()
        yield self.response.deferred

        mock_metrics.timing.assert_called_once_with(
            self.response_class.__name__, mock.ANY
        )

    @defer.inlineCallbacks
    def test_sli_informed_on_done_some_value(self):
        """The SLI is informed when all ok."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'sli_metrics', mock_metrics)
        op_length = 12345
        self.response.start_time = time.time()

        self.response.length = op_length
        self.response.done()
        yield self.response.deferred

        mock_metrics.timing.assert_called_once_with(
            self.response_class.__name__, mock.ANY
        )

    @defer.inlineCallbacks
    def test_sli_informed_on_error(self):
        """The SLI is informed after a problem."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'sli_metrics', mock_metrics)

        self.response.error(ValueError(self.msg))
        yield self.assertFailure(self.response.deferred, ValueError)

        mock_metrics.report.assert_called_once_with(
            'sli_error', self.response_class.__name__
        )


class ListSharesTestCase(SimpleRequestResponseTestCase):
    """Test the ListShares class."""

    response_class = ListShares

    @defer.inlineCallbacks
    def test_process_set_length(self):
        """Set length attribute while processing."""
        # fake share
        share = dict(
            id=None,
            from_me=None,
            to_me=None,
            root_id=None,
            name='name',
            shared_by_username='sby',
            accepted=False,
            shared_to_username='sto',
            shared_by_visible_name='vby',
            shared_to_visible_name='vto',
            access=Share.VIEW,
        )
        # fake user
        user = mock.Mock(root_volume_id='')
        shared_by = [share] * 3
        shared_to = [share] * 2
        user.list_shares.return_value = (shared_by, shared_to)
        user.get_volume_id.return_value = None
        self.response.protocol.user = user

        yield self.response._process()

        self.assertEqual(self.response.length, 5)
        expected_calls = [
            mock.call.list_shares(),
            mock.call.get_volume_id(None),
            mock.call.get_volume_id(None),
            mock.call.get_volume_id(None),
        ]
        self.assertEqual(user.mock_calls, expected_calls)


class ShareAcceptedTestCase(SimpleRequestResponseTestCase):
    """Test the ShareAccepted class."""

    response_class = ShareAccepted


class CreateShareTestCase(SimpleRequestResponseTestCase):
    """Test the CreateShare class."""

    response_class = CreateShare

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'create_share')


class DeleteShareTestCase(SimpleRequestResponseTestCase):
    """Test the DeleteShare class."""

    response_class = DeleteShare


class CreateUDFTestCase(SimpleRequestResponseTestCase):
    """Test the CreateUDF class."""

    response_class = CreateUDF

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'sync_activity')


class DeleteVolumeTestCase(SimpleRequestResponseTestCase):
    """Test the DeleteVolume class."""

    response_class = DeleteVolume

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'sync_activity')


class ListVolumesTestCase(SimpleRequestResponseTestCase):
    """Test the ListVolumes class."""

    response_class = ListVolumes

    @defer.inlineCallbacks
    def test_process_set_length(self):
        """Set length attribute while processing."""
        # fake share
        share = dict(
            id=None,
            root_id=None,
            name='name',
            path="somepath",
            shared_by_username='sby',
            accepted=False,
            shared_by_visible_name='vby',
            access=Share.VIEW,
            generation=9,
            free_bytes=123,
        )
        # fake user
        user = mock.Mock()
        root = share
        shares = [share] * 3
        udfs = [share] * 2
        user.list_volumes.return_value = (root, shares, udfs, 123)
        self.response.protocol.user = user

        yield self.response._process()

        self.assertEqual(self.response.length, 6)
        user.list_volumes.assert_called_once_with()


class ChangePublicAccessTestCase(SimpleRequestResponseTestCase):
    """Test the ChangePublicAccess class."""

    response_class = ChangePublicAccess


class ListPublicFilesTestCase(SimpleRequestResponseTestCase):
    """Test the ListPublicFiles class."""

    response_class = ListPublicFiles

    @defer.inlineCallbacks
    def test_process_set_values(self):
        """Set length attribute and operation data while processing."""
        user = mock.Mock()
        self.response.protocol.user = user

        nodes = [FakeNode(), FakeNode()]
        user.list_public_files.return_value = nodes

        yield self.response._process()

        self.assertEqual(self.response.length, 2)
        self.assertEqual(self.response.operation_data, "public_files=2")
        user.list_public_files.assert_called_once_with()


class UnlinkTestCase(SimpleRequestResponseTestCase):
    """Test the Unlink class."""

    response_class = Unlink

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'sync_activity')


class GetContentResponseTestCase(SimpleRequestResponseTestCase):
    """Test the GetContentResponse class."""

    response_class = GetContentResponse

    def test_download_last_good_state(self):
        """Test that last_good_state_ts gets updated properly."""
        before = time.time()
        time.sleep(0.1)
        self.response.start()
        after = time.time()
        self.assertTrue(before < self.response.last_good_state_ts <= after)
        time.sleep(0.1)

        class FakeProducer:
            """Fake source of data to download."""

            def __init__(self):
                self.deferred = defer.Deferred()
                self.consumer = None

            def resumeProducing(self):
                """Do nothing."""

            pauseProducing = stopProducing = resumeProducing

            def startProducing(self, consumer):
                """Wait a little."""
                time.sleep(0.1)
                consumer.write(b"abc")

        fake_producer = FakeProducer()
        self.response.send(fake_producer)
        self.assertTrue(self.response.last_good_state_ts > after)

    def test_start_sends_comment_on_error(self):
        """_start sends the optional comment on errors."""
        self.response.protocol.user = None
        self.response._start()
        self.assert_comment_present(self.response.auth_required_error)

    def test_on_request_cancelled_error_with_cancel_message(self):
        """_send_protocol_error sends CANCELLED when RequestCancelledError.

        self.response.cancel_message is not None.

        """
        self.response.cancel_message = self.make_protocol_message(msg_id=1)
        assert not self.response.cancelled

        failure = Failure(request.RequestCancelledError(self.msg))
        self.response._send_protocol_error(failure=failure)
        self.assertTrue(self.last_error is None)
        self.assertTrue(self.last_msg is not None)
        self.assertEqual(protocol_pb2.Message.CANCELLED, self.last_msg.type)

    def test_on_request_cancelled_error_without_cancel_message(self):
        """_send_protocol_error logs warning.

        self.response.cancel_message is None.

        """
        self.response.cancel_message = None  # no cancel_message

        failure = Failure(request.RequestCancelledError(self.msg))
        self.response._send_protocol_error(failure=failure)
        self.assertTrue(self.last_error is None)
        self.assertTrue(self.last_msg is None)

        self.handler.assert_warning(str(failure), 'cancel_message is None')

    def test__init__(self):
        """Test __init__."""
        message = self.make_protocol_message()
        response = GetContentResponse(self.server, message)
        self.assertEqual(response.cancel_message, None)
        self.assertEqual(response.message_producer, None)
        self.assertEqual(response.transferred, 0)

    @defer.inlineCallbacks
    def test_transferred_informed_on_done(self):
        """The transferred quantity is informed when all ok."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'metrics', mock_metrics)

        self.response.transferred = 123
        self.response.done()
        yield self.response.deferred

        mock_metrics.gauge.assert_called_once_with(
            'GetContentResponse.transferred', 123
        )

    @defer.inlineCallbacks
    def test_transferred_informed_on_error(self):
        """The transferred quantity is informed after a problem."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'metrics', mock_metrics)

        self.response.transferred = 123
        self.response.error(ValueError(self.msg))
        yield self.assertFailure(self.response.deferred, ValueError)

        mock_metrics.gauge.assert_called_once_with(
            'GetContentResponse.transferred', 123
        )

    @defer.inlineCallbacks
    def test_sli_informed_on_done_default(self):
        """The SLI is NOT informed when all ok."""
        self.patch(
            self.response.protocol.factory.sli_metrics,
            'timing',
            lambda *a: self.fail("Must not be called"),
        )
        self.response.start_time = time.time()
        self.response.done()
        yield self.response.deferred

    @defer.inlineCallbacks
    def test_sli_informed_on_done_some_value(self):
        """The SLI is informed when all ok."""
        self.patch(
            self.response.protocol.factory.sli_metrics,
            'timing',
            lambda *a: self.fail("Must not be called"),
        )
        self.response.start_time = time.time()
        self.response.transferred = 12345
        self.response.done()
        yield self.response.deferred

    @defer.inlineCallbacks
    def test_sli_informed_on_done_zero_value(self):
        """The SLI is informed when all ok."""
        self.patch(
            self.response.protocol.factory.sli_metrics,
            'timing',
            lambda *a: self.fail("Must not be called"),
        )
        self.response.start_time = time.time()
        self.response.transferred = 0
        self.response.done()
        yield self.response.deferred

    def test_sli_informed_on_init(self):
        """The SLI is informed after the operation init part."""
        # fake producer
        producer = mock.Mock()
        # some node
        node = mock.Mock(
            deflated_size=3, size=2, content_hash='hash', crc32=123
        )
        node.get_content.return_value = defer.succeed(producer)
        # the user
        fake_user = mock.Mock(username='username', name='user')
        fake_user.get_node.return_value = defer.succeed(node)
        self.patch(self.response.protocol, 'user', fake_user)
        # the metric itself
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'sli_metrics', mock_metrics)

        self.response._start()

        fake_user.get_node.assert_called_once_with(None, '', '')
        node.get_content.assert_called_once_with(
            user=fake_user, previous_hash='', start=0
        )
        mock_metrics.timing.assert_called_once_with(
            'GetContentResponseInit', mock.ANY
        )


class PutContentResponseTestCase(SimpleRequestResponseTestCase):
    """Test the PutContentResponse class."""

    class PutContentResponse(PutContentResponse):
        """Subclass so we have a __dict__ and can patch it."""

    response_class = PutContentResponse

    class FakeUploadJob(object):
        """Fake an UploadJob."""

        def __init__(self):
            self.bytes = b''
            self.inflated_size_hint = 1000
            self.ops = defer.succeed(None)
            self.deferred = defer.Deferred()
            self.called = []
            self.storage_key = "fake storagekey"

        def stop(self):
            """Fake."""
            self.called.append('stop')

        def connect(self):
            """Flag the call."""
            self.called.append('connect')

        def cancel(self):
            """Flag the call."""
            self.called.append('cancel')

        def add_data(self, bytes):
            """Add data."""
            self.bytes += bytes
            self.called.append({'add_data': bytes})

        def registerProducer(self, producer):
            """Register the producer."""
            self.called.append('registerProducer')

        def unregisterProducer(self):
            """Unregister the producer."""
            self.called.append('unregisterProducer')

        def add_operation(self, op, err):
            self.ops.addCallback(op)
            self.ops.addErrback(err)

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'sync_activity')

    def test__init__(self):
        """Test __init__."""
        message = self.make_protocol_message()
        response = PutContentResponse(self.server, message)
        self.assertEqual(response.cancel_message, None)
        self.assertEqual(response.upload_job, None)
        self.assertEqual(response.source_message, message)
        self.assertEqual(response.protocol, self.server)
        self.assertEqual(response.transferred, 0)

    def test__get_node_info(self):
        """Test _get_node_info."""
        message = self.make_protocol_message(msg_type='PUT_CONTENT')
        message.put_content.node = 'abc'
        response = PutContentResponse(self.server, message)
        node_info = response._get_node_info()
        self.assertEqual(node_info, "node: 'abc'")

    @defer.inlineCallbacks
    def test_transferred_informed_on_done(self):
        """The transferred quantity is informed when all ok."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'metrics', mock_metrics)

        self.response.transferred = 123
        self.response.done()
        yield self.response.deferred

        mock_metrics.gauge.assert_called_once_with(
            'PutContentResponse.transferred', 123
        )

    @defer.inlineCallbacks
    def test_transferred_informed_on_error(self):
        """The transferred quantity is informed after a problem."""
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'metrics', mock_metrics)

        self.response.transferred = 123
        self.response.error(ValueError(self.msg))
        yield self.assertFailure(self.response.deferred, ValueError)

        mock_metrics.gauge.assert_called_once_with(
            'PutContentResponse.transferred', 123
        )

    @defer.inlineCallbacks
    def test_sli_informed_on_done_default(self):
        """The SLI is informed when all ok."""
        self.patch(
            self.response.protocol.factory.sli_metrics,
            'timing',
            lambda *a: self.fail("Must not be called"),
        )
        self.response.start_time = time.time()
        self.response.done()
        yield self.response.deferred

    @defer.inlineCallbacks
    def test_sli_informed_on_done_some_value(self):
        """The SLI is informed when all ok."""
        self.patch(
            self.response.protocol.factory.sli_metrics,
            'timing',
            lambda *a: self.fail("Must not be called"),
        )
        self.response.start_time = time.time()
        self.response.transferred = 12345
        self.response.done()
        yield self.response.deferred

    @defer.inlineCallbacks
    def test_sli_informed_on_done_zero_value(self):
        """The SLI is informed when all ok."""
        self.patch(
            self.response.protocol.factory.sli_metrics,
            'timing',
            lambda *a: self.fail("Must not be called"),
        )
        self.response.start_time = time.time()
        self.response.transferred = 0
        self.response.done()
        yield self.response.deferred

    @defer.inlineCallbacks
    def test_sli_informed_on_init(self):
        """The SLI is informed after the operation init part."""
        # fake uploadjob
        uploadjob = mock.Mock(
            deferred=defer.Deferred(), name='upload-job', offset=5
        )
        uploadjob.connect.return_value = defer.succeed(None)
        self.patch(
            self.response, '_get_upload_job', lambda: defer.succeed(uploadjob)
        )
        # the user
        fake_user = mock.Mock(username='foo')
        self.patch(self.response.protocol, 'user', fake_user)

        # the metric itself
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'sli_metrics', mock_metrics)

        yield self.response._start()

        mock_metrics.timing.assert_called_once_with(
            'PutContentResponseInit', mock.ANY
        )
        uploadjob.connect.assert_called_once_with()

    @defer.inlineCallbacks
    def test_sli_informed_on_commit(self):
        """The SLI is informed after the operation commit part."""
        self.response.state = PutContentResponse.states.commiting
        self.patch(self.response, 'queue_action', lambda _: defer.succeed(0))

        # the metric itself
        mock_metrics = mock.Mock()
        self.patch(self.response.protocol.factory, 'sli_metrics', mock_metrics)

        yield self.response._commit_uploadjob('result')

        mock_metrics.timing.assert_called_once_with(
            'PutContentResponseCommit', mock.ANY
        )

    def test_start_authentication_required(self):
        """Test that _start sends the optional comment on errors."""
        assert self.response.protocol.user is None
        self.response._log_start = mock.Mock()
        self.response.sendError = mock.Mock()
        self.response.done = mock.Mock()

        self.response._start()

        self.assertEqual(self.response.state, PutContentResponse.states.done)
        self.response._log_start.assert_called_once_with()
        self.response.sendError.assert_called_once_with(
            protocol_pb2.Error.AUTHENTICATION_REQUIRED,
            comment=self.response.auth_required_error,
        )
        self.response.done.assert_called_once_with()

    def test_start_upload_started_ok(self):
        """Test _start starts an upload."""
        self.response.protocol.user = 'user'
        self.response._log_start = mock.Mock()
        self.response._start_upload = mock.Mock(return_value=defer.Deferred())

        self.response._start()

        self.assertEqual(self.response.state, PutContentResponse.states.init)
        self.response._log_start.assert_called_once_with()
        self.response._start_upload.assert_called_once_with()

    def test_start_upload_started_error(self):
        """Test _start calls to generic error after a failing upload start."""
        self.response.protocol.user = 'user'

        self.response._log_start = mock.Mock()
        failure = Failure(NameError(self.msg))
        self.response._start_upload = mock.Mock(
            return_value=defer.fail(failure)
        )
        self.response._generic_error = mock.Mock()

        self.response._start()

        self.response._log_start.assert_called_once_with()
        self.response._start_upload.assert_called_once_with()
        self.response._generic_error.assert_called_once_with(failure)

    def test_upload_last_good_state(self):
        """Test that last_good_state_ts gets updated as expected."""
        upload_job = self.FakeUploadJob()
        upload_job.offset = 0
        upload_job.upload_id = str(uuid.uuid4())

        user = mock.Mock(username='username', name='name')
        user.get_upload_job.return_value = upload_job
        self.response.protocol.user = user

        transport = mock.Mock(name='transport')
        self.server.transport = transport
        transport.getPeer.return_value = FakedPeer()

        self.response._log_start = mock.Mock()
        self.response.upload_job = upload_job

        before = time.time()
        time.sleep(0.1)
        self.response.start()
        after = time.time()
        self.assertTrue(before < self.response.last_good_state_ts <= after)
        time.sleep(0.1)

        bytes_msg = self.make_protocol_message('BYTES')
        bytes_msg.bytes.bytes = b"123"

        self.response.processMessage(bytes_msg)

        self.assertTrue(self.response.last_good_state_ts > after)
        self.assertEqual(b"123", upload_job.bytes)
        self.assertEqual(
            self.response.state, PutContentResponse.states.uploading
        )

        user.get_upload_job.assert_called_once_with(
            None,
            '',
            '',
            '',
            0,
            0,
            0,
            session_id=self.session_id,
            magic_hash=None,
            upload_id=None,
        )
        self.response._log_start.assert_called_once_with()
        transport.getPeer.assert_called()
        expected_calls = [  # XXX: missing 'registerProducer'
            'connect',
            {'add_data': b'123'},
        ]
        self.assertEqual(upload_job.called, expected_calls)

    def test__cancel_uploadjob_cancelled(self):
        """Test cancel cancelling the upload_job."""
        self.response.state = PutContentResponse.states.canceling
        self.response.cancel_message = self.make_protocol_message(msg_id=123)
        self.response.upload_job = mock.Mock()

        self.response._cancel()

        self.handler.assert_debug("Canceling the upload job")
        self.response.upload_job.cancel.assert_called_once_with()

    def test__cancel_uploadjob_cancel_None(self):
        """Test cancel not having an upload_job."""
        self.response.state = PutContentResponse.states.canceling
        self.response.cancel_message = self.make_protocol_message(msg_id=123)

        assert self.response.upload_job is None
        self.response._cancel()

        self.handler.assert_not_logged("Canceling the upload job")

    def test__cancel_uploadjob_stopped(self):
        """Test cancel cancelling the upload_job."""
        assert self.response.state != PutContentResponse.states.canceling
        self.response.upload_job = mock.Mock()

        self.response._cancel()

        self.handler.assert_debug("Stoping the upload job after a cancel")
        self.response.upload_job.stop.assert_called_once_with()

    @defer.inlineCallbacks
    def test__cancel_uploadjob_stop_None(self):
        """Test cancel not having an upload_job."""
        assert self.response.state != PutContentResponse.states.canceling
        assert self.response.upload_job is None

        self.response._cancel()
        yield self.response.deferred

        self.handler.assert_not_logged("Stoping the upload job after a cancel")

    def test__cancel_answer_client_yes(self):
        """Test answer is sent to the client because canceling."""
        self.response.state = PutContentResponse.states.canceling

        # set up the original message
        self.response.cancel_message = self.make_protocol_message(msg_id=123)

        # be sure to close the request
        called = []
        self.response.done = lambda: called.append(True)

        # call and check
        self.response._cancel()

        self.assertTrue(called)
        self.assertEqual(self.response.state, PutContentResponse.states.done)
        self.assertEqual(self.last_msg.type, protocol_pb2.Message.CANCELLED)
        self.assertEqual(self.last_msg.id, 123)

    def test__cancel_answer_client_no(self):
        """Test answer is not sent to the client if not canceling."""
        assert self.response.state != PutContentResponse.states.canceling

        # be sure to close the request
        called = []
        self.response.done = lambda: called.append(True)

        # call and check
        self.response._cancel()

        self.assertTrue(called)
        self.assertEqual(self.response.state, PutContentResponse.states.done)

    def test__cancel_always_move_to_canceling(self):
        """Test that we always move to canceling state."""
        assert self.response.state == PutContentResponse.states.init
        self.response.upload_job = upload_job = mock.Mock()

        # be sure to close the request
        called = []
        self.response.done = lambda: called.append(True)

        def save_state():
            """Save current state."""
            called.append(self.response.state)

        upload_job.stop.side_effect = save_state
        # call and check
        self.response._cancel()

        self.handler.assert_debug("Request canceled (in INIT)")
        self.assertEqual(len(called), 2)
        self.assertEqual(called[0], PutContentResponse.states.canceling)
        self.assertEqual(called[1], True)
        self.assertEqual(self.response.state, PutContentResponse.states.done)
        upload_job.stop.assert_called_once_with()

    @defer.inlineCallbacks
    def test_genericerror_log_error(self):
        """Generic error logs when called with an error."""
        assert self.response.state == PutContentResponse.states.init
        yield self.response._generic_error(NameError(self.msg))
        yield self.assertFailure(self.response.deferred, NameError)
        self.handler.assert_warning(
            "Error while in INIT", "NameError", self.msg
        )

    @defer.inlineCallbacks
    def test_genericerror_log_failure(self):
        """Generic error logs when called with a failure."""
        assert self.response.state == PutContentResponse.states.init

        yield self.response._generic_error(Failure(NameError(self.msg)))
        yield self.assertFailure(self.response.deferred, NameError)

        self.handler.assert_warning(
            "Error while in INIT", "NameError", self.msg
        )

    @defer.inlineCallbacks
    def test_genericerror_already_in_error(self):
        """Just log if already in error."""
        self.response.state = PutContentResponse.states.error
        called = []
        self.response._send_protocol_error = called.append
        yield self.response._generic_error(NameError(self.msg))
        self.assertFalse(called)
        self.handler.assert_warning(
            "Error while in ERROR", "NameError", self.msg
        )

    @defer.inlineCallbacks
    def test_genericerror_already_in_done(self):
        """Just log if already in done."""
        self.response.state = PutContentResponse.states.done
        called = []
        self.response._send_protocol_error = called.append
        yield self.response._generic_error(NameError(self.msg))
        self.assertFalse(called)
        self.handler.assert_warning(
            "Error while in DONE", "NameError", self.msg
        )

    @defer.inlineCallbacks
    def test_genericerror_no_uploadjob(self):
        """Don't stop the upload job if doesn't have one."""
        assert self.response.upload_job is None

        yield self.response._generic_error(NameError(self.msg))
        yield self.assertFailure(self.response.deferred, NameError)

        self.handler.assert_not_logged("Stoping the upload job after an error")

    @defer.inlineCallbacks
    def test_genericerror_stop_uploadjob(self):
        """Stop the upload job if has one."""
        self.response.upload_job = mock.Mock()

        yield self.response._generic_error(NameError(self.msg))
        yield self.assertFailure(self.response.deferred, NameError)

        self.handler.assert_debug("Stoping the upload job after an error")
        self.response.upload_job.stop.assert_called_once_with()

    def test_try_again_handling(self):
        """Test how a TRY_AGAIN error is handled."""
        # several patches
        self.response.upload_job = self.FakeUploadJob()
        size_hint = self.response.upload_job.inflated_size_hint
        metrics = mock.Mock()
        self.response.protocol.factory.metrics = metrics
        # These are commented out since the open source fork was published
        # expect(metrics.gauge("upload_error.TRY_AGAIN.NameError", size_hint))

        # call and test
        self.response._log_exception(errors.TryAgain(NameError(self.msg)))

        self.handler.assert_debug("TryAgain", "NameError", str(size_hint))

    @defer.inlineCallbacks
    def test_genericerror_requestcancelled_canceling(self):
        """Test how a RequestCancelledError error is handled when canceling."""
        self.response.state = PutContentResponse.states.canceling
        called = []
        self.response._send_protocol_error = called.append
        self.response.done = called.append
        yield self.response._generic_error(
            request.RequestCancelledError('message')
        )
        self.assertFalse(called)
        self.handler.assert_debug("Request cancelled: message")

    @defer.inlineCallbacks
    def test_genericerror_requestcancelled_other(self):
        """Test how a RequestCancelledError error is handled in other state."""
        assert self.response.state != PutContentResponse.states.canceling
        self.response.upload_job = self.FakeUploadJob()

        failure = Failure(request.RequestCancelledError(self.msg))
        # These are commented out since the open source fork was published
        # expect(response.protocol.factory.metrics.gauge(
        #     "upload_error.RequestCancelledError", 1000))
        self.response.protocol.factory.metrics = mock.Mock()
        self.response._send_protocol_error = mock.Mock()
        self.response.done = mock.Mock()

        yield self.response._generic_error(failure)

        self.assertEqual(self.response.state, PutContentResponse.states.error)
        self.handler.assert_debug("RequestCancelledError", str(1000))
        self.response._send_protocol_error.assert_called_once_with(failure)
        self.response.done.assert_called_once_with()

    @defer.inlineCallbacks
    def test_genericerror_other_errors_ok(self):
        """Generic error handling."""
        self.response.upload_job = self.FakeUploadJob()
        failure = Failure(NameError(self.msg))
        # These are commented out since the open source fork was published
        # expect(response.protocol.factory.metrics.gauge(
        #     "upload_error.NameError", 1000))
        self.response._send_protocol_error = mock.Mock()
        self.response.done = mock.Mock()

        yield self.response._generic_error(failure)

        self.assertEqual(self.response.state, PutContentResponse.states.error)
        self.handler.assert_debug("NameError", str(1000))
        self.response._send_protocol_error.assert_called_once_with(failure)
        self.response.done.assert_called_once_with()

    @defer.inlineCallbacks
    def test_genericerror_other_errors_problem_sendprotocolerror(self):
        """Handle problems in the _send_protocol_error() call."""
        error = Exception("broken")
        self.response._send_protocol_error = mock.Mock(side_effect=error)
        internal = []
        self.response.internal_error = internal.append

        real_error = ValueError('error')
        yield self.response._generic_error(real_error)

        self.assertEqual(self.response.state, PutContentResponse.states.error)
        error = internal[0].value
        self.assertTrue(isinstance(error, Exception))
        self.assertEqual(str(error), "broken")
        self.response._send_protocol_error.assert_called_once_with(mock.ANY)
        [actual] = self.response._send_protocol_error.call_args.args
        self.assertIsInstance(actual, Failure)
        self.assertEqual(actual.value, real_error)

    @defer.inlineCallbacks
    def test_genericerror_other_errors_problem_done(self):
        """Handle problems in the done() call."""
        self.response._send_protocol_error = mock.Mock(
            return_value=defer.succeed(True)
        )
        error = Exception("broken")
        self.response.done = mock.Mock(side_effect=error)
        internal = []
        self.response.internal_error = internal.append

        real_error = ValueError('error')
        yield self.response._generic_error(real_error)

        self.assertEqual(self.response.state, PutContentResponse.states.error)
        error = internal[0].value
        self.assertTrue(isinstance(error, Exception))
        self.assertEqual(str(error), "broken")
        [actual] = self.response._send_protocol_error.call_args.args
        self.assertIsInstance(actual, Failure)
        self.assertEqual(actual.value, real_error)
        self.response.done.assert_called_once_with()

    @defer.inlineCallbacks
    def test__get_upload_job(self):
        """Test get_upload_job."""
        share_id = uuid.uuid4()
        upload_id = str(uuid.uuid4())
        message = self.make_protocol_message(msg_type='PUT_CONTENT')
        message.put_content.share = str(share_id)
        message.put_content.node = 'abc'
        message.put_content.previous_hash = 'p_hash'
        message.put_content.hash = 'hash'
        message.put_content.crc32 = 1
        message.put_content.size = 2
        message.put_content.deflated_size = 3
        message.put_content.magic_hash = 'magic'
        message.put_content.upload_id = upload_id
        response = PutContentResponse(self.server, message)
        response.protocol.working_caps = []
        response.protocol.session_id = 'abc'
        response.protocol.user = mock.Mock()
        response.protocol.user.get_upload_job.return_value = 'TheUploadJob'

        uploadjob = yield response._get_upload_job()

        self.assertEqual(uploadjob, 'TheUploadJob')
        response.protocol.user.get_upload_job.assert_called_once_with(
            share_id,
            'abc',
            'p_hash',
            'hash',
            1,
            2,
            3,
            session_id='abc',
            magic_hash='magic',
            upload_id=upload_id,
        )

    def test_processmessage_uploading_ok(self):
        """Process a message while uploading, all ok."""
        self.response.state = PutContentResponse.states.uploading
        self.response._process_while_uploading = mock.Mock()

        # all message types
        all_msgs = []
        expected_calls = []
        for mtype in "CANCEL_REQUEST EOF BYTES".split():
            message = self.make_protocol_message(msg_type=mtype)
            all_msgs.append(message)
            expected_calls.append(mock.call(message))

        for msg in all_msgs:
            self.response._processMessage(msg)

        self.assertEqual(
            self.response._process_while_uploading.mock_calls, expected_calls
        )

    def test_processmessage_uploading_error(self):
        """Process a message while uploading, explodes."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='BYTES')
        failure = Exception(self.msg)
        self.response._process_while_uploading = mock.Mock(side_effect=failure)
        self.response._generic_error = mock.Mock()

        self.response._processMessage(message)

        self.response._process_while_uploading.assert_called_once_with(message)
        self.response._generic_error.assert_called_once_with(failure)

    def test_processmessage_uploading_bad_message(self):
        """Process a bad message while uploading."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='PUT_CONTENT')
        self.response._processMessage(message)
        self.handler.assert_error(
            "unknown message", str(protocol_pb2.Message.PUT_CONTENT)
        )

    def test_processmessage_init_cancel_ok(self):
        """Process a cancel request while in init, all ok."""
        self.response.state = PutContentResponse.states.init
        message = self.make_protocol_message(msg_type='CANCEL_REQUEST')
        self.response.cancel = mock.Mock()

        self.response._processMessage(message)

        self.assertEqual(
            self.response.state, PutContentResponse.states.canceling
        )
        self.assertEqual(self.response.cancel_message, message)
        self.response.cancel.assert_called_once_with()

    def test_processmessage_init_cancel_error(self):
        """Process a cancel request while in init, explodes."""
        self.response.state = PutContentResponse.states.init
        message = self.make_protocol_message(msg_type='CANCEL_REQUEST')
        failure = Exception(self.msg)
        self.response.cancel = mock.Mock(side_effect=failure)
        self.response._generic_error = mock.Mock()

        self.response._processMessage(message)

        self.response.cancel.assert_called_once_with()
        self.response._generic_error.assert_called_once_with(failure)

    def test_processmessage_init_not_cancel(self):
        """Process other requests while in init."""
        self.response.state = PutContentResponse.states.init
        cancel_called = []
        self.response.cancel = lambda: cancel_called.append(True)

        # all message types except cancel
        all_msgs = []
        for mtype in "EOF BYTES".split():
            message = self.make_protocol_message(msg_type=mtype)
            self.response._processMessage(message)
            all_msgs.append(message.type)

        for mtype in all_msgs:
            self.handler.assert_warning(
                "Received out-of-order", "INIT", str(mtype)
            )
        self.assertFalse(cancel_called)

    def test_processmessage_error(self):
        """Process all requests while in error."""
        self.response.state = PutContentResponse.states.error

        # all message types
        for mtype in "CANCEL_REQUEST EOF BYTES".split():
            message = self.make_protocol_message(msg_type=mtype)
            self.response._processMessage(message)

        self.handler.assert_not_logged("Received out-of-order")

    def test_processmessage_otherstates(self):
        """Process all requests while in other states."""
        for state in "commiting canceling done".split():
            for mtype in "CANCEL_REQUEST EOF BYTES".split():
                self.response.state = getattr(PutContentResponse.states, state)
                message = self.make_protocol_message(msg_type=mtype)
                self.response._processMessage(message)
                chk = "Received out-of-order", state.upper(), str(message.type)
                self.handler.assert_warning(*chk)

    def test_processwhileuploading_cancel(self):
        """Got a cancel request while uploading."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='CANCEL_REQUEST')
        cancel_called = []
        self.response.cancel = lambda: cancel_called.append(True)

        self.response._process_while_uploading(message)
        self.assertEqual(self.response.cancel_message, message)
        self.assertEqual(
            self.response.state, PutContentResponse.states.canceling
        )
        self.assertTrue(cancel_called)

    def test_processwhileuploading_eof_ok(self):
        """Got an eof while uploading, all finished ok."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='EOF')
        self.response.upload_job = self.FakeUploadJob()

        # check what is called
        called = []
        self.response._commit_uploadjob = lambda r: called.append(('commt', r))
        self.response._generic_error = lambda _: called.append('error')

        # call, it should change the state and set up the callbacks
        self.response._process_while_uploading(message)
        self.assertEqual(
            self.response.state, PutContentResponse.states.commiting
        )
        self.assertEqual(called, [('commt', None)])

    def test_processwhileuploading_eof_error_commiting(self):
        """Got an eof while uploading, got an error while commiting."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='EOF')
        self.response.upload_job = self.FakeUploadJob()

        # check what is called
        called = []
        failure = Failure(Exception())
        self.response._commit_uploadjob = (
            lambda r: called.append(('commit', r)) or failure
        )
        self.response._generic_error = lambda f: called.append(('error', f))

        # call, it should change the state and set up the callbacks
        self.response._process_while_uploading(message)
        self.assertEqual(
            self.response.state, PutContentResponse.states.commiting
        )
        self.assertEqual(called, [('commit', None), ('error', failure)])

    def test_processwhileuploading_bytes(self):
        """Got some bytes while uploading."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='BYTES')
        message.bytes.bytes = b"foobar"
        self.response.upload_job = self.FakeUploadJob()
        prv_transferred = self.response.transferred

        self.response._process_while_uploading(message)
        self.assertEqual(self.response.transferred, prv_transferred + 6)
        self.assertEqual(
            self.response.state, PutContentResponse.states.uploading
        )
        self.assertEqual(self.response.upload_job.bytes, b"foobar")

    def test_processwhileuploading_strange(self):
        """Got other message while uploading."""
        self.response.state = PutContentResponse.states.uploading
        message = self.make_protocol_message(msg_type='PUT_CONTENT')
        self.response._process_while_uploading(message)
        self.handler.assert_error(
            "Received unknown message", str(message.type)
        )

    def test_commituploadjob_not_commiting(self):
        """Assure we're still commiting when we reach this."""
        self.response.state = PutContentResponse.states.error
        called = []
        self.response.queue_action = lambda *a, **kw: called.append(True)
        self.response._commit_uploadjob('result')
        self.assertFalse(called)

    def test_commituploadjob_all_ok(self):
        """Normal commiting behaviour."""
        self.response.state = PutContentResponse.states.commiting
        self.response.queue_action = mock.Mock(return_value=defer.succeed(35))
        self.response.done = mock.Mock()

        self.response._commit_uploadjob('result')

        self.assertEqual(self.response.state, PutContentResponse.states.done)
        self.assertEqual(self.last_msg.type, protocol_pb2.Message.OK)
        self.assertEqual(self.last_msg.new_generation, 35)
        self.response.queue_action.assert_called_once_with(mock.ANY)
        self.response.done.assert_called_once_with()

    def test_commituploadjob_ok_but_canceled_by_framework(self):
        """Commit started but was canceled while waiting for queued commit."""
        self.response.state = PutContentResponse.states.commiting
        node = FakeNode()

        def state_changed_to_cancel(response):
            """Change state to cancel before proceeding."""
            self.response.state = PutContentResponse.states.canceling
            return defer.succeed(node)

        self.response.queue_action = mock.Mock(
            side_effect=state_changed_to_cancel
        )
        self.response.done = mock.Mock()
        self.response.sendMessage = mock.Mock()

        self.response._commit_uploadjob('result')

        self.assertEqual(
            self.response.state, PutContentResponse.states.canceling
        )
        self.response.queue_action.assert_called_once_with(mock.ANY)
        # Don't expect done() or any response to client
        self.response.done.assert_not_called()
        self.response.sendMessage.assert_not_called()

    def test_commit_canceled_in_queued_job(self):
        """Commit called but canceled before queued job executes."""
        self.response.upload_job = mock.Mock()
        self.response.state = PutContentResponse.states.commiting

        # Patched queue_action changes state then runs the function

        def cancel_then_run_callback(f):
            """Change state to cancel, then call the function."""
            self.response.state = PutContentResponse.states.canceling
            f()

        self.response.queue_action = mock.Mock(
            side_effect=cancel_then_run_callback
        )
        self.response.done = mock.Mock()
        self.response.sendMessage = mock.Mock()

        self.response._commit_uploadjob('result')

        self.assertEqual(
            self.response.state, PutContentResponse.states.canceling
        )
        self.response.queue_action.assert_called_once_with(mock.ANY)
        # Actual commit will not be called
        self.response.upload_job.commit.assert_not_called()
        # Don't expect done() or any response to client
        self.response.done.assert_not_called()
        self.response.sendMessage.assert_not_called()

    def test_startupload_normal(self):
        """Normal behaviour for the start upload."""
        self.response.state = PutContentResponse.states.init
        upload_job = mock.Mock()
        self.response._get_upload_job = mock.Mock(return_value=upload_job)
        self.response.protocol = mock.Mock()
        self.response._send_begin = mock.Mock()

        self.response._start_upload()

        self.assertEqual(
            self.response.state, PutContentResponse.states.uploading
        )
        self.response._get_upload_job.assert_called_once_with()
        upload_job.deferred.addErrback.assert_called_once_with(
            self.response._generic_error
        )
        upload_job.connect.assert_called_once_with()
        self.response.protocol.release.assert_called_once_with(self.response)
        self.response._send_begin.assert_called_once_with()

    def _startupload_canceling_while_getting_uploadjob(self, state):
        """State changes while waiting for the upload job."""
        self.response.state = PutContentResponse.states.init
        d = defer.Deferred()
        self.response._get_upload_job = lambda: d
        self.response._start_upload()

        # before releasing the deferred, change the state
        self.response.state = state
        upload_job = self.FakeUploadJob()
        d.callback(upload_job)
        self.assertEqual(upload_job.called, ['cancel'])  # not connect
        self.handler.assert_debug(
            "Manually canceling the upload job (in %s)" % state
        )

    def test_startupload_done(self):
        """State changes to done while getting the upload job."""
        state = PutContentResponse.states.done
        self._startupload_canceling_while_getting_uploadjob(state)

    def test_startupload_canceling(self):
        """State changes to canceling while getting the upload job."""
        state = PutContentResponse.states.canceling
        self._startupload_canceling_while_getting_uploadjob(state)

    def test__send_begin(self):
        """Test sendbegin."""
        self.response.upload_job = self.FakeUploadJob()
        self.response.upload_job.offset = 10
        self.response.upload_job.upload_id = 12
        self.response._send_begin()
        self.assertEqual(
            self.last_msg.type, protocol_pb2.Message.BEGIN_CONTENT
        )
        self.assertEqual(self.last_msg.begin_content.offset, 10)
        self.assertEqual(self.last_msg.begin_content.upload_id, '12')

        upload_type = self.response.upload_job.__class__.__name__
        self.handler.assert_debug(
            upload_type, "begin content", "from offset 10", "fake storagekey"
        )

    def test__send_begin_new_upload_id(self):
        """Test sendbegin when the upload_id received is invalid."""
        self.response.upload_job = self.FakeUploadJob()
        self.response.upload_job.offset = 0
        self.response.upload_job.upload_id = 12
        # the client sent an upload_id, but it's different from the one we got
        # from content.py
        self.response.source_message.put_content.upload_id = '11'
        self.response._send_begin()
        self.assertEqual(
            self.last_msg.type, protocol_pb2.Message.BEGIN_CONTENT
        )
        self.assertEqual(self.last_msg.begin_content.offset, 0)
        self.assertEqual(self.last_msg.begin_content.upload_id, '12')

        upload_type = self.response.upload_job.__class__.__name__
        self.handler.assert_debug(
            upload_type, "begin content", "from offset 0", "fake storagekey"
        )

    @defer.inlineCallbacks
    def test_putcontent_double_done(self):
        """Double call to self.done()."""
        self.response.state = PutContentResponse.states.init
        d = defer.Deferred()
        self.response._get_upload_job = lambda: d
        self.response._start_upload()

        # before releasing the deferred, change the state
        upload_job = self.FakeUploadJob()
        upload_job.offset = 1
        upload_job.upload_id = 1
        d.callback(upload_job)
        self.response.done()
        yield self.response.deferred

        called = []
        self.response.error = called.append
        self.response.done()
        yield self.response.deferred

        self.assertEqual(called, [])
        msg = (
            'PutContentResponse 42 - _cancellableInlineCallbacks -> '
            '_inlineCallbacks -> test_putcontent_double_done: '
            'called done() finished=True'
        )
        self.handler.assert_warning(msg)

    @defer.inlineCallbacks
    def test_putcontent_done_after_error(self):
        """Double call to self.done()."""
        self.response.state = PutContentResponse.states.init
        d = defer.Deferred()
        self.response._get_upload_job = lambda: d
        self.response._start_upload()

        # before releasing the deferred, change the state
        upload_job = self.FakeUploadJob()
        upload_job.offset = 1
        upload_job.upload_id = 1
        d.callback(upload_job)
        self.response.error(Failure(ValueError(self.msg)))
        yield self.assertFailure(self.response.deferred, ValueError)

        called = []
        self.response.error = called.append
        self.response.done()
        yield self.response.deferred

        self.assertEqual(called, [])
        msg = (
            'PutContentResponse 42 - _cancellableInlineCallbacks -> '
            '_inlineCallbacks -> test_putcontent_done_after_error: '
            'called done() finished=True'
        )
        self.handler.assert_warning(msg)


class QuerySetCapsResponseTestCase(SimpleRequestResponseTestCase):
    """Test the QuerySetCapsResponse class."""

    response_class = QuerySetCapsResponse


class MoveResponseTestCase(SimpleRequestResponseTestCase):
    """Test the MoveResponse class."""

    response_class = MoveResponse

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'sync_activity')


class MakeResponseTestCase(SimpleRequestResponseTestCase):
    """Test the MakeResponse class."""

    response_class = MakeResponse

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'sync_activity')


class FreeSpaceResponseTestCase(SimpleRequestResponseTestCase):
    """Test the FreeSpaceResponse class."""

    response_class = FreeSpaceResponse


class AccountResponseTestCase(SimpleRequestResponseTestCase):
    """Test the AccountResponse class."""

    response_class = AccountResponse


class AuthenticateResponseTestCase(SimpleRequestResponseTestCase):
    """Test the AuthenticateResponse class."""

    response_class = AuthenticateResponse

    def test_user_activity_indicator(self):
        """Check the user_activity value."""
        self.assertEqual(self.response_class.user_activity, 'connected')

    def test_set_user(self):
        """Check that the user is set after auth."""
        user = FakeUser()
        # set up a fake auth
        auth_provider = self.response.protocol.factory.auth_provider
        auth_provider.authenticate.return_value = user
        called = []
        self.response.protocol.set_user = lambda *a, **kw: called.append(a)

        self.response._process()

        self.assertEqual(called, [(user,)])
        auth_provider.authenticate.assert_called_once_with({}, self.server)

    def _client_metadata(self, expected, expected_metrics):
        """Test client metadata handling in AuthenticateResponse."""
        user = FakeUser()
        # set up a fake auth
        auth_provider = self.response.protocol.factory.auth_provider
        auth_provider.authenticate.return_value = user
        metrics_called = []
        self.patch(
            self.response.protocol.factory.metrics,
            'meter',
            lambda *a: metrics_called.append(a),
        )
        self.response._process()

        self.assertEqual(metrics_called, expected_metrics)
        auth_provider.authenticate.assert_called_once_with({}, self.server)

    def test_client_metadata_valid(self):
        """Test client metadata handling in AuthenticateResponse."""
        md = self.response.source_message.metadata.add()
        md.key = "platform"
        md.value = "linux"
        md = self.response.source_message.metadata.add()
        md.key = "version"
        md.value = "42"
        expected = [("client.platform.linux",), ("client.version.42",)]
        expected_metrics = [
            ("client.platform.linux", 1),
            ("client.version.42", 1),
        ]
        self._client_metadata(expected, expected_metrics)

    def test_client_metadata_invalid_value(self):
        """Test client metadata handling in AuthenticateResponse."""
        md = self.response.source_message.metadata.add()
        md.key = "platform"
        md.value = "Windows XP-SP3 6.1.2008"
        md = self.response.source_message.metadata.add()
        md.key = "version"
        md.value = "1.42"
        expected = [
            ("client.platform.Windows_XP_SP3_6_1_2008",),
            ("client.version.1_42",),
        ]
        expected_metrics = [
            ("client.platform.Windows_XP_SP3_6_1_2008", 1),
            ("client.version.1_42", 1),
        ]
        self._client_metadata(expected, expected_metrics)


class GetDeltaResponseTestCase(SimpleRequestResponseTestCase):
    """Test the GetDeltaResponse class."""

    response_class = GetDeltaResponse

    def test_cooperative_send_delta_info(self):
        """Test that send_delta_info isn't blocking."""
        d = self.response.send_delta_info([], '')
        self.assertTrue(isinstance(d, defer.Deferred))
        # check if _send_delta_info returns a generator
        gen = self.response._send_delta_info([], '')
        self.assertIsInstance(gen, collections.Generator)
        # check if send_delta_info use the cooperator
        called = []
        real_cooperate = task.cooperate

        def cooperate(iterator):
            """Intercept the call to task.cooperate."""
            called.append(iterator)
            return real_cooperate(iterator)

        self.patch(task, 'cooperate', cooperate)
        self.response.send_delta_info([], '')
        self.assertEqual(len(called), 1)
        self.assertIsInstance(called[0], collections.Generator)

    def test_reset_send_delta_info_counter(self):
        """Test that the count is reset on each iteration."""
        self.patch(settings, 'MAX_DELTA_INFO', 5)
        # create a few fake nodes
        nodes = []
        right_now = now()
        for i in range(10):
            node = FakeNode()
            node.id = str(uuid.uuid4())
            node.parent_id = str(uuid.uuid4())
            node.generation = 100
            node.name = "node_%s" % i
            node.is_live = True
            node.is_file = True
            node.is_public = True
            node.content_hash = 'sha1:foo'
            node.crc32 = 10
            node.size = 1024
            node.last_modified = int(time.mktime(right_now.timetuple()))
            nodes.append(node)
        gen = self.response._send_delta_info(nodes, 'share_id')
        next(gen)
        self.assertEqual(gen.gi_frame.f_locals['count'], 0)

    @defer.inlineCallbacks
    def test_process_set_length(self):
        """Set length attribute while processing."""
        # fake message
        message = mock.Mock()
        message.get_delta.share = ''
        message.get_delta.from_generation = 10
        self.response.source_message = message
        # fake user
        user = mock.Mock()
        nodes = [FakeNode(), FakeNode()]
        user.get_delta.return_value = (nodes, 12, 123)
        self.response.protocol.user = user

        yield self.response._process()

        self.assertEqual(self.response.length, 2)
        user.get_delta.assert_called_once_with(None, 10, limit=1000)


class RescanFromScratchResponseTestCase(SimpleRequestResponseTestCase):
    """Test the RescanFromScratchResponse class."""

    class RescanFromScratchResponse(RescanFromScratchResponse):
        """Subclass so we have a __dict__ and can patch it."""

    response_class = RescanFromScratchResponse

    def test_cooperative_send_delta_info(self):
        """Test that send_delta_info isn't blocking."""
        d = self.response.send_delta_info([], '')
        self.assertTrue(isinstance(d, defer.Deferred))
        # check if _send_delta_info returns a generator
        gen = self.response._send_delta_info([], '')
        self.assertIsInstance(gen, collections.Generator)
        # check if send_delta_info use the cooperator
        called = []
        real_cooperate = task.cooperate

        def cooperate(iterator):
            """Intercept the call to task.cooperate."""
            called.append(iterator)
            return real_cooperate(iterator)

        self.patch(task, 'cooperate', cooperate)
        self.response.send_delta_info([], '')
        self.assertEqual(len(called), 1)
        self.assertIsInstance(called[0], collections.Generator)

    @defer.inlineCallbacks
    def test_chunked_get_from_scratch(self):
        """Get the nodes list in chunks."""
        self.patch(settings, 'GET_FROM_SCRATCH_LIMIT', 5)
        # build fake nodes
        nodes = []
        right_now = now()
        for i in range(20):
            node = FakeNode()
            node.id = str(uuid.uuid4())
            node.parent_id = str(uuid.uuid4())
            node.path = "/"
            node.generation = i
            node.name = "node_%s" % i
            node.is_live = True
            node.is_file = True
            node.is_public = True
            node.content_hash = 'sha1:foo'
            node.crc32 = 10
            node.size = 1024
            node.last_modified = int(time.mktime(right_now.timetuple()))
            nodes.append(node)
        # set required caps
        self.response.protocol.working_caps = PREFERRED_CAP
        user = mock.Mock()
        self.patch(self.response, "send_delta_info", lambda *a: None)
        self.response.protocol.user = user
        # expect 3 calls to get_from_scratch
        user.get_from_scratch.side_effect = [
            (nodes[:10], 20, 100),
            (nodes[10:], 20, 100),
            ([], 20, 100),
        ]

        yield self.response._process()

        expected_calls = [
            mock.call.get_from_scratch(None, limit=5),
            mock.call.get_from_scratch(
                None,
                limit=5,
                max_generation=20,
                start_from_path=("/", "node_9"),
            ),
            mock.call.get_from_scratch(
                None,
                limit=5,
                max_generation=20,
                start_from_path=("/", "node_19"),
            ),
        ]
        self.assertEqual(user.mock_calls, expected_calls)

    @defer.inlineCallbacks
    def test_process_set_length(self):
        """Set length attribute while processing."""
        # fake message
        message = mock.Mock()
        message.get_delta.share = ''
        self.response.source_message = message

        # fake user
        user = mock.Mock()
        nodes = [[FakeNode(), FakeNode()], []]
        user.get_from_scratch.side_effect = lambda *a, **k: (
            nodes.pop(0),
            12,
            123,
        )
        self.response.protocol.user = user

        yield self.response._process()

        self.assertEqual(self.response.length, 2)
        expected_calls = [
            mock.call.get_from_scratch(None, limit=2000),
            mock.call.get_from_scratch(
                None,
                start_from_path=('path', 'name'),
                limit=2000,
                max_generation=12,
            ),
        ]
        self.assertEqual(user.mock_calls, expected_calls)


class NodeInfoLogsTestCase(BaseStorageServerTestCase):
    """Check that operations return correct node info."""

    def check(self, response, mes_type, klass=None, mes_name=None, **attrs):
        """Check that get_node_info returns correctly for the message."""
        # build the message
        message = self.make_protocol_message(msg_type=mes_type)

        # optionally, has content!
        if mes_name is not None:
            inner = getattr(message, mes_name)
            for name, value in attrs.items():
                setattr(inner, name, value)

        # put it in the request, get node info, and check
        if klass is None:
            klass = StorageServerRequestResponse
        req = klass(self.server, message)
        req.source_message = message
        self.assertEqual(req._get_node_info(), response)

    def test_simple_ones(self):
        """Test all messages without node info."""
        names = (
            'PROTOCOL_VERSION',
            'PING',
            'AUTH_REQUEST',
            'CREATE_UDF',
            'CREATE_SHARE',
            'QUERY_CAPS',
            'SET_CAPS',
            'FREE_SPACE_INQUIRY',
            'ACCOUNT_INQUIRY',
            'LIST_VOLUMES',
            'LIST_SHARES',
        )
        for name in names:
            self.check(None, name)

    def test_with_nodes(self):
        """Test messages that have node info."""
        data = [
            ('GET_CONTENT', GetContentResponse),
            ('PUT_CONTENT', PutContentResponse),
            ('UNLINK', Unlink),
            ('MOVE', MoveResponse),
        ]
        for name, klass in data:
            self.check("node: 'foo'", name, klass, name.lower(), node='foo')

    def test_with_parent(self):
        """Test messages where the node is the parent."""
        data = [
            ('MAKE_FILE', MakeResponse),
            ('MAKE_DIR', MakeResponse),
        ]
        for name, klass in data:
            self.check("parent: 'foo'", name, klass, 'make', parent_node='foo')

    def test_with_shares(self):
        """Test messages that work on shares."""
        data = [
            ('SHARE_ACCEPTED', ShareAccepted),
            ('DELETE_SHARE', DeleteShare),
        ]
        for name, klass in data:
            self.check(
                "share: 'foo'", name, klass, name.lower(), share_id='foo'
            )

    def test_with_volumes(self):
        """Test messages that work on volumes."""
        self.check(
            "volume: 'foo'",
            'DELETE_VOLUME',
            DeleteVolume,
            'delete_volume',
            volume='foo',
        )
        self.check(
            "volume: 'foo'",
            'GET_DELTA',
            GetDeltaResponse,
            'get_delta',
            share='foo',
        )


class TestLoopingPing(BaseStorageServerTestCase):
    """LoopingPing tests."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestLoopingPing, self).setUp()
        self.patch(self.server, 'ping', lambda: defer.succeed(None))

    def test_idle_timeout_enabled(self):
        """Test that idle_timeout is enabled and works."""
        self.server.ping_loop.idle_timeout = 0.1
        self.server.ping_loop.pong_count = 2
        self.server.ping_loop.schedule()
        self.assertTrue(self.shutdown)

    def test_idle_timeout_disabled(self):
        """Test that disbaled idle_timeout."""
        self.server.ping_loop.idle_timeout = 0
        self.server.ping_loop.schedule()
        self.assertFalse(self.shutdown)


class StorageServerFactoryTestCase(BaseTestCase, TwistedTestCase):
    """Test the StorageServerFactory class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(StorageServerFactoryTestCase, self).setUp()
        self.factory = StorageServerFactory()
        self.handler = self.add_memento_handler(logger, level=logging.DEBUG)

    def test_observer_added(self):
        """Test that the observer was added to Twisted logging."""
        self.assertIn(
            self.factory._deferror_handler, log.theLogPublisher.observers
        )

    def test_noerror(self):
        """No error, no action."""
        self.factory._deferror_handler(dict(isError=False, message=''))
        self.handler.assert_not_logged("error")

    def test_message(self):
        """Just a message."""
        self.factory._deferror_handler(dict(isError=True, message="foobar"))
        self.handler.assert_error("Unhandled error in deferred", "foobar")

    def test_failure(self):
        """Received a full failure."""
        f = Failure(ValueError(self.id()))
        self.factory._deferror_handler(
            dict(isError=True, failure=f, message='')
        )
        self.handler.assert_error(
            "Unhandled error in deferred", "ValueError", self.id()
        )

    def test_trace_users(self):
        """Check trace users are correctly set."""
        # set a specific config to test
        self.patch(settings, 'TRACE_USERS', ['foo', 'bar', 'baz'])
        factory = StorageServerFactory()
        self.assertEqual(factory.trace_users, set(['foo', 'bar', 'baz']))


class BytesMessageProducerTestCase(BaseStorageServerTestCase):
    """Test the BytesMessageProducer class."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(BytesMessageProducerTestCase, self).setUp()
        req = GetContentResponse(
            protocol=self.server, message=self.make_protocol_message()
        )
        self.patch(GetContentResponse, 'sendMessage', lambda *a: None)
        self.producer = FakeProducer()
        self.bmp = BytesMessageProducer(self.producer, req)

    def test_resume_log(self):
        """Log when resumed."""
        self.bmp.resumeProducing()
        self.handler.assert_trace(
            "BytesMessageProducer resumed", str(self.producer)
        )

    def test_stop_log(self):
        """Log when stopped."""
        self.bmp.stopProducing()
        self.handler.assert_trace(
            "BytesMessageProducer stopped", str(self.producer)
        )

    def test_pause_log(self):
        """Log when paused."""
        self.bmp.pauseProducing()
        self.handler.assert_trace(
            "BytesMessageProducer paused", str(self.producer)
        )

    def test_transferred_counting(self):
        """Keep count of transferred data."""
        assert self.bmp.request.transferred == 0
        self.bmp.write(b"foobar")
        self.assertEqual(self.bmp.request.transferred, 6)


class TestMetricsSetup(testcase.TestWithDatabase):
    """Tests that metrics are setup from configs properly"""

    def test_metrics_from_config(self):
        """Test that metrics names get set from the config properly"""
        self.assertEqual(
            "development.filesync.server.001.root",
            metrics.get_meter("root")._namespace,
        )
        self.assertEqual(
            "development.filesync.server.001.user",
            metrics.get_meter("user")._namespace,
        )


class VersionInfoTestCase(TwistedTestCase):
    """Test a the autogenerated version_info dict"""

    def testInfo(self):
        """Validate the available data."""
        self.assertEqual(version_info['revno'], "Revison Number")
        self.assertEqual(version_info['branch_nick'], "Branch Nickname")
        self.assertEqual(version_info['date'], "Date of last update")
        self.assertEqual(version_info['build_date'], "Date of last Build")
        self.assertEqual(version_info['revision_id'], "ID of revision")

    if version_info is None:
        testInfo.skip = 'No version info in this system, bzr probably missing.'
