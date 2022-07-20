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

"""Test the capabilities decorator."""

from magicicadaclient import syncdaemon
from twisted.trial.unittest import TestCase
from twisted.trial.reporter import TestResult
from twisted.internet import defer

from magicicada.server import server as server_module
from magicicada.server.testing.caps_helpers import required_caps
from magicicada.server.testing.aq_helpers import (
    TestWithDatabase,
    failure_expected,
)


class RequiredCapsDecoratorTests(TestCase):
    """Tests for required_caps decorator"""

    timeout = 3

    def test_mismatch(self):
        """Test that a test is correctly skipped."""
        result = TestResult()

        self.patch(syncdaemon, 'REQUIRED_CAPS', set(['supercalifragilistico']))

        class FakeTest(TestCase):
            """Testcase to test the decorator"""
            @required_caps([], validate=False)
            def test_method(innerself):
                """test method that allways fails"""
                innerself.fail()

        FakeTest('test_method').run(result)
        self.assertEqual(1, len(result.skips))

    def test_match(self):
        """Check that a test is executed when the caps match."""
        result = TestResult()

        self.patch(syncdaemon, 'REQUIRED_CAPS', server_module.MIN_CAP)

        class FakeTest(TestCase):
            """Testcase to test the decorator"""
            @required_caps(server_module.MIN_CAP)
            def test_method(innerself):
                """Test method that always pass."""
                innerself.assertTrue(True)

        FakeTest('test_method').run(result)
        self.assertEqual(0, len(result.skips))
        self.assertEqual(1, result.successes)

    def test_not_validate(self):
        """test that a test is executed when the supported_caps_set don't match
        the server SUPPORTED_CAPS and validate=False.
        """
        result = TestResult()

        self.patch(syncdaemon, 'REQUIRED_CAPS', set(['supercalifragilistico']))

        class FakeTest(TestCase):
            """Testcase to test the decorator"""
            @required_caps(['supercalifragilistico'], validate=False)
            def test_method(innerself):
                """test method that always pass"""
                innerself.assertTrue(True)

        FakeTest('test_method').run(result)
        self.assertEqual(0, len(result.skips))
        self.assertEqual(1, result.successes)

    def test_validate(self):
        """test tha a test fails when the supported_caps_set don't match
        the server SUPPORTED_CAPS and validate=True.
        """
        result = TestResult()

        class FakeTest(TestCase):
            """Testcase to test the decorator"""
            @required_caps([], ['supercalifragilistico', 'foo'], ['foo'])
            def test_method(innerself):
                """test method that always pass"""
                innerself.assertTrue(True)

        the_test = FakeTest('test_method')
        the_test.run(result)
        self.assertEqual(0, len(result.skips))
        self.assertEqual(1, len(result.failures))
        self.assertEqual(the_test, result.failures[0][0])


class TestClientCapabilities(TestWithDatabase):
    """Test the client side of query/set capabilities"""

    client = None
    timeout = 5

    # just to restore original values
    _original_supported_caps = server_module.SUPPORTED_CAPS
    _original_required_caps = syncdaemon.REQUIRED_CAPS

    def tearDown(self):
        """cleanup the mess"""
        print('\n** tearDown 1')
        server_module.SUPPORTED_CAPS = self._original_supported_caps
        print('\n** tearDown 2')
        self.patch(syncdaemon, 'REQUIRED_CAPS', self._original_required_caps)
        print('\n** tearDown 3')
        if self.aq.connector is not None:
            print('\n** tearDown 4')
            self.aq.disconnect()
        print('\n** tearDown 5')
        return super(TestClientCapabilities, self).tearDown()

    def assert_message(self, containee, msg=None):
        """Ensure that the containee is in the event queue.

        containee can be callable, in which case it's called before
        asserting.
        """
        ce = containee() if callable(containee) else containee
        self.assertIn(ce, self.listener.q, msg)

    def assertInQ(self, deferred, containee, msg=None):
        """
        deferredly assert that the containee is in the event queue.

        containee can be callable, in which case it's called before
        asserting.
        """
        def check_queue(_):
            "the check itself"
            self.assert_message(containee, msg)
        deferred.addCallback(check_queue)

    def connect(self):
        """Connect the client"""
        d = self.wait_for('SYS_CONNECTION_MADE')
        self.eq.push('SYS_INIT_DONE')
        self.eq.push('SYS_LOCAL_RESCAN_DONE')
        self.eq.push('SYS_USER_CONNECT',
                     access_token=self.access_tokens['jack'])
        self.eq.push('SYS_NET_CONNECTED')
        return d

    @defer.inlineCallbacks
    def test_query_set_capabilities(self):
        """After connecting the server uses the caps specified by client."""
        # self.set_debug()
        print('\n== 1')
        yield self.connect()
        print('\n== 2')
        yield self.wait_for('SYS_SET_CAPABILITIES_OK')
        print('\n== 3')
        # import pdb; pdb.set_trace()

    @defer.inlineCallbacks
    def test_query_bad_capabilities(self):
        """The client handles errors when setting invalid capabilities."""
        # self.set_debug()
        print('\n== 1')
        self.patch(syncdaemon, 'REQUIRED_CAPS', frozenset(['foo']))
        print('\n== 2')
        yield self.connect()
        print('\n== 3')
        yield self.wait_for('SYS_SET_CAPABILITIES_ERROR')
        print('\n== 4')
        self.assert_message(
            ('SYS_SET_CAPABILITIES_ERROR',
             {'error': "The server doesn't have the requested capabilities"}))

    @failure_expected("The server doesn't have the requested capabilities")
    def _test_query_bad_capabilities(self):
        """The client handles errors when setting invalid capabilities."""
        self.set_debug()
        self.patch(syncdaemon, 'REQUIRED_CAPS', frozenset(['foo']))
        needed_event = self.wait_for('SYS_SET_CAPABILITIES_ERROR')
        d = self.connect()
        d.addCallback(lambda _: needed_event)
        self.assertInQ(d, ('SYS_SET_CAPABILITIES_ERROR',
                           {'error': "The server doesn't have the requested "
                            "capabilities"}))
        return d
