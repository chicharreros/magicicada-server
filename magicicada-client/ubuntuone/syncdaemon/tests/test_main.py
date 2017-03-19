# -*- coding: utf-8 -*-
#
# Copyright 2009-2015 Canonical Ltd.
# Copyright 2016-2017 Chicharreros (https://launchpad.net/~chicharreros)
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
""" Tests for main.Main class """

import logging
import os

from twisted.internet import defer, reactor
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.platform import expand_user

from contrib.testing.testcase import (
    BaseTwistedTestCase, FAKED_CREDENTIALS, FakeMonitor
)
from ubuntuone.clientdefs import VERSION
from ubuntuone.logger import NOTE
from ubuntuone.platform import (
    is_link,
    make_dir,
    make_link,
    path_exists,
    remove_dir,
)
from ubuntuone.syncdaemon import main as main_mod


class FakeListener(object):
    """Just an object that will listen something."""

    def handle_default(self, *a):
        """Something! :)"""


class FakedExternalInterface(object):
    """Do nothing."""

    def __init__(self, *a, **kw):
        self._called = []
        self.connect = lambda *a, **kw: self._called.append(('connect', a, kw))
        self.shutdown = lambda *a, **kw: None

    def start(self):
        """Do nothing."""
        return defer.succeed(None)


class MainTests(BaseTwistedTestCase):
    """ Basic tests to check main.Main """

    @defer.inlineCallbacks
    def setUp(self):
        """ Sets up a test. """
        yield super(MainTests, self).setUp()
        self.root = self.mktemp('root')
        self.shares = self.mktemp('shares')
        self.data = self.mktemp('data')
        self.partials_dir = self.mktemp('partials_dir')

        self.patch(main_mod, 'SyncdaemonService', FakedExternalInterface)

        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        self._logger = logging.getLogger('ubuntuone.SyncDaemon')
        self._logger.addHandler(self.handler)
        self.addCleanup(self._logger.removeHandler, self.handler)

    def _get_main_common_params(self):
        """Return the parameters used by the all platforms."""
        return dict(root_dir=self.root,
                    shares_dir=self.shares,
                    data_dir=self.data,
                    partials_dir=self.partials_dir,
                    connection_info='localhost:0:plain',
                    mark_interval=60,
                    handshake_timeout=2,
                    auth_credentials=FAKED_CREDENTIALS,
                    monitor_class=FakeMonitor)

    def build_main(self, **kwargs):
        """Build and return a Main object.

        Use reasonable defaults for the tests, plus whatever extra kwargs are
        passed in.

        """
        # get the params using the platform code to ensure they are correct
        params = self._get_main_common_params()
        params.update(kwargs)
        m = main_mod.Main(**params)
        self.addCleanup(m.shutdown)
        m.local_rescan = lambda *_: m.event_q.push('SYS_LOCAL_RESCAN_DONE')
        return m

    def test_main_initialization(self):
        """test that creating a Main instance works as expected."""
        main = self.build_main()
        self.assertIsInstance(main, main_mod.Main)

    def test_main_start(self):
        """Test that Main.start works."""
        main = self.build_main()
        main.start()

    def test_main_restarts_on_critical_error(self):
        """Test that Main restarts when syncdaemon gets into UNKNOWN_ERROR."""
        self.restarted = False
        main = self.build_main()
        main.restart = lambda: setattr(self, 'restarted', True)
        main.start()
        main.event_q.push('SYS_UNKNOWN_ERROR')
        self.assertTrue(self.restarted)

    @defer.inlineCallbacks
    def test_shutdown_pushes_sys_quit(self):
        """When shutting down, the SYS_QUIT event is pushed."""
        params = self._get_main_common_params()
        main = main_mod.Main(**params)
        events = []
        self.patch(main.event_q, 'push',
                   lambda *a, **kw: events.append((a, kw)))

        yield main.shutdown()
        expected = [(('SYS_USER_DISCONNECT',), {}), (('SYS_QUIT',), {})]
        self.assertEqual(expected, events)

    def test_handshake_timeout(self):
        """Check connecting times out."""
        d0 = defer.Deferred()

        class Handler:
            """Trivial event handler."""
            def handle_SYS_HANDSHAKE_TIMEOUT(self):
                """Pass the test when we get this event."""
                reactor.callLater(0, d0.callback, None)

        main = self.build_main(handshake_timeout=0)

        def fake_connect(*a):
            """Only connect when States told so."""
            main.event_q.push('SYS_CONNECTION_MADE')
            return defer.Deferred()
        main.action_q.connect = fake_connect

        # fake the following to not be executed
        main.get_root = lambda *_: defer.Deferred()
        main.action_q.check_version = lambda *_: defer.Deferred()

        main.event_q.subscribe(Handler())
        main.start()
        main.event_q.push('SYS_NET_CONNECTED')
        main.event_q.push('SYS_USER_CONNECT', access_token='')
        return d0

    def test_create_dirs_already_exists_dirs(self):
        """test that creating a Main instance works as expected."""
        link = os.path.join(self.root, 'Shared With Me')
        self.assertFalse(is_link(link))
        self.assertTrue(path_exists(self.shares))
        self.assertTrue(path_exists(self.root))
        main = self.build_main()
        # check that the shares link is actually a link
        self.assertTrue(is_link(main.shares_dir_link))
        self.assertEqual(link, main.shares_dir_link)

    def test_create_dirs_already_exists_symlink_too(self):
        """test that creating a Main instance works as expected."""
        link = os.path.join(self.root, 'Shared With Me')
        make_link(self.shares, link)
        self.assertTrue(is_link(link))
        self.assertTrue(path_exists(self.shares))
        self.assertTrue(path_exists(self.root))
        main = self.build_main()
        # check that the shares link is actually a link
        self.assertTrue(is_link(main.shares_dir_link))

    def test_create_dirs_already_exists_but_not_symlink(self):
        """test that creating a Main instance works as expected."""
        link = os.path.join(self.root, 'Shared With Me')
        make_dir(link, recursive=True)
        self.assertTrue(path_exists(link))
        self.assertFalse(is_link(link))
        self.assertTrue(path_exists(self.shares))
        self.assertTrue(path_exists(self.root))
        main = self.build_main()
        # check that the shares link is actually a link
        self.assertEqual(main.shares_dir_link, link)
        self.assertFalse(is_link(main.shares_dir_link))

    def test_create_dirs_none_exists(self):
        """test that creating a Main instance works as expected."""
        # remove the existing dirs
        remove_dir(self.root)
        remove_dir(self.shares)
        main = self.build_main()
        # check that the shares link is actually a link
        self.assertTrue(is_link(main.shares_dir_link))
        self.assertTrue(path_exists(self.shares))
        self.assertTrue(path_exists(self.root))

    def test_connect_if_autoconnect_is_enabled(self):
        """If autoconnect option is enabled, connect the syncdaemon."""
        user_config = main_mod.config.get_user_config()
        orig = user_config.get_autoconnect()
        user_config.set_autoconnect(True)
        self.addCleanup(user_config.set_autoconnect, orig)

        main = self.build_main()
        expected = [('connect', (), {'autoconnecting': True})]
        self.assertEqual(main.external._called, expected)

    def test_dont_connect_if_autoconnect_is_disabled(self):
        """If autoconnect option is disabled, do not connect the syncdaemon."""
        user_config = main_mod.config.get_user_config()
        orig = user_config.get_autoconnect()
        user_config.set_autoconnect(False)
        self.addCleanup(user_config.set_autoconnect, orig)

        main = self.build_main()
        self.assertEqual(main.external._called, [])

    def _get_listeners(self, main):
        """Return the subscribed objects."""
        s = set()
        for listener in main.event_q.listener_map.values():
            for x in listener:
                s.add(x)
        return s

    def test_get_homedir(self):
        """The get_homedir returns the root dir."""
        self.patch(main_mod, "user_home", self.home_dir)
        expected = expand_user('~')
        main = self.build_main()
        self.assertEqual(main.get_homedir(), expected)

    def test_get_rootdir(self):
        """The get_rootdir returns the root dir."""
        expected = expand_user(os.path.join('~', 'Ubuntu Test One'))
        main = self.build_main(root_dir=expected)
        self.assertEqual(main.get_rootdir(), expected)

    def test_get_sharesdir(self):
        """The get_sharesdir returns the shares dir."""
        expected = expand_user(os.path.join('~', 'Share it to Me'))
        main = self.build_main(shares_dir=expected)
        self.assertEqual(main.get_sharesdir(), expected)

    def test_get_sharesdirlink(self):
        """The get_sharesdirlink returns the shares dir link."""
        expected = 'Share it to Me'
        main = self.build_main(shares_symlink_name=expected)
        self.assertEqual(main.get_sharesdir_link(),
                         os.path.join(main.get_rootdir(), expected))

    def test_version_is_logged(self):
        """Test that the client version is logged."""
        self.build_main()
        self.assertTrue(self.handler.check_info("client version", VERSION))

    def test_mark(self):
        """Check the MARK logs ok."""
        main = self.build_main()
        main.log_mark()
        shouldlog = ('MARK', "State: 'INIT'", 'queues IDLE', 'connection',
                     'queue: 0', 'offloaded: 0', 'hash: 0')
        self.assertTrue(self.handler.check(NOTE, *shouldlog))
