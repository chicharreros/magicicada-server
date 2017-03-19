# Copyright 2012 Canonical Ltd.
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
"""Platform/File System Notifications test code."""

import logging

from twisted.internet import defer, reactor

from contrib.testing import testcase
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.syncdaemon import event_queue, filesystem_manager
from ubuntuone.syncdaemon.tritcask import Tritcask


class BaseFSMonitorTestCase(testcase.BaseTwistedTestCase):
    """Test the structures where we have the path/watch."""

    timeout = 3

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(BaseFSMonitorTestCase, self).setUp()
        fsmdir = self.mktemp('fsmdir')
        partials_dir = self.mktemp('partials_dir')
        self.root_dir = self.mktemp('root_dir')
        self.vm = testcase.FakeVolumeManager(self.root_dir)
        self.tritcask_dir = self.mktemp("tritcask_dir")
        self.db = Tritcask(self.tritcask_dir)
        self.fs = filesystem_manager.FileSystemManager(fsmdir, partials_dir,
                                                       self.vm, self.db)
        self.fs.create(path=self.root_dir, share_id='', is_dir=True)
        self.fs.set_by_path(path=self.root_dir,
                            local_hash=None, server_hash=None)
        eq = event_queue.EventQueue(self.fs)

        self.deferred = deferred = defer.Deferred()

        class HitMe(object):
            # class-closure, cannot use self, pylint: disable-msg=E0213
            def handle_default(innerself, event, **args):
                reactor.callLater(.1, deferred.callback, True)

        eq.subscribe(HitMe())
        self.monitor = eq.monitor
        self.log_handler = MementoHandler()
        self.log_handler.setLevel(logging.DEBUG)
        self.monitor.log.addHandler(self.log_handler)

    @defer.inlineCallbacks
    def tearDown(self):
        """Clean up the tests."""
        self.monitor.shutdown()
        self.monitor.log.removeHandler(self.log_handler)
        yield super(BaseFSMonitorTestCase, self).tearDown()
