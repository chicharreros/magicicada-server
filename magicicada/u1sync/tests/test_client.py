# Copyright 2010 Canonical Ltd.
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Test the client code."""

from mocker import Mocker
from twisted.trial.unittest import TestCase

from magicicada.u1sync import client


class SyncStorageClientTest(TestCase):
    """Test the SyncStorageClient."""

    def test_conn_made_call_parent(self):
        """The connectionMade method should call the parent."""
        # set up everything
        called = []
        self.patch(client.StorageClient, 'connectionMade',
                   lambda s: called.append(True))
        c = client.SyncStorageClient()
        mocker = Mocker()
        obj = mocker.mock()
        obj.current_protocol
        mocker.result(None)
        obj.current_protocol = c
        obj.observer.connected()
        c.factory = obj

        # call and test
        with mocker:
            c.connectionMade()
        self.assertTrue(called)

    def test_conn_lost_call_parent(self):
        """The connectionLost method should call the parent."""
        # set up everything
        called = []
        self.patch(client.StorageClient, 'connectionLost',
                   lambda s, r: called.append(True))
        c = client.SyncStorageClient()
        mocker = Mocker()
        obj = mocker.mock()
        obj.current_protocol
        mocker.result(None)
        c.factory = obj

        # call and test
        with mocker:
            c.connectionLost()
        self.assertTrue(called)
