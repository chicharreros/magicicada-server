# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Account info tests."""

from twisted.internet import defer
from ubuntuone.storageprotocol import request

from magicicada.filesync import services
from magicicada.filesync.models import StorageUser
from magicicada.server.testing.testcase import TestWithDatabase


class QuotaTest(TestWithDatabase):
    """Test account and quota info."""

    def test_quota(self):
        """Test quota info."""
        usr2 = services.make_storage_user(
            u"otheruser", visible_name=u"Other User",
            max_storage_bytes=self.usr0.max_storage_bytes * 10)
        share = usr2.root.share(self.usr0.id, u"a share", readonly=True)

        @defer.inlineCallbacks
        def do_test(client):
            """Do the actual test."""
            yield client.dummy_authenticate("open sesame")
            result = yield client.get_free_space(request.ROOT)
            self.assertEqual(self.usr0.free_bytes, result.free_bytes)
            self.assertEqual(request.ROOT, result.share_id)
            result = yield client.get_free_space(str(share.id))
            self.assertEqual(usr2.free_bytes, result.free_bytes)
            self.assertEqual(str(share.id), result.share_id)
        return self.callback_test(do_test,
                                  add_default_callbacks=True)

    def test_over_quota(self):
        """Test that 0 bytes free (versus a negative number) is reported
        when over quota."""
        f = self.factory.make_file(
            owner=StorageUser.objects.get(id=self.usr0.id))
        # need to do something that just can't happen normally
        StorageUser.objects.filter(id=self.usr0.id).update(
            max_storage_bytes=f.content.size - 1)

        @defer.inlineCallbacks
        def do_test(client):
            """Do the actual test."""
            yield client.dummy_authenticate("open sesame")
            result = yield client.get_free_space(request.ROOT)
            self.assertEqual(0, result.free_bytes)
            self.assertEqual(request.ROOT, result.share_id)
        return self.callback_test(do_test,
                                  add_default_callbacks=True)

    def test_account_info(self):
        """Test account info."""

        @defer.inlineCallbacks
        def do_test(client):
            """Do the actual test."""
            yield client.dummy_authenticate("open sesame")
            result = yield client.get_account_info()
            self.assertEqual(
                self.usr0.max_storage_bytes, result.purchased_bytes)
        return self.callback_test(do_test, add_default_callbacks=True)
