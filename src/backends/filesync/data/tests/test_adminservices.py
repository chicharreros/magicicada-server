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

"""Tests for the adminservices features."""

from __future__ import unicode_literals

from backends.filesync.data import adminservices as admin, dao, services
from backends.filesync.data.testing.testcase import StorageDALTestCase


class AdminServicesTestCase(StorageDALTestCase):
    """Tests the adminservices module features."""

    def _make_users(self):
        """Create users for tests."""
        usernames = ['bob', 'bobby', 'inez', 'juan', 'tim']
        for i, name in zip(range(5), usernames):
            services.make_storage_user(i, name, name, 2 ** 30)

    def test_StorageUserFinder(self):
        """Test the StorageUserFinder."""
        users = admin.StorageUserFinder()
        self.assertEqual(users.all(), [])
        self.assertEqual(users.count(), 0)
        self.assertEqual(users.is_empty(), True)
        self._make_users()
        # the returning object can be reused
        self.assertEqual(len(users.all()), 5)
        self.assertEqual(users.count(), 5)
        self.assertEqual(users.is_empty(), False)
        self.assertEqual(users[4].username, "tim")
        users.filter = "BOB"
        self.assertEqual(len(users.all()), 2)
        self.assertEqual(users[0].username, "bob")
        self.assertEqual(users[1].username, "bobby")
        users.filter = "juan"
        self.assertEqual(len(users.all()), 1)
        self.assertTrue(isinstance(users[0], dao.StorageUser))
        self.assertEqual(users[0].username, "juan")
        # test slicing
        users.filter = None
        subset = users[2:4]
        self.assertEqual(len(subset), 2)
        self.assertEqual(subset[0].username, "inez")
        self.assertEqual(subset[1].username, "juan")
