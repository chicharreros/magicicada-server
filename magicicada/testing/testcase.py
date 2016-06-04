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

"""TestCases for testing."""

from __future__ import unicode_literals

from django.test import TransactionTestCase
from django.test.client import RequestFactory

from magicicada.testing.factory import Factory


class BaseTestCase(TransactionTestCase):
    """Base TestCase: provides a Factory and a RequestFactory."""

    request_factory = RequestFactory()
    factory = Factory()
    maxDiff = None

    def patch(self, obj, attr_name, new_val):
        """Patch!"""
        old_val = getattr(obj, attr_name)
        setattr(obj, attr_name, new_val)
        self.addCleanup(setattr, obj, attr_name, old_val)
