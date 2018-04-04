# Copyright 2008-2015 Canonical
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Tests for metric services."""

from __future__ import unicode_literals

from mock import patch
from unittest import TestCase

from metrics import get_meter
from metrics.services import revno


class ServicesTest(TestCase):
    """Tests for metric services."""

    def test_meters_revno_with_gauge_meter(self):
        """The service is able to meter a revision by gauge meter."""
        service_meter = get_meter('service')
        with patch.object(service_meter, 'gauge') as gauge:
            revno()
            gauge.assert_called_with('revno', 'revno-undefined')
