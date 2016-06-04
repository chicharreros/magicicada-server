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
from testtools import TestCase

from metrics import get_meter
from metrics.services import oops_saved, revno, version_info


class ServicesTest(TestCase):
    """Tests for metric services."""

    def test_meters_oops_passing_a_report(self):
        """The service is able to meter an oops passing a report."""
        service_meter = get_meter('service')
        with patch.object(service_meter, 'meter') as meter:
            oops_saved(report=dict())
            meter.assert_called_with('oops_saved')

    def test_meters_oops_passing_a_context(self):
        """The service is able to meter an oops passing a context."""
        service_meter = get_meter('service')
        with patch.object(service_meter, 'meter') as meter:
            oops_saved(context='some oops context')
            meter.assert_called_with('oops_saved')

    def test_oops_saved_with_no_report(self):
        """oops_saved returns an empty list with no report."""
        self.assertEqual([], oops_saved())

    def test_oops_saved_with_report_with_no_id(self):
        """oops_saved returns an empty list with no id in the report."""
        self.assertEqual([], oops_saved(report=dict()))

    def test_oops_saved_with_report_with_id(self):
        """oops_saved returns a non-empty list with an id in the report."""
        the_id = 'an id'
        self.assertEqual([the_id], oops_saved(report=dict(id=the_id)))

    def test_meters_revno_with_gauge_meter(self):
        """The service is able to meter a revision by gauge meter."""
        service_meter = get_meter('service')
        with patch.object(service_meter, 'gauge') as gauge:
            revno()
            gauge.assert_called_with('revno', version_info['revno'])
