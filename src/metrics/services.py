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

"""Metric services."""

from __future__ import unicode_literals

from metrics import get_meter
try:
    from versioninfo import version_info
except ImportError:
    version_info = {'revno': 'Undefined'}


def oops_saved(report=None, context=None):
    """A service has OOPSed."""
    meter = get_meter(scope='service')
    meter.meter('oops_saved')
    if report and 'id' in report:
        return [report['id']]
    return []


def revno():
    """Trigger a service revision number update."""
    meter = get_meter(scope='service')
    meter.gauge('revno', version_info['revno'])
