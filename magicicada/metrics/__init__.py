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

"""Support for getting metrics recorded."""

from __future__ import unicode_literals

import logging
import os

from threading import Lock

from django.conf import settings

logger = logging.getLogger(__name__)


class FileBasedMeter(object):
    """A meter that sends stuff to file."""

    # class level lock so all instances are mutually excluded
    _lock = Lock()

    def __init__(self, namespace):
        self._namespace = namespace
        self._counters = {}

    def gauge(self, name, value):
        """Record an absolute reading for C{name} with C{value}."""
        self._write('gauge', name, value)

    def increment(self, name, value=1):
        """Increment counter C{name} by C{count}."""
        self._counters[name] = self._counters.get(name, 0) + value
        self._write('counter', name, self._counters[name])

    def decrement(self, name, value=1):
        """Decrement counter C{name} by C{count}."""
        self._counters[name] = self._counters.get(name, 0) - value
        self._write('counter', name, self._counters[name])

    def timing(self, name, duration):
        """Report that C{name} took C{duration} seconds."""
        self._write('timing', name, duration)

    def meter(self, name, value=1):
        """Mark the occurrence of a given number of events."""
        self._write('meter', name, value)

    def report(self, name, value):
        """Report a generic metric.

        Used for server side plugins without client support.
        """
        self._write('report', name, value)

    def _write(self, kind, name, value):
        record = "%s.%s %s=%s" % (self._namespace, name, kind, value)
        with self._lock:
            logger.info(record)


def _build_namespace(namespace):
    """Build the base namespace for all this' process metrics."""
    assert settings.ENVIRONMENT_NAME, "Missing environment_name value"
    assert settings.SERVICE_GROUP, "Missing service_group value"
    service_name = os.environ.get("FSYNC_SERVICE_NAME", settings.SERVICE_NAME)
    instance_id = os.environ.get("FSYNC_INSTANCE_ID", settings.INSTANCE_ID)
    return "%s.%s.%s.%03d.%s" % (
        settings.ENVIRONMENT_NAME, settings.SERVICE_GROUP,
        service_name, int(instance_id), namespace)


# cache to store the FileBasedMeters for the same namespace
_cache = {}


def get_meter(namespace):
    """Get a meter for the given namespace.

    Defaults to instance scope, which generates a metric containing the
    instance id as part of it's namespace.
    """
    try:
        fbm = _cache[namespace]
    except KeyError:
        full_namespace = _build_namespace(namespace)
        fbm = _cache[namespace] = FileBasedMeter(full_namespace)
    return fbm
