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

"""Tests for monitoring dump."""

from __future__ import unicode_literals

import shutil
import tempfile

import mock
from django.conf import settings
from twisted.trial.unittest import TestCase

from magicicada.monitoring.dump import gc, gc_dump, meliae_dump, scanner


class TestDump(TestCase):
    """Test dump."""

    def setUp(self):
        super(TestDump, self).setUp()
        log_folder = settings.LOG_FOLDER
        temp_folder = tempfile.mkdtemp()
        settings.LOG_FOLDER = temp_folder
        self.addCleanup(setattr, settings, 'LOG_FOLDER', log_folder)
        self.addCleanup(shutil.rmtree, temp_folder)

    def test_meliae_dump(self):
        """Check that the dump works."""
        collect = mock.Mock()
        self.patch(gc, 'collect',  collect)
        dump_all_objects = mock.Mock()
        self.patch(scanner, 'dump_all_objects', dump_all_objects)

        self.assertIn("Output written to:", meliae_dump())

        collect.assert_called_once_with()
        dump_all_objects.assert_called_once_with(mock.ANY)

    def test_meliae_dump_error(self):
        """Check the error case."""
        dump_all_objects = mock.Mock(side_effect=ValueError())
        self.patch(scanner, 'dump_all_objects', dump_all_objects)

        self.assertIn("Error while trying to dump memory", meliae_dump())

        dump_all_objects.assert_called_once_with(mock.ANY)

    def test_gc_dumps_count_ok(self):
        """Check that the count dump works."""
        get_count = mock.Mock(return_value=(400, 20, 3))
        self.patch(gc, 'get_count', get_count)
        garbage = iter([])
        self.patch(gc, 'garbage', garbage)

        self.assertIn("GC count is (400, 20, 3)", gc_dump())

    def test_gc_dumps_garbage_ok(self):
        """Check that the garbage dump works."""
        get_count = mock.Mock(return_value=0)
        self.patch(gc, 'get_count',  get_count)
        garbage = iter(['foo', 666])
        self.patch(gc, 'garbage', garbage)

        self.assertIn("2 garbage items written", gc_dump())

    def test_gc_dump_error_generic(self):
        """Something bad happens when dumping gc."""
        get_count = mock.Mock(side_effect=ValueError())
        self.patch(gc, 'get_count', get_count)

        self.assertIn("Error while trying to dump GC", gc_dump())

    def test_gc_dump_error_garbage(self):
        """Support something that breaks in repr."""
        class Strange(object):
            """Weird object that breaks on repr."""
            def __repr__(self):
                raise ValueError('foo')

        garbage = iter([Strange()])
        self.patch(gc, 'garbage', garbage)

        self.assertIn("1 garbage items written", gc_dump())
