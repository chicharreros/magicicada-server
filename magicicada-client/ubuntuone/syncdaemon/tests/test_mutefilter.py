#
# Author: Facundo Batista <facundo@canonical.com>
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
#
# Copyright 2009-2012 Canonical Ltd.
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
"""Tests for the Mute Filter."""

import unittest

from ubuntuone.syncdaemon.mute_filter import MuteFilter


class MuteFilterTests(unittest.TestCase):
    """Tests the MuteFilter class."""

    def setUp(self):
        self.mf = MuteFilter()

    def test_empty(self):
        """Nothing there."""
        self.assertFalse(self.mf._cnt)

    def test_add_one_nodata(self):
        """Adds one element without data."""
        self.mf.add("foo")
        self.assertEqual(self.mf._cnt, dict(foo=[{}]))

    def test_add_one_withdata(self):
        """Adds one element with data."""
        self.mf.add("foo", bar=3)
        self.assertEqual(self.mf._cnt, dict(foo=[{'bar': 3}]))

    def test_add_two_event_different(self):
        """Adds two elements, different event."""
        self.mf.add("foo", a=1)
        self.mf.add("bar", a=1)
        self.assertEqual(self.mf._cnt, dict(foo=[{'a': 1}], bar=[{'a': 1}]))

    def test_add_two_data_different(self):
        """Adds two elements, different data."""
        self.mf.add("foo", a=1)
        self.mf.add("foo", b=1)
        self.assertEqual(self.mf._cnt, dict(foo=[{'a': 1}, {'b': 1}]))

    def test_add_two_equal(self):
        """Adds one element twice."""
        self.mf.add("foo")
        self.mf.add("foo")
        self.assertEqual(self.mf._cnt, dict(foo=[{}, {}]))

    def test_add_two_equal_and_third(self):
        """Adds one element."""
        self.mf.add("foo")
        self.mf.add("bar", b=3)
        self.mf.add("bar", b=3)
        self.assertEqual(
            self.mf._cnt, dict(foo=[{}], bar=[{'b': 3}, {'b': 3}]))

    def test_pop_simple(self):
        """Pops one element."""
        self.mf.add("foo")
        self.assertFalse(self.mf.pop("bar"))
        self.assertEqual(self.mf._cnt, dict(foo=[{}]))
        self.assertTrue(self.mf.pop("foo"))
        self.assertFalse(self.mf._cnt)

    def test_pop_complex(self):
        """Pops several elements."""
        # add several
        self.mf.add("foo", a=5)
        self.mf.add("bar")
        self.mf.add("bar")
        self.assertEqual(self.mf._cnt, dict(foo=[{'a': 5}], bar=[{}, {}]))

        # clean bar
        self.assertTrue(self.mf.pop("bar"))
        self.assertEqual(self.mf._cnt, dict(foo=[{'a': 5}], bar=[{}]))
        self.assertTrue(self.mf.pop("bar"))
        self.assertEqual(self.mf._cnt, dict(foo=[{'a': 5}]))
        self.assertFalse(self.mf.pop("bar"))
        self.assertEqual(self.mf._cnt, dict(foo=[{'a': 5}]))

        # clean foo
        self.assertTrue(self.mf.pop("foo", a=5))
        self.assertFalse(self.mf._cnt)
        self.assertFalse(self.mf.pop("foo"))
        self.assertFalse(self.mf._cnt)
