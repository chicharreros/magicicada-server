# -*- coding: utf-8 -*-
#
# Author: Manuel de la Pena <manuel@canonical.com>
#
# Copyright 2011-2012 Canonical Ltd.
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
"""Test for the pyinotify implementation on windows."""

import sys

from twisted.internet import defer
from twisted.trial.unittest import TestCase

from ubuntuone.platform.filesystem_notifications.pyinotify_agnostic import (
    RawOutputFormat)


class RawOutputFormatTest(TestCase):
    """Test te formatter to ensure it can deal with mbcs."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(RawOutputFormatTest, self).setUp()
        self.format = {'normal': 'normal'}
        self.formatter = RawOutputFormat(self.format)

    def test_simple_unicode(self):
        """Test the formatting of a simple value that is unicode."""
        attr = 'attribute'
        self.format[attr] = attr
        value = u'ñoño'
        expected_result = (attr + value.encode(
                           sys.getfilesystemencoding(), 'replace') +
                           self.format['normal'])
        self.assertEqual(expected_result, self.formatter.simple(value, attr))

    def test_simple_not_unicode(self):
        """Test the formatting of a simple value that is not unicode."""
        attr = 'attribute'
        self.format[attr] = attr
        value = True
        expected_result = (attr + str(value) + self.format['normal'])
        self.assertEqual(expected_result, self.formatter.simple(value, attr))
