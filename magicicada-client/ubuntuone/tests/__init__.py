# Copyright (C) 2009-2012 Canonical Ltd.
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

"""Tests for the project."""

from __future__ import unicode_literals

from collections import defaultdict
from functools import wraps

from twisted.internet import defer
from twisted.trial import unittest


class TestCase(unittest.TestCase):
    """Customized test case that keeps tracks of method calls."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestCase, self).setUp()
        self._called = False

    def _set_called(self, *args, **kwargs):
        """Keep track of a method call."""
        self._called = (args, kwargs)


class Recorder(object):
    """A class that records every call clients made to it."""

    no_wrap = ['_called']
    _next_result = None

    def __init__(self, *args, **kwargs):
        self._called = defaultdict(list)

    def __getattribute__(self, attr_name):
        """Override so we can record calls to members."""
        try:
            result = super(Recorder, self).__getattribute__(attr_name)
        except AttributeError:
            def result(*a, **kw):
                return self._next_result
            super(Recorder, self).__setattr__(attr_name, result)

        if attr_name in super(Recorder, self).__getattribute__('no_wrap'):
            return result

        called = super(Recorder, self).__getattribute__('_called')

        def wrap_me(f):
            """Wrap 'f'."""
            @wraps(f)
            def inner(*a, **kw):
                """Keep track of calls to 'f', execute it and return result."""
                called[attr_name].append((a, kw))
                return f(*a, **kw)

            return inner

        if callable(result):
            return wrap_me(result)
        else:
            return result
