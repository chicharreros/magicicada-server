# -*- coding: utf-8 -*-
#
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
""" Tests for logger utils """

from __future__ import with_statement

import logging

from twisted.internet import defer
from twisted.trial import unittest

from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipIfOS

from ubuntuone.syncdaemon.logger import (
    DebugCapture,
    NOTE,
    TRACE,
    root_logger,
    twisted_logger,
    filesystem_logger,
    MultiFilter,
)


class DebugCaptureTest(unittest.TestCase):
    """Tests for DebugCapture context manager."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the logger and the handler"""
        yield super(DebugCaptureTest, self).setUp()
        self.handler = MementoHandler()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)

    @defer.inlineCallbacks
    def tearDown(self):
        """close the handler and restore the logger (Logger's are global)"""
        yield super(DebugCaptureTest, self).tearDown()
        self.handler.close()
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)

    def test_capture_in_debug_or_lower(self):
        """Test simple capture with the logger in DEBUG level"""
        self.logger.debug('a message')
        self.assertEqual(1, len(self.handler.records))
        self.handler.records = []

        self.logger.setLevel(TRACE)
        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should never reach the handler')
            self.assertEqual(0, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(1, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should never reach the handler')
            self.logger.warning('a warning')
            self.logger.debug('another debug message')
            self.assertEqual(0, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(3, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should never reach the handler')
            self.logger.info('a info message')
            self.logger.debug('another debug message')
            self.assertEqual(0, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(3, len(self.handler.records), messages)

    def test_capture_non_debug_levels(self):
        """Test debug log capture in levels > DEBUG"""
        levels = [logging.INFO, logging.ERROR, NOTE, logging.CRITICAL]
        for level in levels:
            self.logger.setLevel(level)
            self._test_capture()
            self.logger.setLevel(logging.DEBUG)
            self.handler.records = []

    def _test_capture(self):
        """Tests for simple debug capture in INFO level"""
        self.logger.debug('a message')
        self.assertEqual(0, len(self.handler.records))
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should never reach the handler')
            self.assertEqual(1, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(0, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should never reach the handler')
            self.logger.warning('a warning')
            self.logger.debug('another debug message')
            self.assertEqual(2, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(1, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should never reach the handler')
            self.logger.info('a info message')
            self.logger.debug('another debug message')
            self.assertEqual(2, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(1, len(self.handler.records), messages)

    def test_dump_on_unhandled_error(self):
        """Test that all captured debug info is dumped on a unhandled error and
        the error itself is logged too
        """
        self.logger.setLevel(logging.INFO)
        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler 1')
            self.assertEqual(1, len(dc.records))
            raise Exception('Expected exception!')
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(2, len(self.handler.records), messages)

    def test_dump_on_unhandled_error_in_DEBUG(self):
        """Test that all captured debug info is dumped on a unhandled error and
        the error itself is logged too (in DEBUG level)
        """
        # now with level <= DEBUG
        self.logger.setLevel(logging.DEBUG)
        self.handler.records = []
        self.logger.setLevel(logging.INFO)
        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler 1')
            self.assertEqual(1, len(dc.records))
            raise Exception('Expected exception!')
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(2, len(self.handler.records), messages)

    def test_dump_on_error_log(self):
        """Test that all captured debug info is dumped on ERROR log"""
        self.logger.setLevel(logging.INFO)
        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.error('Oops! an error')
            self.assertEqual(2, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(2, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.error('Oops! an error')
            self.logger.debug('another message')
            self.assertEqual(3, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(3, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.error('Oops! an error')
            self.logger.debug('another message')
            self.logger.error('Oh my! another error!')
            self.assertEqual(4, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(4, len(self.handler.records), messages)

    def test_dump_on_error_log_DEBUG(self):
        """Test that all captured debug info is dumped on ERROR log"""
        self.logger.setLevel(logging.DEBUG)
        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.error('Oops! an error')
            self.assertEqual(0, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(2, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.error('Oops! an error')
            self.logger.debug('another message')
            self.assertEqual(0, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(3, len(self.handler.records), messages)
        self.handler.records = []

        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.error('Oops! an error')
            self.logger.debug('another message')
            self.logger.error('Oh my! another error!')
            self.assertEqual(0, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(4, len(self.handler.records), messages)

    def test_dump_on_critical_log(self):
        """Test that the dump also works on levels > ERROR"""
        self.logger.setLevel(logging.INFO)
        with DebugCapture(self.logger) as dc:
            self.logger.debug('a message that should go to the handler')
            self.logger.critical('Oops! an error')
            self.assertEqual(2, len(dc.records))
        messages = [r.getMessage() for r in self.handler.records]
        self.assertEqual(2, len(self.handler.records), messages)


class FilterTests(unittest.TestCase):
    """Tests log filters"""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the logger and the handler"""
        yield super(FilterTests, self).setUp()
        self.handler = MementoHandler()
        self.handler.setLevel(logging.DEBUG)
        root_logger.addHandler(self.handler)
        self.addCleanup(root_logger.removeHandler, self.handler)

        if filesystem_logger is not None:
            filesystem_logger.addHandler(self.handler)
            self.addCleanup(filesystem_logger.removeHandler, self.handler)

        twisted_logger.addHandler(self.handler)
        self.addCleanup(twisted_logger.removeHandler, self.handler)

        self.addCleanup(self.handler.close)

    @skipIfOS('win32', 'There is not filesystem_logger implementation in '
              'windows yet, see bug #823316.')
    def test_multiple_filters(self):
        """Tests logging with more than one filter."""
        test_logger = logging.getLogger('ubuntuone.SyncDaemon.FilterTest')
        test_logger.debug('debug info 0')
        self.assertEqual(1, len(self.handler.records))
        self.handler.addFilter(
            MultiFilter(['ubuntuone.SyncDaemon', 'twisted', 'pyinotify']))
        test_logger.debug('debug info 1')
        self.assertEqual(2, len(self.handler.records))


class MultiFilterTest(unittest.TestCase):
    """Tests for logger.MultiFilter"""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the logger and the handler"""
        yield super(MultiFilterTest, self).setUp()
        self.handler = MementoHandler()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)

    @defer.inlineCallbacks
    def tearDown(self):
        """close the handler and restore the logger (Logger's are global)"""
        yield super(MultiFilterTest, self).tearDown()
        self.handler.close()
        self.logger.removeHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)

    def test_no_filters(self):
        """Tests filtering without any filter in self.filters."""
        self.handler.addFilter(MultiFilter())
        self.logger.debug('this msg should be logged')
        self.assertEqual(1, len(self.handler.records))

    def test_single_filter(self):
        """Tests filtering with one filter."""
        self.handler.addFilter(MultiFilter([self.__class__.__name__]))
        self.logger.debug('this msg should be logged')
        self.assertEqual(1, len(self.handler.records))
        other_logger = logging.getLogger("NO_LOG."+self.__class__.__name__)
        other_logger.debug('this msg shouldn\'t be logged')
        self.assertEqual(1, len(self.handler.records))

    def test_multiple_filters(self):
        """Tests filtering with more than one filter."""
        self.handler.addFilter(
            MultiFilter([self.__class__.__name__,
                         self.__class__.__name__ + ".child"]))
        no_logger = logging.getLogger("NO_LOG."+self.__class__.__name__)
        yes_logger = logging.getLogger(self.__class__.__name__ + '.child')
        self.logger.debug('this msg should be logged')
        self.assertEqual(1, len(self.handler.records))
        no_logger.debug('this msg shouldn\'t be logged')
        self.assertEqual(1, len(self.handler.records))
        yes_logger.debug('this msg from a child logger should be logged')
        self.assertEqual(2, len(self.handler.records))
