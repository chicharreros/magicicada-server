# Copyright 2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Test the basic meter functionality."""

from __future__ import unicode_literals

import logging
import unittest

import metrics

from ubuntuone.devtools.handlers import MementoHandler


class FileBasedMeterTestCase(unittest.TestCase):
    """Test the file based meter."""

    def setUp(self):
        # instanciar, colgarse del logger con memento!
        self.meter = metrics.FileBasedMeter("test_namespace")

        # configure the memento handler to do the testings
        self.handler = MementoHandler()
        self.handler.level = logging.INFO
        self.handler.debug = True
        self.meter._logger.addHandler(self.handler)
        self.addCleanup(self.meter._logger.removeHandler, self.handler)

    def test_gauge(self):
        self.meter.gauge("name", "value")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "gauge=value"))

    def test_increment_first(self):
        self.meter.increment("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=1"))

    def test_increment_several(self):
        self.meter.increment("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=1"))
        self.meter.increment("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=2"))
        self.meter.increment("name", 5)
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=7"))

    def test_decrement_first(self):
        self.meter.decrement("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=-1"))

    def test_decrement_several(self):
        self.meter.decrement("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=-1"))
        self.meter.decrement("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=-2"))
        self.meter.decrement("name", 5)
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=-7"))

    def test_increment_decrement_mixed(self):
        self.meter.increment("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=1"))
        self.meter.decrement("name", 3)
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=-2"))
        self.meter.increment("name")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "counter=-1"))

    def test_timing(self):
        self.meter.timing("name", 0.55)
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "timing=0.55"))

    def test_meter(self):
        self.meter.meter("name", 123)
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "meter=123"))

    def test_report(self):
        self.meter.report("name", "whatever")
        self.assertTrue(self.handler.check_info(
            "test_namespace.name", "report=whatever"))


class GetMeterTestCase(unittest.TestCase):
    """Test the get meter."""

    def test_simple(self):
        meter = metrics.get_meter('namespace')
        self.assertIsInstance(meter, metrics.FileBasedMeter)

    def test_repeated_same_namespace(self):
        meter1 = metrics.get_meter('same_namespace')
        meter2 = metrics.get_meter('same_namespace')
        self.assertIs(meter1, meter2)

    def test_repeated_different_namespace(self):
        meter1 = metrics.get_meter('a_namespace')
        meter2 = metrics.get_meter('other_namespace')
        self.assertIsNot(meter1, meter2)
