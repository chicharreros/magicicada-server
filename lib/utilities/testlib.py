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

"""Library of functions used in tests."""

from __future__ import unicode_literals

import logging
import os
import re

from unittest import TestSuite, TestLoader, defaultTestLoader

import django

from django.test.runner import DiscoverRunner
from twisted.internet.base import DelayedCall
from twisted.trial.reporter import (
    TreeReporter, TestResultDecorator, SubunitReporter)
from twisted.trial.runner import TrialRunner


COVERAGE_DIR = "./tmp/coverage"
WORKING_DIR = "./tmp/trial"

django.setup()
logging.setLoggerClass(logging.Logger)


class StopOnFailureDecorator(TestResultDecorator):
    """TestResult decorator that stop the test on the first failure/error."""

    def addFailure(self, test, fail):
        """
        Forward the failure to TreeReporter and stop the test if
        stop_early is True
        """
        self._originalReporter.addFailure(test, fail)
        self._originalReporter.stop()

    def addError(self, test, error):
        """
        Forward the error to TreeReporter and stop the test if
        stop_early is True
        """
        self._originalReporter.addError(test, error)
        self._originalReporter.stop()


class LogsOnFailureDecorator(TestResultDecorator):
    """Show some logs to stdout on failure/error."""

    _logs_to_show = [
        'tmp/filesync-server-tests.log',
        'tmp/xdg_cache/ubuntuone/log/syncdaemon.log',
    ]

    def __init__(self, *a, **k):
        self._logs_positions = {}
        cwd = os.getcwd()
        self._abspath_logs = [os.path.join(cwd, l) for l in self._logs_to_show]
        TestResultDecorator.__init__(self, *a, **k)

    def startTest(self, test):
        """Record the logs positions when the test starts."""
        for log in self._abspath_logs:
            if os.path.exists(log):
                self._logs_positions[log] = os.stat(log).st_size
            else:
                self._logs_positions[log] = 0
        TestResultDecorator.startTest(self, test)

    def _show_the_logs(self):
        """Show the logs to stdout since the failed test started."""
        for log in self._abspath_logs:
            prev_pos = self._logs_positions[log]
            print "\n-------- Dumping log:", repr(log)
            if os.path.exists(log):
                with open(log) as fh:
                    fh.seek(prev_pos)
                    print fh.read(),
                print "------------ end log:", repr(log)
            else:
                print "------------ log not found!"

    def addFailure(self, test, fail):
        """Show the log and forward the failure."""
        self._show_the_logs()
        TestResultDecorator.addFailure(self, test, fail)

    def addError(self, test, error):
        """Show the log and forward the error."""
        self._show_the_logs()
        TestResultDecorator.addError(self, test, error)


class CustomSuite(TestSuite):

    filter_fn = None

    def addTest(self, test):
        if not self.filter_fn(test):
            return
        return super(CustomSuite, self).addTest(test)


class RegexTestLoader(TestLoader):

    suiteClass = CustomSuite

    def __init__(self, filter_test, *args, **kwargs):
        self.suiteClass.filter_fn = lambda s, t: filter_test(t)
        super(RegexTestLoader, self).__init__(*args, **kwargs)


def load_unittest(relpath, loader=None):
    """Load unit tests from a Python module with the given relative path."""
    assert relpath.endswith(".py"), (
        "%s does not appear to be a Python module" % relpath)
    modpath = relpath.replace(os.path.sep, ".")[:-3]
    module = __import__(modpath, None, None, [""])

    # If the module has a 'suite' or 'test_suite' function, use that
    # to load the tests.
    if hasattr(module, "suite"):
        return module.suite()
    elif hasattr(module, "test_suite"):
        return module.test_suite()

    if loader is None:
        loader = defaultTestLoader
    return loader.loadTestsFromModule(module)


class MagicicadaRunner(DiscoverRunner):

    def __init__(self, factory, filter_test, verbosity=1):
        self.factory = factory
        self.loader = RegexTestLoader(filter_test)
        self.server_suite = TestSuite()
        self.non_server_suite = TestSuite()
        super(MagicicadaRunner, self).__init__(verbosity=verbosity)

    def add_tests_for_dir(self, testdir, testpaths, topdir):
        """Helper for build_suite; searches a particular testdir for tests.

        @param testdir: The directory to search for tests.
        @param testpaths: If provided, only tests in this sequence will
                          be considered.  If not provided, all tests are
                          considered.
        @param topdir: the top-level source directory
        @return: TestSuite will all the tests

        """
        for root, dirnames, filenames in os.walk(testdir):

            # Only process files found within directories named "tests".
            if not os.path.basename(root).endswith('tests'):
                continue

            for filename in filenames:
                filepath = os.path.join(root, filename)
                relpath = filepath[len(testdir) + 1:]

                if testpaths:
                    top_relpath = os.path.abspath(filepath)[len(topdir) + 1:]
                    # Skip any tests not in testpaths.
                    for testpath in testpaths:
                        if top_relpath.startswith(testpath):
                            break
                    else:
                        continue

                if relpath.startswith('server/'):
                    suite = self.server_suite
                else:
                    suite = self.non_server_suite
                if filename.endswith(".py") and filename.startswith("test_"):
                    suite.addTest(load_unittest(relpath, self.loader))

    def build_suite(self, test_labels, extra_tests):
        topdir, testdirs, testpaths = test_labels
        for testdir in testdirs:
            self.add_tests_for_dir(testdir, testpaths, topdir)

    def run_suite(self, suite=None, **kwargs):
        non_server_result = super(MagicicadaRunner, self).run_suite(
            self.non_server_suite, **kwargs)
        if not non_server_result.wasSuccessful():
            return non_server_result

        server_result = TrialRunner(
            reporterFactory=self.factory, realTimeErrors=True,
            workingDirectory=WORKING_DIR).run(self.server_suite)
        return server_result

    def suite_result(self, suite, result, **kwargs):
        return result


def test_with_trial(options, topdir, testdirs, testpaths):
    """The main testing entry point."""
    # parse arguments
    reporter_decorators = []
    if options.one:
        reporter_decorators.append(StopOnFailureDecorator)
    if options.logs_on_failure:
        reporter_decorators.append(LogsOnFailureDecorator)

    def factory(*args, **kwargs):
        """Custom factory tha apply the decorators to the TreeReporter"""
        if options.subunit:
            return SubunitReporter(*args, **kwargs)
        else:
            result = TreeReporter(*args, **kwargs)
            for decorator in reporter_decorators:
                result = decorator(result)
            return result

    include_re = None
    if options.test:
        include_re = re.compile('.*%s.*' % options.test)

    exclude_re = None
    if options.ignore:
        exclude_re = re.compile('.*%s.*' % options.ignore)

    if options.debug:
        DelayedCall.debug = True

    def filter_test(t):
        result = True
        try:
            test_id = t.id()
        except AttributeError:
            pass  # not a test, keep looking
        else:
            if include_re and not include_re.match(test_id):
                result = False
            if exclude_re and exclude_re.match(test_id):
                result = False
        return result

    runner = MagicicadaRunner(
        factory, filter_test, verbosity=options.verbosity)
    result = runner.run_tests(test_labels=(topdir, testdirs, testpaths))
    return not result.wasSuccessful()
