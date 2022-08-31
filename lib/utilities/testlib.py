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

"""Library of functions used in tests."""

import os
import re

from unittest import TestSuite, TestLoader, defaultTestLoader

import django
from django.conf import settings
from django.test.runner import DiscoverRunner
from twisted.internet import defer
from twisted.internet.base import DelayedCall
from twisted.python import failure
from twisted.trial.reporter import (
    TreeReporter,
    TestResultDecorator,
    SubunitReporter,
)
from twisted.trial.runner import TrialRunner


COVERAGE_DIR = "./tmp/coverage"
WORKING_DIR = "./tmp/trial"


def set_twisted_debug():
    DelayedCall.debug = True
    failure.startDebugMode()
    defer.setDebugging(True)


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
        self._abspath_logs = [
            os.path.join(cwd, ll) for ll in self._logs_to_show
        ]
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
            print("\n-------- Dumping log:", repr(log))
            if os.path.exists(log):
                with open(log) as fh:
                    fh.seek(prev_pos)
                    print(fh.read(), end=' ')
                print("------------ end log:", repr(log))
            else:
                print("------------ log not found!")

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
        "%s does not appear to be a Python module" % relpath
    )
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
    """A custom subclass of DiscoverRunner.

    class DiscoverRunner(
        pattern='test*.py', top_level=None, verbosity=1, interactive=True,
        failfast=False, keepdb=False, reverse=False, debug_mode=False,
        debug_sql=False, parallel=0, tags=None, exclude_tags=None,
        test_name_patterns=None, pdb=False, buffer=False,
        enable_faulthandler=True, timing=True, shuffle=False, logger=None,
        **kwargs)

    DiscoverRunner will search for tests in any file matching pattern.

    top_level can be used to specify the directory containing your top-level
    Python modules. Usually Django can figure this out automatically, so it’s
    not necessary to specify this option. If specified, it should generally be
    the directory containing your manage.py file.

    verbosity determines the amount of notification and debug information that
    will be printed to the console; 0 is no output, 1 is normal output, and 2
    is verbose output.

    If interactive is True, the test suite has permission to ask the user for
    instructions when the test suite is executed. An example of this behavior
    would be asking for permission to delete an existing test database. If
    interactive is False, the test suite must be able to run without any manual
    intervention.

    If failfast is True, the test suite will stop running after the first test
    failure is detected.

    If keepdb is True, the test suite will use the existing database, or create
    one if necessary. If False, a new database will be created, prompting the
    user to remove the existing one, if present.

    If reverse is True, test cases will be executed in the opposite order. This
    could be useful to debug tests that aren’t properly isolated and have side
    effects. Grouping by test class is preserved when using this option. This
    option can be used in conjunction with --shuffle to reverse the order for a
    particular random seed.

    debug_mode specifies what the DEBUG setting should be set to prior to
    running tests.

    parallel specifies the number of processes. If parallel is greater than 1,
    the test suite will run in parallel processes. If there are fewer test
    cases than configured processes, Django will reduce the number of processes
    accordingly. Each process gets its own database. This option requires the
    third-party tblib package to display tracebacks correctly.

    tags can be used to specify a set of tags for filtering tests. May be
    combined with exclude_tags.

    exclude_tags can be used to specify a set of tags for excluding tests. May
    be combined with tags.

    If debug_sql is True, failing test cases will output SQL queries logged to
    the django.db.backends logger as well as the traceback. If verbosity is 2,
    then queries in all tests are output.

    test_name_patterns can be used to specify a set of patterns for filtering
    test methods and classes by their names.

    If pdb is True, a debugger (pdb or ipdb) will be spawned at each test error
    or failure.

    If buffer is True, outputs from passing tests will be discarded.

    If enable_faulthandler is True, faulthandler will be enabled.

    If timing is True, test timings, including database setup and total run
    time, will be shown.

    If shuffle is an integer, test cases will be shuffled in a random order
    prior to execution, using the integer as a random seed. If shuffle is None,
    the seed will be generated randomly. In both cases, the seed will be logged
    and set to self.shuffle_seed prior to running tests. This option can be
    used to help detect tests that aren’t properly isolated. Grouping by test
    class is preserved when using this option.

    logger can be used to pass a Python Logger object. If provided, the logger
    will be used to log messages instead of printing to the console. The logger
    object will respect its logging level rather than the verbosity.

    Django may, from time to time, extend the capabilities of the test runner
    by adding new arguments. The **kwargs declaration allows for this
    expansion. If you subclass DiscoverRunner or write your own test runner,
    ensure it accepts **kwargs.

    Your test runner may also define additional command-line options. Create or
    override an add_arguments(cls, parser) class method and add custom
    arguments by calling parser.add_argument() inside the method, so that the
    test command will be able to use those arguments.

    """

    def __init__(
        self,
        one=False,
        logs_on_failure=False,
        test=None,
        ignore=None,
        subunit=False,
        verbosity=1,
        debug=False,
        **kwargs
    ):
        reporter_decorators = []
        if one:
            reporter_decorators.append(StopOnFailureDecorator)
        if logs_on_failure:
            reporter_decorators.append(LogsOnFailureDecorator)

        def factory(*args, **kwargs):
            """Custom factory tha apply the decorators to the TreeReporter"""
            if subunit:
                return SubunitReporter(*args, **kwargs)
            else:
                result = TreeReporter(*args, **kwargs)
                for decorator in reporter_decorators:
                    result = decorator(result)
                return result

        include_re = None
        if test:
            include_re = re.compile('.*%s.*' % test)

        exclude_re = None
        if ignore:
            exclude_re = re.compile('.*%s.*' % ignore)

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

        self.factory = factory
        self.loader = RegexTestLoader(filter_test)
        self.server_suite = TestSuite()
        self.non_server_suite = TestSuite()
        super(MagicicadaRunner, self).__init__(verbosity=verbosity, **kwargs)
        if debug:
            set_twisted_debug()

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
                relpath = filepath[len(testdir) + 1 :]

                if testpaths:
                    top_relpath = os.path.abspath(filepath)[len(topdir) + 1 :]
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
        return self.non_server_suite

    def run_suite(self, suite=None, **kwargs):
        non_server_result = super(MagicicadaRunner, self).run_suite(
            self.non_server_suite, **kwargs
        )
        if not non_server_result.wasSuccessful():
            return non_server_result

        server_result = TrialRunner(
            reporterFactory=self.factory,
            realTimeErrors=True,
            workingDirectory=WORKING_DIR,
        ).run(self.server_suite)
        return server_result

    def suite_result(self, suite, result, **kwargs):
        return result


def test_with_trial(options, topdir, testdirs, testpaths):
    """The main testing entry point."""
    # hook twisted.python.log with standard logging
    from twisted.python import log

    observer = log.PythonLoggingObserver('twisted')
    observer.start()

    django.setup()

    runner = MagicicadaRunner(**options.__dict__)
    result = runner.run_tests(test_labels=(topdir, testdirs, testpaths))
    failed = not result.wasSuccessful()
    return failed
