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

"""TestCases for testing."""

import logging

from collections import defaultdict

from django.test import TransactionTestCase
from django.test.client import RequestFactory

from magicicada import settings
from magicicada.testing.factory import Factory


class MementoHandler(logging.Handler):
    """A handler class which store logging records in a list."""

    def __init__(self, *args, **kwargs):
        """Create the instance, and add a records attribute."""
        logging.Handler.__init__(self, *args, **kwargs)
        self.records = []
        self.records_by_level = defaultdict(list)

    def emit(self, record):
        """ Just add the record to self.records. """
        self.format(record)
        self.records.append(record)
        self.records_by_level[record.levelno].append(record)

    def reset(self):
        self.records = []
        self.records_by_level = defaultdict(list)

    def dump_records(self):
        """Dumps the contents of the MementoHandler."""
        print("MementoHandler records:")
        for rec in self.records:
            print("\t", rec.exc_info)
            print("\t", logging.getLevelName(rec.levelno))
            print("\t\t", rec.message)
            print("\t\t", rec.exc_text)

    def message_in_record(self, message, record, exc_info=None):
        result = message in record.getMessage()
        if not result and record.exc_text:
            result = message in record.exc_text
        if exc_info is not None:
            result = result and exc_info in record.exc_info
        return result

    def check(self, level, msgs, exc_info=None):
        """Verifies that the msgs are logged in the specified level"""
        missing = []
        result = None
        for m in msgs:
            for rec in self.records_by_level[level]:
                if self.message_in_record(m, rec, exc_info=exc_info):
                    result = rec
                    break
            else:
                missing.append(m)
        if missing:
            error = ('Missing logging messsages for level %s:\n\n%s\n\n'
                     'Existing records:\n\n%s')
            missing = '\n'.join(missing)
            current = '\n'.join(
                r.getMessage() for r in self.records_by_level[level])
            raise AssertionError(error % (level, missing, current))

        return result

    def assert_trace(self, *msgs):
        """Shortcut for checking in TRACE."""
        return self.check(settings.TRACE, msgs)

    def assert_debug(self, *msgs):
        """Shortcut for checking in DEBUG."""
        return self.check(logging.DEBUG, msgs)

    def assert_info(self, *msgs):
        """Shortcut for checking in INFO."""
        return self.check(logging.INFO, msgs)

    def assert_warning(self, *msgs):
        """Shortcut for checking in WARNING."""
        return self.check(logging.WARNING, msgs)

    def assert_error(self, *msgs):
        """Shortcut for checking in ERROR."""
        return self.check(logging.ERROR, msgs)

    def assert_critical(self, *msgs):
        """Shortcut for checking in CRITICAL."""
        return self.check(logging.CRITICAL, msgs)

    def assert_exception(self, exc_info, *msgs):
        """Shortcut for checking exceptions."""
        return self.check(logging.ERROR, msgs, exc_info=exc_info)

    def assert_not_logged(self, *msgs):
        error = 'Message %r should not be logged (found %r).'
        for m in msgs:
            for rec in self.records:
                if self.message_in_record(m, rec):
                    raise AssertionError(error % (m, rec))


class BaseTestCase(TransactionTestCase):
    """Base TestCase: provides a Factory and a RequestFactory."""

    request_factory = RequestFactory()
    factory = Factory()
    maxDiff = None

    def patch(self, obj, attr_name, new_val):
        """Patch!"""
        old_val = getattr(obj, attr_name)
        setattr(obj, attr_name, new_val)
        self.addCleanup(setattr, obj, attr_name, old_val)

    def add_memento_handler(self, logger, level=None):
        result = MementoHandler()
        if level is not None:
            result.setLevel(level)
            original = logger.level
            logger.setLevel(level)
            self.addCleanup(logger.setLevel, original)
        logger.addHandler(result)
        self.addCleanup(logger.removeHandler, result)
        return result
