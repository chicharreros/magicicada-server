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

"""Manage database connections and stores to the storage database."""

from __future__ import unicode_literals

import logging
import math
import random
import sys
import time

from functools import wraps

from django.core.exceptions import ObjectDoesNotExist
from django.db import InternalError, transaction


logger = logging.getLogger(__name__)
_run_on_rollback = []


def on_rollback(func):
    _run_on_rollback.append(func)


class Atomic(transaction.Atomic):

    def run_and_clear_rollback_hooks(self):
        global _run_on_rollback
        try:
            while True:
                func = _run_on_rollback.pop(0)
                func()
        except IndexError:
            pass
        finally:
            _run_on_rollback = []

    def __exit__(self, exc_type, exc_value, traceback):
        result = super(Atomic, self).__exit__(exc_type, exc_value, traceback)
        if exc_type is not None:
            self.run_and_clear_rollback_hooks()
        return result


def atomic(using=None, savepoint=True):
    # Bare decorator: @atomic -- although the first argument is called
    # `using`, it's actually the function being decorated.
    if callable(using):
        return Atomic(transaction.DEFAULT_DB_ALIAS, savepoint)(using)
    # Decorator: @atomic(...) or context manager: with atomic(...): ...
    else:
        return Atomic(using, savepoint)


fsync_commit = atomic
fsync_readonly = atomic
fsync_readonly_slave = atomic


class RetryLimitReached(Exception):
    """Raised when there have been to many retries."""

    def __init__(self, msg, extra_info=None):
        super(RetryLimitReached, self).__init__(msg)
        self.extra_info = extra_info


def retryable_transaction(max_time=4.0, max_retries=3, variance=0.5,
                          exceptions=(InternalError,)):
    """Make sure that transactions are retried after conflicts.

    This function builds a decorator to be used.
    """
    # XXX("lucio.torre", "we need to measure here to find reasonable " \
    #                    "default parameters for this")
    def inner(function):
        """The actual decorator"""
        # we need to define scale so that it makes delay_time never add
        # to more than max_time given max_retries
        scale = 1
        _variance = 0

        def delay_time(step):
            """generates a delay for each step"""
            # delay_time(0) == 0
            return (((math.exp(step) - 1) / scale) /
                    (1 + random.random() * _variance))

        total_time = sum(delay_time(i) for i in range(max_retries))
        _variance = variance
        scale = total_time / max_time

        @wraps(function)
        def decorated(*args, **kwargs):
            """the new decorated function"""
            count = 0
            while True:
                time.sleep(delay_time(count))
                try:
                    value = function(*args, **kwargs)
                except exceptions, e:
                    info = sys.exc_info()
                    try:
                        if isinstance(e, InternalError):
                            logger.exception(
                                "Got an InternalError, retrying. (count: %s, "
                                "max_retries: %s)", count, max_retries)
                        count += 1
                        if count >= max_retries:
                            # include the original error name in the new
                            # exception
                            msg = ("Maximum retries (%i) reached. "
                                   "Please try again. (Original error: %s: %s)"
                                   % (count, e.__class__.__name__, e))
                            # and add the detailed error as extra_info
                            extra = "%s: %s" % (e.__class__.__name__, str(e))

                            class RetryLimitExceeded(RetryLimitReached,
                                                     info[0]):
                                """A dynamic exception type which preserves
                                the original type as well."""

                            raise RetryLimitExceeded(msg, extra_info=extra)
                    finally:
                        # We clear this variable to avoid creating a
                        # reference cycle between traceback and this
                        # frame.
                        info = None
                else:
                    break
            return value
        return decorated
    return inner


def get_object_or_none(qs, *args, **kwargs):
    qs = getattr(qs, 'objects', qs)
    try:
        result = qs.get(*args, **kwargs)
    except ObjectDoesNotExist:
        result = None
    return result
