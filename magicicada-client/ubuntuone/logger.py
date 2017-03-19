# ubuntuone.syncdaemon.logger - logging utilities
#
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
#
# Copyright 2010-2012 Canonical Ltd.
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
"""Ubuntuone client logging utilities and config. """

from __future__ import with_statement

import contextlib
import functools
import logging
import re
import sys
import weakref

from logging.handlers import TimedRotatingFileHandler


# extra levels
# be more verbose than logging.DEBUG(10)
TRACE = 5
# info that we almost always want to log (logging.ERROR - 1)
NOTE = logging.ERROR - 1

# map names to the extra levels
levels = {'TRACE': TRACE, 'NOTE': NOTE}
for k, v in levels.items():
    logging.addLevelName(v, k)


class Logger(logging.Logger):
    """Logger that support our custom levels."""

    def note(self, msg, *args, **kwargs):
        """log at NOTE level"""
        if self.isEnabledFor(NOTE):
            self._log(NOTE, msg, args, **kwargs)

    def trace(self, msg, *args, **kwargs):
        """log at TRACE level"""
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)


class DayRotatingFileHandler(TimedRotatingFileHandler):
    """A mix of TimedRotatingFileHandler and RotatingFileHandler configured for
    daily rotation but that uses the suffix and extMatch of Hourly rotation, in
    order to allow seconds based rotation on each startup.
    The log file is also rotated when the specified size is reached.
    """

    def __init__(self, *args, **kwargs):
        """ create the instance and override the suffix and extMatch.
        Also accepts a maxBytes keyword arg to rotate the file when it reachs
        maxBytes.
        """
        kwargs['when'] = 'D'
        kwargs['backupCount'] = LOGBACKUP
        # check if we are in 2.5, only for PQM
        if sys.version_info[:2] >= (2, 6):
            kwargs['delay'] = 1
        if 'maxBytes' in kwargs:
            self.maxBytes = kwargs.pop('maxBytes')
        else:
            self.maxBytes = 0
        TimedRotatingFileHandler.__init__(self, *args, **kwargs)
        # override suffix
        self.suffix = "%Y-%m-%d_%H-%M-%S"
        self.extMatch = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.

        Basically, see if TimedRotatingFileHandler.shouldRollover and if it's
        False see if the supplied record would cause the file to exceed
        the size limit we have.

        The size based rotation are from logging.handlers.RotatingFileHandler
        """
        if TimedRotatingFileHandler.shouldRollover(self, record):
            return 1
        else:
            # check the size
            if self.stream is None:                 # delay was set...
                self.stream = self._open()
            if self.maxBytes > 0:                   # are we rolling over?
                msg = "%s\n" % self.format(record)
                # due to non-posix-compliant Windows feature
                self.stream.seek(0, 2)
                if self.stream.tell() + len(msg) >= self.maxBytes:
                    return 1
            return 0


class MultiFilter(logging.Filter):
    """Our own logging.Filter.

    To allow filter by multiple names in a single handler or logger.

    """

    def __init__(self, names=None):
        logging.Filter.__init__(self)
        self.names = names or []
        self.filters = []
        for name in self.names:
            self.filters.append(logging.Filter(name))

    def filter(self, record):
        """Determine if the specified record is to be logged.

        This work a bit different from the standard logging.Filter, the
        record is logged if at least one filter allows it.
        If there are no filters, the record is allowed.

        """
        if not self.filters:
            # no filters, allow the record
            return True
        for f in self.filters:
            if f.filter(record):
                return True
        return False


class DebugCapture(logging.Handler):
    """
    A context manager to capture debug logs.
    """

    def __init__(self, logger, raise_unhandled=False, on_error=True):
        """Creates the instance.

        @param logger: the logger to wrap
        @param raise_unhandled: raise unhandled errors (which are alse logged)
        @param on_error: if it's True (default) the captured debug info is
        dumped if a record with log level >= ERROR is logged.
        """
        logging.Handler.__init__(self, logging.DEBUG)
        self.on_error = on_error
        self.dirty = False
        self.raise_unhandled = raise_unhandled
        self.records = []
        # insert myself as the handler for the logger
        self.logger = weakref.proxy(logger)
        # store the logger log level
        self.old_level = logger.level
        # remove us from the Handler list and dict
        self.close()

    def emit_debug(self):
        """emit stored records to the original logger handler(s)"""
        enable_debug = self.enable_debug
        for record in self.records:
            for slave in self.slaves:
                with enable_debug(slave):
                    slave.handle(record)

    @contextlib.contextmanager
    def enable_debug(self, obj):
        """context manager that temporarily changes the level attribute of obj
        to logging.DEBUG.
        """
        old_level = obj.level
        obj.level = logging.DEBUG
        yield obj
        obj.level = old_level

    def clear(self):
        """cleanup the captured records"""
        self.records = []

    def install(self):
        """Install the debug capture in the logger"""
        self.slaves = self.logger.handlers
        self.logger.handlers = [self]
        # set the logger level in DEBUG
        self.logger.setLevel(logging.DEBUG)

    def uninstall(self):
        """restore the logger original handlers"""
        # restore the logger
        self.logger.handlers = self.slaves
        self.logger.setLevel(self.old_level)
        self.clear()
        self.dirty = False
        self.slaves = []

    def emit(self, record):
        """A emit() that append the record to the record list"""
        self.records.append(record)

    def handle(self, record):
        """ handle a record """
        # if its a DEBUG level record then intercept otherwise
        # pass through to the original logger handler(s)
        if self.old_level <= logging.DEBUG:
            return sum(slave.handle(record) for slave in self.slaves)
        if record.levelno == logging.DEBUG:
            return logging.Handler.handle(self, record)
        elif (self.on_error and record.levelno >= logging.ERROR and
                record.levelno != NOTE):
            # if it's >= ERROR keep it, but mark the dirty falg
            self.dirty = True
            return logging.Handler.handle(self, record)
        else:
            return sum(slave.handle(record) for slave in self.slaves)

    def __enter__(self):
        """ContextManager API"""
        self.install()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """ContextManager API"""
        if exc_type is not None:
            self.emit_debug()
            self.on_error = False
            self.logger.error('unhandled exception',
                              exc_info=(exc_type, exc_value, traceback))
        elif self.dirty:
            # emit all debug messages collected after the error
            self.emit_debug()
        self.uninstall()
        if self.raise_unhandled and exc_type is not None:
            raise exc_type, exc_value, traceback
        else:
            return True


def log_call(log_func, with_args=True, with_result=True):
    """Decorator to add a log entry using 'log_func'.

    If not 'with_args', do not log arguments. Same apply to 'with_result'.

    An example of use would be:

    @log_call(logger.debug)
    def f(a, b, c):
        ....

    """

    def middle(f):
        """Add logging when calling 'f'."""

        @functools.wraps(f)
        def inner(*args, **kwargs):
            """Call f(*args, **kwargs)."""
            if with_args:
                a, kw = args, kwargs
            else:
                a, kw = '<hidden args>', '<hidden kwargs>'
            log_func('%s: args %r, kwargs %r.', f.__name__, a, kw)

            res = f(*args, **kwargs)

            if with_result:
                log_func('%s: result %r.', f.__name__, res)

            return res

        return inner

    return middle


# configure the thing #
LOGBACKUP = 5  # the number of log files to keep around

basic_formatter = logging.Formatter(
    fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
debug_formatter = logging.Formatter(
    fmt="%(asctime)s %(name)s %(module)s %(lineno)s %(funcName)s %(message)s")

# a constant to change the default DEBUG level value
_DEBUG_LOG_LEVEL = logging.DEBUG


# partial config of the handler to rotate when the file size is 1MB
CustomRotatingFileHandler = functools.partial(DayRotatingFileHandler,
                                              maxBytes=1048576)

# use our logger as the default Logger class
logging.setLoggerClass(Logger)
