# Copyright 2009-2012 Canonical Ltd.
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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
""" SyncDaemon logging utilities and config. """

from __future__ import with_statement

import logging
import sys
import os
import zlib

from ubuntuone.logger import (
    _DEBUG_LOG_LEVEL,
    basic_formatter,
    CustomRotatingFileHandler,
    DayRotatingFileHandler,
    Logger,
    MultiFilter,
)
from ubuntuone.platform.logger import ubuntuone_log_dir
# api compatibility imports
from ubuntuone import logger
from ubuntuone.platform import get_filesystem_logger, setup_filesystem_logging
DebugCapture = logger.DebugCapture
NOTE = logger.NOTE
TRACE = logger.TRACE


class mklog(object):
    """
    Create a logger that keeps track of the method where it's being
    called from, in order to make more informative messages.
    """
    __slots__ = ('logger', 'zipped_desc')

    def __init__(self, _logger, _method, _share, _uid, *args, **kwargs):
        # args are _-prepended to lower the chances of them
        # conflicting with kwargs

        all_args = []
        for arg in args:
            all_args.append(
                repr(arg).decode('ascii', 'replace').encode('ascii', 'replace')
            )
        for k, v in kwargs.items():
            v = repr(v).decode('ascii', 'replace').encode('ascii', 'replace')
            all_args.append("%s=%r" % (k, v))
        args = ", ".join(all_args)

        desc = "%-28s share:%-40r node:%-40r %s(%s) " % (_method, _share,
                                                         _uid, _method, args)
        desc = desc.replace('%', '%%')
        self.zipped_desc = zlib.compress(desc, 9)
        self.logger = _logger

    def _log(self, logger_func, *args):
        """Generalized form of the different logging methods."""
        desc = zlib.decompress(self.zipped_desc)
        text = desc + args[0]
        logger_func(text, *args[1:])

    def debug(self, *args):
        """Log at level DEBUG"""
        self._log(self.logger.debug, *args)

    def info(self, *args):
        """Log at level INFO"""
        self._log(self.logger.info, *args)

    def warn(self, *args):
        """Log at level WARN"""
        self._log(self.logger.warn, *args)

    def error(self, *args):
        """Log at level ERROR"""
        self._log(self.logger.error, *args)

    def exception(self, *args):
        """Log an exception"""
        self._log(self.logger.exception, *args)

    def note(self, *args):
        """Log at NOTE level (high-priority info) """
        self._log(self.logger.high, *args)

    def trace(self, *args):
        """Log at level TRACE"""
        self._log(self.logger.trace, *args)

    def callbacks(self, success_message='success', success_arg='',
                  failure_message='failure'):
        """
        Return a callback and an errback that log success or failure
        messages.

        The callback/errback pair are pass-throughs; they don't
        interfere in the callback/errback chain of the deferred you
        add them to.
        """
        def callback(arg, success_arg=success_arg):
            "it worked!"
            if callable(success_arg):
                success_arg = success_arg(arg)
            self.debug(success_message, success_arg)
            return arg

        def errback(failure):
            "it failed!"
            self.error(failure_message, failure.getErrorMessage())
            self.debug('traceback follows:\n\n' + failure.getTraceback(), '')
            return failure
        return callback, errback

LOGFILENAME = os.path.join(ubuntuone_log_dir, 'syncdaemon.log')
EXLOGFILENAME = os.path.join(ubuntuone_log_dir, 'syncdaemon-exceptions.log')
INVALIDLOGFILENAME = os.path.join(
    ubuntuone_log_dir, 'syncdaemon-invalid-names.log')
BROKENLOGFILENAME = os.path.join(
    ubuntuone_log_dir, 'syncdaemon-broken-nodes.log')


root_logger = logging.getLogger("ubuntuone.SyncDaemon")
twisted_logger = logging.getLogger('twisted')

filesystem_logger = get_filesystem_logger()
# now restore our custom logger class
logging.setLoggerClass(Logger)

root_handler = CustomRotatingFileHandler(filename=LOGFILENAME)
exception_handler = CustomRotatingFileHandler(filename=EXLOGFILENAME)


def init():
    # root logger
    root_logger.propagate = False
    root_logger.setLevel(_DEBUG_LOG_LEVEL)
    root_handler.addFilter(MultiFilter(['ubuntuone.SyncDaemon',
                                        'twisted', 'pyinotify']))
    root_handler.setFormatter(basic_formatter)
    root_handler.setLevel(_DEBUG_LOG_LEVEL)
    root_logger.addHandler(root_handler)
    # exception logs
    exception_handler.setFormatter(basic_formatter)
    exception_handler.setLevel(logging.ERROR)
    # add the exception handler to the root logger
    logging.getLogger('').addHandler(exception_handler)
    root_logger.addHandler(exception_handler)

    # hook twisted.python.log with standard logging
    from twisted.python import log
    observer = log.PythonLoggingObserver('twisted')
    observer.start()
    # configure the logger to only show errors
    twisted_logger.propagate = False
    twisted_logger.setLevel(logging.ERROR)
    twisted_logger.addHandler(root_handler)
    twisted_logger.addHandler(exception_handler)

    # set the filesystem logging
    setup_filesystem_logging(filesystem_logger, root_handler)

    # invalid filenames log
    invnames_logger = logging.getLogger("ubuntuone.SyncDaemon.InvalidNames")
    invnames_logger.setLevel(_DEBUG_LOG_LEVEL)
    invnames_handler = CustomRotatingFileHandler(filename=INVALIDLOGFILENAME)
    invnames_handler.setFormatter(basic_formatter)
    invnames_handler.setLevel(logging.INFO)
    invnames_logger.addHandler(invnames_handler)

    # broken nodes log
    brokennodes_logger = logging.getLogger("ubuntuone.SyncDaemon.BrokenNodes")
    brokennodes_logger.setLevel(_DEBUG_LOG_LEVEL)
    brokennodes_handler = CustomRotatingFileHandler(filename=BROKENLOGFILENAME)
    brokennodes_handler.setFormatter(basic_formatter)
    brokennodes_handler.setLevel(logging.INFO)
    brokennodes_logger.addHandler(brokennodes_handler)


def configure_logging(level, maxBytes, backupCount):
    """configure level, maxBytes and backupCount in all handlers"""
    set_level(level)
    set_max_bytes(maxBytes)
    set_backup_count(backupCount)


def set_level(level):
    """set 'level' as the level for all the logger/handlers"""
    root_logger.setLevel(level)
    root_handler.setLevel(level)


def set_max_bytes(size):
    """set the maxBytes value in all the handlers"""
    root_handler.maxBytes = size
    exception_handler.maxBytes = size


def set_backup_count(count):
    """set the backup count in all the handlers"""
    root_handler.backupCount = count
    exception_handler.backupCount = count


def set_debug(dest):
    """ Set the level to debug of all registered loggers, and replace their
    handlers. if debug_level is file, syncdaemon-debug.log is used. If it's
    stdout, all the logging is redirected to stdout. If it's stderr, to stderr.

    @param dest: a string with a one or more of 'file', 'stdout', and 'stderr'
                 e.g. 'file stdout'
    """
    if not [v for v in ['file', 'stdout', 'stderr'] if v in dest]:
        # invalid dest value, let the loggers alone
        return
    sd_filter = MultiFilter(['ubuntuone.SyncDaemon', 'twisted', 'pyinotify'])
    if 'file' in dest:
        # setup the existing loggers in debug
        root_handler.setLevel(_DEBUG_LOG_LEVEL)
        logfile = os.path.join(ubuntuone_log_dir, 'syncdaemon-debug.log')
        root_handler.baseFilename = os.path.abspath(logfile)
        # don't cap the file size
        set_max_bytes(0)
    for name in ['ubuntuone.SyncDaemon', 'twisted']:
        logger = logging.getLogger(name)
        logger.setLevel(_DEBUG_LOG_LEVEL)
        if 'stderr' in dest:
            stderr_handler = logging.StreamHandler()
            stderr_handler.setFormatter(basic_formatter)
            stderr_handler.setLevel(_DEBUG_LOG_LEVEL)
            stderr_handler.addFilter(sd_filter)
            logger.addHandler(stderr_handler)
        if 'stdout' in dest:
            stdout_handler = logging.StreamHandler(sys.stdout)
            stdout_handler.setFormatter(basic_formatter)
            stdout_handler.setLevel(_DEBUG_LOG_LEVEL)
            stdout_handler.addFilter(sd_filter)
            logger.addHandler(stdout_handler)


def set_server_debug(dest):
    """ Set the level to debug of all registered loggers, and replace their
    handlers. if debug_level is file, syncdaemon-debug.log is used. If it's
    stdout, all the logging is redirected to stdout.

    @param dest: a string containing 'file' and/or 'stdout', e.g: 'file stdout'
    """
    logger = logging.getLogger("storage.server")
    logger.setLevel(5)  # this shows server messages
    if 'file' in dest:
        filename = os.path.join(ubuntuone_log_dir, 'syncdaemon-debug.log')
        handler = DayRotatingFileHandler(filename=filename)
        handler.setFormatter(basic_formatter)
        handler.setLevel(5)  # this shows server messages
        logger.addHandler(handler)
    if 'stdout' in dest:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(basic_formatter)
        stdout_handler.setLevel(5)  # this shows server messages
        logger.addHandler(stdout_handler)
    if 'stderrt' in dest:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(basic_formatter)
        stdout_handler.setLevel(5)  # this shows server messages
        logger.addHandler(stdout_handler)


# if we are in debug mode, replace/add the handlers
DEBUG = os.environ.get("MAGICICADA_DEBUG", None)
if DEBUG:
    set_debug(DEBUG)

# configure server logging if SERVER_DEBUG != None
SERVER_DEBUG = os.environ.get("SERVER_DEBUG", None)
if SERVER_DEBUG:
    set_server_debug(SERVER_DEBUG)


def rotate_logs():
    """do a rollover of the three handlers"""
    # ignore the missing file error on a failed rollover
    try:
        root_handler.doRollover()
    except OSError:
        pass
    try:
        exception_handler.doRollover()
    except OSError:
        pass
