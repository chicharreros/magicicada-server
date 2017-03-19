# ubuntuone.syncdaemon.config - SyncDaemon config utilities
#
# Copyright 2009-2012 Canonical Ltd.
# Copyright 2017 Chicharreros (https://launchpad.net/~chicharreros)
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
"""SyncDaemon config"""

from __future__ import with_statement

import os
import functools
import logging

from ConfigParser import NoOptionError, NoSectionError
from optparse import OptionParser
from dirspec.basedir import (
    load_config_paths,
    save_config_path,
    xdg_data_home,
    xdg_cache_home,
)
from dirspec.utils import unicode_path

from ubuntuone.platform import expand_user

# the try/except is to work with older versions of configglue (that
# had everything that is now configglue.inischema.* as configglue.*).
# The naming shenanigans are to work around pyflakes being completely
# stupid WRT people catching ImportErrors
normoptname = None
try:
    from configglue.glue import normoptname as old_normoptname
    from configglue import TypedConfigParser as old_tcp
except ImportError:
    from configglue.inischema import TypedConfigParser as new_tcp

    def normoptname(_, section, option):
        if section == "__main__":
            return option
        return section + "_" + option

if normoptname is None:
    normoptname = old_normoptname
    TypedConfigParser = old_tcp
    del old_normoptname, old_tcp
else:
    TypedConfigParser = new_tcp
    del new_tcp
# end of naming shenanigans

CONFIG_FILE = 'syncdaemon.conf'
CONFIG_LOGS = 'logging.conf'

# sections
THROTTLING = 'bandwidth_throttling'
MAIN = '__main__'

# global logger
logger = logging.getLogger('ubuntuone.SyncDaemon.config')

# get (and possibly create if don't exists) the user config file
_user_config_path = os.path.join(save_config_path('ubuntuone'),
                                 CONFIG_FILE)

# module private config instance.
# this object is the shared config
_user_config = None


def path_from_unix(path):
    return path.replace('/', os.path.sep)


def home_dir_parser(value):
    """Parser for the root_dir and shares_dir options.

    Return the path using user home + value.

    """
    path = path_from_unix(value)
    result = expand_user(path)
    assert isinstance(result, str)
    return result


def xdg_cache_dir_parser(value):
    """Parser for the data_dir option.

    Return the path using xdg_cache_home + value.

    """
    result = os.path.join(xdg_cache_home, path_from_unix(value))
    assert isinstance(result, str)
    return result


def xdg_data_dir_parser(value):
    """Parser for the data_dir option.

    Return the path using xdg_data_home + value.

    """
    result = os.path.join(xdg_data_home, path_from_unix(value))
    assert isinstance(result, str)
    return result


def server_connection_parser(value):
    """Parser for the server connection info."""
    results = []
    for item in value.split(","):
        ci_parts = item.split(':')
        if len(ci_parts) == 2:
            host, port = ci_parts
            mode = 'ssl'  # default
        elif len(ci_parts) == 3:
            host, port, mode = ci_parts
        else:
            raise ValueError(
                "--server info must be HOST:PORT or HOST:PORT:SSL_MODE")

        if mode == 'plain':
            use_ssl = False
            disable_ssl_verify = False
        elif mode == 'ssl':
            use_ssl = True
            disable_ssl_verify = False
        elif mode == 'ssl_noverify':
            use_ssl = True
            disable_ssl_verify = True
        else:
            raise ValueError(
                "--server form (HOST:PORT:SSL_MODE) accepts the following"
                "SSL_MODE options only: 'plain', 'ssl', 'ssl_noverify'")
        results.append({
            'host': host,
            'port': int(port),
            'use_ssl': use_ssl,
            'disable_ssl_verify': disable_ssl_verify,
        })
    return results


def log_level_parser(value):
    """Parser for "logging" module log levels.

    The logging API sucks big time, the only way to trustworthy find if the
    log level is defined is to check the private attribute.
    """
    try:
        level = logging._levelNames[value]
    except KeyError:
        # if level don't exists in our custom levels, fallback to DEBUG
        level = logging.DEBUG
    return level


def throttling_limit_parser(value):
    """parser for throttling limit values, if value <= 0 returns None"""
    value = int(value)
    if value <= 0:
        return None
    else:
        return value


def get_parsers():
    """returns a list of tuples: (name, parser)"""
    return [('home_dir', home_dir_parser),
            ('xdg_cache', xdg_cache_dir_parser),
            ('xdg_data', xdg_data_dir_parser),
            ('log_level', log_level_parser),
            ('connection', server_connection_parser),
            ('throttling_limit', throttling_limit_parser)]


def get_config_files():
    """ return the path to the config files or and empty list.
    The search path is based on the paths returned by load_config_paths
    but it's returned in reverse order (e.g: /etc/xdg first).
    """
    config_files = []
    for xdg_config_dir in load_config_paths('ubuntuone'):
        xdg_config_dir = unicode_path(xdg_config_dir)
        config_file = os.path.join(xdg_config_dir, CONFIG_FILE)
        if os.path.exists(config_file):
            config_files.append(config_file)

        config_logs = os.path.join(xdg_config_dir, CONFIG_LOGS)
        if os.path.exists(config_logs):
            config_files.append(config_logs)

    # reverse the list as load_config_paths returns the user dir first
    config_files.reverse()
    # if we are running from a branch, get the config files from it too
    config_file = os.path.join(os.path.dirname(__file__), os.path.pardir,
                               os.path.pardir, 'data', CONFIG_FILE)
    if os.path.exists(config_file):
        config_files.append(config_file)

    config_logs = os.path.join(os.path.dirname(__file__), os.path.pardir,
                               os.path.pardir, 'data', CONFIG_LOGS)
    if os.path.exists(config_logs):
        config_files.append(config_logs)

    return config_files


def get_user_config(config_file=_user_config_path, config_files=None):
    """return the shared _Config instance"""
    global _user_config
    if _user_config is None:
        _user_config = _Config(config_file, config_files)
    return _user_config


def requires_section(section):
    """decorator to enforce the existence of a section in the config."""
    def wrapper(meth):
        """the wrapper"""
        def wrapped(self, *args, **kwargs):
            """the real thing, wrap the method and do the job"""
            if not self.has_section(section):
                self.add_section(section)
            return meth(self, *args, **kwargs)
        functools.update_wrapper(wrapped, meth)
        return wrapped
    return wrapper


class SyncDaemonConfigParser(TypedConfigParser):
    """Custom TypedConfigParser with upgrade support and syncdaemon parsers."""

    def __init__(self, *args, **kwargs):
        super(SyncDaemonConfigParser, self).__init__(*args, **kwargs)
        self.upgrade_hooks = {}
        for name, parser in get_parsers():
            self.add_parser(name, parser)
        self.add_upgrade_hook(MAIN, 'log_level', upgrade_log_level)

    def add_upgrade_hook(self, section, option, func):
        """Add an upgrade hook for (section, option)"""
        if (section, option) in self.upgrade_hooks:
            raise ValueError('An upgrade hook for %s, %s already exists' %
                             (section, option))
        self.upgrade_hooks[(section, option)] = func

    def parse_all(self):
        """Override default parse_all() and call upgrade_all() after it"""
        super(SyncDaemonConfigParser, self).parse_all()
        self.upgrade_all()

    def upgrade_all(self):
        """Iterate over all upgrade_hooks and execute them."""
        for section, option in self.upgrade_hooks:
            if self.has_option(section, option):
                self.upgrade_hooks[(section, option)](self)


def upgrade_log_level(cp):
    """upgrade log_level to logging-level option"""
    if not cp.has_option('logging', 'level'):
        # an old default config, someone changed it
        # just replace the setting
        old = cp.get(MAIN, 'log_level')
        cp.set('logging', 'level', old)
    else:
        current = cp.get('logging', 'level')
        parser = current.parser
        old = cp.get(MAIN, 'log_level')
        if isinstance(old.value, basestring):
            # wasn't parsed
            old.value = parser(old.value)
        if parser(current.attrs['default']) == current.value:
            # override the default in the new setting
            current.value = old.value
            cp.set('logging', 'level', current)
    # else, we ignore the setting as we have a non-default
    # value in logging-level (newer setting wins)
    logger.warning("Found deprecated config option 'log_level'"
                   " in section: MAIN")
    cp.remove_option(MAIN, 'log_level')


class _Config(SyncDaemonConfigParser):
    """Minimal config object to read/write config values
    from/to the user config file.
    Most of the methods in this class aren't thread-safe.

    Only supports bandwidth throttling options.

    Ideally TypedConfigParser should implement a write method that converts
    from configglue.attributed.ValueWithAttrs back to str in order to take
    advantage of all the nice tricks of configglue.
    """

    def __init__(self, config_file=_user_config_path, config_files=None):
        """Create the instance, add our custom parsers and
        read the config file
        """
        super(_Config, self).__init__()
        self.config_file = config_file
        self.read(config_file)
        # create and fill the default typed config
        self.default = self._load_defaults(config_files)
        # create the overridden typed config
        self.overridden = SyncDaemonConfigParser()
        self.overridden.parse_all()

    @staticmethod
    def _load_defaults(config_files):
        """load typed defaults from config_files"""
        cp = SyncDaemonConfigParser()
        if config_files is None:
            config_files = get_config_files()
        cp.read(config_files)
        cp.parse_all()
        return cp

    def save(self):
        """Save the config object to disk"""
        # We should not use standard functions from os_helper here,
        # because the configglue superclasses do not use them.
        # Instead, all paths used in this module should be "native",
        # that is: utf-8 str on linux, or (unicode or mbcs str) on windows
        from ubuntuone.platform import native_rename

        # cleanup empty sections
        for section in [MAIN, THROTTLING]:
            if self.has_section(section) and not self.options(section):
                self.remove_section(section)
        with open(self.config_file + '.new', 'w') as fp:
            self.write(fp)
        if os.path.exists(self.config_file):
            native_rename(self.config_file, self.config_file + '.old')
        native_rename(self.config_file + '.new', self.config_file)

    def get_parsed(self, section, option):
        """get that fallbacks to our custom defaults"""
        try:
            return self.overridden.get(section, option).value
        except (NoOptionError, NoSectionError):
            try:
                value = super(_Config, self).get(section, option)
                # get the parser from the default config
                default = self.default.get(section, option)
                return default.parser(value)
            except NoOptionError:
                return self.default.get(section, option).value

    def override_options(self, overridden_options):
        """Merge in the values provided by the options object, into
        self.overridden TypedConfigParser.
        This override the default and user configured values only if the values
        are != to the default ones. These 'overriden' values are not saved
        to user config file.
        """
        for section, optname, value in overridden_options:
            if section not in self.overridden.sections():
                self.overridden.add_section(section)
            self.overridden.set(section, optname, value)
        self.overridden.parse_all()

    # throttling section get/set
    @requires_section(THROTTLING)
    def set_throttling(self, enabled):
        self.set(THROTTLING, 'on', str(enabled))

    @requires_section(THROTTLING)
    def set_throttling_read_limit(self, bytes):
        self.set(THROTTLING, 'read_limit', bytes)

    @requires_section(THROTTLING)
    def set_throttling_write_limit(self, bytes):
        self.set(THROTTLING, 'write_limit', bytes)

    @requires_section(THROTTLING)
    def get_throttling(self):
        return self.get_parsed(THROTTLING, 'on')

    @requires_section(THROTTLING)
    def get_throttling_read_limit(self):
        return self.get_parsed(THROTTLING, 'read_limit')

    @requires_section(THROTTLING)
    def get_throttling_write_limit(self):
        return self.get_parsed(THROTTLING, 'write_limit')

    @requires_section(MAIN)
    def set_udf_autosubscribe(self, enabled):
        self.set(MAIN, 'udf_autosubscribe', str(enabled))

    @requires_section(MAIN)
    def get_udf_autosubscribe(self):
        return self.get_parsed(MAIN, 'udf_autosubscribe')

    @requires_section(MAIN)
    def set_share_autosubscribe(self, enabled):
        self.set(MAIN, 'share_autosubscribe', str(enabled))

    @requires_section(MAIN)
    def get_share_autosubscribe(self):
        return self.get_parsed(MAIN, 'share_autosubscribe')

    # files sync enablement get/set
    @requires_section(MAIN)
    def set_files_sync_enabled(self, enabled):
        self.set(MAIN, 'files_sync_enabled', str(enabled))

    @requires_section(MAIN)
    def get_files_sync_enabled(self):
        return self.get_parsed(MAIN, 'files_sync_enabled')

    @requires_section(MAIN)
    def set_autoconnect(self, enabled):
        self.set(MAIN, 'autoconnect', str(enabled))

    @requires_section(MAIN)
    def get_autoconnect(self):
        return self.get_parsed(MAIN, 'autoconnect')

    @requires_section(MAIN)
    def get_use_trash(self):
        return self.get_parsed(MAIN, 'use_trash')

    @requires_section(MAIN)
    def set_use_trash(self, enabled):
        self.set(MAIN, 'use_trash', str(enabled))

    @requires_section(MAIN)
    def get_simult_transfers(self):
        """Get the simultaneous transfers value."""
        return self.get_parsed(MAIN, 'simult_transfers')

    @requires_section(MAIN)
    def set_simult_transfers(self, value):
        """Set the simultaneous transfers value."""
        self.set(MAIN, 'simult_transfers', str(value))

    @requires_section(MAIN)
    def get_max_payload_size(self):
        """Get the maximum payload size."""
        return self.get_parsed(MAIN, 'max_payload_size')

    @requires_section(MAIN)
    def set_max_payload_size(self, value):
        """Set the maximum payload size."""
        self.set(MAIN, 'max_payload_size', str(value))

    @requires_section(MAIN)
    def get_memory_pool_limit(self):
        """Get the memory pool limit."""
        return self.get_parsed(MAIN, 'memory_pool_limit')

    @requires_section(MAIN)
    def set_memory_pool_limit(self, value):
        """Set the memory pool limit."""
        self.set(MAIN, 'memory_pool_limit', str(value))


def configglue(fileobj, *filenames, **kwargs):
    """Populate an OptionParser with options and defaults taken from a
    series of files.

    @param fileobj: An INI file, as a file-like object.
    @param filenames: An optional series of filenames to merge.
    @param kwargs: options passed on to the OptionParser constructor except for
    @param args: parse these args (defaults to sys.argv[1:])
    """
    cp = SyncDaemonConfigParser()
    cp.readfp(fileobj)
    cp.read(filenames)
    cp.parse_all()

    args = kwargs.pop('args', None)

    op = OptionParser(**kwargs)

    for section in cp.sections():
        if section == MAIN:
            og = op
            tpl = '--%(option)s'
        else:
            og = op.add_option_group(section)
            tpl = '--%(section)s-%(option)s'
        for optname in cp.options(section):
            option = cp.get(section, optname)
            if 'help' in option.attrs:
                option.attrs['help'] %= option.attrs
            if option.is_empty:
                default = None
            else:
                default = option.value
            og.add_option(tpl % {'section': section.lower(),
                                 'option': optname.lower()},
                          **dict(option.attrs, default=default))

    options, args = op.parse_args(args)

    overridden = []
    for section in cp.sections():
        for optname, optval in cp.items(section):
            normopt = normoptname(cp, section, optname)
            value = getattr(options, normopt)
            if optval.value != value:
                # the value has been overridden by an argument;
                # re-parse it.
                setattr(options, normopt, optval.parser(value))
                overridden.append((section, optname, value))

    config_files = [fileobj.name] + list(filenames)
    config = get_user_config(config_files=config_files)
    config.override_options(overridden)
    return op, options, args
