# encoding: utf-8
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
"""Tests for the syncdaemon config module."""

from __future__ import with_statement

import logging
import os

from ConfigParser import ConfigParser
from twisted.internet import defer
from twisted.trial.unittest import TestCase
from dirspec.basedir import (
    xdg_data_home,
    xdg_cache_home,
)

from contrib.testing.testcase import BaseTwistedTestCase
from ubuntuone import platform
from ubuntuone.platform import open_file, path_exists
from ubuntuone.syncdaemon import config


class TestConfigBasic(BaseTwistedTestCase):
    """Basic _Config object tests."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TestConfigBasic, self).setUp()
        self.test_root = self.mktemp()

    def assertThrottlingSection(self, expected, current, on, read, write):
        """Assert equality for two ConfigParser."""
        self.assertEqual(expected.getboolean(config.THROTTLING, 'on'), on)
        self.assertEqual(
            expected.getint(config.THROTTLING, 'read_limit'), read)
        self.assertEqual(
            expected.getint(config.THROTTLING, 'write_limit'), write)
        self.assertEqual(expected.getboolean(config.THROTTLING, 'on'),
                         current.get_throttling())
        self.assertEqual(expected.getint(config.THROTTLING, 'read_limit'),
                         current.get_throttling_read_limit())
        self.assertEqual(expected.getint(config.THROTTLING, 'write_limit'),
                         current.get_throttling_write_limit())

    def test_load_empty(self):
        """Test loading the a non-existent config file."""
        conf_file = os.path.join(self.test_root, 'test_missing_config.conf')
        # create the config object with an empty config file
        conf = config._Config(conf_file)
        self.assertEqual(False, conf.get_throttling())
        self.assertEqual(2097152, conf.get_throttling_read_limit())
        self.assertEqual(2097152, conf.get_throttling_write_limit())

    def test_load_basic(self):
        """Test loading the config file with only the throttling values."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = 1000\n')
            fp.write('write_limit = 200\n')
        conf = config._Config(conf_file)
        self.assertEqual(True, conf.get_throttling())
        self.assertEqual(1000, conf.get_throttling_read_limit())
        self.assertEqual(200, conf.get_throttling_write_limit())

    def test_load_extra_data(self):
        """Test loading the a config file with other sections too."""
        conf_file = os.path.join(self.test_root, 'test_load_extra_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('log_level = INFO\n')
            fp.write('disable_ssl_verify = True\n')
            fp.write('\n')
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = 1000\n')
            fp.write('write_limit = 200\n')
        conf = config._Config(conf_file)
        self.assertEqual(True, conf.get_throttling())
        self.assertEqual(1000, conf.get_throttling_read_limit())
        self.assertEqual(200, conf.get_throttling_write_limit())

    def test_write_new(self):
        """Test writing the throttling section to a new config file."""
        conf_file = os.path.join(self.test_root, 'test_write_new_config.conf')
        self.assertFalse(path_exists(conf_file))
        conf = config._Config(conf_file)
        conf.set_throttling(True)
        conf.set_throttling_read_limit(1000)
        conf.set_throttling_write_limit(100)
        conf.save()
        # load the config in a barebone ConfigParser and check
        conf_1 = ConfigParser()
        conf_1.read(conf_file)
        self.assertThrottlingSection(conf_1, conf, True, 1000, 100)

    def test_write_existing(self):
        """Test writing the throttling section to a existing config file."""
        conf_file = os.path.join(self.test_root,
                                 'test_write_existing_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = False\n')
            fp.write('read_limit = 1000\n')
            fp.write('write_limit = 100\n')
        self.assertTrue(path_exists(conf_file))
        conf = config._Config(conf_file)
        conf.set_throttling(True)
        conf.set_throttling_read_limit(2000)
        conf.set_throttling_write_limit(200)
        conf.save()
        # load the config in a barebone ConfigParser and check
        conf_1 = ConfigParser()
        conf_1.read(conf_file)
        self.assertThrottlingSection(conf_1, conf, True, 2000, 200)

    def test_write_extra(self):
        """Writing the throttling back to the file, with extra sections."""
        conf_file = os.path.join(
            self.test_root, 'test_write_extra_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('log_level = INFO\n')
            fp.write('disable_ssl_verify = True\n')
            fp.write('\n')
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = False\n')
            fp.write('read_limit = 2000\n')
            fp.write('write_limit = 200\n')
        self.assertTrue(path_exists(conf_file))
        conf = config._Config(conf_file)
        conf.set_throttling(True)
        conf.set_throttling_read_limit(3000)
        conf.set_throttling_write_limit(300)
        conf.save()
        # load the config in a barebone ConfigParser and check
        conf_1 = ConfigParser()
        conf_1.read(conf_file)
        self.assertThrottlingSection(conf_1, conf, True, 3000, 300)
        self.assertEqual(conf_1.get('__main__', 'log_level'),
                         conf.get('__main__', 'log_level'))
        self.assertEqual(conf_1.getboolean('__main__', 'disable_ssl_verify'),
                         conf.getboolean('__main__', 'disable_ssl_verify'))

    def test_write_existing_partial(self):
        """Writing a partially updated throttling section to existing file."""
        conf_file = os.path.join(self.test_root,
                                 'test_write_existing_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = 1000\n')
            fp.write('write_limit = 100\n')
        self.assertTrue(path_exists(conf_file))
        conf = config._Config(conf_file)
        conf.set_throttling(False)
        conf.save()
        # load the config in a barebone ConfigParser and check
        conf_1 = ConfigParser()
        conf_1.read(conf_file)
        self.assertThrottlingSection(conf_1, conf, False, 1000, 100)

    def test_load_negative_limits(self):
        """Test loading the config file with negative read/write limits."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = -1\n')
            fp.write('write_limit = -1\n')
        conf = config._Config(conf_file)
        self.assertEqual(True, conf.get_throttling())
        self.assertEqual(None, conf.get_throttling_read_limit())
        self.assertEqual(None, conf.get_throttling_write_limit())

    def test_load_partial_config(self):
        """Test loading a partial config file and fallback to defaults."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = 1\n')
        conf = config._Config(conf_file)
        self.assertEqual(True, conf.get_throttling())
        self.assertEqual(1, conf.get_throttling_read_limit())
        self.assertEqual(2097152, conf.get_throttling_write_limit())

    def test_override(self):
        """Test loading the config file with only the throttling values."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = 1000\n')
            fp.write('write_limit = 200\n')
        conf = config._Config(conf_file)
        conf_orig = config._Config(conf_file)
        overridden_opts = [('bandwidth_throttling', 'on', False)]
        conf.override_options(overridden_opts)
        self.assertEqual(False, conf.get_throttling())
        self.assertFalse(conf.get_throttling() == conf_orig.get_throttling())
        self.assertEqual(1000, conf.get_throttling_read_limit())
        self.assertEqual(200, conf.get_throttling_write_limit())
        conf.save()
        # load the config in a barebone ConfigParser and check
        conf_1 = ConfigParser()
        conf_1.read(conf_file)
        self.assertThrottlingSection(conf_1, conf_orig, True, 1000, 200)

    def test_load_udf_autosubscribe(self):
        """Test load/set/override of udf_autosubscribe config value."""
        conf_file = os.path.join(self.test_root,
                                 'test_udf_autosubscribe_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('log_level = INFO\n')
            fp.write('disable_ssl_verify = True\n')
            fp.write('udf_autosubscribe = True\n')
            fp.write('\n')
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = True\n')
            fp.write('read_limit = 1000\n')
            fp.write('write_limit = 200\n')

        # keep a original around
        conf_orig = config._Config(conf_file)

        # load the config
        conf = config._Config(conf_file)
        self.assertTrue(conf.get_udf_autosubscribe())
        # change it to False
        conf.set_udf_autosubscribe(False)
        self.assertFalse(conf.get_udf_autosubscribe())
        # save, load and check
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertFalse(conf_1.get_udf_autosubscribe())
        # change it to True
        conf.set_udf_autosubscribe(True)
        self.assertTrue(conf.get_udf_autosubscribe())
        # save, load and check
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertTrue(conf_1.get_udf_autosubscribe())

        # load the config, check the override of the value
        conf = config._Config(conf_file)
        self.assertTrue(conf.get_udf_autosubscribe())
        overridden_opts = [('__main__', 'udf_autosubscribe', False)]
        conf.override_options(overridden_opts)
        self.assertFalse(conf.get_udf_autosubscribe())
        self.assertNotEqual(conf.get_udf_autosubscribe(),
                            conf_orig.get_udf_autosubscribe())
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertEqual(True, conf_1.get_udf_autosubscribe())

    def test_load_share_autosubscribe(self):
        """Test load/set/override of share_autosubscribe config value."""
        conf_file = os.path.join(self.test_root,
                                 'test_share_autosubscribe_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('share_autosubscribe = True\n')

        # keep a original around
        conf_orig = config._Config(conf_file)

        # load the config
        conf = config._Config(conf_file)
        self.assertTrue(conf.get_share_autosubscribe())
        # change it to False
        conf.set_share_autosubscribe(False)
        self.assertFalse(conf.get_share_autosubscribe())
        # save, load and check
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertFalse(conf_1.get_share_autosubscribe())
        # change it to True
        conf.set_share_autosubscribe(True)
        self.assertTrue(conf.get_share_autosubscribe())
        # save, load and check
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertTrue(conf_1.get_share_autosubscribe())

        # load the config, check the override of the value
        conf = config._Config(conf_file)
        self.assertTrue(conf.get_share_autosubscribe())
        overridden_opts = [('__main__', 'share_autosubscribe', False)]
        conf.override_options(overridden_opts)
        self.assertFalse(conf.get_share_autosubscribe())
        self.assertNotEqual(conf.get_share_autosubscribe(),
                            conf_orig.get_share_autosubscribe())
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertEqual(True, conf_1.get_share_autosubscribe())

    def test_load_autoconnect(self):
        """Test load/set/override of autoconnect config value."""
        conf_file = os.path.join(self.test_root,
                                 'test_autoconnect_config.conf')
        # ensure that autoconnect is True
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('autoconnect = True\n')

        # keep a original around
        conf_orig = config._Config(conf_file)

        # assert default is correct
        self.assertTrue(conf_orig.get_autoconnect(),
                        'autoconnect is True by default.')

        # load the config
        conf = config._Config(conf_file)
        self.assertTrue(conf.get_autoconnect())

        # change it to False
        conf.set_autoconnect(False)
        self.assertFalse(conf.get_autoconnect())

        # save, load and check
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertFalse(conf_1.get_autoconnect())
        # change it to True
        conf.set_autoconnect(True)
        self.assertTrue(conf.get_autoconnect())
        # save, load and check
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertTrue(conf_1.get_autoconnect())

        # load the config, check the override of the value
        conf = config._Config(conf_file)
        self.assertTrue(conf.get_autoconnect())
        overridden_opts = [('__main__', 'autoconnect', False)]
        conf.override_options(overridden_opts)
        self.assertFalse(conf.get_autoconnect())
        self.assertNotEqual(conf.get_autoconnect(),
                            conf_orig.get_autoconnect())
        conf.save()
        conf_1 = config._Config(conf_file)
        self.assertEqual(True, conf_1.get_autoconnect())

    def test_get_simult_transfers(self):
        """Get simult transfers."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        with open_file(conf_file, 'w') as fh:
            fh.write('[__main__]\n')
            fh.write('simult_transfers = 12345\n')
        conf = config._Config(conf_file)
        self.assertEqual(conf.get_simult_transfers(), 12345)

    def test_set_simult_transfers(self):
        """Set simult transfers."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        with open_file(conf_file, 'w') as fh:
            fh.write('[__main__]\n')
            fh.write('simult_transfers = 12345\n')
        conf = config._Config(conf_file)
        conf.set_simult_transfers(666)
        self.assertEqual(conf.get_simult_transfers(), 666)

    def test_get_max_payload_size(self):
        """Get the maximum payload size."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        with open_file(conf_file, 'w') as fh:
            fh.write('[__main__]\n')
            fh.write('max_payload_size = 12345\n')
        conf = config._Config(conf_file)
        self.assertEqual(conf.get_max_payload_size(), 12345)

    def test_set_max_payload_size(self):
        """Set the maximum payload size."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        with open_file(conf_file, 'w') as fh:
            fh.write('[__main__]\n')
            fh.write('max_payload_size = 12345\n')
        conf = config._Config(conf_file)
        conf.set_max_payload_size(666)
        self.assertEqual(conf.get_max_payload_size(), 666)

    def test_get_memory_pool_limit(self):
        """Get the memory pool limit."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        with open_file(conf_file, 'w') as fh:
            fh.write('[__main__]\n')
            fh.write('memory_pool_limit = 12345\n')
        conf = config._Config(conf_file)
        self.assertEqual(conf.get_memory_pool_limit(), 12345)

    def test_set_memory_pool_limit(self):
        """Set the memory pool limit."""
        conf_file = os.path.join(self.test_root, 'test_load_config.conf')
        with open_file(conf_file, 'w') as fh:
            fh.write('[__main__]\n')
            fh.write('memory_pool_limit = 12345\n')
        conf = config._Config(conf_file)
        conf.set_memory_pool_limit(666)
        self.assertEqual(conf.get_memory_pool_limit(), 666)


class UnicodePathsTestCase(TestCase):
    """Tests for unicode paths."""

    def test_get_config_files_path_encoding(self):
        """Check that get_config_files uses paths in the right encoding."""
        temp = self.mktemp()
        fake_path = os.path.join(temp, u"Ñandú")
        os.makedirs(fake_path)
        with open(os.path.join(fake_path, config.CONFIG_FILE), "w") as f:
            f.write("this is a fake config file")
        self.patch(
            config, "load_config_paths", lambda _: [fake_path.encode("utf8")])
        config_files = config.get_config_files()
        branch_config = os.path.join(fake_path, config.CONFIG_FILE)
        self.assertIn(branch_config, config_files)

    def test_load_branch_configuration(self):
        """Check that the configuration from the branch is loaded."""
        config_files = [os.path.normpath(p) for p in config.get_config_files()]
        rootdir = os.environ['ROOTDIR']
        branch_config = os.path.join(rootdir, "data", config.CONFIG_FILE)
        branch_logging_config = os.path.join(
            rootdir, "data", config.CONFIG_LOGS)
        self.assertIn(branch_config, config_files)
        self.assertIn(branch_logging_config, config_files)


class ConfigglueParsersTests(BaseTwistedTestCase):
    """Tests for our custom configglue parsers."""

    def test_throttling_limit_parser(self):
        """Test throttling_limit_parser."""
        good_value = '20480'
        unset_value = '-1'
        bad_value = 'hola'
        invalid_value = None
        zero_value = '0'
        parser = config.throttling_limit_parser
        self.assertEqual(20480, parser(good_value))
        self.assertEqual(None, parser(unset_value))
        self.assertRaises(ValueError, parser, bad_value)
        self.assertRaises(TypeError, parser, invalid_value)
        self.assertEqual(None, parser(zero_value))

    def test_log_level_parser(self):
        """Test log_level_parser."""
        good_value = 'INFO'
        bad_value = 'hola'
        invalid_value = None
        parser = config.log_level_parser
        self.assertEqual(logging.INFO, parser(good_value))
        self.assertEqual(logging.DEBUG, parser(bad_value))
        self.assertEqual(logging.DEBUG, parser(invalid_value))

    def test_serverconnection_simple_defaultmode(self):
        results = config.server_connection_parser('test.host:666')
        self.assertEqual(results, [{
            'host': 'test.host',
            'port': 666,
            'use_ssl': True,
            'disable_ssl_verify': False,
        }])

    def test_serverconnection_simple_plain(self):
        results = config.server_connection_parser('test.host:666:plain')
        self.assertEqual(results, [{
            'host': 'test.host',
            'port': 666,
            'use_ssl': False,
            'disable_ssl_verify': False,
        }])

    def test_serverconnection_simple_ssl(self):
        results = config.server_connection_parser('test.host:666:ssl')
        self.assertEqual(results, [{
            'host': 'test.host',
            'port': 666,
            'use_ssl': True,
            'disable_ssl_verify': False,
        }])

    def test_serverconnection_simple_noverify(self):
        results = config.server_connection_parser('test.host:666:ssl_noverify')
        self.assertEqual(results, [{
            'host': 'test.host',
            'port': 666,
            'use_ssl': True,
            'disable_ssl_verify': True,
        }])

    def test_serverconnection_simple_bad_mode(self):
        self.assertRaises(
            ValueError, config.server_connection_parser, 'host:666:badmode')

    def test_serverconnection_simple_too_many_parts(self):
        self.assertRaises(
            ValueError, config.server_connection_parser, 'host:666:plain:what')

    def test_serverconnection_simple_too_few_parts(self):
        self.assertRaises(
            ValueError, config.server_connection_parser, 'test.host')

    def test_serverconnection_simple_port_not_numeric(self):
        self.assertRaises(
            ValueError, config.server_connection_parser, 'test.host:port')

    def test_serverconnection_multiple(self):
        results = config.server_connection_parser(
            'test.host1:666:plain,host2.com:447')
        self.assertEqual(results, [{
            'host': 'test.host1',
            'port': 666,
            'use_ssl': False,
            'disable_ssl_verify': False,
        }, {
            'host': 'host2.com',
            'port': 447,
            'use_ssl': True,
            'disable_ssl_verify': False,
        }])


class XdgHomeParsersTests(BaseTwistedTestCase):
    """Tests for our custom xdg parsers."""

    good_value = '~/hola/mundo'
    name = 'home'
    xdg_dir = os.path.join('', 'home', 'fake')

    @defer.inlineCallbacks
    def setUp(self):
        yield super(XdgHomeParsersTests, self).setUp()
        self.parser = getattr(config, '%s_dir_parser' % self.name)

    def test_good_value(self):
        """Test the parser using a good value."""
        homedir = os.path.join('', 'home', 'fake')
        self.patch(platform, 'user_home', homedir)
        expected = os.path.join(self.xdg_dir, 'hola', 'mundo')
        actual = self.parser(self.good_value)
        self.assertEqual(expected, actual)
        self.assertIsInstance(actual, str)
        self.assertNotIsInstance(actual, unicode)

    def test_bad_value(self):
        """Test the parser using a bad value."""
        bad_value = '/hola'
        self.assertEqual(config.path_from_unix(bad_value),
                         self.parser(bad_value))

    def test_invalid_value(self):
        """Test the parser using an invalid value."""
        invalid_value = None
        self.assertRaises(AttributeError, self.parser, invalid_value)


class XdgCacheParsersTests(XdgHomeParsersTests):
    """Tests for our custom xdg parsers."""

    good_value = 'hola/mundo'
    name = 'xdg_cache'
    xdg_dir = xdg_cache_home


class XdgDataParsersTests(XdgCacheParsersTests):
    """Tests for our custom xdg parsers."""

    good_value = 'hola/mundo'
    name = 'xdg_data'
    xdg_dir = xdg_data_home


class SyncDaemonConfigParserTests(BaseTwistedTestCase):
    """Tests for SyncDaemonConfigParser."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(SyncDaemonConfigParserTests, self).setUp()
        self.test_root = self.mktemp()
        self.default_config = os.path.join(os.environ['ROOTDIR'], 'data',
                                           'syncdaemon.conf')
        self.logging_config = os.path.join(os.environ['ROOTDIR'], 'data',
                                           'logging.conf')
        self.cp = config.SyncDaemonConfigParser()
        self.cp.readfp(file(self.default_config))
        self.cp.readfp(file(self.logging_config))

    def test_log_level_old_config(self):
        """Test log_level upgrade hook."""
        conf_file = os.path.join(self.test_root, 'test_old_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('log_level = DEBUG\n')
        self.assertTrue(path_exists(conf_file))
        self.cp.read([conf_file])
        self.cp.parse_all()
        self.assertEqual(self.cp.get('logging', 'level').value, 10)

    def test_log_level_new_config(self):
        """Test log_level upgrade hook with new config."""
        conf_file = os.path.join(self.test_root, 'test_new_config.conf')
        # write some throttling values to the config file
        with open_file(conf_file, 'w') as fp:
            fp.write('[logging]\n')
            fp.write('level = DEBUG\n')
        self.assertTrue(path_exists(conf_file))
        self.cp.read([conf_file])
        self.cp.parse_all()
        self.assertEqual(self.cp.get('logging', 'level').value, 10)

    def test_log_level_old_and_new_config(self):
        """Test log_level upgrade hook with a mixed config."""
        conf_file = os.path.join(self.test_root,
                                 'test_old_and_new_config.conf')
        # write some throttling values to the config file (not default ones)
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('log_level = NOTE\n')
            fp.write('[logging]\n')
            fp.write('level = ERROR\n')
        self.assertTrue(path_exists(conf_file))
        self.cp.read([conf_file])
        self.cp.parse_all()
        self.assertEqual(self.cp.get('logging', 'level').value, logging.ERROR)

    def test_old_default_config(self):
        """Test log_level upgrade hook with an old default config."""
        self.cp.read(config.get_config_files()[0])
        # fake an old config
        value = self.cp.get('logging', 'level.default')
        help = self.cp.get('logging', 'level.help')
        parser = self.cp.get('logging', 'level.parser')
        self.cp.set('__main__', 'log_level.default', value)
        self.cp.set('__main__', 'log_level.help', help)
        self.cp.set('__main__', 'log_level.parser', parser)
        self.cp.remove_option('logging', 'level.default')
        self.cp.remove_option('logging', 'level.help')
        self.cp.remove_option('logging', 'level.parser')
        # parse it
        self.cp.parse_all()
        new_value = self.cp.get('logging', 'level')
        self.assertEqual(new_value.value, new_value.parser(value))

    def test_add_upgrade_hook(self):
        """Test add_upgrade_hook method."""
        self.cp.add_upgrade_hook('foo', 'bar', lambda x: None)
        self.assertIn(('foo', 'bar'), self.cp.upgrade_hooks)
        # try to add the same upgrade_hook
        self.assertRaises(ValueError, self.cp.add_upgrade_hook, 'foo', 'bar',
                          lambda x: None)

    def test_ignore_one(self):
        """Test ignore files config, one regex."""
        conf_file = os.path.join(self.test_root, 'test_new_config.conf')
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('ignore = .*\\.pyc\n')  # all .pyc files
        self.assertTrue(path_exists(conf_file))
        self.cp.read([conf_file])
        self.cp.parse_all()
        self.assertEqual(self.cp.get('__main__', 'ignore').value, [r'.*\.pyc'])

    def test_ignore_two(self):
        """Test ignore files config, two regexes."""
        conf_file = os.path.join(self.test_root, 'test_new_config.conf')
        with open_file(conf_file, 'w') as fp:
            fp.write('[__main__]\n')
            fp.write('ignore = .*\\.pyc\n')  # all .pyc files
            fp.write('         .*\\.sw[opnx]\n')  # all gvim temp files
        self.assertTrue(path_exists(conf_file))
        self.cp.read([conf_file])
        self.cp.parse_all()
        self.assertEqual(self.cp.get('__main__', 'ignore').value,
                         ['.*\\.pyc', '.*\\.sw[opnx]'])

    def test_fs_monitor_not_default(self):
        """Test get monitor."""
        monitor_id = 'my_monitor'
        conf_file = os.path.join(self.test_root, 'test_new_config.conf')
        with open_file(conf_file, 'w') as fd:
            fd.write('[__main__]\n')
            fd.write('fs_monitor = %s\n' % monitor_id)
        self.assertTrue(path_exists(conf_file))
        self.cp.read([conf_file])
        self.cp.parse_all()
        self.assertEqual(
            self.cp.get('__main__', 'fs_monitor').value, monitor_id)

    def test_use_trash_default(self):
        """Test default configuration for use_trash."""
        self.cp.parse_all()
        self.assertEqual(self.cp.get('__main__', 'use_trash').value, True)

    def test_ignore_libreoffice_lockfiles(self):
        """Test the default config includes ignoring libreoffice lockfiles."""
        self.cp.parse_all()
        self.assertIn(r'\A\.~lock\..*#\Z',
                      self.cp.get('__main__', 'ignore').value)

    def test_simult_transfers(self):
        """Test default configuration for simultaneous transfers."""
        self.cp.parse_all()
        self.assertEqual(self.cp.get('__main__', 'simult_transfers').value, 10)

    def test_memory_pool_limit(self):
        """Test default configuration for memory pool limit."""
        self.cp.parse_all()
        configured = self.cp.get('__main__', 'memory_pool_limit').value
        self.assertEqual(configured, 200)
