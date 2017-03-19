# -*- coding: utf-8 -*-
#
# Copyright 2011-2012 Canonical Ltd.
# Copyright 2015-2017 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Test the gsettings parser."""

import logging

from twisted.trial.unittest import TestCase
from ubuntuone.devtools.handlers import MementoHandler

from ubuntuone.utils import gsettings

TEMPLATE_GSETTINGS_OUTPUT = """\
org.gnome.system.proxy autoconfig-url '{autoconfig_url}'
org.gnome.system.proxy ignore-hosts {ignore_hosts:s}
org.gnome.system.proxy mode '{mode}'
org.gnome.system.proxy.ftp host '{ftp_host}'
org.gnome.system.proxy.ftp port {ftp_port}
org.gnome.system.proxy.http authentication-password '{auth_password}'
org.gnome.system.proxy.http authentication-user '{auth_user}'
org.gnome.system.proxy.http host '{http_host}'
org.gnome.system.proxy.http port {http_port}
org.gnome.system.proxy.http use-authentication {http_use_auth}
org.gnome.system.proxy.https host '{https_host}'
org.gnome.system.proxy.https port {https_port}
org.gnome.system.proxy.socks host '{socks_host}'
org.gnome.system.proxy.socks port {socks_port}
"""

BASE_GSETTINGS_VALUES = {
    "autoconfig_url": "",
    "ignore_hosts": ["localhost", "127.0.0.0/8"],
    "mode": "none",
    "ftp_host": "",
    "ftp_port": 0,
    "auth_password": "",
    "auth_user": "",
    "http_host": "",
    "http_port": 0,
    "http_use_auth": "false",
    "https_host": "",
    "https_port": 0,
    "socks_host": "",
    "socks_port": 0,
}


class ProxySettingsTestCase(TestCase):
    """Test the getting of the proxy settings."""

    def test_gsettings_cmdline_correct(self):
        """The command line used to get the proxy settings is the right one."""
        expected = "gsettings list-recursively org.gnome.system.proxy".split()
        called = []

        def append_output(args):
            """Append the output and return some settings."""
            called.append(args)
            return TEMPLATE_GSETTINGS_OUTPUT.format(**BASE_GSETTINGS_VALUES)

        self.patch(gsettings.subprocess, "check_output", append_output)
        gsettings.get_proxy_settings()
        self.assertEqual(called[0], expected)

    def test_gsettings_parser_none(self):
        """Test a parser of gsettings."""
        expected = {}
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**BASE_GSETTINGS_VALUES)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertEqual(ps, expected)

    def _assert_parser_anonymous(self, scheme):
        """Assert the parsing of anonymous settings."""
        template_values = dict(BASE_GSETTINGS_VALUES)
        expected_host = "expected_host"
        expected_port = 54321
        expected = {
            "host": expected_host,
            "port": expected_port,
        }
        template_values.update({
            "mode": "manual",
            scheme + "_host": expected_host,
            scheme + "_port": expected_port,
        })
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertEqual(ps[scheme], expected)

    def test_gsettings_parser_http_anonymous(self):
        """Test a parser of gsettings."""
        self._assert_parser_anonymous('http')

    def test_gsettings_parser_https_anonymus(self):
        """Test a parser of gsettings."""
        self._assert_parser_anonymous('https')

    def test_gsettings_empty_ignore_hosts(self):
        """Missing values in the ignore hosts."""
        troublesome_value = "@as []"
        template_values = dict(BASE_GSETTINGS_VALUES)
        template_values["ignore_hosts"] = troublesome_value
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertEqual(ps, {})

    def test_gsettings_cannot_parse(self):
        """Some weird setting that cannot be parsed is logged with warning."""
        memento = MementoHandler()
        memento.setLevel(logging.DEBUG)
        gsettings.logger.addHandler(memento)
        self.addCleanup(gsettings.logger.removeHandler, memento)

        troublesome_value = "#bang"
        template_values = dict(BASE_GSETTINGS_VALUES)
        template_values["ignore_hosts"] = troublesome_value
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertTrue(memento.check_warning(gsettings.CANNOT_PARSE_WARNING %
                                              troublesome_value))
        self.assertEqual(ps, {})

    def test_gsettings_parser_http_authenticated(self):
        """Test a parser of gsettings."""
        template_values = dict(BASE_GSETTINGS_VALUES)
        expected_host = "expected_host"
        expected_port = 54321
        expected_user = "carlitos"
        expected_password = "very secret password"
        expected = {
            "host": expected_host,
            "port": expected_port,
            "username": expected_user,
            "password": expected_password,
        }
        template_values.update({
            "mode": "manual",
            "http_host": expected_host,
            "http_port": expected_port,
            "auth_user": expected_user,
            "auth_password": expected_password,
            "http_use_auth": "true",
        })
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertEqual(ps["http"], expected)

    def _assert_parser_authenticated_url(self, scheme):
        """Test a parser of gsettings with creds in the url."""
        template_values = dict(BASE_GSETTINGS_VALUES)
        expected_host = "expected_host"
        expected_port = 54321
        expected_user = "carlitos"
        expected_password = "very secret password"
        composed_url = '%s:%s@%s' % (expected_user, expected_password,
                                     expected_host)
        expected = {
            "host": expected_host,
            "port": expected_port,
            "username": expected_user,
            "password": expected_password,
        }
        template_values.update({
            "mode": "manual",
            scheme + "_host": composed_url,
            scheme + "_port": expected_port,
            "http_use_auth": "false",
        })
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertEqual(ps[scheme], expected)

    def test_gsettings_parser_http_authenticated_url(self):
        """Test a parser of gsettings with creds in the url."""
        self._assert_parser_authenticated_url('http')

    def test_gsettings_parser_https_authenticated_url(self):
        """Test a parser of gsettings with creds in the url."""
        self._assert_parser_authenticated_url('https')

    def test_gsettings_auth_over_url(self):
        """Test that the settings are more important that the url."""
        template_values = dict(BASE_GSETTINGS_VALUES)
        expected_host = "expected_host"
        expected_port = 54321
        expected_user = "carlitos"
        expected_password = "very secret password"
        composed_url = '%s:%s@%s' % ('user', 'random',
                                     expected_host)
        http_expected = {
            "host": expected_host,
            "port": expected_port,
            "username": expected_user,
            "password": expected_password,
        }
        template_values.update({
            "mode": "manual",
            "http_host": composed_url,
            "http_port": expected_port,
            "auth_user": expected_user,
            "auth_password": expected_password,
            "http_use_auth": "true",
        })
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertEqual(ps["http"], http_expected)

    def _assert_parser_empty_url(self, scheme):
        """Assert the parsing of an empty url."""
        template_values = dict(BASE_GSETTINGS_VALUES)
        template_values.update({
            "mode": "manual",
            scheme + "_host": '',
            scheme + "_port": 0,
            "http_use_auth": "false",
        })
        fake_output = TEMPLATE_GSETTINGS_OUTPUT.format(**template_values)
        self.patch(gsettings.subprocess, "check_output",
                   lambda _: fake_output)
        ps = gsettings.get_proxy_settings()
        self.assertNotIn(scheme, ps)

    def test_gsettings_parser_empty_http_url(self):
        """Test when there is no http proxy set."""
        self._assert_parser_empty_url('http')

    def test_gsettings_parser_empty_https_url(self):
        """Test when there is no https proxy set."""
        self._assert_parser_empty_url('https')


class ParseProxyHostTestCase(TestCase):
    """Test the parsing of the domain."""

    def test_onlyhost(self):
        """Parse a host with no username or password."""
        sample = "hostname"
        hostname, username, password = gsettings.parse_proxy_host(sample)
        self.assertEqual(username, None)
        self.assertEqual(password, None)
        self.assertEqual(hostname, "hostname")

    def test_user_and_host(self):
        """Parse host just with the username."""
        sample = "username@hostname"
        hostname, username, password = gsettings.parse_proxy_host(sample)
        self.assertEqual(username, "username")
        self.assertEqual(password, None)
        self.assertEqual(hostname, "hostname")

    def test_user_pass_and_host(self):
        """Test parsing a host with a username and password."""
        sample = "username:password@hostname"
        hostname, username, password = gsettings.parse_proxy_host(sample)
        self.assertEqual(username, "username")
        self.assertEqual(password, "password")
        self.assertEqual(hostname, "hostname")

    def test_username_with_at(self):
        """Test parsing the host with a username with @."""
        sample = "username@company.com:password@hostname"
        hostname, username, password = gsettings.parse_proxy_host(sample)
        self.assertEqual(username, "username@company.com")
        self.assertEqual(password, "password")
        self.assertEqual(hostname, "hostname")

    def test_username_with_at_nopass(self):
        """Test parsing the host without a password."""
        sample = "username@company.com@hostname"
        hostname, username, password = gsettings.parse_proxy_host(sample)
        self.assertEqual(username, "username@company.com")
        self.assertEqual(password, None)
        self.assertEqual(hostname, "hostname")

    def test_user_pass_with_colon_and_host(self):
        """Test parsing the host with a password that contains :."""
        sample = "username:pass:word@hostname"
        hostname, username, password = gsettings.parse_proxy_host(sample)
        self.assertEqual(username, "username")
        self.assertEqual(password, "pass:word")
        self.assertEqual(hostname, "hostname")
