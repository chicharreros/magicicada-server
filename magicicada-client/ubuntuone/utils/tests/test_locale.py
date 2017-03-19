# -*- coding: utf-8 -*-
#
# Copyright 2013 Canonical Ltd.
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

"""Tests for the locale utilities."""

from twisted.trial.unittest import TestCase

from ubuntuone.utils import locale

NO_VALUE = object()


class LocaleTestCase(TestCase):
    """Test case for functions related to locale."""

    def setUp(self):
        d = super(LocaleTestCase, self).setUp()
        self.save_environ("LC_CTYPE")
        self.save_environ("LANG")
        return d

    def save_environ(self, env_var_name):
        """Save the value of an environment variable."""
        old_value = locale.os.environ.get(env_var_name, NO_VALUE)
        self.addCleanup(self.restore_environ, env_var_name, old_value)
        locale.os.environ[env_var_name] = "fake_locale"

    def restore_environ(self, env_var_name, old_value):
        """Restore the value of an environment variable."""
        if old_value is NO_VALUE:
            if env_var_name in locale.os.environ:
                del(locale.os.environ[env_var_name])
        else:
            locale.os.environ[env_var_name] = old_value

    def test_fix_turkish_locale_when_turkish(self):
        """The fix_turkish_locale function skips when no locale set."""
        locale.os.environ["LANG"] = "tr_TR.UTF-8"
        del(locale.os.environ["LC_CTYPE"])
        locale.fix_turkish_locale()
        self.assertEqual(locale.os.environ["LC_CTYPE"], locale.SAFE_LOCALE)

    def test_fix_turkish_locale_when_other(self):
        """The fix_turkish_locale function skips when no locale set."""
        locale.os.environ["LANG"] = "en_EN.UTF-8"
        del(locale.os.environ["LC_CTYPE"])
        locale.fix_turkish_locale()
        self.assertEqual(locale.os.environ.get("LC_CTYPE", NO_VALUE), NO_VALUE)

    def test_fix_turkish_locale_when_LANG_unset(self):
        """The fix_turkish_locale function skips when no locale set."""
        del(locale.os.environ["LANG"])
        del(locale.os.environ["LC_CTYPE"])
        locale.fix_turkish_locale()
        self.assertEqual(locale.os.environ.get("LC_CTYPE", NO_VALUE), NO_VALUE)

    def test_fix_turkish_locale_when_LC_CTYPE_not_turkish(self):
        """The fix is skipped if the LC_CTYPE is already non-turkish."""
        original = "es_ES.UTF-8"
        locale.os.environ["LANG"] = "tr_TR.UTF-8"
        locale.os.environ["LC_CTYPE"] = original
        locale.fix_turkish_locale()
        self.assertEqual(locale.os.environ.get("LC_CTYPE", NO_VALUE), original)

    def test_fix_turkish_locale_when_LC_CTYPE_is_turkish(self):
        """The fix is applied if the LC_CTYPE is turkish."""
        locale.os.environ["LANG"] = "es_ES.UTF-8"
        locale.os.environ["LC_CTYPE"] = "tr_TR.UTF-8"
        locale.fix_turkish_locale()
        self.assertEqual(locale.os.environ.get("LC_CTYPE", NO_VALUE),
                         locale.SAFE_LOCALE)
