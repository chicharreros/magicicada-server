# -*- coding: utf-8 -*-
#
# Copyright 2012 Canonical Ltd.
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

"""Test the platform-specific translation functions."""

import os
import sys

from twisted.internet import defer
from ubuntuone.devtools.testcases import TestCase, skipIfNotOS

from ubuntuone.utils import translation

TEST_DOMAIN = 'test-domain'
TEST_LANG_DEFAULTS_EN_FIRST = ['en', 'pt-PT']
TEST_LANG_DEFAULTS = ['es', 'en', 'pt-PT']
TEST_FALLBACK_PATH = 'test-path/to/mofiles'
TEST_FROZEN_PATH = 'frozen-test-path/to/mofiles'


class MockGettextTranslations(object):
    """Mock translations to test properties"""
    ugettext = 'ugettext'
    gettext = 'gettext'


class MockNSUserDefaults(object):
    """Mock defaults for _get_languages on darwin."""

    def standardUserDefaults(self):
        return {'AppleLanguages': TEST_LANG_DEFAULTS}


class TranslationsTestCase(TestCase):
    """Test getting the right gettext translations."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(TranslationsTestCase, self).setUp()
        self._called = []

    def _set_called(self, *args, **kwargs):
        """call recorder"""
        self._called.append((args, kwargs))
        return MockGettextTranslations()

    def test_import(self):
        """Test whether import translation defines _ as a builtin."""
        import ubuntuone.utils.translation
        assert ubuntuone.utils.translation
        self.assertFalse('_' in __builtins__)

    @skipIfNotOS('darwin', 'Test requires pyobjc-Cocoa')
    def test_get_languages_darwin(self):
        """Test getting the user's list of preferred languages."""
        import Cocoa
        assert Cocoa
        self.patch(Cocoa, 'NSUserDefaults', MockNSUserDefaults())
        langs = translation._get_languages()
        self.assertEqual(langs, TEST_LANG_DEFAULTS)

    def test_get_languages_linux(self):
        """Test that we will use gettext defaults on linux."""
        self.patch(sys, 'platform', 'linux2')
        langs = translation._get_languages()
        self.assertEqual(langs, None)

    def test_get_translations_data_path_darwin_frozen(self):
        """Test getting the location of the compiled translation files."""
        self.patch(sys, 'platform', 'darwin')
        sys.frozen = 'yes'
        self.addCleanup(delattr, sys, 'frozen')
        self.patch(translation, '__file__',
                   os.path.join('path', 'to', 'Main.app', 'ignore', 'me'))

        path = translation._get_translations_data_path()

        self.assertEqual(path, os.path.join('path', 'to', 'Main.app',
                                            'Contents', 'Resources',
                                            'translations'))

    def test_get_translations_data_path_darwin_unfrozen_nofallback(self):
        """Test that we use gettext defaults on darwin when not frozen."""
        self.patch(sys, 'platform', 'darwin')
        path = translation._get_translations_data_path()
        self.assertEqual(path, None)

    def test_get_translations_data_path_darwin_unfrozen_fallback(self):
        """Test that we use fallback on darwin when not frozen."""
        self.patch(sys, 'platform', 'darwin')
        expected = "a-test-path"
        path = translation._get_translations_data_path(expected)
        self.assertEqual(path, expected)

    def test_get_translations_data_path_linux(self):
        """Test that we use gettext defaults on linux."""
        path = translation._get_translations_data_path()
        self.assertEqual(path, None)

    def _call_get_gettext(self, platform, py_version, fallback=None):
        """Helper function to patch and call translation.get_gettext."""
        self.patch(sys, 'platform', platform)
        self.patch(sys, 'version_info', py_version)
        self.patch(translation.gettext, 'translation', self._set_called)

        if fallback:
            g_func = translation.get_gettext(TEST_DOMAIN, fallback)
        else:
            g_func = translation.get_gettext(TEST_DOMAIN)

        if py_version == (2,):
            self.assertEqual(g_func, 'ugettext')
        else:
            self.assertEqual(g_func, 'gettext')

    def test_get_gettext_linux_py2(self):
        """test get_gettext on linux py2"""
        self._call_get_gettext('linux2', py_version=(2,))

    def test_get_gettext_linux_py3(self):
        """test get_gettext on linux py3"""
        self._call_get_gettext('linux2', py_version=(3,))

    def _call_get_gettext_nonlinux(self, frozen, py_version,
                                   lang_en_first=False):
        """Helper function for non-linux runs of get_gettext."""
        if lang_en_first:
            lang_rv = TEST_LANG_DEFAULTS_EN_FIRST
        else:
            lang_rv = TEST_LANG_DEFAULTS
        self.patch(translation, '_get_languages', lambda: lang_rv)
        if frozen:
            expected_path = TEST_FROZEN_PATH
            sys.frozen = 'yes'
            self.addCleanup(delattr, sys, 'frozen')
        else:
            expected_path = TEST_FALLBACK_PATH

        self.patch(translation, '_get_translations_data_path',
                   lambda x: expected_path)

        self._call_get_gettext('notlinux', py_version)

        # This tests a special case if 'en' is the first language, we
        # don't give the path, so we will get the fallback
        # NullTranslation instance that will use the keys and not look
        # for en translations, which we do not ship.
        if lang_en_first:
            expected_arg = ((TEST_DOMAIN,), {'fallback': True})
            self.assertEqual(self._called, [expected_arg])
        else:
            # Check for lang_rv[:1] (must be a list) because we only
            # send first language, in order to fall back to 'en' even
            # though we don't ship an en.mo
            expected_arg = (
                (TEST_DOMAIN, expected_path),
                {'languages': lang_rv[:1], 'fallback': True})

            self.assertEqual(self._called, [expected_arg])

    def test_get_gettext_nonlinux_frozen_py2(self):
        """test get_gettext on nonlinux frozen and py2"""
        self._call_get_gettext_nonlinux(frozen=True, py_version=(2,))

    def test_get_gettext_nonlinux_frozen_py3(self):
        """test get_gettext on nonlinux frozen and py3"""
        self._call_get_gettext_nonlinux(frozen=True, py_version=(3,))

    def test_get_gettext_nonlinux_unfrozen_py2(self):
        """test get_gettext on nonlinux un-frozen and py2"""
        self._call_get_gettext_nonlinux(frozen=False, py_version=(2,))

    def test_get_gettext_nonlinux_unfrozen_py3(self):
        """test get_gettext on nonlinux un-frozen and py3"""
        self._call_get_gettext_nonlinux(frozen=False, py_version=(3,))

    def test_get_gettext_nonlinux_frozen_py2_enfirst(self):
        """test get_gettext returning nulltranslations when lang[0] = en"""
        self._call_get_gettext_nonlinux(
            frozen=True, py_version=(2,), lang_en_first=True)

    def test_get_gettext_darwin_unfrozen_fallback(self):
        """test using fallback path from source"""
        self.patch(translation, '_get_languages', lambda: ['not-en'])
        self._call_get_gettext('darwin', (2,), TEST_FALLBACK_PATH)
        self.assertEqual(
            self._called,
            [((TEST_DOMAIN, TEST_FALLBACK_PATH),
              {'languages': ['not-en'], 'fallback': True})])

    def test_get_gettext_win32_unfrozen_fallback(self):
        """test using fallback path from source"""
        self.patch(translation, '_get_languages', lambda: ['not-en'])
        self._call_get_gettext('win32', (2,), TEST_FALLBACK_PATH)
        self.assertEqual(
            self._called,
            [((TEST_DOMAIN, TEST_FALLBACK_PATH),
              {'languages': ['not-en'], 'fallback': True})])
