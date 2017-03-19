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

"""Tests for the common helper functions."""

from __future__ import unicode_literals

import logging
import sys
import os

from twisted.internet import defer
from twisted.web import resource
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testing.txwebserver import HTTPWebServer

from ubuntuone import utils
from ubuntuone.tests import TestCase

CONSTANTS_MODULE = 'ubuntuone.clientdefs'
NOT_DEFINED = object()


class FakedConstantsModule(object):
    """Fake the 'ubuntuone.controlpanel.constants' module."""

    PROJECT_DIR = '/tmp/foo/bar'
    BIN_DIR = '/tmp/foo/bin'


class GetProjectDirTestCase(TestCase):
    """Test case for get_project_dir when constants module is not defined."""

    DIR_NAME = utils.DATA_SUFFIX
    DIR_CONSTANT = 'PROJECT_DIR'
    DIR_GETTER = 'get_project_dir'

    @defer.inlineCallbacks
    def setUp(self):
        yield super(GetProjectDirTestCase, self).setUp()
        self._constants = sys.modules.get(CONSTANTS_MODULE, NOT_DEFINED)
        sys.modules[CONSTANTS_MODULE] = None  # force ImportError

        self.memento = MementoHandler()
        self.memento.setLevel(logging.DEBUG)
        utils.logger.addHandler(self.memento)
        self.addCleanup(utils.logger.removeHandler, self.memento)

        self.get_dir = getattr(utils, self.DIR_GETTER)

    @defer.inlineCallbacks
    def tearDown(self):
        if self._constants is not NOT_DEFINED:
            sys.modules[CONSTANTS_MODULE] = self._constants
        else:
            sys.modules.pop(CONSTANTS_MODULE)
        yield super(GetProjectDirTestCase, self).tearDown()

    def test_get_dir_relative(self):
        """The relative path for the data directory is correctly retrieved."""
        module = utils.os.path.dirname(utils.__file__)
        rel_data = utils.os.path.join(module,
                                      utils.os.path.pardir,
                                      utils.os.path.pardir,
                                      self.DIR_NAME)
        expected_dir = utils.os.path.abspath(rel_data)

        # ensure expected_path exists at os level
        self.patch(utils.os.path, 'exists', lambda path: path == expected_dir)

        result = self.get_dir()
        self.assertEqual(expected_dir, result)

    def test_get_dir_none_exists(self):
        """No data directory exists, return None and log as error."""
        self.patch(utils.os.path, 'exists', lambda path: False)
        sys.modules[CONSTANTS_MODULE] = None

        self.assertRaises(AssertionError, self.get_dir)
        msg = 'get_dir: can not build a valid path.'
        self.assertTrue(self.memento.check_error(msg))


class GetProjectDirWithConstantsTestCase(GetProjectDirTestCase):
    """Test case for get_dir when constants module is defined."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(GetProjectDirWithConstantsTestCase, self).setUp()
        self.patch(utils.os.path, 'exists', lambda path: False)
        self._constants = sys.modules.get(CONSTANTS_MODULE, NOT_DEFINED)
        sys.modules[CONSTANTS_MODULE] = FakedConstantsModule()

    def test_get_dir(self):
        """If the constants.py module exists, use PROJECT_DIR from it."""
        result = self.get_dir()
        expected = getattr(sys.modules[CONSTANTS_MODULE], self.DIR_CONSTANT)
        self.assertEqual(expected, result)


class GetBinDirTestCase(GetProjectDirTestCase):
    """Test case for get_bin_dir when constants module is not defined."""

    DIR_NAME = utils.BIN_SUFFIX
    DIR_CONSTANT = 'BIN_DIR'
    DIR_GETTER = 'get_bin_dir'


class GetBinDirWithConstantsTestCase(GetProjectDirWithConstantsTestCase):
    """Test case for get_bin_dir when constants module is defined."""

    DIR_NAME = utils.BIN_SUFFIX
    DIR_CONSTANT = 'BIN_DIR'
    DIR_GETTER = 'get_bin_dir'


class GetDataFileTestCase(TestCase):
    """Test cases for get_data_file."""

    def test_get_data_file(self):
        """The path for a data file is correctly retrieved."""
        dummy_dir = '/yadda/yadda'
        dummy_file = 'test.png'
        self.patch(utils, 'get_project_dir', lambda: dummy_dir)
        result = utils.get_data_file(dummy_file)
        expected = utils.os.path.join(dummy_dir, dummy_file)
        self.assertEqual(expected, result)


class GetCertDirTestCase(TestCase):
    """Test determining the cert location."""

    @defer.inlineCallbacks
    def setUp(self):
        yield super(GetCertDirTestCase, self).setUp()

    def test_win(self):
        """Test geting a path when Common AppData is defined."""
        self.patch(utils, "__file__",
                   os.path.join("path", "to", "ubuntuone",
                                "utils", "__init__.py"))
        self.patch(sys, "platform", "win32")
        path = utils.get_cert_dir()
        self.assertEqual(path, os.path.join("path", "to", "data"))

    def test_darwin_frozen(self):
        """Test that we get a path with .app in it on frozen darwin."""
        self.patch(sys, "platform", "darwin")
        sys.frozen = "macosx-app"
        self.addCleanup(delattr, sys, "frozen")
        self.patch(utils, "__file__",
                   os.path.join("path", "to", "Main.app", "ignore"))
        path = utils.get_cert_dir()
        self.assertEqual(path, os.path.join("path", "to", "Main.app",
                                            "Contents", "Resources"))

    def test_darwin_unfrozen(self):
        """Test that we get a source-relative path on unfrozen darwin."""
        self.patch(sys, "platform", "darwin")
        self.patch(utils, "__file__",
                   os.path.join("path", "to", "ubuntuone",
                                "utils", "__init__.py"))
        path = utils.get_cert_dir()
        self.assertEqual(path, os.path.join("path", "to", "data"))

    def test_linux(self):
        """Test that linux gets the right path."""
        self.patch(sys, "platform", "linux2")
        path = utils.get_cert_dir()
        self.assertEqual(path, "/etc/ssl/certs")


class RootResource(resource.Resource):
    """A root resource that logs the number of calls."""

    isLeaf = True

    def __init__(self, *args, **kwargs):
        """Initialize this fake instance."""
        resource.Resource.__init__(self, *args, **kwargs)
        self.count = 0
        self.request_headers = []

    def render_HEAD(self, request):
        """Increase the counter on each render."""
        self.count += 1
        self.request_headers.append(request.requestHeaders)
        return ""


class MockWebServer(HTTPWebServer):
    """A mock webserver for testing."""

    def __init__(self):
        """Start up this instance."""
        root = RootResource()
        super(MockWebServer, self).__init__(root)
