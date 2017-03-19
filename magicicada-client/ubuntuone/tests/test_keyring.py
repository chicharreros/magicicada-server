# -*- coding: utf-8 -*-
#
# Copyright 2010-2012 Canonical Ltd.
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

"""Tests for the keyring common module."""

from __future__ import unicode_literals

from twisted.internet import defer
from twisted.internet.defer import inlineCallbacks
from twisted.trial.unittest import TestCase

from ubuntuone import keyring


class MockItem(object):
    """An item contains a secret, lookup attributes and has a label."""

    def __init__(self, label, collection, attr, value):
        """Initialize a new Item."""
        self.label = label
        self.collection = collection
        self.attributes = attr
        self.value = value

    def get_value(self):
        """Retrieve the secret for this item."""
        return defer.succeed(self.value)

    def delete(self):
        """Delete this item."""
        self.collection.items.remove(self)
        return defer.succeed(None)

    def matches(self, search_attr):
        """See if this item matches a given search."""
        for k, val in search_attr.items():
            if k not in self.attributes:
                return False
            if self.attributes[k] != val:
                return False
        return True


class MockCollection(object):
    """A collection of items containing secrets."""

    def __init__(self, label, service):
        """Initialize a new collection."""
        self.label = label
        self.service = service
        self.items = []

    def create_item(self, label, attr, value, replace=True):
        """Create an item with the given attributes, secret and label."""
        item = MockItem(label, self, attr, value)
        self.items.append(item)
        return defer.succeed(item)


class MockSecretService(object):
    """A class that mocks txsecrets.SecretService."""

    def __init__(self, *args, **kwargs):
        super(MockSecretService, self).__init__(*args, **kwargs)
        self.collections = {}

    def open_session(self, window_id=0):
        """Open a unique session for the caller application."""
        return defer.succeed(self)

    def search_items(self, attributes):
        """Find items in any collection."""
        results = []
        for collection in self.collections.values():
            for item in collection.items:
                if item.matches(attributes):
                    results.append(item)
        return defer.succeed(results)

    def create_collection(self, label):
        """Create a new collection with the specified properties."""
        collection = MockCollection(label, self)
        self.collections[label] = collection
        if "default" not in self.collections:
            self.collections["default"] = collection
        return defer.succeed(collection)

    def get_default_collection(self):
        """The collection were default items should be created."""
        if len(self.collections) == 0:
            self.create_collection("default")
        return defer.succeed(self.collections["default"])


class TestGetHostname(TestCase):
    """Test the function that gets the hostname."""

    def test_get_hostname(self):
        """The common case."""
        fake_hostname = "fake hostname"
        self.patch(keyring.socket, "gethostname", lambda: fake_hostname)
        self.assertEqual(keyring.gethostname(), fake_hostname)

    def test_get_hostname_uses_filesystem_encoding(self):
        """The fs encoding is used to decode the name returned by socket."""
        fake_hostname = "Привет-ПК"
        hostname_koi8r = fake_hostname.encode("koi8-r")
        self.patch(keyring.socket, "gethostname", lambda: hostname_koi8r)
        self.patch(keyring.sys, "getfilesystemencoding", lambda: "koi8-r")
        self.assertEqual(keyring.gethostname(), fake_hostname)


class TestTokenNameBuilder(TestCase):
    """Test the function that builds the token name."""

    def check_build(self, sample_app_name, sample_hostname, expected_result):
        """Check the build of a given token."""
        self.patch(keyring, "gethostname", lambda *a: sample_hostname)
        result = keyring.get_token_name(sample_app_name)
        self.assertEqual(result, expected_result)

    def test_get_simple_token_name(self):
        """A simple token name is built right."""
        sample_app_name = "UbuntuTwo"
        sample_hostname = "Darkstar"
        expected_result = "UbuntuTwo @ Darkstar"
        self.check_build(sample_app_name, sample_hostname, expected_result)

    def test_get_complex_token_name_for_app_name(self):
        """A complex token name is built right too."""
        sample_app_name = "Ubuntu @ Eleven"
        sample_hostname = "Mate+Cocido"
        expected_result = "Ubuntu @ Eleven @ Mate+Cocido"
        self.check_build(sample_app_name, sample_hostname, expected_result)

    def test_get_complex_token_name_for_hostname(self):
        """A complex token name is built right too."""
        sample_app_name = "Ubuntu Eleven"
        sample_hostname = "Mate @ Cocido"
        expected_result = "Ubuntu Eleven @ Mate AT Cocido"
        self.check_build(sample_app_name, sample_hostname, expected_result)

    def test_get_unicode_appname_token_name(self):
        """A token name with unicode in the app name."""
        sample_app_name = "Ubuntu 四百六十九"
        sample_hostname = "Darkstar"
        expected_result = "Ubuntu 四百六十九 @ Darkstar"
        self.check_build(sample_app_name, sample_hostname, expected_result)

    def test_get_utf8_hostname_token_name(self):
        """A token name with utf8 in the host name."""
        sample_app_name = "Ubuntu Eleven"
        sample_hostname = "Привет-ПК"
        expected_result = "Ubuntu Eleven @ Привет-ПК"
        self.check_build(sample_app_name, sample_hostname, expected_result)


class TestKeyring(TestCase):
    """Test the keyring related functions."""

    timeout = 5

    @defer.inlineCallbacks
    def setUp(self):
        """Initialize the mock used in these tests."""
        yield super(TestKeyring, self).setUp()
        self.mock_service = None
        self.service = self.patch(keyring, "SecretService",
                                  self.get_mock_service)
        self.patch(keyring, "gethostname", lambda: "darkstar")

    def get_mock_service(self):
        """Create only one instance of the mock service per test."""
        if self.mock_service is None:
            self.mock_service = MockSecretService()
        return self.mock_service

    @inlineCallbacks
    def test_set_credentials(self):
        """Test that the set method does not erase previous keys."""
        sample_creds = {"name": "sample creds name"}
        sample_creds2 = {"name": "sample creds name 2"}
        kr = keyring.Keyring()
        yield kr.set_credentials("appname", sample_creds)
        yield kr.set_credentials("appname", sample_creds2)

        self.assertEqual(len(kr.service.collections["default"].items), 2)

    @inlineCallbacks
    def test_delete_credentials(self):
        """Test that a given key is deleted."""
        sample_creds = {"name": "sample creds name"}
        kr = keyring.Keyring()
        yield kr.set_credentials("appname", sample_creds)
        yield kr.delete_credentials("appname")

        self.assertEqual(len(kr.service.collections["default"].items), 1)

    @inlineCallbacks
    def test_get_credentials(self):
        """Test that credentials are properly retrieved."""
        sample_creds = {"name": "sample creds name"}
        kr = keyring.Keyring()
        yield kr.set_credentials("appname", sample_creds)

        result = yield kr.get_credentials("appname")
        self.assertEqual(result, sample_creds)
