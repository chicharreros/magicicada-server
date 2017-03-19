# -*- coding: utf-8 -*-
#
# Copyright 2011-2012 Canonical Ltd.
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

"""Handle keys in the local kerying."""

from __future__ import unicode_literals

import logging
import socket
import sys

try:
    from urllib.parse import parse_qsl, urlencode
except ImportError:
    from urllib import urlencode
    from urlparse import parse_qsl

from twisted.internet.defer import inlineCallbacks, returnValue

from ubuntuone.clientdefs import NAME
from ubuntuone.utils import compat
from ubuntuone.utils.txsecrets import SecretService


logger = logging.getLogger(__name__)

TOKEN_SEPARATOR = ' @ '
SEPARATOR_REPLACEMENT = ' AT '


def gethostname():
    """Get the hostname, return the name as unicode."""
    sys_encoding = sys.getfilesystemencoding()
    hostname = socket.gethostname()
    if isinstance(hostname, compat.binary_type):
        return hostname.decode(sys_encoding)
    return hostname


def get_token_name(app_name):
    """Build the token name.. Return an unicode."""
    computer_name = gethostname()
    computer_name = computer_name.replace(TOKEN_SEPARATOR,
                                          SEPARATOR_REPLACEMENT)

    assert isinstance(computer_name, compat.text_type)
    assert isinstance(computer_name, compat.text_type)

    return TOKEN_SEPARATOR.join((app_name, computer_name))


class Keyring(object):
    """A Keyring for a given application name."""

    def __init__(self):
        """Initialize this instance."""
        self.service = SecretService()

    def _get_keyring_attr(self, app_name):
        """Build the keyring attributes for this credentials."""
        attr = {"key-type": "%s credentials" % NAME,
                "token-name": get_token_name(app_name)}
        return attr

    @inlineCallbacks
    def _find_keyring_item(self, app_name, attr=None):
        """Return the keyring item or None if not found."""
        if attr is None:
            attr = self._get_keyring_attr(app_name)
        logger.debug("Finding all items for app_name %r.", app_name)
        items = yield self.service.search_items(attr)
        if len(items) == 0:
            # if no items found, return None
            logger.debug("No items found!")
            returnValue(None)

        logger.debug("Returning first item found.")
        returnValue(items[0])

    @inlineCallbacks
    def set_credentials(self, app_name, cred):
        """Set the credentials."""
        # Creates the secret from the credentials
        secret = urlencode(cred)

        attr = self._get_keyring_attr(app_name)
        # Add our credentials to the keyring
        yield self.service.open_session()
        collection = yield self.service.get_default_collection()
        yield collection.create_item(app_name, attr, secret, True)

    @inlineCallbacks
    def get_credentials(self, app_name):
        """A deferred with the secret in a dictionary."""
        # If we have no attributes, return None
        logger.debug("Getting credentials for %r.", app_name)
        yield self.service.open_session()
        item = yield self._find_keyring_item(app_name)
        if item is not None:
            logger.debug("Parsing secret.")
            secret = yield item.get_value()
            returnValue(dict(parse_qsl(secret)))

        # nothing was found
        returnValue(None)

    @inlineCallbacks
    def delete_credentials(self, app_name):
        """Delete a set of credentials from the keyring."""
        attr = self._get_keyring_attr(app_name)
        # Add our credentials to the keyring
        yield self.service.open_session()
        collection = yield self.service.get_default_collection()
        yield collection.create_item(app_name, attr, "secret!", True)

        item = yield self._find_keyring_item(app_name)
        if item is not None:
            yield item.delete()
