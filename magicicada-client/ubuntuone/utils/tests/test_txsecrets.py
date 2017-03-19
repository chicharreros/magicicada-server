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

"""Tests for txkeyring."""

import logging
import uuid

import dbus.service

from twisted.internet.defer import inlineCallbacks, returnValue
from ubuntuone.devtools.testcases.dbus import DBusTestCase

from ubuntuone.utils import txsecrets

KEY_TYPE_ATTR = {"key-type": "Foo credentials"}
ERROR_CREATE_BUT_LOCKED = "Cannot create an item in a locked collection"
PROMPT_BASE_PATH = "/org/freedesktop/secrets/prompt"
SESSION_BASE_PATH = "/org/freedesktop/secrets/session"
COLLECTION_BASE_PATH = "/org/freedesktop/secrets/collection/"
SAMPLE_CONTENT_TYPE = "text/plain; charset=utf8"


class InvalidProperty(Exception):
    """An exception for when invalid properties are passed in."""


class SampleMiscException(Exception):
    """An exception that will be turned into a DBus Exception."""


class ItemMock(dbus.service.Object):
    """An item contains a secret, lookup attributes and has a label."""
    get_secret_fail = False
    delete_fail = False
    delete_prompt = False
    dismissed = False

    def __init__(self, collection, label, attributes, value, *args, **kwargs):
        """Initialize this instance."""
        super(ItemMock, self).__init__(*args, **kwargs)
        self.collection = collection
        self.label = label
        self.attributes = attributes
        self.value = value

    @dbus.service.method(dbus_interface=txsecrets.ITEM_IFACE,
                         out_signature="o")
    def Delete(self):
        """Delete this item."""
        if self.delete_fail:
            raise SampleMiscException()
        self.collection.items.remove(self)
        if self.delete_prompt:
            prompt_path = create_object_path(PROMPT_BASE_PATH)
            prompt = self.dbus_publish(prompt_path, PromptMock,
                                       result="",
                                       dismissed=self.dismissed)
            return prompt
        else:
            return "/"

    @dbus.service.method(dbus_interface=txsecrets.ITEM_IFACE,
                         in_signature="o", out_signature="(oayay)")
    def GetSecret(self, session):
        """Retrieve the secret for this item."""
        if self.get_secret_fail:
            raise SampleMiscException()
        return (session, "", self.value)

    def matches(self, search_attr):
        """See if this item matches a given search."""
        for k, val in search_attr.items():
            if k not in self.attributes:
                return False
            if self.attributes[k] != val:
                return False
        return True


class PromptMock(dbus.service.Object):
    """A prompt necessary to complete an operation."""

    def __init__(self, dismissed=True,
                 result=dbus.String("", variant_level=1), *args, **kwargs):
        """Initialize this instance."""
        super(PromptMock, self).__init__(*args, **kwargs)
        self.dismissed = dismissed
        self.result = result

    @dbus.service.method(dbus_interface=txsecrets.PROMPT_IFACE,
                         in_signature="s")
    def Prompt(self, window_id):
        """Perform the prompt."""
        self.Completed(self.dismissed, self.result)

    @dbus.service.signal(dbus_interface=txsecrets.PROMPT_IFACE,
                         signature="bv")
    def Completed(self, dismissed, result):
        """The prompt and operation completed."""


class BaseCollectionMock(dbus.service.Object):
    """Base collection of items containing secrets."""
    SUPPORTS_MULTIPLE_OBJECT_PATHS = True
    SUPPORTS_MULTIPLE_CONNECTIONS = True
    create_item_prompt = False
    dismissed = False
    create_item_fail = False
    locked = False
    unlock_prompts = False
    item_mock_class = ItemMock

    item_attrs_property = txsecrets.ITEM_ATTRIBUTES_PROPERTY_OLD
    item_label_property = txsecrets.ITEM_LABEL_PROPERTY_OLD
    clxn_label_property = txsecrets.CLXN_LABEL_PROPERTY_OLD

    def __init__(self, label, *args, **kwargs):
        """Initialize this instance."""
        super(BaseCollectionMock, self).__init__(*args, **kwargs)
        self.items = []
        self.label = label

    def _create_item(self, properties, secret, replace):
        """Create an item with the given attributes, secret and label.

        If replace is set, then it replaces an item already present with the
        same values for the attributes.
        """
        if self.create_item_fail:
            raise SampleMiscException()
        if self.locked:
            raise SampleMiscException(ERROR_CREATE_BUT_LOCKED)
        attributes = properties[self.item_attrs_property]
        item_label = properties[self.item_label_property]
        value = secret[2]
        item_path = create_object_path(make_coll_path(self.label))
        item = self.dbus_publish(item_path, self.item_mock_class, self,
                                 item_label, attributes, value)
        self.items.append(item)
        if self.create_item_prompt:
            prompt_path = create_object_path(PROMPT_BASE_PATH)
            prompt = self.dbus_publish(prompt_path, PromptMock,
                                       result=item,
                                       dismissed=self.dismissed)
            return "/", prompt
        else:
            return item, "/"

    @dbus.service.method(dbus_interface=txsecrets.PROPERTIES_IFACE,
                         in_signature="ss", out_signature="v")
    def Get(self, interface, propname):
        """The only property implemented is Label."""
        if interface == txsecrets.COLLECTION_IFACE and \
                propname == self.clxn_label_property:
            return dbus.String(self.label)
        raise InvalidProperty("Invalid property: {}".format(propname))


class CollectionMock(BaseCollectionMock):
    """Collection of items containing secrets."""

    @dbus.service.method(dbus_interface=txsecrets.COLLECTION_IFACE,
                         in_signature="a{sv}(oayay)b", out_signature="oo",
                         byte_arrays=True)
    def CreateItem(self, properties, secret, replace):
        """Expose the _create_item method on DBus."""
        assert len(secret) == 3
        return self._create_item(properties, secret, replace)


class SessionMock(dbus.service.Object):
    """A session tracks state between the service and a client application."""

    @dbus.service.method(dbus_interface=txsecrets.SESSION_IFACE)
    def Close(self):
        """Close this session."""


def make_coll_path(label):
    """Make the path to a collection with its label"""
    return COLLECTION_BASE_PATH + label


class SecretServiceMock(dbus.service.Object):
    """The Secret Service manages all the sessions and collections."""
    create_collection_prompt = False
    create_collection_fail = False
    open_session_fail = False
    dismissed = False
    collection_mock_class = CollectionMock

    clxn_label_property = txsecrets.CLXN_LABEL_PROPERTY_OLD
    collections_property = txsecrets.COLLECTIONS_PROPERTY_OLD

    def __init__(self, *args, **kwargs):
        """Initialize this instance."""
        super(SecretServiceMock, self).__init__(*args, **kwargs)
        self.sessions = {}
        self.collections = {}
        self.aliases = {}

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="sv", out_signature="vo")
    def OpenSession(self, algorithm, algorithm_parameters):
        """Open a unique session for the caller application."""
        if self.open_session_fail:
            raise SampleMiscException()
        session_path = create_object_path(SESSION_BASE_PATH)
        session = self.dbus_publish(session_path, SessionMock)
        self.sessions[session_path] = session
        return True, session

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="a{sv}", out_signature="oo")
    def CreateCollection(self, properties):
        """Create a new collection with the specified properties."""
        if self.create_collection_fail:
            raise SampleMiscException()
        label = str(properties[self.clxn_label_property])
        coll_path = make_coll_path(label)
        collection = self.dbus_publish(coll_path, self.collection_mock_class,
                                       label)
        self.collections[label] = collection

        if self.create_collection_prompt:
            prompt_path = create_object_path(PROMPT_BASE_PATH)
            prompt = self.dbus_publish(prompt_path, PromptMock,
                                       result=collection,
                                       dismissed=self.dismissed)
            return "/", prompt
        else:
            return collection, "/"

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="a{ss}", out_signature="aoao")
    def SearchItems(self, attributes):
        """Find items in any collection."""
        unlocked_items = []
        locked_items = []
        for c in self.collections.values():
            if c.locked:
                append_item = locked_items.append
            else:
                append_item = unlocked_items.append
            for i in c.items:
                if i.matches(attributes):
                    append_item(i)

        return unlocked_items, locked_items

    def unlock_objects(self, objects):
        """Unlock the objects or its containers."""
        for c in self.collections.values():
            for l in c.locations:
                path = l[1]
                if path in objects:
                    c.locked = False
            for i in c.items:
                for l in i.locations:
                    path = l[1]
                    if path in objects:
                        c.locked = False

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="ao", out_signature="aoo")
    def Unlock(self, objects):
        """Unlock the specified objects."""
        locked = []
        unlocked = []
        for c in self.collections.values():
            for i in c.items:
                path = i.__dbus_object_path__
                if path in objects:
                    if c.unlock_prompts:
                        locked.append(path)
                    else:
                        unlocked.append(path)
        if locked:
            prompt_path = create_object_path(PROMPT_BASE_PATH)
            self.unlock_objects(objects)
            prompt = self.dbus_publish(prompt_path, PromptMock,
                                       result=locked,
                                       dismissed=self.dismissed)
            return unlocked, prompt
        else:
            self.unlock_objects(objects)
            return objects, "/"

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="s", out_signature="o")
    def ReadAlias(self, name):
        """Get the collection with the given alias."""
        result = self.aliases.get(name, "/")
        return result

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="so")
    def SetAlias(self, name, collection_path):
        """Setup a collection alias."""
        self.aliases[name] = collection_path

    @dbus.service.method(dbus_interface=txsecrets.PROPERTIES_IFACE,
                         in_signature="ss", out_signature="v")
    def Get(self, interface, propname):
        """The only property implemented is Collections."""
        if interface == txsecrets.SERVICE_IFACE and \
                propname == self.collections_property:
            coll_paths = [make_coll_path(l) for l in self.collections]
            return dbus.Array(coll_paths, signature="o", variant_level=1)
        raise InvalidProperty("Invalid property: {}".format(propname))


class AltItemMock(ItemMock):
    """The secret in this item has a content_type."""

    @dbus.service.method(dbus_interface=txsecrets.ITEM_IFACE,
                         in_signature="o", out_signature="(oayays)")
    def GetSecret2(self, session):
        """Retrieve the secret for this item."""
        if self.get_secret_fail:
            raise SampleMiscException()
        return (session, "", self.value, SAMPLE_CONTENT_TYPE)


class AltCollectionMock(BaseCollectionMock):
    """The secrets in this collection have a content_type field."""

    item_mock_class = AltItemMock

    item_attrs_property = txsecrets.ITEM_ATTRIBUTES_PROPERTY
    item_label_property = txsecrets.ITEM_LABEL_PROPERTY
    clxn_label_property = txsecrets.CLXN_LABEL_PROPERTY

    @dbus.service.method(dbus_interface=txsecrets.COLLECTION_IFACE,
                         in_signature="a{sv}(oayays)b", out_signature="oo",
                         byte_arrays=True)
    def CreateItem(self, properties, secret, replace):
        """Expose the _create_item method on DBus."""
        assert len(secret) == 4
        return self._create_item(properties, secret, replace)


class AltSecretServiceMock(SecretServiceMock):
    """The secrets in this service have a content_type field."""

    collection_mock_class = AltCollectionMock

    clxn_label_property = txsecrets.CLXN_LABEL_PROPERTY
    collections_property = txsecrets.COLLECTIONS_PROPERTY

    @dbus.service.method(dbus_interface=txsecrets.SERVICE_IFACE,
                         in_signature="a{sv}s", out_signature="oo")
    def CreateCollection(self, properties, alias):
        """Create a new collection with the specified properties."""
        collection, prompt = super(AltSecretServiceMock,
                                   self).CreateCollection(properties)
        self.SetAlias(alias, collection)
        return collection, prompt


def create_object_path(base):
    """Create a random object path given a base path."""
    random = uuid.uuid4().hex
    return base + "/" + random


class TextFilter(object):
    """Prevents the logging of messages containing a given text."""

    def __init__(self, *args):
        """Initialize this filter."""
        super(TextFilter, self).__init__()
        self.filtered_strings = args

    def filter(self, record):
        """See if we need to filter a given log record."""
        return not any(s in record.msg for s in self.filtered_strings)


class BaseTestCase(DBusTestCase):
    """Base class for DBus tests."""
    timeout = 10
    secret_service_class = SecretServiceMock

    @inlineCallbacks
    def setUp(self):
        yield super(BaseTestCase, self).setUp()
        self.session_bus = dbus.SessionBus()
        self.mock_service = self.dbus_publish(txsecrets.SECRETS_SERVICE,
                                              self.secret_service_class)
        self.secretservice = txsecrets.SecretService()
        self.silence_dbus_logging()

    def silence_dbus_logging(self):
        """Silence the warnings printed by dbus that pollute test results."""
        logger = logging.getLogger('dbus.connection')
        logfilter = TextFilter("Unable to set arguments")
        logger.addFilter(logfilter)
        self.addCleanup(logger.removeFilter, logfilter)

    def dbus_publish(self, object_path, object_class, *args, **kwargs):
        """Create an object and publish it on the bus."""
        name = self.session_bus.request_name(txsecrets.BUS_NAME,
                                             dbus.bus.NAME_FLAG_DO_NOT_QUEUE)
        self.assertNotEqual(name, dbus.bus.REQUEST_NAME_REPLY_EXISTS)
        mock_object = object_class(*args, object_path=object_path,
                                   conn=self.session_bus, **kwargs)
        self.addCleanup(mock_object.remove_from_connection,
                        connection=self.session_bus,
                        path=object_path)
        mock_object.dbus_publish = self.dbus_publish
        return mock_object

    @inlineCallbacks
    def create_sample_collection(self, label, make_alias=True,
                                 publish_default_path=False):
        """Create a collection with a given label."""
        coll = yield self.secretservice.create_collection(label)
        if make_alias:
            coll_path = make_coll_path(label)
            self.mock_service.SetAlias("default", coll_path)
        if publish_default_path:
            mock_object = self.mock_service.collections[label]
            mock_object.add_to_connection(self.session_bus,
                                          txsecrets.DEFAULT_COLLECTION)
            self.addCleanup(mock_object.remove_from_connection,
                            connection=self.session_bus,
                            path=txsecrets.DEFAULT_COLLECTION)
        returnValue(coll)


class SecretServiceTestCase(BaseTestCase):
    """Test the Secret Service class."""

    @inlineCallbacks
    def test_open_session(self):
        """The secret service session is opened."""
        result = yield self.secretservice.open_session()
        self.assertEqual(result, self.secretservice)

    @inlineCallbacks
    def test_open_session_throws_dbus_error_as_failure(self):
        """The secret service open session throws a dbus error as a failure."""
        d = self.secretservice.open_session()
        self.mock_service.open_session_fail = True
        yield self.assertFailure(d, dbus.exceptions.DBusException)

    @inlineCallbacks
    def test_open_session_fails_before_opening_as_failure(self):
        """A dbus error before opening the session is thrown as a failure."""

        def fail(*args, **kwargs):
            """Throw a DBus exception."""
            raise dbus.exceptions.DBusException()

        self.patch(txsecrets.dbus, "SessionBus", fail)
        d = self.secretservice.open_session()
        self.mock_service.open_session_fail = True
        yield self.assertFailure(d, dbus.exceptions.DBusException)

    @inlineCallbacks
    def test_create_collection(self):
        """The secret service creates a collection."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        self.assertIn(collection_label, self.mock_service.collections)

    @inlineCallbacks
    def test_create_collection_prompt(self):
        """The secret service creates a collection after a prompt."""
        yield self.secretservice.open_session()
        self.mock_service.create_collection_prompt = True
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        self.assertIn(collection_label, self.mock_service.collections)

    @inlineCallbacks
    def test_create_collection_prompt_dismissed(self):
        """The service fails to create collection when prompt dismissed."""
        yield self.secretservice.open_session()
        self.mock_service.create_collection_prompt = True
        self.mock_service.dismissed = True
        collection_label = "sample_keyring"
        yield self.assertFailure(
            self.create_sample_collection(collection_label),
            txsecrets.UserCancelled)

    @inlineCallbacks
    def test_create_collection_throws_dbus_error(self):
        """The service fails to create collection on a DBus error."""
        yield self.secretservice.open_session()
        self.mock_service.create_collection_fail = True
        collection_label = "sample_keyring"
        yield self.assertFailure(
            self.create_sample_collection(collection_label),
            dbus.exceptions.DBusException)

    @inlineCallbacks
    def test_prompt_accepted(self):
        """A prompt is accepted."""
        yield self.secretservice.open_session()
        expected_result = "hello world"
        prompt_path = "/prompt"
        self.dbus_publish(prompt_path, PromptMock, result=expected_result,
                          dismissed=False)
        result = yield self.secretservice.do_prompt(prompt_path)
        self.assertEqual(result, expected_result)

    @inlineCallbacks
    def test_prompt_dismissed(self):
        """A prompt is dismissed with a UserCancelled failure."""
        yield self.secretservice.open_session()
        expected_result = "hello world2"
        prompt_path = "/prompt"
        self.dbus_publish(prompt_path, PromptMock, result=expected_result,
                          dismissed=True)
        d = self.secretservice.do_prompt(prompt_path)
        self.assertFailure(d, txsecrets.UserCancelled)

    @inlineCallbacks
    def test_search_unlocked_items(self):
        """The secret service searchs for unlocked items."""
        yield self.secretservice.open_session()
        coll = yield self.create_sample_collection("sample_keyring")
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        value = yield items[0].get_value()
        self.assertEqual(value, sample_secret)

    @inlineCallbacks
    def test_search_locked_items(self):
        """The secret service searchs for locked items."""
        yield self.secretservice.open_session()
        collection_name = "sample_keyring"
        coll = yield self.create_sample_collection(collection_name)
        mock_collection = self.mock_service.collections[collection_name]
        attr = KEY_TYPE_ATTR
        sample_secret = "secret99!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        mock_collection.locked = True

        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        value = yield items[0].get_value()
        self.assertEqual(value, sample_secret)

    @inlineCallbacks
    def test_search_locked_items_prompts(self):
        """The secret service searchs for locked items after a prompt."""
        yield self.secretservice.open_session()
        collection_name = "sample_keyring"
        coll = yield self.create_sample_collection(collection_name)
        mock_collection = self.mock_service.collections[collection_name]
        attr = KEY_TYPE_ATTR
        sample_secret = "secret99!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        mock_collection.locked = True
        mock_collection.unlock_prompts = True

        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        value = yield items[0].get_value()
        self.assertEqual(value, sample_secret)

    @inlineCallbacks
    def test_search_locked_items_prompts_dismissed(self):
        """Service fails search for locked items after dismissed prompt."""
        yield self.secretservice.open_session()
        collection_name = "sample_keyring"
        coll = yield self.create_sample_collection(collection_name)
        mock_collection = self.mock_service.collections[collection_name]
        self.mock_service.dismissed = True
        attr = KEY_TYPE_ATTR
        sample_secret = "secret99!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        mock_collection.locked = True
        mock_collection.unlock_prompts = True

        d = self.secretservice.search_items(attr)
        yield self.assertFailure(d, txsecrets.UserCancelled)

    @inlineCallbacks
    def test_search_items_merges_unlocked_and_locked_items(self):
        """search_items merges unlocked and locked items."""
        yield self.secretservice.open_session()
        attr = KEY_TYPE_ATTR

        collection_name = "coll1"
        coll = yield self.create_sample_collection(collection_name)
        mock_coll1 = self.mock_service.collections[collection_name]
        unlocked_secret = "coll 1 secret!"
        yield coll.create_item("Cucaracha", attr, unlocked_secret)
        mock_coll1.locked = False
        mock_coll1.unlock_prompts = False

        collection_name = "coll2"
        coll = yield self.create_sample_collection(collection_name)
        mock_coll2 = self.mock_service.collections[collection_name]
        locked_secret = "coll 2 secret!"
        yield coll.create_item("Cucaracha", attr, locked_secret)
        mock_coll2.locked = True
        mock_coll2.unlock_prompts = False

        result = yield self.secretservice.search_items(attr)
        self.assertEqual(len(result), 2)

    @inlineCallbacks
    def test_search_items_merges_unlocked_locked_and_prompt_items(self):
        """search_items merges unlocked, locked and prompt items."""
        yield self.secretservice.open_session()
        attr = KEY_TYPE_ATTR

        collection_name = "coll1"
        coll = yield self.create_sample_collection(collection_name)
        mock_coll1 = self.mock_service.collections[collection_name]
        unlocked_secret = "coll 1 secret!"
        yield coll.create_item("Cucaracha", attr, unlocked_secret)
        mock_coll1.locked = False
        mock_coll1.unlock_prompts = False

        collection_name = "coll2"
        coll = yield self.create_sample_collection(collection_name)
        mock_coll2 = self.mock_service.collections[collection_name]
        locked_secret = "coll 2 secret!"
        yield coll.create_item("Cucaracha", attr, locked_secret)
        mock_coll2.locked = True
        mock_coll2.unlock_prompts = False

        collection_name = "coll3"
        coll = yield self.create_sample_collection(collection_name)
        mock_coll3 = self.mock_service.collections[collection_name]
        locked_secret = "coll 3 secret!"
        yield coll.create_item("Cucaracha", attr, locked_secret)
        mock_coll3.locked = True
        mock_coll3.unlock_prompts = True

        result = yield self.secretservice.search_items(attr)
        self.assertEqual(len(result), 3)

    @inlineCallbacks
    def test_get_collections(self):
        """The list of all collections is returned."""
        collection_names = ["collection1", "collection2"]

        yield self.secretservice.open_session()
        for name in collection_names:
            yield self.create_sample_collection(name)
        collections = yield self.secretservice.get_collections()
        self.assertEqual(len(collections), len(collection_names))

    @inlineCallbacks
    def test_get_default_collection_honours_default_path(self):
        """The default collection is returned from the default path."""
        yield self.secretservice.open_session()
        collection_name = "sample_default_keyring"
        yield self.create_sample_collection(collection_name, make_alias=False,
                                            publish_default_path=True)
        self.assertEqual(len(self.mock_service.collections), 1)
        yield self.secretservice.get_default_collection()
        self.assertEqual(len(self.mock_service.collections), 1)

    @inlineCallbacks
    def test_get_default_collection_honours_readalias(self):
        """The default collection is returned if default alias set."""
        yield self.secretservice.open_session()
        collection_name = "sample_default_keyring"
        yield self.create_sample_collection(collection_name)
        self.assertEqual(len(self.mock_service.collections), 1)
        yield self.secretservice.get_default_collection()
        self.assertEqual(len(self.mock_service.collections), 1)

    @inlineCallbacks
    def test_get_default_collection_created_if_no_default(self):
        """The default collection is created if there's no default."""
        yield self.secretservice.open_session()
        collection_name = "sample_nondefault_keyring"
        yield self.create_sample_collection(collection_name, make_alias=False)
        self.assertEqual(len(self.mock_service.collections), 1)
        yield self.secretservice.get_default_collection()
        self.assertEqual(len(self.mock_service.collections), 2)

    @inlineCallbacks
    def test_get_default_collection_created_if_nonexistent(self):
        """The default collection is created if it doesn't exist yet."""
        yield self.secretservice.open_session()
        self.assertEqual(len(self.mock_service.collections), 0)
        yield self.secretservice.get_default_collection()
        self.assertEqual(len(self.mock_service.collections), 1)

    @inlineCallbacks
    def test_get_default_collection_set_as_default_if_nonexistent(self):
        """The default collection is set as default if it doesn't exist yet."""
        yield self.secretservice.open_session()
        yield self.secretservice.get_default_collection()
        self.assertIn(txsecrets.DEFAULT_LABEL, self.mock_service.aliases)

    @inlineCallbacks
    def test_get_default_collection_is_unlocked_default_path(self):
        """The default collection is unlocked before being returned."""
        yield self.secretservice.open_session()
        collection_name = "sample_keyring"
        self.assertEqual(len(self.mock_service.collections), 0)
        coll = yield self.create_sample_collection(collection_name,
                                                   make_alias=False,
                                                   publish_default_path=True)
        self.assertEqual(len(self.mock_service.collections), 1)
        mock_collection = self.mock_service.collections[collection_name]
        mock_collection.locked = True
        yield self.secretservice.get_default_collection()
        attr = KEY_TYPE_ATTR
        sample_secret = "secret!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        self.assertEqual(len(mock_collection.items), 1)

    @inlineCallbacks
    def test_get_default_collection_is_unlocked_readalias(self):
        """The default collection is unlocked before being returned."""
        yield self.secretservice.open_session()
        collection_name = "sample_keyring"
        self.assertEqual(len(self.mock_service.collections), 0)
        coll = yield self.create_sample_collection(collection_name)
        self.assertEqual(len(self.mock_service.collections), 1)
        mock_collection = self.mock_service.collections[collection_name]
        mock_collection.locked = True
        yield self.secretservice.get_default_collection()
        attr = KEY_TYPE_ATTR
        sample_secret = "secret!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        self.assertEqual(len(mock_collection.items), 1)


class CollectionTestCase(BaseTestCase):
    """Test the Collection class."""

    @inlineCallbacks
    def test_get_label(self):
        """The collection gets its own label from the keyring."""
        yield self.secretservice.open_session()
        expected_label = "sample_keyring"
        yield self.create_sample_collection(expected_label)
        coll = yield self.secretservice.get_default_collection()
        result = yield coll.get_label()
        self.assertEqual(result, expected_label)

    @inlineCallbacks
    def test_create_item(self):
        """The collection creates an item."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        coll = yield self.secretservice.get_default_collection()
        mock_collection = self.mock_service.collections[collection_label]
        attr = KEY_TYPE_ATTR
        sample_secret = "secret!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        self.assertEqual(len(mock_collection.items), 1)
        self.assertEqual(mock_collection.items[0].value, sample_secret)

    @inlineCallbacks
    def test_create_item_prompt(self):
        """The collection creates an item after a prompt."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        coll = yield self.secretservice.get_default_collection()
        mock_collection = self.mock_service.collections[collection_label]
        mock_collection.create_item_prompt = True
        attr = KEY_TYPE_ATTR
        sample_secret = "secret2!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        self.assertEqual(len(mock_collection.items), 1)
        self.assertEqual(mock_collection.items[0].value, sample_secret)

    @inlineCallbacks
    def test_create_item_prompt_dismissed(self):
        """The collection fails to create an item when prompt is dismissed."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        coll = yield self.secretservice.get_default_collection()
        mock_collection = self.mock_service.collections[collection_label]
        mock_collection.create_item_prompt = True
        mock_collection.dismissed = True
        attr = KEY_TYPE_ATTR
        sample_secret = "secret3!"
        yield self.assertFailure(coll.create_item("Cuca", attr, sample_secret),
                                 txsecrets.UserCancelled)

    @inlineCallbacks
    def test_create_item_throws_dbus_error(self):
        """The collection fails to create an item when DBus fails."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        coll = yield self.secretservice.get_default_collection()
        mock_collection = self.mock_service.collections[collection_label]
        mock_collection.create_item_fail = True
        attr = KEY_TYPE_ATTR
        sample_secret = "secret4!"
        yield self.assertFailure(coll.create_item("Cuca", attr, sample_secret),
                                 dbus.exceptions.DBusException)


class ItemTestCase(BaseTestCase):
    """Test the Item class."""

    @inlineCallbacks
    def test_get_value(self):
        """The secret value is retrieved from the item."""
        yield self.secretservice.open_session()
        coll = yield self.create_sample_collection("sample_keyring")
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        value = yield items[0].get_value()
        self.assertEqual(value, sample_secret)

    @inlineCallbacks
    def test_get_value_throws_dbus_error(self):
        """The secret value is not retrieved if DBus fails."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        coll = yield self.create_sample_collection(collection_label)
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        mock = self.mock_service.collections[collection_label].items[0]
        mock.get_secret_fail = True
        yield self.assertFailure(items[0].get_value(),
                                 dbus.exceptions.DBusException)

    @inlineCallbacks
    def test_delete(self):
        """The item is deleted."""
        yield self.secretservice.open_session()
        coll = yield self.create_sample_collection("sample_keyring")
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        yield items[0].delete()
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 0)

    @inlineCallbacks
    def test_delete_prompt(self):
        """The item is deleted after a prompt."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        coll = yield self.create_sample_collection(collection_label)
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        mock_item = self.mock_service.collections[collection_label].items[0]
        mock_item.delete_prompt = True
        yield items[0].delete()
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 0)

    @inlineCallbacks
    def test_delete_prompt_dismissed(self):
        """The item is not deleted after a dismissed prompt."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        coll = yield self.create_sample_collection(collection_label)
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        mock_item = self.mock_service.collections[collection_label].items[0]
        mock_item.delete_prompt = True
        mock_item.dismissed = True
        yield self.assertFailure(items[0].delete(), txsecrets.UserCancelled)

    @inlineCallbacks
    def test_delete_throws_dbus_error(self):
        """The item is not deleted when a DBus error happens."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        coll = yield self.create_sample_collection(collection_label)
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        mock_item = self.mock_service.collections[collection_label].items[0]
        mock_item.delete_fail = True
        yield self.assertFailure(items[0].delete(),
                                 dbus.exceptions.DBusException)


class AltItemTestCase(BaseTestCase):
    """Test the Item class with 4 fields in the secret struct."""
    secret_service_class = AltSecretServiceMock

    @inlineCallbacks
    def test_create_item_four_fields_per_secret(self):
        """The collection creates an item when the dbus struct has 4 fields."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        yield self.create_sample_collection(collection_label)
        coll = yield self.secretservice.get_default_collection()
        mock_collection = self.mock_service.collections[collection_label]
        attr = KEY_TYPE_ATTR
        sample_secret = "secret!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        self.assertEqual(len(mock_collection.items), 1)
        self.assertEqual(mock_collection.items[0].value, sample_secret)

    @inlineCallbacks
    def test_get_value_four_fields_per_secret(self):
        """The code works fine when the secret dbus struct has 4 fields."""
        yield self.secretservice.open_session()
        collection_label = "sample_keyring"
        coll = yield self.create_sample_collection(collection_label)
        attr = KEY_TYPE_ATTR
        sample_secret = "secret83!"
        yield coll.create_item("Cucaracha", attr, sample_secret)
        items = yield self.secretservice.search_items(attr)
        self.assertEqual(len(items), 1)
        value = yield items[0].get_value()
        self.assertEqual(value, sample_secret)
