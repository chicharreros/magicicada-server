#
# Author: Guillermo Gonzalez <guillermo.gonzalez@canonical.com>
#
# Copyright 2009-2012 Canonical Ltd.
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
"""Test file based persistent shelf."""

from __future__ import with_statement

import cPickle
import os
import hashlib
import unittest

from twisted.internet import defer
from ubuntuone.devtools.testcases import skipIfOS

from contrib.testing.testcase import BaseTwistedTestCase
from ubuntuone.platform import (
    open_file,
    path_exists,
)
from ubuntuone.syncdaemon.file_shelf import (
    FileShelf,
    CachedFileShelf,
    LRUCache,
    CacheInconsistencyError,
)


BROKEN_PICKLE = '\axb80\x02}q\x01(U\x01aU\x04testq\x02U\x01bU\x06brokenq\x03u.'


class TestFileShelf(BaseTwistedTestCase):
    """Test the FileShelf """
    fileshelf_class = FileShelf

    @defer.inlineCallbacks
    def setUp(self):
        """Set up a test."""
        yield super(TestFileShelf, self).setUp()
        self.path = self.mktemp('shelf')
        self.shelf = self.fileshelf_class(self.path)

    def test_bad_depth(self):
        """Test that the shelf reject invalid depth at creation time """
        self.assertRaises(
            ValueError, self.fileshelf_class, self.path, depth=-1)

    def test_bad_path(self):
        """Test that the shelf removes the previous shelve file and create a
        directory for the new file based shelf at creation time.
        """
        path = os.path.join(self.path, 'shelf_file')
        open_file(path, 'w').close()
        self.fileshelf_class(path)
        self.assertTrue(os.path.isdir(path))

    def test_different_depth_sizes(self):
        """Test the basic operations (delitem, getitem, setitem) with
        depths between 0 and len(hashlib.sha1().hexdigest())
        """
        base_path = os.path.join(self.path, 'shelf_depth-')
        sha1 = hashlib.sha1()
        for idx in xrange(0, len(sha1.hexdigest())):
            path = base_path + str(idx)
            shelf = self.fileshelf_class(path, depth=idx)
            key = sha1.hexdigest()
            # test __setitem__
            shelf[key] = 'foo'
            key_path = os.path.join(path, *[key[i] for i in xrange(0, idx)])
            self.assertTrue(path_exists(os.path.join(key_path, key)))
            # test __getitem__
            self.assertEqual('foo', shelf[key])
            # test __delitem__
            del shelf[key]
            self.assertRaises(KeyError, shelf.__getitem__, key)
            self.assertFalse(path_exists(os.path.join(key_path, key)))

    def test_invalid_keys(self):
        """Test the exception raised when invalid keys are eused ('', None)"""
        self.assertRaises(ValueError, self.shelf.__setitem__, None, 'foo')
        self.assertRaises(ValueError, self.shelf.__setitem__, '', 'foo')

    def test_contains(self):
        """Test that it behaves with the 'in' """
        path = os.path.join(self.path, 'shelf_depth')
        shelf = self.fileshelf_class(path)
        shelf["foo"] = "bar"
        self.assertTrue("foo" in shelf)
        self.assertFalse("baz" in shelf)
        self.assertEqual('bar', shelf.get('foo'))
        self.assertEqual(None, shelf.get('baz', None))

    def test_pop(self):
        """Test that it behaves with the .pop() """
        path = os.path.join(self.path, 'shelf_depth')
        shelf = self.fileshelf_class(path)
        shelf["foo"] = "bar"
        self.assertEqual("bar", shelf.pop("foo"))
        self.assertFalse("foo" in shelf)

        # bad key
        self.assertRaises(KeyError, shelf.pop, "no-key")

    def test_get(self):
        """Test that it behaves with the .get(key, default) """
        path = os.path.join(self.path, 'shelf_get')
        shelf = self.fileshelf_class(path)
        shelf["foo"] = "bar"
        self.assertEqual('bar', shelf.get('foo'))
        self.assertEqual('bar', shelf.get('foo', None))
        self.assertEqual(None, shelf.get('baz'))
        self.assertFalse(shelf.get('baz', False))

    def test_items(self):
        """Test that it behaves with the .items() """
        path = os.path.join(self.path, 'shelf_get')
        shelf = self.fileshelf_class(path)
        shelf["foo"] = "bar"
        self.assertEqual([('foo', 'bar')],
                         [(k, v) for k, v in shelf.items()])
        shelf["foo1"] = "bar1"
        items = [(k, v) for k, v in shelf.items()]
        self.assertIn(('foo', 'bar'), items)
        self.assertIn(('foo1', 'bar1'), items)

    def test_broken_metadata_without_backup(self):
        """test the shelf behavior when it hit a broken metadata file without
        backup.
        """
        self.shelf['bad_file'] = {}
        path = self.shelf.key_file('bad_file')
        open_file(path, 'w').close()
        self.assertRaises(KeyError, self.shelf.__getitem__, 'bad_file')

        self.shelf['broken_pickle'] = {}
        path = self.shelf.key_file('broken_pickle')
        with open_file(path, 'w') as f:
            f.write(BROKEN_PICKLE)
        self.assertRaises(KeyError, self.shelf.__getitem__, 'broken_pickle')

    def test_broken_metadata_with_backup(self):
        """test that each time a metadata file is updated a .old is kept"""
        self.shelf['bad_file'] = {'value': 'old'}
        path = self.shelf.key_file('bad_file')
        self.assertFalse(path_exists(path+'.old'))
        self.assertEqual({'value': 'old'}, self.shelf['bad_file'])
        # force the creation of the .old file
        self.shelf['bad_file'] = {'value': 'new'}
        self.assertTrue(path_exists(path+'.old'))
        # check that the new value is there
        self.assertEqual({'value': 'new'}, self.shelf['bad_file'])
        # write the current md file fwith 0 bytes
        open_file(path, 'w').close()
        # test that the old value is retrieved
        self.assertEqual({'value': 'old'}, self.shelf['bad_file'])

        self.shelf['broken_pickle'] = {'value': 'old'}
        path = self.shelf.key_file('broken_pickle')
        # check that .old don't exist
        self.assertFalse(path_exists(path+'.old'))
        # force the creation of the .old file
        self.shelf['broken_pickle'] = {'value': 'new'}
        # check that .old exists
        self.assertTrue(path_exists(path+'.old'))
        # check that the new value is there
        self.assertEqual({'value': 'new'}, self.shelf['broken_pickle'])
        # write random bytes to the md file
        with open_file(path, 'w') as f:
            f.write(BROKEN_PICKLE)
        # check that the old value is retrieved
        self.assertEqual({'value': 'old'}, self.shelf['broken_pickle'])

    def test_keys_with_old_and_new(self):
        """test keys() with .old and .new files around"""
        self.shelf["foo"] = "bar"
        self.shelf["foo1"] = "bar1"
        open_file(self.shelf.key_file('foo')+'.old', 'w').close()
        open_file(self.shelf.key_file('foo1')+'.old', 'w').close()
        open_file(self.shelf.key_file('foo')+'.new', 'w').close()
        open_file(self.shelf.key_file('foo1')+'.new', 'w').close()
        self.assertEqual(set(['foo', 'foo1']), set(self.shelf.keys()))

    def test_corrupted_backup(self):
        """test getitem if also the .old file is corrupted"""
        self.shelf["foo"] = "bar"
        # create the .old backup
        self.shelf["foo"] = "bar1"
        # write 0 bytes to both
        open_file(self.shelf.key_file('foo')+'.old', 'w').close()
        open_file(self.shelf.key_file('foo'), 'w').close()
        self.assertRaises(KeyError, self.shelf.__getitem__, 'foo')

    def test_endless_borken_backups(self):
        """test getitem  with a lot of files named .old.old.....old"""
        self.shelf["foo"] = "bar"
        path = self.shelf.key_file('foo')
        open_file(self.shelf.key_file('foo'), 'w').close()
        for _ in xrange(20):
            open_file(path + '.old', 'w').close()
            path += '.old'
        self.assertRaises(KeyError, self.shelf.__getitem__, 'foo')

    def test_delete_backups_too(self):
        """test that delitem also deletes the .old/.new files left around"""
        self.shelf["foo"] = "bar"
        # create the .old backup
        self.shelf["foo"] = "bar1"
        path = self.shelf.key_file('foo')
        # create a .new file (a hard reboot during the rename dance)
        open_file(path+'.new', 'w').close()
        # write 0 bytes to both
        del self.shelf['foo']
        self.assertFalse(path_exists(path))
        self.assertFalse(path_exists(path+'.old'), 'there is a .old file!')
        self.assertFalse(path_exists(path+'.new'), 'there is a .new file!')

    @skipIfOS('win32', 'Skipped because code is deprecated on Windows.')
    def test_custom_unpickle(self):
        """Test the _pickle and _unpikle methods."""
        self.mktemp('my_shelf')

        class InMemoryFileShelf(FileShelf):
            """A in-memory FileShelf."""

            values = {}

            def key_file(self, key):
                """Noop key_file method."""
                return key

            def _check_and_create_dirs(self, path):
                """Noop"""
                pass

            def _unpickle(self, fd):
                """Custom _unpickle."""
                return cPickle.loads(self.values[fd.name])

            def _pickle(self, value, fd, protocol=2):
                """Custom _pickle."""
                key = fd.name.strip('.new')
                self.values[key] = cPickle.dumps(value, protocol=protocol)

        shelf = InMemoryFileShelf(self.path)
        shelf['foo'] = 'bar'
        self.assertIn('foo', shelf.values)
        self.assertEqual(shelf.values['foo'], cPickle.dumps('bar', protocol=2))

    def test_broken_metadata_iteritems(self):
        """Test that broken metadata is ignored during iteritems."""
        self.shelf['ok_key'] = {'status': 'this is valid metadata'}
        self.shelf['bad_file'] = {}
        path = self.shelf.key_file('bad_file')
        open_file(path, 'w').close()
        self.assertRaises(KeyError, self.shelf.__getitem__, 'bad_file')
        self.assertEqual(1, len(list(self.shelf.iteritems())))
        self.assertFalse(path_exists(path))

        self.shelf['broken_pickle'] = {}
        path = self.shelf.key_file('broken_pickle')
        with open_file(path, 'w') as f:
            f.write(BROKEN_PICKLE)
        self.assertRaises(KeyError, self.shelf.__getitem__, 'broken_pickle')
        self.assertEqual(1, len(list(self.shelf.iteritems())))
        self.assertFalse(path_exists(path))

    def test_broken_metadata_items(self):
        """Test that broken metadata is ignored during iteritems."""
        self.shelf['ok_key'] = {'status': 'this is valid metadata'}
        self.shelf['bad_file'] = {}
        path = self.shelf.key_file('bad_file')
        open_file(path, 'w').close()
        self.assertRaises(KeyError, self.shelf.__getitem__, 'bad_file')
        self.assertEqual(1, len(list(self.shelf.items())))
        self.assertFalse(path_exists(path))

        self.shelf['broken_pickle'] = {}
        path = self.shelf.key_file('broken_pickle')
        with open_file(path, 'w') as f:
            f.write(BROKEN_PICKLE)
        self.assertRaises(KeyError, self.shelf.__getitem__, 'broken_pickle')
        self.assertEqual(1, len(list(self.shelf.items())))
        self.assertFalse(path_exists(path))


class CachedFileShelfTests(TestFileShelf):
    """TestFileShelf tests but using CachedFileShelf"""
    fileshelf_class = CachedFileShelf

    def test_hit_miss_properties(self):
        """test the cache hits/misses properties"""
        try:
            self.shelf['missingkey']
        except KeyError:
            self.assertEqual(self.shelf.cache_misses, 1)
        else:
            self.fail('We have a key in the shelf, but it should be empty!!')
        self.shelf['realkey'] = 'realvalue'
        self.shelf['realkey']
        self.shelf['realkey']
        self.assertEqual(self.shelf.cache_hits, 1)

    def test_broken_metadata_with_backup(self):
        """overrides parent test as we have the value in the cache."""
        self.shelf['bad_file'] = {'value': 'old'}
        path = self.shelf.key_file('bad_file')
        self.assertFalse(path_exists(path+'.old'))
        self.assertEqual({'value': 'old'}, self.shelf['bad_file'])
        # force the creation of the .old file
        self.shelf['bad_file'] = {'value': 'new'}
        self.assertTrue(path_exists(path+'.old'))
        # check that the new value is there
        self.assertEqual({'value': 'new'}, self.shelf['bad_file'])
        # write the current md file fwith 0 bytes
        open_file(path, 'w').close()
        # HERE IS THE DIFFERENCE with the parent tests
        # test that the new value is retrieved from the cache!
        self.assertEqual({'value': 'new'}, self.shelf['bad_file'])

        self.shelf['broken_pickle'] = {'value': 'old'}
        path = self.shelf.key_file('broken_pickle')
        # check that .old don't exist
        self.assertFalse(path_exists(path+'.old'))
        # force the creation of the .old file
        self.shelf['broken_pickle'] = {'value': 'new'}
        # check that .old exists
        self.assertTrue(path_exists(path+'.old'))
        # check that the new value is there
        self.assertEqual({'value': 'new'}, self.shelf['broken_pickle'])
        # write random bytes to the md file
        with open_file(path, 'w') as f:
            f.write(BROKEN_PICKLE)
        # HERE IS THE DIFFERENCE with the parent tests
        # test that the new value is retrieved from the cache!
        self.assertEqual({'value': 'new'}, self.shelf['broken_pickle'])


class LRUCacheTests(unittest.TestCase):
    """Test the LRUCache class"""

    def test_setitem(self):
        """test __delitem__ method"""
        cache = LRUCache(100, 4)
        # set some data in the cache
        values = [('key'+str(i), i) for i in range(100)]
        for i, j in values:
            cache[i] = j
        self.assertEqual(len(cache._queue), len(values))
        self.assertEqual(len(cache._cache), len(values))

    def test_getitem(self):
        """test __delitem__ method"""
        cache = LRUCache(100, 4)
        # set some data in the cache
        values = [('key'+str(i), i) for i in range(100)]
        for i, j in values:
            cache[i] = j
        self.assertEqual(len(cache._queue), len(values))
        self.assertEqual(len(cache._cache), len(values))
        # compare all the items with the values
        for i, j in values:
            self.assertEqual(cache[i], j)

    def test_delitem(self):
        """test __delitem__ method"""
        cache = LRUCache(100, 4)
        values = [('key'+str(i), i) for i in range(100)]
        for i, j in values:
            cache[i] = j
        self.assertEqual(len(cache._queue), len(values))
        self.assertEqual(len(cache._cache), len(values))
        for item in cache._cache.copy():
            del cache[item]
        self.assertEqual(len(cache._queue), 0)
        self.assertEqual(len(cache._cache), 0)

    def test_update(self):
        """test the update method, chacking the refcount and queue."""
        cache = LRUCache(100, 4)
        cache.update('key1')
        self.assertEqual(len(cache._queue), 1)
        self.assertEqual(len(cache._refcount), 1)
        self.assertEqual(cache._refcount['key1'], 1)
        cache.update('key1')
        self.assertEqual(len(cache._queue), 2)
        self.assertEqual(len(cache._refcount), 1)
        self.assertEqual(cache._refcount['key1'], 2)

    def test_purge(self):
        """Test the queue compact and cache purge"""
        cache = LRUCache(100, 4)
        values = [('key'+str(i), j) for i in range(50) for j in range(8)]
        for i, j in values:
            cache[i] = j
        # we hit the limit
        self.assertEqual(len(cache._queue), 400)
        self.assertEqual(len(cache._cache), 50)
        # insert key1 item to compact the queue
        cache[values[0][0]] = values[0][1]
        self.assertEqual(len(cache._queue), 50)
        self.assertEqual(len(cache._cache), 50)

        # now with a key not present in the cache
        cache = LRUCache(100, 4)
        for i, j in values:
            cache[i] = j
        # we hit the limit
        self.assertEqual(len(cache._queue), 400)
        self.assertEqual(len(cache._cache), 50)
        # insert key1 item to compact the queue
        cache['non-present-key'] = 'some value'
        self.assertEqual(len(cache._queue), 51)
        self.assertEqual(len(cache._cache), 51)

    def test_statistics(self):
        """Tests if the cache correclty keeps track of misses and hits."""
        cache = LRUCache(100, 4)
        # set some data in the cache
        values = [('key'+str(i), i) for i in range(10)]
        for i, j in values:
            cache[i] = j
        self.assertEqual(len(cache._queue), len(values))
        self.assertEqual(len(cache._cache), len(values))
        # compare 4 items with the values
        for i, j in values[:4]:
            self.assertEqual(cache[i], j)
        # check the hits value
        self.assertEqual(cache.hits, 4)
        # try to get items not present in the cache
        for i, j in values[5:10]:
            self.assertRaises(KeyError, cache.__getitem__, i*10)
        self.assertEqual(cache.misses, 5)

    def test_inconsistency(self):
        """Test that the consistency checking works as expected"""
        cache = LRUCache(2, 1)
        cache['foo'] = 'bar'
        # add it again to the _queue to force a inconsistency
        cache._queue.append('foo')
        self.assertRaises(CacheInconsistencyError,
                          cache.__setitem__, 'bar', 'foo')

    def test_delete(self):
        """test the cache consistency after a delete."""
        cache = LRUCache(2, 1)
        # set some items in the shelf
        cache['key1'] = 'I ant to breake the cache'
        cache['key2'] = 'I ant to breake the cache'
        # delete the key1, this shouldn't brake the cache._refcount
        del cache['key1']
        # get the key2 two times, in order to trigger the cache compact
        # sure this statements have an affect
        cache['key2']
        try:
            cache['key2']
        except CacheInconsistencyError, e:
            self.fail(e)
