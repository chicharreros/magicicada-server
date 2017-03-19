# ubuntuone.storagefs.diskcache - disk-backed filesystem cache
#
# Authors: Facundo Batista <facundo@canonical.com>
#          Guillermo Gonzalez  <guillermo.gonzalez@canonical.com>
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
"""Storage shelf using a files tree."""

from __future__ import with_statement

import cPickle
import os
import stat
import errno

from collections import deque
from UserDict import DictMixin

from ubuntuone.platform import (
    make_dir,
    open_file,
    path_exists,
    remove_file,
    rename,
    stat_path,
    walk,
)


class FileShelf(object, DictMixin):
    """ File based shelf.

    It support arbritary python objects as values (anything accepted by
    cPickle).  And support any valid file name as key.
    """

    def __init__(self, path, depth=3):
        """ Create a FileShelf.

        @param path: the path to use as the root of the shelf
        @param depth: the directory depth to use, can't be < 0. default is 3
        """
        self._path = path
        if depth < 0:
            raise ValueError("depth must be >= 0")
        self._depth = depth
        self._check_and_create_dirs(self._path)

    def _check_and_create_dirs(self, path):
        """ check if the path isn't a file and in case it don't exists,
        creates it
        """
        try:
            stat_result = stat_path(path)
            # is a regular file?
            if stat.S_ISREG(stat_result.st_mode):
                remove_file(path)
                make_dir(path, True)
            # else, the dir is already there
        except OSError, e:
            if e.errno == errno.ENOENT:
                # the file or dir don't exist
                make_dir(path, True)
            else:
                raise

    def key_file(self, key):
        """ get the real key used by the storage from a key """
        # cannot use None to create files in the disk
        if key is None:
            raise ValueError("Invalid key: %r" % key)

        # length always needs to be longer (we have a uuid after all)
        if len(key) < self._depth:
            raise ValueError("The key (%r) needs to be longer!" % key)

        letters = [key[i] for i in xrange(0, self._depth)]
        return os.path.join(os.path.join(self._path, *letters), key)

    def has_key(self, key):
        """ True if the the shelf has the key """
        return path_exists(self.key_file(key))

    def keys(self):
        """ returns a iterator over the keys """
        splitext = os.path.splitext
        for dirpath, dirnames, filenames in walk(self._path):
            for filename in filenames:
                # just in case a .new file was left around
                ext = splitext(filename)[1]
                if ext != ".new" and ext != ".old":
                    yield filename

    def pop(self, key):
        """ returns the key and deletes the entry """
        k = self[key]
        del self[key]
        return k

    def __contains__(self, key):
        """ returns if the file storage has that key """
        try:
            self[key]
        except KeyError:
            return False
        else:
            return True

    def _unpickle(self, fd):
        """Unpickle the contents of fd, fd must be a file-like object.
        This method allow subclasses to customize the unpickling.

        """
        return cPickle.load(fd)

    def _load_pickle(self, key, path):
        """Load a pickle form path that belongs to key.

        If the pickle is mising or broken, fallback to an previous version
        if it exists.

        """
        try:
            with open_file(path, "rb") as fd:
                data = self._unpickle(fd)
        except (EOFError, cPickle.UnpicklingError, ValueError):
            # the metadata is broked, try to get .old version if it's available
            old_path = path + '.old'
            # only search for a single .old in the name
            if os.path.splitext(path)[1] != '.old' and \
               path_exists(old_path):
                return self._load_pickle(key, old_path)
            else:
                raise KeyError(key)
        except (IOError, OSError):
            raise KeyError(key)
        else:
            return data

    def __getitem__(self, key):
        """ getitem backed by the file storage """
        return self._load_pickle(key, self.key_file(key))

    def _pickle(self, value, fd, protocol):
        """Pickle value in fd using protocol."""
        cPickle.dump(value, fd, protocol=protocol)

    def __setitem__(self, key, value):
        """ setitem backed by the file storage """
        path = self.key_file(key)
        new_path = path + ".new"
        old_path = path + ".old"
        self._check_and_create_dirs(os.path.dirname(path))
        with open_file(new_path, "wb") as fh:
            self._pickle(value, fh, protocol=2)
            fh.flush()
        if path_exists(path):
            rename(path, old_path)
        rename(new_path, path)

    def __delitem__(self, key):
        """ delitem backed by the file storage """
        path = self.key_file(key)
        try:
            remove_file(self.key_file(key))
        except OSError:
            raise KeyError(key)
        # also delete backup files
        for path in [path + '.old', path + '.new']:
            try:
                remove_file(path)
            except OSError:
                # ignore any OSError
                pass

    def __len__(self):
        """ The len of the shelf.
        To get len(keys) we need to iterate over the full key set.
        """
        counter = 0
        for key in self.keys():
            counter += 1
        return counter

    def iteritems(self):
        """Custom iteritems that discard 'broken' metadata."""
        for k in self:
            try:
                yield (k, self[k])
            except KeyError:
                del self[k]
                continue


class CachedFileShelf(FileShelf):
    """A extension of FileShelf that uses a cache of 1500 items"""

    def __init__(self, *args, **kwargs):
        """Create the instance"""
        self._max_size = kwargs.pop('cache_size', 1000)
        self._compact_threshold = kwargs.pop('cache_compact_threshold', 4)
        super(CachedFileShelf, self).__init__(*args, **kwargs)
        # XXX: the size of the cache and the compact threshold needs to be
        # tweaked once we get more statistics from real usage
        self._cache = LRUCache(self._max_size, self._compact_threshold)

    @property
    def cache_misses(self):
        """proterty to access the internal cache misses"""
        return self._cache.misses

    @property
    def cache_hits(self):
        """proterty to access the internal cache hits"""
        return self._cache.hits

    def __getitem__(self, key):
        """ getitem backed by the file storage """
        try:
            return self._cache[key]
        except KeyError:
            value = super(CachedFileShelf, self).__getitem__(key)
            # add it to the cache
            self._cache[key] = value
            return value

    def __setitem__(self, key, value):
        """ setitem backed by the file storage """
        super(CachedFileShelf, self).__setitem__(key, value)
        if key in self._cache:
            self._cache[key] = value

    def __delitem__(self, key):
        """ delitem backed by the file storage """
        super(CachedFileShelf, self).__delitem__(key)
        if key in self._cache:
            del self._cache[key]


class LRUCache(object):
    """A least-recently-used|updated cache with maximum size.

    The object(s) added to the cache must be hashable.
    Cache performance statistics stored in self.hits and self.misses.

    Based on recipe #252524 by Raymond Hettinger
    """
    def __init__(self, maxsize, compact_threshold=4):
        """Create the instance.
        @param maxsize:
        @param compact_threshold:
        """
        self._maxsize = maxsize
        self._compact_threshold = compact_threshold
        self._cache = {}      # mapping of args to results
        self._queue = deque()  # order that keys have been accessed
        self._refcount = {}   # number of times each key is in the access queue
        self.hits = 0
        self.misses = 0

    def __getitem__(self, key):
        """return the item from the cache or raise KeyError."""
        try:
            result = self._cache[key]
            self.hits += 1
        except KeyError:
            # get the value and increase misses
            self.misses += 1
            raise
        else:
            self.update(key)
            self.purge()
        return result

    def __setitem__(self, key, value):
        """set the key, value in the cache"""
        self._cache[key] = value
        self.update(key)
        self.purge()

    def __delitem__(self, key):
        """removes the key, value from the cache"""
        del self._cache[key]
        # remove the key (and it dupes) from the queue
        for _ in xrange(self._refcount.pop(key)):
            self._queue.remove(key)

    def __contains__(self, key):
        """returns True if key is in the cache"""
        return key in self._cache

    def update(self, key):
        """Update the least recently used|updated and refcount"""
        self._queue.append(key)
        self._refcount[key] = self._refcount.get(key, 0) + 1

    def purge(self):
        """Purge least recently accessed cache contents and periodically
        compact the queue by duplicate keys.
        """
        while len(self._cache) > self._maxsize:
            k = self._queue.popleft()
            self._refcount[k] -= 1
            if not self._refcount[k]:
                if k in self._cache:
                    del self._cache[k]
                del self._refcount[k]

        # Periodically compact the queue by duplicate keys
        queue_len = len(self._queue)
        if queue_len > self._maxsize * self._compact_threshold:
            for _ in xrange(queue_len):
                k = self._queue.popleft()
                if self._refcount[k] == 1:
                    self._queue.append(k)
                else:
                    self._refcount[k] -= 1
            if (not (len(self._queue) == len(self._cache) ==
                     len(self._refcount) == sum(self._refcount.itervalues()))):
                # create a custom exception for this error
                raise CacheInconsistencyError(len(self._queue),
                                              len(self._cache),
                                              len(self._refcount),
                                              sum(self._refcount.itervalues()))


class CacheInconsistencyError(Exception):
    """Exception representing a inconsistency in the cache"""

    def __str__(self):
        return (
            "Inconsistency in the cache: queue: %d cache: %d refcount: %d "
            "sum(refcount.values): %d" % self.args)
