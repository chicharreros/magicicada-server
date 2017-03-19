#
# Authors: Facundo Batista <facundo@canonical.com>
#          Alejandro J. Cura <alecu@canonical.com>
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
"""Tests the Hashs Queue."""

from __future__ import with_statement

import os
import random
import time
import logging
import threading

from StringIO import StringIO
from twisted.trial.unittest import TestCase as TwistedTestCase
from twisted.internet import defer, reactor
from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.devtools.testcases import skipTest

from contrib.testing.testcase import BaseTwistedTestCase
from ubuntuone.platform import open_file, stat_path
from ubuntuone.syncdaemon import hash_queue
from ubuntuone.syncdaemon.hash_queue import HASHQUEUE_DELAY
from ubuntuone.storageprotocol.content_hash import content_hash_factory, crc32

FAKE_TIMESTAMP = 1


class FakeEventQueue(object):
    """Faked EventQueue class."""

    def __init__(self, deferred, expected_events=1):
        """Initialize this fake instance."""
        super(FakeEventQueue, self).__init__()
        self.deferred = deferred
        self.received = []
        self.expected_events = expected_events

    def push(self, event, **kwargs):
        """Callback."""
        self.received.append((hash_queue.time.time(), event, kwargs))
        if len(self.received) == self.expected_events:
            self.deferred.callback(event)


class FakeTimeModule(object):
    """A fake time module."""

    def __init__(self):
        """Initialize this fake instance."""
        super(FakeTimeModule, self).__init__()
        self.timestamp = 1000
        self.sleep_calls = []
        self.time_calls = []

    def time(self):
        """Return the current timestamp."""
        self.time_calls.append(self.timestamp)
        return self.timestamp

    def sleep(self, delay):
        """A forced nap."""
        self.sleep_calls.append(delay)
        self.timestamp += delay


class FakeReceiver(object):
    """Fake Receiver class."""

    def __init__(self, events_limit=1):
        super(FakeReceiver, self).__init__()
        self.events = []
        self.deferred = defer.Deferred()
        self.events_limit = events_limit

    def push(self, event, **kwargs):
        """Callback."""
        self.events.append((event, kwargs))
        if len(self.events) == self.events_limit:
            self.deferred.callback((event, kwargs))


class HasherTests(BaseTwistedTestCase):
    """Test the whole stuff to receive signals."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(HasherTests, self).setUp()
        self.test_dir = self.mktemp('test_dir')
        self.timeout = 2
        self.patch(hash_queue, "HASHQUEUE_DELAY", 0.0)

    def test_live_process(self):
        """Check that the hasher lives and dies."""
        # create the hasher
        mark = object()
        queue = hash_queue.UniqueQueue()
        hasher = hash_queue._Hasher(queue, mark, FakeReceiver())
        hasher.start()

        # it's aliveeeeeeee!
        self.assertTrue(hasher.isAlive())

        # stop it, and release the processor to let the other thread run
        hasher.stop()
        self.addCleanup(hasher.join, timeout=5)
        time.sleep(.1)

        # "I see dead threads"
        self.assertFalse(hasher.isAlive())

    @defer.inlineCallbacks
    def test_called_back_log_ok(self):
        """Test that the hasher produces correct info."""
        # create the hasher
        mark = object()
        queue = hash_queue.UniqueQueue()
        receiver = FakeReceiver()
        hasher = hash_queue._Hasher(queue, mark, receiver)

        # log config
        handler = MementoHandler()
        handler.setLevel(logging.DEBUG)
        hasher.logger.addHandler(handler)
        self.addCleanup(hasher.logger.removeHandler, handler)

        # send what to hash
        testfile = os.path.join(self.test_dir, "testfile")
        with open_file(testfile, "wb") as fh:
            fh.write("foobar")
        item = ((testfile, "mdid"), FAKE_TIMESTAMP)
        queue.put(item)

        # start the hasher after putting the work items
        hasher.start()

        # wait event and stop hasher
        yield receiver.deferred
        hasher.stop()
        hasher.join(timeout=5)

        # check log
        log_msg = [r.message for r in handler.records
                   if "path hash pushed" in r.message][0]
        self.assertTrue("path" in log_msg)
        self.assertTrue("hash" in log_msg)
        self.assertTrue("crc" in log_msg)
        self.assertTrue("size" in log_msg)
        self.assertTrue("st_ino" in log_msg)
        self.assertTrue("st_size" in log_msg)
        self.assertTrue("st_mtime" in log_msg)

    @defer.inlineCallbacks
    def test_called_back_ok(self):
        """Test that the hasher produces correct info."""
        # create the hasher
        mark = object()
        queue = hash_queue.UniqueQueue()
        receiver = FakeReceiver()
        hasher = hash_queue._Hasher(queue, mark, receiver)

        # send what to hash
        testfile = os.path.join(self.test_dir, "testfile")
        with open_file(testfile, "wb") as fh:
            fh.write("foobar")
        item = ((testfile, "mdid"), FAKE_TIMESTAMP)
        queue.put(item)

        # start the hasher after putting the work items
        hasher.start()
        # release the processor and check
        event, kwargs = yield receiver.deferred
        # stop hasher
        hasher.stop()
        hasher.join(timeout=5)

        self.assertEqual(event, "HQ_HASH_NEW")
        # calculate what we should receive
        realh = content_hash_factory()
        realh.hash_object.update("foobar")
        should_be = realh.content_hash()
        curr_stat = stat_path(testfile)
        self.assertEqual(should_be, kwargs['hash'])
        for attr in ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid',
                     'st_gid', 'st_size', 'st_ctime', 'st_mtime'):
            self.assertEqual(getattr(curr_stat, attr),
                             getattr(kwargs['stat'], attr))

    @defer.inlineCallbacks
    def test_called_back_error(self):
        """Test that the hasher signals error when no file."""
        # create the hasher
        mark = object()
        queue = hash_queue.UniqueQueue()
        receiver = FakeReceiver()
        hasher = hash_queue._Hasher(queue, mark, receiver)

        # send what to hash
        item = (("not_to_be_found", "foo"), FAKE_TIMESTAMP)
        queue.put(item)

        # start the hasher after putting the work items
        hasher.start()
        # release the processor and check
        event, kwargs = yield receiver.deferred
        # stop hasher
        hasher.stop()
        hasher.join(timeout=5)

        self.assertEqual(event, "HQ_HASH_ERROR")
        self.assertEqual(kwargs['mdid'], "foo")

    @defer.inlineCallbacks
    def test_order(self):
        """The hasher should return in order."""
        # calculate what we should receive
        should_be = []
        for i in range(10):
            hasher = content_hash_factory()
            text = "supercalifragilistico"+str(i)
            hasher.hash_object.update(text)
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            with open_file(tfile, "wb") as fh:
                fh.write("supercalifragilistico"+str(i))
            d = dict(path=tfile, hash=hasher.content_hash(),
                     crc32=crc32(text), size=len(text), stat=stat_path(tfile))
            should_be.append(("HQ_HASH_NEW", d))

        # create the hasher
        mark = object()
        queue = hash_queue.UniqueQueue()
        d = defer.Deferred()
        receiver = FakeReceiver(events_limit=10)
        hasher = hash_queue._Hasher(queue, mark, receiver)

        # send what to hash
        for i in range(10):
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            item = ((tfile, "mdid"), FAKE_TIMESTAMP)
            queue.put(item)

        # start the hasher after putting the work items
        hasher.start()
        # release the processor and check
        event, kwargs = yield receiver.deferred
        # stop hasher
        hasher.stop()
        hasher.join(timeout=5)

        self.assertEqual(receiver.events, should_be)

    @defer.inlineCallbacks
    def test_large_content(self):
        """The hasher works ok for a lot of info."""
        # calculate what we should receive
        testinfo = "".join(chr(random.randint(0, 255)) for i in range(100000))
        hasher = content_hash_factory()
        hasher.hash_object.update(testinfo)
        testfile = os.path.join(self.test_dir, "testfile")
        testhash = hasher.content_hash()

        # create the hasher
        mark = object()
        queue = hash_queue.UniqueQueue()

        receiver = FakeReceiver()
        hasher = hash_queue._Hasher(queue, mark, receiver)
        # send what to hash
        with open_file(testfile, "wb") as fh:
            fh.write(testinfo)
        item = ((testfile, "mdid"), FAKE_TIMESTAMP)
        queue.put(item)

        # start the hasher after putting the work items
        hasher.start()
        # release the processor and check
        event, kwargs = yield receiver.deferred
        # stop hasher
        hasher.stop()
        hasher.join(timeout=5)

        self.assertEqual(event, "HQ_HASH_NEW")
        self.assertEqual(kwargs.get('path'), testfile)
        self.assertEqual(kwargs.get('hash'), testhash)

    @defer.inlineCallbacks
    def test_open_file_with_rb(self):
        """Check that the file to hash is opened with 'rb' mode."""
        called = []

        orig = hash_queue.open_file

        def faked_open_file(*a):
            called.append(a)
            return orig(*a)

        self.patch(hash_queue, 'open_file', faked_open_file)

        queue = hash_queue.UniqueQueue()
        testfile = os.path.join(self.test_dir, "testfile")
        with open_file(testfile, "wb") as fh:
            fh.write("foobar")
        item = ((testfile, "mdid"), FAKE_TIMESTAMP)
        queue.put(item)

        d = defer.Deferred()
        eq = FakeEventQueue(d)

        hasher = hash_queue._Hasher(queue=queue, end_mark='end-mark',
                                    event_queue=eq)
        # start the hasher after putting the work items
        hasher.start()

        yield d
        hasher.stop()

        self.assertEqual(called, [(testfile, 'rb')])


class HasherSleepTests(BaseTwistedTestCase):
    """The hasher thread sleeps sometimes too."""

    timeout = 3

    def setUpWithCount(self, expected_events=1):
        """Initialize this test instance."""
        self.test_dir = self.mktemp('test_dir')
        self.fake_time = FakeTimeModule()
        self.patch(hash_queue, "time", self.fake_time)
        self.queue = hash_queue.UniqueQueue()

        self.testfile = os.path.join(self.test_dir, "testfile")
        with open_file(self.testfile, "wb") as fh:
            fh.write("foobar")

        self.event_d = defer.Deferred()
        self.eq = FakeEventQueue(self.event_d, expected_events)
        self.hasher = hash_queue._Hasher(
            queue=self.queue, end_mark='end-mark', event_queue=self.eq)

        def stop_hasher():
            """Safely stop the hasher."""
            self.hasher.stop()
            self.hasher.join(timeout=5)
            self.assertFalse(self.hasher.isAlive())

        self.addCleanup(stop_hasher)

    @defer.inlineCallbacks
    def test_hasher_sleeps(self):
        """The hasher thread sleeps while it waits."""
        self.setUpWithCount(expected_events=1)
        item_time = self.fake_time.timestamp + HASHQUEUE_DELAY
        item = ((self.testfile, "fake_mdid"), item_time)
        self.queue.put(item)
        # start the hasher after putting the work items
        self.hasher.start()
        yield self.event_d
        self.assertEqual(self.fake_time.sleep_calls, [HASHQUEUE_DELAY])

    @defer.inlineCallbacks
    def test_hasher_does_not_sleep_if_not_needed(self):
        """The hasher thread does not sleep if not needed."""
        self.setUpWithCount(expected_events=1)
        item_time = self.fake_time.timestamp - 1
        item = ((self.testfile, "fake_mdid"), item_time)
        self.queue.put(item)
        # start the hasher after putting the work items
        self.hasher.start()
        yield self.event_d
        self.assertEqual(self.fake_time.sleep_calls, [])

    @defer.inlineCallbacks
    def test_hasher_sleeping_complex(self):
        """A complex test for the sleeping beauty."""
        self.setUpWithCount(expected_events=3)

        initial_time = self.fake_time.timestamp

        item_time1 = initial_time + HASHQUEUE_DELAY
        item1 = ((self.testfile, "fake_mdid1"), item_time1)
        self.queue.put(item1)

        item_time2 = initial_time + HASHQUEUE_DELAY * 1.1
        item2 = ((self.testfile, "fake_mdid2"), item_time2)
        self.queue.put(item2)

        item_time3 = initial_time + HASHQUEUE_DELAY * 1.2
        item3 = ((self.testfile, "fake_mdid2"), item_time3)
        self.queue.put(item3)

        item_time4 = initial_time + HASHQUEUE_DELAY * 1.3
        item4 = ((self.testfile, "fake_mdid3"), item_time4)
        self.queue.put(item4)

        item_time5 = initial_time + HASHQUEUE_DELAY * 1.4
        item5 = ((self.testfile, "fake_mdid1"), item_time5)
        self.queue.put(item5)
        # start the hasher after putting the work items
        self.hasher.start()

        yield self.event_d
        expected_naps = [
            item_time3 - initial_time,
            item_time4 - item_time3,
            item_time5 - item_time4,
        ]
        self.assertEqual(self.fake_time.sleep_calls, expected_naps)


class HashQueueTests(BaseTwistedTestCase):
    """Test the whole stuff to receive signals."""

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the test."""
        yield super(HashQueueTests, self).setUp()
        self.test_dir = self.mktemp('test_dir')
        self.timeout = 2
        self.patch(hash_queue, "HASHQUEUE_DELAY", 0.0)
        self.log = logging.getLogger("ubuntuone.SyncDaemon.TEST")
        self.log.info("starting test %s.%s", self.__class__.__name__,
                      self._testMethodName)

    @defer.inlineCallbacks
    def test_called_back_ok(self):
        """Test that the hasher produces correct info."""
        # create the hasher
        receiver = FakeReceiver()
        hq = hash_queue.HashQueue(receiver)
        self.addCleanup(hq.shutdown)

        # send what to hash
        testfile = os.path.join(self.test_dir, "testfile")
        with open_file(testfile, "wb") as fh:
            fh.write("foobar")
        hq.insert(testfile, "mdid")

        # release the processor and check
        event, kwargs = yield receiver.deferred

        self.assertEqual(event, "HQ_HASH_NEW")
        # calculate what we should receive
        realh = content_hash_factory()
        realh.hash_object.update("foobar")
        should_be = realh.content_hash()
        curr_stat = stat_path(testfile)
        self.assertEqual(should_be, kwargs['hash'])
        for attr in ('st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid',
                     'st_gid', 'st_size', 'st_ctime', 'st_mtime'):
            self.assertEqual(getattr(curr_stat, attr),
                             getattr(kwargs['stat'], attr))

    @defer.inlineCallbacks
    def test_called_back_error(self):
        """Test that the hasher generates an error when no file."""
        # create the hasher
        receiver = FakeReceiver()
        hq = hash_queue.HashQueue(receiver)
        self.addCleanup(hq.shutdown)
        call_later_called = []

        # the call is delayed
        original_call_later = reactor.callLater

        def fake_call_later(delay, func, *args, **kwargs):
            """Fake call later that checks and calls."""
            if func == reactor.callFromThread:
                # if it is *our* call, check the args
                self.assertEqual(delay, .1)
                self.assertEqual(args, (receiver.push, 'HQ_HASH_ERROR'))
                self.assertEqual(kwargs, dict(mdid='foo'))
                call_later_called.append(True)
            return original_call_later(delay, func, *args, **kwargs)

        self.patch(reactor, 'callLater', fake_call_later)

        # send what to hash
        hq.insert("not_to_be_found", "foo")

        event, kwargs = yield receiver.deferred
        self.assertEqual(event, "HQ_HASH_ERROR")
        self.assertEqual(kwargs['mdid'], "foo")
        self.assertTrue(call_later_called)

    @skipTest('Causing intermittent failures. LP: #935568')
    def test_being_hashed(self):
        """Tell if something is being hashed."""
        tfile1 = os.path.join(self.test_dir, "tfile1")
        open_file(tfile1, "wb").close()
        tfile2 = os.path.join(self.test_dir, "tfile2")
        open_file(tfile2, "wb").close()

        class C(object):
            """Bogus."""
            def push(self, e, **k):
                """None."""
        hq = hash_queue.HashQueue(C())
        self.addCleanup(hq.shutdown)

        event = threading.Event()

        def f(*a):
            """Fake _hash."""
            event.wait()
            return "foo"

        self.patch(hash_queue._Hasher, '_hash', f)
        self.addCleanup(event.set)

        # nothing yet
        self.assertFalse(hq.is_hashing(tfile1, "mdid"))

        # push something, test for it and for other stuff
        hq.insert(tfile1, "mdid")
        self.assertTrue(hq.is_hashing(tfile1, "mdid"))
        self.assertFalse(hq.is_hashing(tfile2, "mdid"))

        # push tfile2, that gets queued, and check again
        hq.insert(tfile2, "mdid")
        self.assertTrue(hq.is_hashing(tfile2, "mdid"))

    @defer.inlineCallbacks
    def test_order(self):
        """The hasher should return in order."""
        # calculate what we should receive
        should_be = []
        for i in range(10):
            hasher = content_hash_factory()
            text = "supercalifragilistico"+str(i)
            hasher.hash_object.update(text)
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            with open_file(tfile, "wb") as fh:
                fh.write("supercalifragilistico"+str(i))
            d = dict(path=tfile, hash=hasher.content_hash(),
                     crc32=crc32(text), size=len(text), stat=stat_path(tfile))
            should_be.append(("HQ_HASH_NEW", d))

        receiver = FakeReceiver(events_limit=10)
        hq = hash_queue.HashQueue(receiver)
        self.addCleanup(hq.shutdown)

        # send what to hash
        for i in range(10):
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            hq.insert(tfile, "mdid")

        # release the processor and check
        event, kwargs = yield receiver.deferred
        self.assertEqual(receiver.events, should_be)

    @defer.inlineCallbacks
    def test_unique(self):
        """The hasher should return in order."""
        # calculate what we should receive
        should_be = []
        for i in range(10):
            hasher = content_hash_factory()
            text = "supercalifragilistico"+str(i)
            hasher.hash_object.update(text)
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            with open_file(tfile, "wb") as fh:
                fh.write("supercalifragilistico"+str(i))
            d = dict(path=tfile, hash=hasher.content_hash(),
                     crc32=crc32(text), size=len(text), stat=stat_path(tfile))
            should_be.append(("HQ_HASH_NEW", d))

        receiver = FakeReceiver(events_limit=10)
        hq = hash_queue.HashQueue(receiver)
        self.addCleanup(hq.shutdown)
        # stop the hasher so we can test the unique items in the queue
        hq.hasher.stop()
        self.log.debug('Hasher stopped (forced)')
        # allow the hasher to fully stop
        time.sleep(0.1)
        # create a new hasher just like the HashQueue creates it
        hq.hasher = hash_queue._Hasher(hq._queue, hq._end_mark, receiver)
        hq.hasher.setDaemon(True)

        # send to hash twice
        for i in range(10):
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            hq.insert(tfile, "mdid")
            hq.insert(tfile, "mdid")
        # start the hasher
        self.log.debug('Hasher started (forced)')
        hq.hasher.start()
        # insert the last item to check the uniqueness in the queue while
        # the hasher is running
        for i in range(9, 10):
            tfile = os.path.join(self.test_dir, "tfile"+str(i))
            hq.insert(tfile, "mdid")

        # release the processor and check
        event, kwargs = yield receiver.deferred
        # stop hasher
        hq.hasher.stop()
        hq.hasher.join(timeout=5)
        self.assertEqual(receiver.events, should_be)

    @defer.inlineCallbacks
    def test_interrupt_current(self):
        """Test that the hasher correctly interrupts a inprogress task."""
        # calculate what we should receive
        testinfo = os.urandom(1000)
        hasher = content_hash_factory()
        hasher.hash_object.update(testinfo)
        testfile = os.path.join(self.test_dir, "testfile")
        testhash = hasher.content_hash()
        # send what to hash
        with open_file(testfile, "wb") as fh:
            fh.write(testinfo)

        class FakeFile(StringIO):
            """An endless file."""

            def read(self, size=10):
                """Return random bytes."""
                return os.urandom(size)

            # context manager API
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        old_open = hash_queue.open_file

        class OpenFaker(object):
            """A class to fake open for specific paths"""

            def __init__(self, paths):
                self.paths = paths
                self.done = False

            def __call__(self, path, mode='r'):
                """the custom open implementation"""
                if self.done or path not in self.paths:
                    return old_open(path, mode)
                else:
                    self.done = True
                    return FakeFile()

        open_faker = OpenFaker([testfile])
        hash_queue.open_file = open_faker

        receiver = FakeReceiver()
        hq = hash_queue.HashQueue(receiver)
        self.addCleanup(setattr, hash_queue, 'open_file', old_open)
        self.addCleanup(hq.shutdown)

        hq.insert(testfile, "mdid")

        # insert it again, to cancel the first one
        reactor.callLater(0.1, hq.insert, testfile, "mdid")

        event, kwargs = yield receiver.deferred
        self.assertEqual(event, "HQ_HASH_NEW")
        self.assertEqual(kwargs.get('path'), testfile)
        self.assertEqual(kwargs.get('hash'), testhash)

    def test_shutdown(self):
        """Test that the HashQueue shutdown """
        hq = hash_queue.HashQueue(FakeReceiver())
        hq.shutdown()
        self.assertTrue(hq._stopped)

    def test_shutdown_while_hashing(self):
        """Test that the HashQueue is shutdown ASAP while it's hashing."""
        # create large data in order to test
        testinfo = os.urandom(500000)
        hasher = content_hash_factory()
        hasher.hash_object.update(testinfo)
        testfile = os.path.join(self.test_dir, "testfile")
        # send what to hash
        with open_file(testfile, "wb") as fh:
            fh.write(testinfo)
        hq = hash_queue.HashQueue(FakeReceiver())
        # read in small chunks, so we have more iterations
        hq.hasher.chunk_size = 2**10
        hq.insert(testfile, "mdid")
        time.sleep(0.1)
        hq.shutdown()
        # block until the hash is stopped and the queue is empty
        # a shutdown clears the queue
        hq._queue.join()
        self.assertFalse(hq.hasher.hashing)
        self.assertTrue(hq.hasher._stopped)
        # self.assertFalse(hq.hasher.isAlive())
        self.assertTrue(hq._queue.empty())

    def test_insert_post_shutdown(self):
        """test inserting a path after the shutdown"""
        hq = hash_queue.HashQueue(FakeReceiver())
        hq.shutdown()
        hq.insert('foo', 'mdid')
        self.assertFalse(hq.is_hashing('foo', 'mdid'))


class UniqueQueueTests(TwistedTestCase):
    """Tests for hash_queue.UniqueQueue"""

    def test_unique_elements(self):
        """Test that the queue actually holds unique elements."""
        queue = hash_queue.UniqueQueue()
        queue.put(('item1', "mdid"))
        queue.put(('item1', "mdid"))
        self.assertEqual(1, queue.qsize())
        queue.get()
        self.assertEqual(0, queue.qsize())
        queue.put(('item1', "mdid"))
        queue.put(('item2', "mdid"))
        queue.put(('item1', "mdid"))
        queue.put(('item2', "mdid"))
        self.assertEqual(2, queue.qsize())
        queue.get()
        queue.get()
        self.assertEqual(0, queue.qsize())

    def test_previous_item_discarded(self):
        """It's the previous instance of an item the one that's discarded."""
        item1 = ('item1', "mdid")
        item2 = ('item2', "mdid")
        queue = hash_queue.UniqueQueue()
        queue.put(item1)
        queue.put(item2)
        queue.put(item1)
        result = queue.get()
        self.assertEqual(result, item2)

    def test_contains(self):
        """test contains functionality"""
        queue = hash_queue.UniqueQueue()
        fake_timestamp_1 = 1
        fake_timestamp_2 = 2

        # nothing in it
        self.assertFalse(("item1", "mdid") in queue)

        # put one and check
        item1 = (('item1', "mdid"), fake_timestamp_1)
        queue.put(item1)
        self.assertTrue(("item1", "mdid") in queue)
        self.assertFalse(("item2", "mdid") in queue)

        # put second and check
        item2 = (('item2', "mdid"), fake_timestamp_2)
        queue.put(item2)
        self.assertTrue(("item1", "mdid") in queue)
        self.assertTrue(("item2", "mdid") in queue)

    def test_clear(self):
        """test clear method"""
        queue = hash_queue.UniqueQueue()
        queue.put(('item1', "mdid"))
        queue.put(('item2', "mdid"))
        self.assertEqual(2, queue.qsize())
        # check that queue.clear actually clear the queue
        queue.clear()
        self.assertEqual(0, queue.qsize())
        queue.put(('item3', "mdid"))
        queue.put(('item4', "mdid"))
        queue.get()
        self.assertEqual(2, queue.unfinished_tasks)
        self.assertEqual(1, queue.qsize())
        # check that queue.clear also cleanup unfinished_tasks
        queue.clear()
        self.assertEqual(0, queue.unfinished_tasks)
        self.assertEqual(0, queue.qsize())

    def test_clear_unfinished_tasks(self):
        """test the clear wakeup waiting threads."""
        queue = hash_queue.UniqueQueue()
        d = defer.Deferred()

        def consumer(queue, d):
            # wait util unfinished_tasks == 0
            queue.join()
            reactor.callFromThread(d.callback, True)

        def check(result):
            self.assertTrue(result)

        d.addCallback(check)
        t = threading.Thread(target=consumer, args=(queue, d))
        t.setDaemon(True)
        queue.put(('item1', "mdid"))
        t.start()
        reactor.callLater(0.1, queue.clear)
        return d
