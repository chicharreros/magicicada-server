# ubuntuone.syncdaemon.tests.test_pathlockingtree - PathLockingTree tests
#
# Author: Facundo Batista <facundo@canonical.com>
#
# Copyright 2011-2012 Canonical Ltd.
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
""" ActionQueue tests """

import logging

from twisted.internet import defer
from twisted.trial.unittest import TestCase as TwistedTestCase

from ubuntuone.devtools.handlers import MementoHandler
from ubuntuone.syncdaemon.action_queue import PathLockingTree


class InternalDeferredTests(TwistedTestCase):
    """Test the internal deferreds handling functionality."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(InternalDeferredTests, self).setUp()
        self.plt = PathLockingTree()

    def test_single_element_old(self):
        """Add to a single element that was there."""
        self.plt.acquire('path')
        self.plt.acquire('path')

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        child = self.plt.root['children_nodes']['path']

        # child has right values
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 2)

    def test_single_element_new(self):
        """Add a single element that is new."""
        self.plt.acquire('path')

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        child = self.plt.root['children_nodes']['path']

        # child has right values
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

    def test_two_element_both_old(self):
        """Add to two already there elements."""
        self.plt.acquire('path1', 'path2')
        self.plt.acquire('path1', 'path2')

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        child = self.plt.root['children_nodes']['path1']

        # root's child has right values
        self.assertEqual(len(child['children_nodes']), 1)
        self.assertEqual(len(child['children_deferreds']), 2)
        self.assertEqual(len(child['node_deferreds']), 0)

        # root's grandchild has right values
        child = child['children_nodes']['path2']
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 2)

    def test_two_element_both_new(self):
        """Add to two new elements."""
        self.plt.acquire('path1', 'path2')

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        child = self.plt.root['children_nodes']['path1']

        # root's child has right values
        self.assertEqual(len(child['children_nodes']), 1)
        self.assertEqual(len(child['children_deferreds']), 1)
        self.assertEqual(len(child['node_deferreds']), 0)

        # root's grandchild has right values
        child = child['children_nodes']['path2']
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

    def test_two_element_mixed(self):
        """Add to one new and one old elements."""
        # first one
        self.plt.acquire('path1')

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        child = self.plt.root['children_nodes']['path1']

        # root's child has right values
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

        # second one
        self.plt.acquire('path1', 'path2')

        # root's child has right values
        self.assertEqual(len(child['children_nodes']), 1)
        self.assertEqual(len(child['children_deferreds']), 1)
        self.assertEqual(len(child['node_deferreds']), 1)

        # root's grandchild has right values
        child = child['children_nodes']['path2']
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

    def test_element_to_longer_branch(self):
        """Add element in the middle of longer branch."""
        # first a long one, then a shorter one
        self.plt.acquire(*"abc")
        self.plt.acquire("a")

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        child = self.plt.root['children_nodes']['a']

        # root's child has right values
        self.assertEqual(len(child['children_nodes']), 1)
        self.assertEqual(len(child['children_deferreds']), 1)
        self.assertEqual(len(child['node_deferreds']), 1)

        # root's grandchild has right values
        child = child['children_nodes']['b']
        self.assertEqual(len(child['children_nodes']), 1)
        self.assertEqual(len(child['children_deferreds']), 1)
        self.assertEqual(len(child['node_deferreds']), 0)

        # root's grandgrandchild has right values
        child = child['children_nodes']['c']
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

    def test_second_to_root(self):
        """Add other root child."""
        self.plt.acquire("path1")
        self.plt.acquire("path2")

        # root has two children
        self.assertEqual(len(self.plt.root['children_nodes']), 2)

        # root's child 1 has right values
        child = self.plt.root['children_nodes']['path1']
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

        # root's child 2 has right values
        child = self.plt.root['children_nodes']['path2']
        self.assertEqual(len(child['children_nodes']), 0)
        self.assertEqual(len(child['children_deferreds']), 0)
        self.assertEqual(len(child['node_deferreds']), 1)

    def test_diverging_branch(self):
        """Add a branch that separates from other."""
        # first a long one, then a shorter one
        self.plt.acquire(*"abcd")
        self.plt.acquire(*"abj")

        # root has only one child
        self.assertEqual(len(self.plt.root['children_nodes']), 1)

        # node a values
        node_a = self.plt.root['children_nodes']['a']
        self.assertEqual(len(node_a['children_nodes']), 1)
        self.assertEqual(len(node_a['children_deferreds']), 2)
        self.assertEqual(len(node_a['node_deferreds']), 0)

        # node a values
        node_b = node_a['children_nodes']['b']
        self.assertEqual(len(node_b['children_nodes']), 2)
        self.assertEqual(len(node_b['children_deferreds']), 2)
        self.assertEqual(len(node_b['node_deferreds']), 0)

        # node c values
        node_c = node_b['children_nodes']['c']
        self.assertEqual(len(node_c['children_nodes']), 1)
        self.assertEqual(len(node_c['children_deferreds']), 1)
        self.assertEqual(len(node_c['node_deferreds']), 0)

        # node a values
        node_d = node_c['children_nodes']['d']
        self.assertEqual(len(node_d['children_nodes']), 0)
        self.assertEqual(len(node_d['children_deferreds']), 0)
        self.assertEqual(len(node_d['node_deferreds']), 1)

        # node a values
        node_j = node_b['children_nodes']['j']
        self.assertEqual(len(node_j['children_nodes']), 0)
        self.assertEqual(len(node_j['children_deferreds']), 0)
        self.assertEqual(len(node_j['node_deferreds']), 1)


class LockingTests(TwistedTestCase):
    """Test the locking between elements."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(LockingTests, self).setUp()
        self.plt = PathLockingTree()

    @defer.inlineCallbacks
    def test_none_before(self):
        """Not lock because nothing there before."""
        yield self.plt.acquire("path")

    @defer.inlineCallbacks
    def test_same_path_one_previous(self):
        """Lock on same path, one previous command."""
        release = yield self.plt.acquire("path")
        d = self.plt.acquire("path")

        # add func first and change value later, to check when released
        d.addCallback(lambda _: self.assertTrue(was_later))

        was_later = True
        release()
        yield d

    @defer.inlineCallbacks
    def test_same_path_two_previous(self):
        """Lock on same path, two previous commands."""
        releases = []
        d1 = self.plt.acquire("path")
        d1.addCallback(releases.append)
        d2 = self.plt.acquire("path")
        d2.addCallback(releases.append)

        # add func first, test all releases were made before the check
        d3 = self.plt.acquire("path")
        d3.addCallback(lambda _: self.assertFalse(releases))

        releases.pop(0)()
        releases.pop(0)()
        yield d3

    def test_deferred_can_be_cancelled(self):
        """The path locking can be cancelled without harm."""
        releases = []
        d1 = self.plt.acquire("path")
        d1.addCallback(lambda _: releases.append(1))
        d2 = self.plt.acquire("path")
        d2.addCallback(lambda _: releases.append(2))

        # the first one should not be locked
        self.assertEqual(releases, [1])

        # cancel the second deferred, but it still needs to pass ok
        d2.cancel()
        self.assertEqual(releases, [1, 2])

    @defer.inlineCallbacks
    def test_same_path_having_parent(self):
        """Lock with parent having just the parent."""
        yield self.plt.acquire("path1")
        yield self.plt.acquire("path1", "path2")

    @defer.inlineCallbacks
    def test_same_path_having_children(self):
        """Lock with parent having just the parent."""
        yield self.plt.acquire("path1", "path2", "path3")
        yield self.plt.acquire("path1", "path2")

    @defer.inlineCallbacks
    def test_with_parent_none(self):
        """Lock with parent but empty."""
        yield self.plt.acquire("path", on_parent=True)

    @defer.inlineCallbacks
    def test_with_parent_just_parent(self):
        """Lock with parent having just the parent."""
        release = yield self.plt.acquire("path1")
        d = self.plt.acquire("path1", "path2", on_parent=True)

        # add func first and change value later, to check when released
        d.addCallback(lambda _: self.assertTrue(was_later))

        was_later = True
        release()
        yield d

    @defer.inlineCallbacks
    def test_with_parent_having_same(self):
        """Lock with parent having also the same path."""
        releases = []
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abcd")
        d.addCallback(releases.append)

        # add func first, test all releases were made before the check
        d = self.plt.acquire(*"abcd", on_parent=True)
        d.addCallback(lambda _: self.assertFalse(releases))

        releases.pop(0)()
        releases.pop(0)()
        yield d

    @defer.inlineCallbacks
    def test_with_parent_multiple(self):
        """Lock with some commands in parent and same."""
        releases = []
        d = self.plt.acquire(*"abcd")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abcd")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)

        # add func first, test all releases were made before the check
        d = self.plt.acquire(*"abcd", on_parent=True)
        d.addCallback(lambda _: self.assertFalse(releases))

        releases.pop(0)()
        releases.pop(0)()
        releases.pop(0)()
        releases.pop(0)()
        yield d

    @defer.inlineCallbacks
    def test_with_parent_having_just_children(self):
        """Lock with parent but only has children."""
        yield self.plt.acquire("path1", "path2", "path3")
        yield self.plt.acquire("path1", "path2", on_parent=True)

    @defer.inlineCallbacks
    def test_with_children_none(self):
        """Lock with children but empty."""
        yield self.plt.acquire("path", on_children=True)

    @defer.inlineCallbacks
    def test_with_children_just_children(self):
        """Lock with children having just a child."""
        release = yield self.plt.acquire("path1", "path2")
        d = self.plt.acquire("path1", on_children=True)

        # add func first and change value later, to check when released
        d.addCallback(lambda _: self.assertTrue(was_later))

        was_later = True
        release()
        yield d

    @defer.inlineCallbacks
    def test_with_children_having_same(self):
        """Lock with children having also the same path."""
        releases = []
        d = self.plt.acquire(*"ab")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)

        # add func first, test all releases were made before the check
        d = self.plt.acquire(*"ab", on_children=True)
        d.addCallback(lambda _: self.assertFalse(releases))

        releases.pop(0)()
        releases.pop(0)()
        yield d

    @defer.inlineCallbacks
    def test_with_children_multiple(self):
        """Lock with some commands in children and same."""
        releases = []
        d = self.plt.acquire(*"ab")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"ab")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)

        # add func first, test all releases were made before the check
        d = self.plt.acquire(*"ab", on_children=True)
        d.addCallback(lambda _: self.assertFalse(releases))

        releases.pop(0)()
        releases.pop(0)()
        releases.pop(0)()
        releases.pop(0)()
        yield d

    @defer.inlineCallbacks
    def test_with_children_and_parent_all_mixed(self):
        """Lock with some commands everywhere, :p."""
        releases = []
        d = self.plt.acquire(*"ab")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"abc")
        d.addCallback(releases.append)
        d = self.plt.acquire(*"a")
        d.addCallback(releases.append)

        # add func first, test all releases were made before the check
        d = self.plt.acquire(*"ab", on_children=True, on_parent=True)
        d.addCallback(lambda _: self.assertFalse(releases))

        releases.pop(0)()
        releases.pop(0)()
        releases.pop(0)()
        releases.pop(0)()
        yield d


class CleaningTests(TwistedTestCase):
    """Test that the releases clean the tree."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(CleaningTests, self).setUp()
        self.plt = PathLockingTree()

    @defer.inlineCallbacks
    def test_simple(self):
        """Simple clean, add one, release it."""
        release = yield self.plt.acquire("path")
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_add_two_release_one(self):
        """Add two different paths, release them by one."""
        release1 = yield self.plt.acquire("path1")
        release2 = yield self.plt.acquire("path2")
        self.assertEqual(len(self.plt.root['children_nodes']), 2)

        release1()
        self.assertEqual(len(self.plt.root['children_nodes']), 1)

        release2()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_longer_branch(self):
        """Simple clean, but using a longer branch."""
        release = yield self.plt.acquire(*"abc")
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_overlapped_release_shorter(self):
        """Overlap two paths, release shorter."""
        release1 = yield self.plt.acquire(*"abc")
        release2 = yield self.plt.acquire(*"ab")

        # release shorter, check structure
        release2()
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        node_a = self.plt.root['children_nodes']['a']
        self.assertEqual(len(node_a['children_nodes']), 1)
        self.assertEqual(len(node_a['children_deferreds']), 1)
        self.assertEqual(len(node_a['node_deferreds']), 0)
        node_b = node_a['children_nodes']['b']
        self.assertEqual(len(node_b['children_nodes']), 1)
        self.assertEqual(len(node_b['children_deferreds']), 1)
        self.assertEqual(len(node_b['node_deferreds']), 0)
        node_c = node_b['children_nodes']['c']
        self.assertEqual(len(node_c['children_nodes']), 0)
        self.assertEqual(len(node_c['children_deferreds']), 0)
        self.assertEqual(len(node_c['node_deferreds']), 1)

        # release longer, empty now!
        release1()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_overlapped_release_longer(self):
        """Overlap two paths, release longer."""
        release1 = yield self.plt.acquire(*"abc")
        release2 = yield self.plt.acquire(*"ab")

        # release longer, check structure
        release1()
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        node_a = self.plt.root['children_nodes']['a']
        self.assertEqual(len(node_a['children_nodes']), 1)
        self.assertEqual(len(node_a['children_deferreds']), 1)
        self.assertEqual(len(node_a['node_deferreds']), 0)
        node_b = node_a['children_nodes']['b']
        self.assertEqual(len(node_b['children_nodes']), 0)
        self.assertEqual(len(node_b['children_deferreds']), 0)
        self.assertEqual(len(node_b['node_deferreds']), 1)

        # release shorter, empty now!
        release2()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_same_long_path_double(self):
        """Two long branchs."""
        release1 = yield self.plt.acquire(*"ab")

        releases = []
        d = self.plt.acquire(*"ab")
        d.addCallback(releases.append)

        # release first, check structure
        release1()
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        node_a = self.plt.root['children_nodes']['a']
        self.assertEqual(len(node_a['children_nodes']), 1)
        self.assertEqual(len(node_a['children_deferreds']), 1)
        self.assertEqual(len(node_a['node_deferreds']), 0)
        node_b = node_a['children_nodes']['b']
        self.assertEqual(len(node_b['children_nodes']), 0)
        self.assertEqual(len(node_b['children_deferreds']), 0)
        self.assertEqual(len(node_b['node_deferreds']), 1)

        # release second, empty now!
        releases.pop(0)()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_diverging_branch(self):
        """Diverging branches."""
        release1 = yield self.plt.acquire(*"abc")
        release2 = yield self.plt.acquire(*"aj")

        # release longer, check structure
        release1()
        self.assertEqual(len(self.plt.root['children_nodes']), 1)
        node_a = self.plt.root['children_nodes']['a']
        self.assertEqual(len(node_a['children_nodes']), 1)
        self.assertEqual(len(node_a['children_deferreds']), 1)
        self.assertEqual(len(node_a['node_deferreds']), 0)
        node_j = node_a['children_nodes']['j']
        self.assertEqual(len(node_j['children_nodes']), 0)
        self.assertEqual(len(node_j['children_deferreds']), 0)
        self.assertEqual(len(node_j['node_deferreds']), 1)

        # release second, empty now!
        release2()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)


class LoggingTests(TwistedTestCase):
    """Test the logging."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(LoggingTests, self).setUp()
        self.plt = PathLockingTree()

        self.handler = MementoHandler()
        self.plt.logger.setLevel(logging.DEBUG)
        self.plt.logger.propagate = False
        self.plt.logger.addHandler(self.handler)
        self.addCleanup(self.plt.logger.removeHandler, self.handler)

    @defer.inlineCallbacks
    def test_logger_can_be_given(self):
        """Accept an external logger."""
        logger = logging.getLogger("ubuntuone.SyncDaemon.Test")
        handler = MementoHandler()
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False

        # acquire and test
        release = yield self.plt.acquire('path', logger=logger)
        self.assertTrue(handler.check_debug("acquiring on"))

        # release and test
        release()
        self.assertTrue(handler.check_debug("releasing"))

    def test_acquire_single_default(self):
        """Single path, full check."""
        self.plt.acquire('path')
        self.assertTrue(self.handler.check_debug(
                        "acquiring on", "path",
                        "(on_parent=False, on_children=False)", "wait for: 0"))

    def test_acquire_single_on_parent(self):
        """Single path, on parent."""
        self.plt.acquire('path', on_parent=True)
        self.assertTrue(self.handler.check_debug("on_parent=True"))

    def test_acquire_single_on_children(self):
        """Single path, on children."""
        self.plt.acquire('path', on_children=True)
        self.assertTrue(self.handler.check_debug("on_children=True"))

    def test_acquire_single_on_both(self):
        """Single path, on both."""
        self.plt.acquire('path', on_parent=True, on_children=True)
        self.assertTrue(self.handler.check_debug(
                        "(on_parent=True, on_children=True)"))

    def test_acquire_multiple(self):
        """Single path, on both."""
        self.plt.acquire('1', '2', *"abc")
        self.assertTrue(self.handler.check_debug("'1', '2', 'a', 'b', 'c'"))

    def test_acquire_waiting(self):
        """Single path, on both."""
        self.plt.acquire('path')
        self.assertTrue(self.handler.check_debug("wait for: 0"))

        self.plt.acquire('path')
        self.assertTrue(self.handler.check_debug("wait for: 1"))

        self.plt.acquire('path')
        self.assertTrue(self.handler.check_debug("wait for: 2"))

    @defer.inlineCallbacks
    def test_release_simple(self):
        """Single release."""
        release = yield self.plt.acquire("path")
        release()
        self.assertTrue(self.handler.check_debug("releasing",
                                                 "path", "remaining: 0"))

    @defer.inlineCallbacks
    def test_release_double(self):
        """Double release."""
        release1 = yield self.plt.acquire("path1")
        release2 = yield self.plt.acquire("path2")
        release1()
        self.assertTrue(self.handler.check_debug("releasing",
                                                 "path1", "remaining: 1"))
        release2()
        self.assertTrue(self.handler.check_debug("releasing",
                                                 "path2", "remaining: 0"))

    @defer.inlineCallbacks
    def test_release_longer_branches(self):
        """Longer branches."""
        release = yield self.plt.acquire(*"abcde")
        self.plt.acquire(*"abc")
        self.plt.acquire(*"abcdefg")
        self.plt.acquire(*"abklop")
        self.plt.acquire(*"foobar")
        release()
        self.assertTrue(self.handler.check_debug("releasing",
                                                 "'a', 'b', 'c', 'd', 'e'",
                                                 "remaining: 4"))


class PathFixingTests(TwistedTestCase):
    """Test the path fixing."""

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(PathFixingTests, self).setUp()
        self.plt = PathLockingTree()

        self.handler = MementoHandler()
        self.plt.logger.setLevel(logging.DEBUG)
        self.plt.logger.propagate = False
        self.plt.logger.addHandler(self.handler)
        self.addCleanup(self.plt.logger.removeHandler, self.handler)

    def test_clean_pathlocktree(self):
        """A fix over nothing stored."""
        self.plt.fix_path(tuple('abc'), tuple('abX'))
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_simple_leaf(self):
        """Simple change for a leaf."""
        from_path = tuple('abc')
        to_path = tuple('abX')
        release = yield self.plt.acquire(*from_path)

        # get leaf deferred
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_c = node_b['children_nodes']['c']
        original_deferreds = node_c['node_deferreds']

        # fix path
        self.plt.fix_path(from_path, to_path)

        # get deferred from new path, assert is the same
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_X = node_b['children_nodes']['X']
        self.assertEqual(node_X['node_deferreds'], original_deferreds)

        # release, it should be clean now
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_complex_leaf(self):
        """Change for a leaf with two items."""
        from_path = tuple('abc')
        to_path = tuple('abX')

        releases = []
        d = self.plt.acquire(*from_path)
        d.addCallback(releases.append)
        d = self.plt.acquire(*from_path)
        d.addCallback(releases.append)

        # get leaf deferred
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_c = node_b['children_nodes']['c']
        original_deferreds = node_c['node_deferreds']

        # rename
        self.plt.fix_path(from_path, to_path)

        # get deferred from new path, assert is the same
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_X = node_b['children_nodes']['X']
        self.assertEqual(node_X['node_deferreds'], original_deferreds)

        # acquire with other one, assert that it's not released
        d = self.plt.acquire(*to_path)
        d.addCallback(lambda f: self.assertFalse(releases) or f)

        # release
        releases.pop(0)()
        releases.pop(0)()
        release = yield d
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_simple_not_leaf(self):
        """Simple change for not a leaf."""
        from_path = tuple('abc')
        to_path = tuple('aXc')
        releases = []
        d = self.plt.acquire(*from_path)
        d.addCallback(releases.append)

        # get leaf deferred
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_c = node_b['children_nodes']['c']
        original_deferreds = node_c['node_deferreds']

        # rename
        self.plt.fix_path(from_path, to_path)

        # get deferred from new path, assert is the same
        node_a = self.plt.root['children_nodes']['a']
        node_X = node_a['children_nodes']['X']
        node_c = node_X['children_nodes']['c']
        self.assertEqual(node_c['node_deferreds'], original_deferreds)

        # acquire with other one, assert that it's not released
        d = self.plt.acquire(*to_path)
        d.addCallback(lambda f: self.assertFalse(releases) or f)

        # release
        releases.pop(0)()
        release = yield d
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_same_tree(self):
        """Move a leaf one level up."""
        from_path = tuple('abcd')
        to_path = tuple('abd')
        releases = []
        d = self.plt.acquire(*from_path)
        d.addCallback(releases.append)

        # get leaf deferred
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_c = node_b['children_nodes']['c']
        node_d = node_c['children_nodes']['d']
        original_deferreds = node_d['node_deferreds']

        # rename
        self.plt.fix_path(from_path, to_path)

        # get deferred from new path, assert is the same
        node_a = self.plt.root['children_nodes']['a']
        node_b = node_a['children_nodes']['b']
        node_d = node_b['children_nodes']['d']
        self.assertEqual(node_d['node_deferreds'], original_deferreds)

        # check also that the 'c' node is gone
        self.assertNotIn('c', node_b['children_nodes'])

        # acquire with other one, assert that it's not released
        d = self.plt.acquire(*to_path)
        d.addCallback(lambda f: self.assertFalse(releases) or f)

        # release
        releases.pop(0)()
        release = yield d
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_parents_move_child(self):
        """Complex change involving parents, renaming child."""
        releases = []
        d = self.plt.acquire('a', 'b')
        d.addCallback(releases.append)
        d = self.plt.acquire('a', 'b', 'c', on_parent=True)
        d.addCallback(releases.append)

        # rename
        self.plt.fix_path(('a', 'b', 'c'), ('a', 'b', 'X'))

        # acquire with other one, assert that it's not released
        d = self.plt.acquire('a', 'b', 'X')
        d.addCallback(lambda f: self.assertFalse(releases) or f)

        # release
        releases.pop(0)()
        releases.pop(0)()
        release = yield d
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_parents_move_parent(self):
        """Complex change involving parents, renaming parent."""
        releases = []
        d = self.plt.acquire('a', 'b')
        d.addCallback(releases.append)
        d = self.plt.acquire('a', 'b', 'c', on_parent=True)
        d.addCallback(releases.append)

        # rename
        self.plt.fix_path(('a', 'b'), ('a', 'X'))

        # acquire with other one, assert that there's only one
        # left to release ('aXC', as releasing 'aX' will trigger
        # this one)
        d = self.plt.acquire('a', 'X', 'd', on_parent=True)
        d.addCallback(lambda f: self.assertEqual(len(releases), 1) and f)

        # release first the parent, then the child
        releases.pop(0)()
        releases.pop(0)()
        release = yield d
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    @defer.inlineCallbacks
    def test_very_different_children(self):
        """Aquire changing the children a lot."""
        releases = []
        d = self.plt.acquire('a', 'b', 'c', 'd')
        d.addCallback(releases.append)
        d = self.plt.acquire('a', 'b', 'c', on_children=True)
        d.addCallback(releases.append)

        # rename
        self.plt.fix_path(('a', 'b', 'c', 'd'), ('a', 'b', 'X', 'Y'))

        # acquire with other one, assert that there's only one
        # left to release ('aXC', as releasing 'aX' will trigger
        # this one)
        d = self.plt.acquire('a', 'b', 'X', on_children=True)
        d.addCallback(lambda f: self.assertEqual(len(releases), 1) and f)

        # release first the parent, then the child
        releases.pop(0)()
        releases.pop(0)()
        release = yield d
        release()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    def test_double_simple(self):
        """Simple but duplicate acquiring."""
        releases = []
        d = self.plt.acquire('GetDelta', '')
        d.addCallback(releases.append)
        d = self.plt.acquire('GetDelta', '')
        d.addCallback(releases.append)
        releases.pop(0)()
        releases.pop(0)()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    def test_moving_over(self):
        """Move over something that still exists."""
        releases = []
        d = self.plt.acquire('a', 'b', 'c')
        d.addCallback(releases.append)
        d = self.plt.acquire('a', 'b', 'd')
        d.addCallback(releases.append)

        # rename
        self.plt.fix_path(('a', 'b', 'd'), ('a', 'b', 'c'))

        # release both
        releases.pop(0)()
        releases.pop(0)()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)

    def test_irl_complicated_example(self):
        """Just a complicated move I found IRL."""
        releases = []
        d = self.plt.acquire('temp', 'drizzle', '.bzr', 'checkout', 'limbo',
                             'new-19', 'handshake.cc')
        d.addCallback(releases.append)

        # rename
        fix_from = ('temp', 'drizzle', '.bzr', 'checkout', 'limbo', 'new-19')
        fix_to = ('temp', 'drizzle', 'libdrizzle')
        self.plt.fix_path(fix_from, fix_to)

        # release it
        releases.pop(0)()
        self.assertEqual(len(self.plt.root['children_nodes']), 0)
