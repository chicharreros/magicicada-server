# Copyright 2009 Canonical Ltd.
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Tests for tree merging."""

import uuid
import os

from unittest import TestCase

from magicicadaprotocol.dircontent_pb2 import FILE, DIRECTORY

from magicicada.u1sync.genericmerge import MergeNode, generic_merge
from magicicada.u1sync.merge import (
    merge_trees,
    ClobberLocalMerge,
    ClobberServerMerge,
    SyncMerge,
)


def accumulate_path(nodes, name, partial_parent):
    """pre-merge which accumulates a path"""
    return os.path.join(partial_parent, name)


def capture_merge(nodes, partial_result, child_results):
    """post-merge which accumulates merge results."""
    return (nodes, partial_result, child_results)


class MergeTest(TestCase):
    """Tests for generic tree merges."""

    def test_generic_merge(self):
        """Tests that generic merge behaves as expected."""
        tree_a = MergeNode(
            DIRECTORY,
            children={
                'foo': MergeNode(FILE, uuid=uuid.uuid4()),
                'bar': MergeNode(FILE, uuid=uuid.uuid4()),
            },
            uuid=uuid.uuid4(),
        )
        tree_b = MergeNode(
            DIRECTORY,
            children={
                'bar': MergeNode(FILE, uuid=uuid.uuid4()),
                'baz': MergeNode(FILE, uuid=uuid.uuid4()),
            },
            uuid=uuid.uuid4(),
        )
        result = generic_merge(
            trees=[tree_a, tree_b],
            pre_merge=accumulate_path,
            post_merge=capture_merge,
            partial_parent="",
            name="ex",
        )
        expected_result = (
            [tree_a, tree_b],
            "ex",
            {
                'foo': ([tree_a.children['foo'], None], "ex/foo", {}),
                'bar': (
                    [tree_a.children['bar'], tree_b.children['bar']],
                    "ex/bar",
                    {},
                ),
                'baz': ([None, tree_b.children['baz']], "ex/baz", {}),
            },
        )
        self.assertEqual(expected_result, result)

    def test_clobber(self):
        """Tests clobbering merges."""
        server_tree = MergeNode(
            DIRECTORY,
            children={
                'foo': MergeNode(FILE, content_hash="dummy:abc"),
                'bar': MergeNode(FILE, content_hash="dummy:xyz"),
                'baz': MergeNode(FILE, content_hash="dummy:aaa"),
            },
        )
        local_tree = MergeNode(
            DIRECTORY,
            children={
                'foo': MergeNode(FILE, content_hash="dummy:cde"),
                'bar': MergeNode(FILE, content_hash="dummy:zyx"),
                'hoge': MergeNode(FILE, content_hash="dummy:bbb"),
            },
        )
        result_tree = merge_trees(
            local_tree,
            local_tree,
            server_tree,
            server_tree,
            ClobberServerMerge(),
        )
        self.assertEqual(local_tree, result_tree)
        result_tree = merge_trees(
            local_tree,
            local_tree,
            server_tree,
            server_tree,
            ClobberLocalMerge(),
        )
        self.assertEqual(server_tree, result_tree)

    def test_sync(self):
        """Test sync merges."""
        server_tree = MergeNode(
            DIRECTORY,
            children={
                'bar': MergeNode(FILE, content_hash="dummy:xyz"),
                'baz': MergeNode(FILE, content_hash="dummy:aaa"),
                'foo': MergeNode(FILE, content_hash="dummy:abc"),
            },
        )
        old_server_tree = MergeNode(DIRECTORY, children={})
        local_tree = MergeNode(
            DIRECTORY,
            children={
                'bar': MergeNode(FILE, content_hash="dummy:xyz"),
                'foo': MergeNode(FILE, content_hash="dummy:abc"),
                'hoge': MergeNode(FILE, content_hash="dummy:bbb"),
            },
        )
        old_local_tree = MergeNode(DIRECTORY, children={})
        expected_tree = MergeNode(
            DIRECTORY,
            children={
                'bar': MergeNode(FILE, content_hash="dummy:xyz"),
                'baz': MergeNode(FILE, content_hash="dummy:aaa"),
                'foo': MergeNode(FILE, content_hash="dummy:abc"),
                'hoge': MergeNode(FILE, content_hash="dummy:bbb"),
            },
        )
        result_tree = merge_trees(
            old_local_tree,
            local_tree,
            old_server_tree,
            server_tree,
            SyncMerge(),
        )
        self.assertEqual(result_tree, expected_tree)
