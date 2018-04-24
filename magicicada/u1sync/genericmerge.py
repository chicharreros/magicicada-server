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

"""A generic abstraction for merge operations on directory trees."""

from itertools import chain

from ubuntuone.storageprotocol.dircontent_pb2 import DIRECTORY


class MergeNode(object):
    """A filesystem node.  Should generally be treated as immutable."""
    def __init__(self, node_type, content_hash=None, uuid=None, children=None,
                 conflict_info=None):
        """Initializes a node instance."""
        self.node_type = node_type
        self.children = children
        self.uuid = uuid
        self.content_hash = content_hash
        self.conflict_info = conflict_info

    def __eq__(self, other):
        """Equality test."""
        if type(other) is not type(self):
            return False
        return (self.node_type == other.node_type and
                self.children == other.children and
                self.uuid == other.uuid and
                self.content_hash == other.content_hash and
                self.conflict_info == other.conflict_info)

    def __ne__(self, other):
        """Non-equality test."""
        return not self.__eq__(other)


def show_tree(tree, indent="", name="/"):
    """Prints a tree."""
    if tree.node_type == DIRECTORY:
        type_str = "DIR "
    else:
        type_str = "FILE"
    print "%s%-36s %s %s  %s" % (indent, tree.uuid, type_str, name,
                                 tree.content_hash)
    if tree.node_type == DIRECTORY and tree.children is not None:
        for name in sorted(tree.children.keys()):
            subtree = tree.children[name]
            show_tree(subtree, indent="  " + indent, name=name)


def generic_merge(trees, pre_merge, post_merge, partial_parent, name):
    """Generic tree merging function."""

    partial_result = pre_merge(nodes=trees, name=name,
                               partial_parent=partial_parent)

    def tree_children(tree):
        """Returns children if tree is not None"""
        return tree.children if tree is not None else None

    child_dicts = [tree_children(t) or {} for t in trees]
    child_names = set(chain(*[cs.iterkeys() for cs in child_dicts]))
    child_results = {}
    for child_name in child_names:
        subtrees = [cs.get(child_name, None) for cs in child_dicts]
        child_result = generic_merge(trees=subtrees,
                                     pre_merge=pre_merge,
                                     post_merge=post_merge,
                                     partial_parent=partial_result,
                                     name=child_name)
        child_results[child_name] = child_result

    return post_merge(nodes=trees, partial_result=partial_result,
                      child_results=child_results)
