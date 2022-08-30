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

"""Code for merging changes between modified trees."""

import os
import uuid

from magicicadaprotocol.dircontent_pb2 import DIRECTORY

from magicicada.u1sync.genericmerge import MergeNode, generic_merge


class NodeTypeMismatchError(Exception):
    """Node types don't match."""


def merge_trees(
    old_local_tree, local_tree, old_remote_tree, remote_tree, merge_action
):
    """Performs a tree merge using the given merge action."""

    def pre_merge(nodes, name, partial_parent):
        """Accumulates path and determines merged node type."""
        old_local_node, local_node, old_remote_node, remote_node = nodes
        (parent_path, parent_type) = partial_parent
        path = os.path.join(parent_path, name)
        node_type = merge_action.get_node_type(
            old_local_node=old_local_node,
            local_node=local_node,
            old_remote_node=old_remote_node,
            remote_node=remote_node,
            path=path,
        )
        return (path, node_type)

    def post_merge(nodes, partial_result, child_results):
        """Drops deleted children and merges node."""
        old_local_node, local_node, old_remote_node, remote_node = nodes
        (path, node_type) = partial_result
        if node_type == DIRECTORY:
            merged_children = dict(
                (name, child)
                for (name, child) in child_results.items()
                if child is not None
            )
        else:
            merged_children = None
        return merge_action.merge_node(
            old_local_node=old_local_node,
            local_node=local_node,
            old_remote_node=old_remote_node,
            remote_node=remote_node,
            node_type=node_type,
            merged_children=merged_children,
        )

    return generic_merge(
        trees=[old_local_tree, local_tree, old_remote_tree, remote_tree],
        pre_merge=pre_merge,
        post_merge=post_merge,
        name="",
        partial_parent=("", None),
    )


class SyncMerge(object):
    """Performs a bidirectional sync merge."""

    def get_node_type(
        self, old_local_node, local_node, old_remote_node, remote_node, path
    ):
        """Requires that all node types match."""
        node_type = None
        for node in (old_local_node, local_node, remote_node):
            if node is not None:
                if node_type is not None:
                    if node.node_type != node_type:
                        message = "Node types don't match for %s" % path
                        raise NodeTypeMismatchError(message)
                else:
                    node_type = node.node_type
        return node_type

    def merge_node(
        self,
        old_local_node,
        local_node,
        old_remote_node,
        remote_node,
        node_type,
        merged_children,
    ):
        """Performs bidirectional merge of node state."""

        def node_content_hash(node):
            """Returns node content hash if node is not None"""
            return node.content_hash if node is not None else None

        old_local_content_hash = node_content_hash(old_local_node)
        local_content_hash = node_content_hash(local_node)
        old_remote_content_hash = node_content_hash(old_remote_node)
        remote_content_hash = node_content_hash(remote_node)

        locally_deleted = old_local_node is not None and local_node is None
        deleted_on_server = old_remote_node is not None and remote_node is None
        # updated means modified or created
        locally_updated = (
            not locally_deleted
            and old_local_content_hash != local_content_hash
        )
        updated_on_server = (
            not deleted_on_server
            and old_remote_content_hash != remote_content_hash
        )

        has_merged_children = (
            merged_children is not None and len(merged_children) > 0
        )

        either_node_exists = local_node is not None or remote_node is not None
        should_delete = (locally_deleted and not updated_on_server) or (
            deleted_on_server and not locally_updated
        )

        if (either_node_exists and not should_delete) or has_merged_children:
            if (
                node_type != DIRECTORY
                and locally_updated
                and updated_on_server
                and local_content_hash != remote_content_hash
            ):
                # local_content_hash will become the merged content_hash;
                # save remote_content_hash in conflict info
                conflict_info = (str(uuid.uuid4()), remote_content_hash)
            else:
                conflict_info = None
            node_uuid = remote_node.uuid if remote_node is not None else None
            if locally_updated:
                content_hash = local_content_hash or remote_content_hash
            else:
                content_hash = remote_content_hash or local_content_hash
            return MergeNode(
                node_type=node_type,
                uuid=node_uuid,
                children=merged_children,
                content_hash=content_hash,
                conflict_info=conflict_info,
            )
        else:
            return None


class ClobberServerMerge(object):
    """Clobber server to match local state."""

    def get_node_type(
        self, old_local_node, local_node, old_remote_node, remote_node, path
    ):
        """Return local node type."""
        if local_node is not None:
            return local_node.node_type
        else:
            return None

    def merge_node(
        self,
        old_local_node,
        local_node,
        old_remote_node,
        remote_node,
        node_type,
        merged_children,
    ):
        """Copy local node and associate with remote uuid (if applicable)."""
        if local_node is None:
            return None
        if remote_node is not None:
            node_uuid = remote_node.uuid
        else:
            node_uuid = None
        return MergeNode(
            node_type=local_node.node_type,
            uuid=node_uuid,
            content_hash=local_node.content_hash,
            children=merged_children,
        )


class ClobberLocalMerge(object):
    """Clobber local state to match server."""

    def get_node_type(
        self, old_local_node, local_node, old_remote_node, remote_node, path
    ):
        """Return remote node type."""
        if remote_node is not None:
            return remote_node.node_type
        else:
            return None

    def merge_node(
        self,
        old_local_node,
        local_node,
        old_remote_node,
        remote_node,
        node_type,
        merged_children,
    ):
        """Copy the remote node."""
        if remote_node is None:
            return None
        return MergeNode(
            node_type=node_type,
            uuid=remote_node.uuid,
            content_hash=remote_node.content_hash,
            children=merged_children,
        )
