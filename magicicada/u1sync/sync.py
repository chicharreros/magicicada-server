# coding: utf-8
#
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

"""Sync.

After merging, these routines are used to synchronize state locally and on
the server to correspond to the merged result.

"""

from __future__ import with_statement, unicode_literals

import os
import logging

from magicicadaprotocol import request
from magicicadaprotocol.dircontent_pb2 import DIRECTORY, SYMLINK

from magicicada.u1sync.client import UnsupportedOperationError
from magicicada.u1sync.genericmerge import MergeNode, generic_merge
from magicicada.u1sync.utils import safe_mkdir


EMPTY_HASH = b""
UPLOAD_SYMBOL = "▲"
DOWNLOAD_SYMBOL = "▼"
CONFLICT_SYMBOL = "!"
DELETE_SYMBOL = "X"
logger = logging.getLogger(__name__)


def get_conflict_path(path, conflict_info):
    """Return path for conflict file corresponding to path."""
    dir, name = os.path.split(path)
    unique_id = conflict_info[0]
    return os.path.join(dir, "conflict-%s-%s" % (unique_id, name))


def name_from_path(path):
    """Return unicode name from last path component."""
    return os.path.split(path)[1]


class NodeSyncError(Exception):
    """Error syncing node."""


class NodeCreateError(NodeSyncError):
    """Error creating node."""


class NodeUpdateError(NodeSyncError):
    """Error updating node."""


class NodeDeleteError(NodeSyncError):
    """Error deleting node."""


def sync_tree(merged_tree, original_tree, sync_mode, path):
    """Performs actual synchronization."""

    def pre_merge(nodes, name, partial_parent):
        """Create nodes and write content as required."""
        (merged_node, original_node) = nodes
        (parent_path, parent_display_path, parent_uuid,
         parent_synced) = partial_parent

        utf8_name = name  # .encode("utf-8")
        path = os.path.join(parent_path, utf8_name)
        display_path = os.path.join(parent_display_path, utf8_name)
        node_uuid = None

        synced = False
        if merged_node is not None:
            if merged_node.node_type == DIRECTORY:
                if original_node is not None:
                    synced = True
                    node_uuid = original_node.uuid
                else:
                    logger.debug("%s   %s", sync_mode.symbol, display_path)
                    try:
                        create_dir = sync_mode.create_directory
                        node_uuid = create_dir(parent_uuid=parent_uuid,
                                               path=path)
                        synced = True
                    except NodeCreateError:
                        logging.exception('NodeCreateError on sync_tree:')
            elif merged_node.content_hash is None:
                logger.debug("?   %s", display_path)
            elif (original_node is None or
                  original_node.content_hash != merged_node.content_hash or
                  merged_node.conflict_info is not None):
                conflict_info = merged_node.conflict_info
                if conflict_info is not None:
                    conflict_symbol = CONFLICT_SYMBOL
                else:
                    conflict_symbol = " "
                logger.debug(
                    "%s %s %s",
                    sync_mode.symbol, conflict_symbol, display_path)
                if original_node is not None:
                    node_uuid = original_node.uuid or merged_node.uuid
                    original_hash = original_node.content_hash or EMPTY_HASH
                else:
                    node_uuid = merged_node.uuid
                    original_hash = EMPTY_HASH
                try:
                    sync_mode.write_file(
                        node_uuid=node_uuid,
                        content_hash=merged_node.content_hash,
                        old_content_hash=original_hash, path=path,
                        parent_uuid=parent_uuid, conflict_info=conflict_info,
                        node_type=merged_node.node_type)
                    synced = True
                except NodeSyncError:
                    logging.exception('NodeSyncError on sync_tree:')
            else:
                synced = True

        return (path, display_path, node_uuid, synced)

    def post_merge(nodes, partial_result, child_results):
        """Delete nodes."""
        (merged_node, original_node) = nodes
        (path, display_path, node_uuid, synced) = partial_result

        if merged_node is None:
            assert original_node is not None
            logger.debug(
                "%s %s %s",
                sync_mode.symbol, DELETE_SYMBOL, display_path)
            try:
                if original_node.node_type == DIRECTORY:
                    sync_mode.delete_directory(node_uuid=original_node.uuid,
                                               path=path)
                else:
                    # files or symlinks
                    sync_mode.delete_file(node_uuid=original_node.uuid,
                                          path=path)
                synced = True
            except NodeDeleteError:
                logger.exception('NodeDeleteError on post_merge:')

        if synced:
            model_node = merged_node
        else:
            model_node = original_node

        if model_node is not None:
            if model_node.node_type == DIRECTORY:
                child_iter = child_results.items()
                merged_children = dict(
                    (name, child) for (name, child) in child_iter
                    if child is not None)
            else:
                # if there are children here it's because they failed to delete
                merged_children = None
            return MergeNode(node_type=model_node.node_type,
                             uuid=model_node.uuid,
                             children=merged_children,
                             content_hash=model_node.content_hash)
        else:
            return None

    return generic_merge(trees=[merged_tree, original_tree],
                         pre_merge=pre_merge, post_merge=post_merge,
                         partial_parent=(path, "", None, True), name="")


def download_tree(merged_tree, local_tree, client, share_uuid, path, dry_run):
    """Downloads a directory."""
    if dry_run:
        downloader = DryRun(symbol=DOWNLOAD_SYMBOL)
    else:
        downloader = Downloader(client=client, share_uuid=share_uuid)
    return sync_tree(merged_tree=merged_tree, original_tree=local_tree,
                     sync_mode=downloader, path=path)


def upload_tree(merged_tree, remote_tree, client, share_uuid, path, dry_run):
    """Uploads a directory."""
    if dry_run:
        uploader = DryRun(symbol=UPLOAD_SYMBOL)
    else:
        uploader = Uploader(client=client, share_uuid=share_uuid)
    return sync_tree(merged_tree=merged_tree, original_tree=remote_tree,
                     sync_mode=uploader, path=path)


class DryRun(object):
    """A class which implements the sync interface but does nothing."""
    def __init__(self, symbol):
        """Initializes a DryRun instance."""
        self.symbol = symbol

    def create_directory(self, parent_uuid, path):
        """Doesn't create a directory."""
        return None

    def write_file(self, node_uuid, old_content_hash, content_hash,
                   parent_uuid, path, conflict_info, node_type):
        """Doesn't write a file."""
        return None

    def delete_directory(self, node_uuid, path):
        """Doesn't delete a directory."""

    def delete_file(self, node_uuid, path):
        """Doesn't delete a file."""


class Downloader(object):
    """A class which implements the download half of syncing."""
    def __init__(self, client, share_uuid):
        """Initializes a Downloader instance."""
        self.client = client
        self.share_uuid = share_uuid
        self.symbol = DOWNLOAD_SYMBOL

    def create_directory(self, parent_uuid, path):
        """Creates a directory."""
        try:
            safe_mkdir(path)
        except OSError as e:
            raise NodeCreateError(
                "Error creating local directory %s: %s" % (path, e))
        return None

    def write_file(self, node_uuid, old_content_hash, content_hash,
                   parent_uuid, path, conflict_info, node_type):
        """Creates a file and downloads new content for it."""
        if conflict_info:
            # download to conflict file rather than overwriting local changes
            path = get_conflict_path(path, conflict_info)
            content_hash = conflict_info[1]
        try:
            if node_type == SYMLINK:
                self.client.download_string(
                    share_uuid=self.share_uuid, node_uuid=node_uuid,
                    content_hash=content_hash)
            else:
                self.client.download_file(
                    share_uuid=self.share_uuid, node_uuid=node_uuid,
                    content_hash=content_hash, filename=path)
        except (request.StorageRequestError, UnsupportedOperationError) as e:
            if os.path.exists(path):
                raise NodeUpdateError(
                    "Error downloading content for %s: %s" % (path, e))
            else:
                raise NodeCreateError(
                    "Error locally creating %s: %s" % (path, e))

    def delete_directory(self, node_uuid, path):
        """Deletes a directory."""
        try:
            os.rmdir(path)
        except OSError as e:
            raise NodeDeleteError("Error locally deleting %s: %s" % (path, e))

    def delete_file(self, node_uuid, path):
        """Deletes a file."""
        try:
            os.remove(path)
        except OSError as e:
            raise NodeDeleteError("Error locally deleting %s: %s" % (path, e))


class Uploader(object):
    """A class which implements the upload half of syncing."""
    def __init__(self, client, share_uuid):
        """Initializes an uploader instance."""
        self.client = client
        self.share_uuid = share_uuid
        self.symbol = UPLOAD_SYMBOL

    def create_directory(self, parent_uuid, path):
        """Creates a directory on the server."""
        name = name_from_path(path)
        try:
            return self.client.create_directory(share_uuid=self.share_uuid,
                                                parent_uuid=parent_uuid,
                                                name=name)
        except (request.StorageRequestError, UnsupportedOperationError) as e:
            raise NodeCreateError("Error remotely creating %s: %s" % (path, e))

    def write_file(self, node_uuid, old_content_hash, content_hash,
                   parent_uuid, path, conflict_info, node_type):
        """Creates a file on the server and uploads new content for it."""

        if conflict_info:
            # move conflicting file out of the way on the server
            conflict_path = get_conflict_path(path, conflict_info)
            conflict_name = name_from_path(conflict_path)
            try:
                self.client.move(share_uuid=self.share_uuid,
                                 parent_uuid=parent_uuid,
                                 name=conflict_name,
                                 node_uuid=node_uuid)
            except (request.StorageRequestError,
                    UnsupportedOperationError) as e:
                raise NodeUpdateError(
                    "Error remotely renaming %s to %s: %s" %
                    (path, conflict_path, e))
            node_uuid = None
            old_content_hash = EMPTY_HASH

        if node_type == SYMLINK:
            try:
                target = os.readlink(path)
            except OSError as e:
                raise NodeCreateError(
                    "Error retrieving link target for %s: %s" % (path, e))
        else:
            target = None

        name = name_from_path(path)
        if node_uuid is None:
            try:
                if node_type == SYMLINK:
                    node_uuid = self.client.create_symlink(
                        share_uuid=self.share_uuid, parent_uuid=parent_uuid,
                        name=name, target=target)
                    old_content_hash = content_hash
                else:
                    node_uuid = self.client.create_file(
                        share_uuid=self.share_uuid, parent_uuid=parent_uuid,
                        name=name)
            except (request.StorageRequestError,
                    UnsupportedOperationError) as e:
                raise NodeCreateError(
                    "Error remotely creating %s: %s" % (path, e))

        if old_content_hash != content_hash:
            try:
                if node_type == SYMLINK:
                    self.client.upload_string(
                        share_uuid=self.share_uuid, node_uuid=node_uuid,
                        content_hash=content_hash,
                        old_content_hash=old_content_hash, content=target)
                else:
                    self.client.upload_file(
                        share_uuid=self.share_uuid, node_uuid=node_uuid,
                        content_hash=content_hash,
                        old_content_hash=old_content_hash, filename=path)
            except (request.StorageRequestError,
                    UnsupportedOperationError) as e:
                raise NodeUpdateError(
                    "Error uploading content for %s: %s" % (path, e))

    def delete_directory(self, node_uuid, path):
        """Deletes a directory."""
        try:
            self.client.unlink(share_uuid=self.share_uuid, node_uuid=node_uuid)
        except (request.StorageRequestError, UnsupportedOperationError) as e:
            raise NodeDeleteError("Error remotely deleting %s: %s" % (path, e))

    def delete_file(self, node_uuid, path):
        """Deletes a file."""
        try:
            self.client.unlink(share_uuid=self.share_uuid, node_uuid=node_uuid)
        except (request.StorageRequestError, UnsupportedOperationError) as e:
            raise NodeDeleteError("Error remotely deleting %s: %s" % (path, e))
