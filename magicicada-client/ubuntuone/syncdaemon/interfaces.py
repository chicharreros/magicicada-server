# -*- coding: utf-8 -*-
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
"""This is the interface of the ActionQueue."""

from zope.interface import Interface, Attribute


class IContentQueue(Interface):
    """
    The content queue is the part of access queue that manages uploads
    and downloads of content.
    """

    def cancel_download(share_id, node_id):
        """
        Try to cancel any download for the given node.

        The return value is whether we've been able to cancel a
        download.
        """

    def cancel_upload(share_id, node_id):
        """
        Try to cancel any upload for the given node.

        The return value is whether we're sure that we've been able to
        cancel an upload. We might succeed without knowing it,
        however.
        """

    def download(share_id, node_id, server_hash, path):
        """Go get the content for the given node."""

    def upload(share_id, node_id, previous_hash, hash, crc32, size, path):
        """Upload the content of the node."""


class IMetaQueue(Interface):
    """
    The MetaQueue is the part of AccessQueue that manages transfers of
    metadata.
    """

    def make_file(share_id, parent_id, name, marker, path):
        """
        Ask the server to create a file called name in the given
        parent; and use marker as a marker in the ensuing
        notification.
        """

    def make_dir(share_id, parent_id, name, marker, path):
        """
        Ask the server to make a directory called name in the given
        parent, and use marker as a marker in the ensuing
        notification.
        """

    def move(share_id, node_id, old_parent_id, new_parent_id, new_name,
             path_from, path_to):
        """
        Ask the server to move a node to the given parent and name.
        """

    def unlink(share_id, parent_id, node_id, path, is_dir):
        """
        Unlink the given node.
        """

    def inquire_free_space(share_id):
        """
        Inquire after free space in the given volume and put the result on
        the event queue.
        """

    def inquire_account_info():
        """Ask the state of the user's account (purchased space, etc)."""

    def list_shares():
        """
        Get a list of the shares, and put the result on the event queue.
        """

    def answer_share(share_id, answer):
        """Answer the offer of a share."""

    def create_share(node, share_to, name, access_level, marker, path):
        """
        Ask the server to create a share.
        """

    def delete_share(share_id):
        """Delete a offered share."""

    def create_udf(path, name, marker):
        """Create a User Defined Folder.

        @param path: the path in disk to the UDF.
        @param name: the name of the UDF.
        @param marker: a marker identifying this UDF request.

        Result will be signaled using events:
            - AQ_CREATE_UDF_OK on succeess.
            - AQ_CREATE_UDF_ERROR on failure.
        """

    def list_volumes():
        """List all the volumes the user has.

        This includes the volumes:
            - all the user's UDFs.
            - all the shares the user has accepted.
            - the root-root volume.

        Result will be signaled using events.
            - AQ_LIST_VOLUMES for the volume list.

        """

    def delete_volume(volume_id, path):
        """Delete a volume on the server, removing the associated tree.

        @param volume_id: the id of the volume to delete.
        @param path: the path of the volume to delete

        Result will be signaled using events:
            - AQ_DELETE_VOLUME_OK on success.
            - AQ_DELETE_VOLUME_ERROR on failure.

        """

    def change_public_access(share_id, node_id, is_public):
        """Change the public access of a file.

        @param share_id: the id of the share holding the file.
        @param node_id: the id of the file.
        @param is_public: whether to make the file public.

        Result will be signaled using events:
            - AQ_CHANGE_PUBLIC_ACCESS_OK on success.
            - AQ_CHANGE_PUBLIC_ACCESS_ERROR on failure.
        """

    def get_public_files():
        """Get the list of public files.

        Result will be signaled using events:
            - AQ_PUBLIC_FILES_LIST_OK on success.
            - AQ_PUBLIC_FILES_LIST_ERROR on failure.
        """

    def get_delta(volume_id, generation):
        """Get a delta from generation for the volume.

        @param volume_id: the id of the volume to get the delta.
        @param generation: the generation to get the delta from.

        Result will be signaled using events:
            - AQ_DELTA_OK on succeess.
            - AQ_DELTA_ERROR on generic failure.
            - AQ_DELTA_NOT_POSSIBLE if the server told so

        """

    def rescan_from_scratch(volume_id):
        """Get a delta from scratch for the volume.

        @param volume_id: the id of the volume to get the delta.

        Result will be signaled using events:
            - AQ_RESCAN_FROM_SCRATCH_OK on succeess.
            - AQ_RESCAN_FROM_SCRATCH_ERROR on generic failure.
        """

    def node_is_with_queued_move(share_id, node_id):
        """True if a Move is queued for that node."""


class IActionQueue(IContentQueue, IMetaQueue):
    """
    The access queue itself.
    """

    queue = Attribute("The RequestQueue.")
    uuid_map = Attribute("The marker/uuid deferred map.")

    def connect():
        """Open a (possibly SSL) connection to the API server on (host, port).

        Once you've connected, authenticate.
        """

    def disconnect():
        """Close the connection."""


class IMarker(Interface):
    """
    A marker interface for telling server uuids apart from markers.
    """
