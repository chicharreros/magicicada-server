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

"""Routines for loading/storing u1sync mirror metadata."""

from __future__ import with_statement

import os
import uuid

from contextlib import contextmanager
import cPickle as pickle
from errno import ENOENT

from ubuntuone.storageprotocol.dircontent_pb2 import DIRECTORY

from magicicada.u1sync.merge import MergeNode
from magicicada.u1sync.utils import safe_unlink


class Metadata(object):
    """Object representing mirror metadata."""

    def __init__(self, local_tree=None, remote_tree=None, share_uuid=None,
                 root_uuid=None, path=None):
        """Populate fields."""
        self.local_tree = local_tree
        self.remote_tree = remote_tree
        self.share_uuid = share_uuid
        self.root_uuid = root_uuid
        self.path = path


def read(metadata_dir):
    """Read metadata for a mirror rooted at directory."""
    index_file = os.path.join(metadata_dir, "local-index")
    share_uuid_file = os.path.join(metadata_dir, "share-uuid")
    root_uuid_file = os.path.join(metadata_dir, "root-uuid")
    path_file = os.path.join(metadata_dir, "path")

    index = read_pickle_file(index_file, {})
    share_uuid = read_uuid_file(share_uuid_file)
    root_uuid = read_uuid_file(root_uuid_file)
    path = read_string_file(path_file, '/')

    local_tree = index.get("tree", None)
    remote_tree = index.get("remote_tree", None)

    if local_tree is None:
        local_tree = MergeNode(node_type=DIRECTORY, children={})
    if remote_tree is None:
        remote_tree = MergeNode(node_type=DIRECTORY, children={})

    return Metadata(local_tree=local_tree, remote_tree=remote_tree,
                    share_uuid=share_uuid, root_uuid=root_uuid,
                    path=path)


def write(metadata_dir, info):
    """Writes all metadata for the mirror rooted at directory."""
    share_uuid_file = os.path.join(metadata_dir, "share-uuid")
    root_uuid_file = os.path.join(metadata_dir, "root-uuid")
    index_file = os.path.join(metadata_dir, "local-index")
    path_file = os.path.join(metadata_dir, "path")
    if info.share_uuid is not None:
        write_uuid_file(share_uuid_file, info.share_uuid)
    else:
        safe_unlink(share_uuid_file)
    if info.root_uuid is not None:
        write_uuid_file(root_uuid_file, info.root_uuid)
    else:
        safe_unlink(root_uuid_file)
    write_string_file(path_file, info.path)
    write_pickle_file(index_file, {"tree": info.local_tree,
                                   "remote_tree": info.remote_tree})


def write_pickle_file(filename, value):
    """Writes a pickled python object to a file."""
    with atomic_update_file(filename) as stream:
        pickle.dump(value, stream, 2)


def write_string_file(filename, value):
    """Writes a string to a file with an added line feed, or
    deletes the file if value is None.
    """
    if value is not None:
        with atomic_update_file(filename) as stream:
            stream.write(value)
            stream.write('\n')
    else:
        safe_unlink(filename)


def write_uuid_file(filename, value):
    """Writes a UUID to a file."""
    write_string_file(filename, str(value))


def read_pickle_file(filename, default_value=None):
    """Reads a pickled python object from a file."""
    try:
        with open(filename, "rb") as stream:
            return pickle.load(stream)
    except IOError as e:
        if e.errno != ENOENT:
            raise
        return default_value


def read_string_file(filename, default_value=None):
    """Reads a string from a file, discarding the final character."""
    try:
        with open(filename, "r") as stream:
            return stream.read()[:-1]
    except IOError as e:
        if e.errno != ENOENT:
            raise
        return default_value


def read_uuid_file(filename, default_value=None):
    """Reads a UUID from a file."""
    try:
        with open(filename, "r") as stream:
            return uuid.UUID(stream.read()[:-1])
    except IOError as e:
        if e.errno != ENOENT:
            raise
        return default_value


@contextmanager
def atomic_update_file(filename):
    """Returns a context manager for atomically updating a file."""
    temp_filename = "%s.%s" % (filename, uuid.uuid4())
    try:
        with open(temp_filename, "w") as stream:
            yield stream
        os.rename(temp_filename, filename)
    finally:
        safe_unlink(temp_filename)
