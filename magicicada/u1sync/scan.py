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

"""Code for scanning local directory state."""

import hashlib
import logging
import os
import shutil

from errno import ENOTDIR, EINVAL

from magicicadaprotocol.dircontent_pb2 import DIRECTORY, FILE, SYMLINK

from magicicada.u1sync.genericmerge import MergeNode
from magicicada.u1sync.utils import should_sync


logger = logging.getLogger(__name__)
EMPTY_HASH = "sha1:%s" % hashlib.sha1().hexdigest()


def scan_directory(path, display_path=""):
    """Scans a local directory and builds an in-memory tree from it."""
    if display_path != "":
        logger.debug(display_path)

    link_target = None
    child_names = None
    try:
        link_target = os.readlink(path)
    except OSError as e:
        if e.errno != EINVAL:
            raise
        try:
            child_names = os.listdir(path)
        except OSError as e:
            if e.errno != ENOTDIR:
                raise

    if link_target is not None:
        # symlink
        sum = hashlib.sha1()
        sum.update(link_target)
        content_hash = "sha1:%s" % sum.hexdigest()
        return MergeNode(node_type=SYMLINK, content_hash=content_hash)
    elif child_names is not None:
        # directory
        child_names = [
            n for n in child_names if should_sync(n.decode("utf-8"))]
        child_paths = [(os.path.join(path, child_name),
                        os.path.join(display_path, child_name))
                       for child_name in child_names]
        children = [scan_directory(child_path, child_display_path)
                    for (child_path, child_display_path) in child_paths]
        unicode_child_names = [n.decode("utf-8") for n in child_names]
        children = dict(zip(unicode_child_names, children))
        return MergeNode(node_type=DIRECTORY, children=children)
    else:
        # regular file
        sum = hashlib.sha1()

        class HashStream(object):
            """Stream that computes hashes."""
            def write(self, bytes):
                """Accumulate bytes."""
                sum.update(bytes)

        with open(path, "r") as stream:
            shutil.copyfileobj(stream, HashStream())
        content_hash = "sha1:%s" % sum.hexdigest()
        return MergeNode(node_type=FILE, content_hash=content_hash)
