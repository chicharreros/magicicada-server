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

"""Miscellaneous utility functions."""

import os

from errno import EEXIST, ENOENT

from magicicada.u1sync.constants import METADATA_DIR_NAME, SPECIAL_FILE_RE


def should_sync(filename):
    """Returns True if the filename should be synced.

    @param filename: a unicode filename

    """
    return (filename != METADATA_DIR_NAME and
            not SPECIAL_FILE_RE.match(filename))


def safe_mkdir(path):
    """Creates a directory if it does not already exist."""
    try:
        os.mkdir(path)
    except OSError, e:
        if e.errno != EEXIST:
            raise


def safe_unlink(path):
    """Unlinks a file if it exists."""
    try:
        os.remove(path)
    except OSError, e:
        if e.errno != ENOENT:
            raise
