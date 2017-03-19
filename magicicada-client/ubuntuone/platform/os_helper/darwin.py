# ubuntuone.platform.os_helper - darwin platform imports
#
# Copyright 2012 Canonical Ltd.
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
"""
Darwin import for ubuntuone-client

This module has to have all darwin specific modules and provide the
api required to support the darwin platform.
"""

import errno
import logging
import os
import shutil
import unicodedata

from ubuntuone.platform.os_helper import unix

platform = "darwin"

logger = logging.getLogger('ubuntuone.SyncDaemon')


set_no_rights = unix.set_no_rights
set_file_readonly = unix.set_file_readonly
set_file_readwrite = unix.set_file_readwrite
set_dir_readonly = unix.set_dir_readonly
set_dir_readwrite = unix.set_dir_readwrite
allow_writes = unix.allow_writes
remove_file = unix.remove_file
remove_tree = unix.remove_tree
remove_dir = unix.remove_dir
path_exists = unix.path_exists
is_dir = unix.is_dir
make_dir = unix.make_dir
open_file = unix.open_file
rename = unix.rename
native_rename = unix.native_rename
recursive_move = unix.recursive_move
make_link = unix.make_link
is_link = unix.is_link
remove_link = unix.remove_link
access = unix.access
can_write = unix.can_write
stat_path = unix.stat_path
is_root = unix.is_root
get_path_list = unix.get_path_list
normpath = unix.normpath
get_os_valid_path = unix.get_os_valid_path


def move_to_trash(path):
    """Move the file or dir to trash.

    If had any error, or the system can't do it, just remove it.

    Handles the case where path lies on a removable volume.
    """
    full_path = os.path.abspath(path)

    if not path_exists(full_path):
        raise OSError(errno.ENOENT, 'File could %r not be found.' % full_path)
    if full_path.startswith("/Volumes/"):
        components = full_path.split(os.path.sep)
        vol_components = components[:3]
        file_components = [".Trashes", str(os.geteuid()),
                           os.path.basename(full_path)]
        trashpath = os.path.sep.join(vol_components + file_components)
    else:
        trashpath = os.path.expanduser("~/.Trash")

    try:
        shutil.move(path, trashpath)
    except Exception, reason:
        logger.warning("Problems moving to trash! (%r) Removing anyway: %r",
                       reason, path)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


def set_application_name(app_name):
    """Set the name of the application."""
    # nothing to be done let the plist take care of it


# TODO: Implement this decorators to fix some encoding issues in darwin

def is_valid_syncdaemon_path(path_indexes=None):
    def decorator(func):
        def wrapped(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapped
    return decorator


def is_valid_os_path(path_indexes=None):
    def decorator(func):
        def wrapped(*args, **kwargs):
            for i in path_indexes:
                assert isinstance(args[i], str), 'Path %r should be str.'
            return func(*args, **kwargs)
        return wrapped
    return decorator


def os_path(path_indexes=None):
    if path_indexes is None:
        path_indexes = [0]

    def decorator(func):
        def wrapped(*args, **kwargs):
            for i in path_indexes:
                assert isinstance(args[i], str), 'Path %r should be str.'
            return func(*args, **kwargs)
        return wrapped
    return decorator


def get_syncdaemon_valid_path(path):
    """Get a 'darwin' path and modify it so that it can be used in sd."""
    return unicodedata.normalize('NFC', path.decode('utf-8')).encode('utf-8')


def read_link(path):
    """Read the destination of a link."""
    destination = os.readlink(path)
    return get_syncdaemon_valid_path(destination)


def listdir(directory):
    """List a directory."""
    return map(get_syncdaemon_valid_path, os.listdir(directory))


def walk(path, topdown=True):
    """Walk a dir."""
    for dirpath, dirnames, filenames in os.walk(path, topdown):
        dirpath = get_syncdaemon_valid_path(dirpath)
        dirnames = map(get_syncdaemon_valid_path, dirnames)
        filenames = map(get_syncdaemon_valid_path, filenames)
        yield dirpath, dirnames, filenames
