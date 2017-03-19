# -*- encoding: utf-8 -*-
#
# Copyright 2009-2013 Canonical Ltd.
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
"""Platform specific bindings."""

import os
import sys

from dirspec.utils import user_home

from ubuntuone.platform import ipc
from ubuntuone.platform import logger
from ubuntuone.platform import os_helper


# define a platform string separate from sys.platform to be sent to
# the server for metrics in ActionQueue.authenticate().
if sys.platform == "win32":
    platform = "win32"
elif sys.platform == "darwin":
    platform = "darwin"
else:
    platform = "linux"


def expand_user(path):
    """Fix Python expanduser for weird chars in windows."""
    assert isinstance(path, str)
    try:
        path.decode('utf-8')
    except UnicodeDecodeError:
        raise AssertionError('The path %r must be encoded in utf-8' % path)
    tilde = '~'
    if (not path.startswith(tilde) or
            (len(path) > 1 and path[1:2] != os.path.sep)):
        return path
    result = path.replace('~', user_home, 1)

    assert isinstance(result, str)
    try:
        result.decode('utf-8')
    except UnicodeDecodeError:
        raise AssertionError('The path %r must be encoded in utf-8' % result)
    return result


access = os_helper.access
allow_writes = os_helper.allow_writes
can_write = os_helper.can_write
get_path_list = os_helper.get_path_list
is_dir = os_helper.is_dir
is_link = os_helper.is_link
is_root = os_helper.is_root
listdir = os_helper.listdir
make_dir = os_helper.make_dir
make_link = os_helper.make_link
move_to_trash = os_helper.move_to_trash
native_rename = os_helper.native_rename
normpath = os_helper.normpath
open_file = os_helper.open_file
path_exists = os_helper.path_exists
read_link = os_helper.read_link
recursive_move = os_helper.recursive_move
remove_dir = os_helper.remove_dir
remove_file = os_helper.remove_file
remove_link = os_helper.remove_link
remove_tree = os_helper.remove_tree
rename = os_helper.rename
set_application_name = os_helper.set_application_name
set_dir_readonly = os_helper.set_dir_readonly
set_dir_readwrite = os_helper.set_dir_readwrite
set_file_readonly = os_helper.set_file_readonly
set_file_readwrite = os_helper.set_file_readwrite
set_no_rights = os_helper.set_no_rights
stat_path = os_helper.stat_path
walk = os_helper.walk

# From Logger
setup_filesystem_logging = logger.setup_filesystem_logging
get_filesystem_logger = logger.get_filesystem_logger

# IPC
ExternalInterface = ipc.ExternalInterface
is_already_running = ipc.is_already_running
