# -*- coding: utf-8 *-*
#
# Copyright 2011-2012 Canonical Ltd.
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
"""Multiplatform tools to interact with the os."""

import sys


if sys.platform == "win32":
    from ubuntuone.platform.os_helper import windows
    source = windows
elif sys.platform == "darwin":
    from ubuntuone.platform.os_helper import darwin
    source = darwin
else:
    from ubuntuone.platform.os_helper import linux
    source = linux

set_no_rights = source.set_no_rights
set_file_readonly = source.set_file_readonly
set_file_readwrite = source.set_file_readwrite
set_dir_readonly = source.set_dir_readonly
set_dir_readwrite = source.set_dir_readwrite
allow_writes = source.allow_writes
remove_file = source.remove_file
remove_tree = source.remove_tree
remove_dir = source.remove_dir
path_exists = source.path_exists
is_dir = source.is_dir
make_dir = source.make_dir
open_file = source.open_file
rename = source.rename
native_rename = source.native_rename
recursive_move = source.recursive_move
make_link = source.make_link
read_link = source.read_link
is_link = source.is_link
remove_link = source.remove_link
listdir = source.listdir
walk = source.walk
access = source.access
can_write = source.can_write
stat_path = source.stat_path
move_to_trash = source.move_to_trash
set_application_name = source.set_application_name
is_root = source.is_root
get_path_list = source.get_path_list
normpath = source.normpath

# Decorators

get_os_valid_path = source.get_os_valid_path
is_valid_syncdaemon_path = source.is_valid_syncdaemon_path
is_valid_os_path = source.is_valid_os_path
os_path = source.os_path
