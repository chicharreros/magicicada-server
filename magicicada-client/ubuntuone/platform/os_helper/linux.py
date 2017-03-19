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
"""
Linux import for ubuntuone-client

This module has to have all linux specific modules and provide the api required
to support the linux platform.
"""

import errno
import logging
import os
import shutil

try:
    from gi.repository import Gio, GLib
    has_gi = True
except ImportError:
    import gio
    has_gi = False

from ubuntuone.platform.os_helper import unix

platform = "linux2"

logger = logging.getLogger('ubuntuone.SyncDaemon')


def move_to_trash(path):
    """Move the file or dir to trash.

    If had any error, or the system can't do it, just remove it.
    """
    if has_gi:
        not_supported = Gio.IOErrorEnum.NOT_SUPPORTED
        try:
            return_code = Gio.File.new_for_path(path).trash(None)
        except GLib.GError:
            exc = OSError()
            exc.errno = errno.ENOENT
            raise exc
    else:
        not_supported = gio.ERROR_NOT_SUPPORTED
        try:
            return_code = gio.File(path).trash()
        except gio.Error:
            exc = OSError()
            exc.errno = errno.ENOENT
            raise exc

    if not return_code or return_code == not_supported:
        logger.warning("Problems moving to trash! (%s) Removing anyway: %r",
                       return_code, path)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


def set_application_name(app_name):
    """Set the name of the application."""
    if has_gi:
        from gi.repository import GObject
        GObject.set_application_name(app_name)
    else:
        import gobject
        gobject.set_application_name(app_name)


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
read_link = unix.read_link
is_link = unix.is_link
remove_link = unix.remove_link
listdir = unix.listdir
walk = unix.walk
access = unix.access
can_write = unix.can_write
stat_path = unix.stat_path
is_root = unix.is_root
get_path_list = unix.get_path_list
normpath = unix.normpath
get_os_valid_path = unix.get_os_valid_path
is_valid_syncdaemon_path = None
is_valid_os_path = None
os_path = None
