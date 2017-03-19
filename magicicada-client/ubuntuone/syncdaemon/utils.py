# -*- coding: utf-8 -*-
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
"""Utility functions for ubuntuone client."""

import os
import sys

from twisted.python import procutils

try:
    from dirspec.utils import get_program_path
except ImportError:
    get_program_path = (
        lambda exe_name, **kw: os.path.abspath(
            os.path.join(os.path.curdir, 'bin', exe_name)))


SYNCDAEMON_EXECUTABLE = 'ubuntuone-syncdaemon'
TUNNEL_EXECUTABLE = 'ubuntuone-proxy-tunnel'

DARWIN_APP_NAMES = {SYNCDAEMON_EXECUTABLE: 'UbuntuOne Syncdaemon.app',
                    TUNNEL_EXECUTABLE: 'UbuntuOne Proxy Tunnel.app'}


def _get_bin_cmd(exe_name, extra_fallbacks=[]):
    """Get cmd+args to launch 'exe_name'."""
    syncdaemon_dir = os.path.dirname(__file__)
    ubuntuone_dir = os.path.dirname(syncdaemon_dir)
    tree_dir = os.path.dirname(ubuntuone_dir)
    fallback_dirs = [os.path.join(tree_dir, 'bin')] + extra_fallbacks
    path = get_program_path(exe_name,
                            fallback_dirs=fallback_dirs,
                            app_names=DARWIN_APP_NAMES)
    cmd_args = [path]

    # adjust cmd for platforms using buildout-generated python
    # wrappers
    if getattr(sys, 'frozen', None) is None:
        if sys.platform in ('darwin'):
            cmd_args.insert(0, 'python')
        elif sys.platform in ('win32'):
            cmd_args.insert(0, procutils.which("python.exe")[0])

    return cmd_args


def get_sd_bin_cmd():
    """Get cmd + args to launch syncdaemon executable."""
    return _get_bin_cmd(SYNCDAEMON_EXECUTABLE)


def get_tunnel_bin_cmd(extra_fallbacks):
    """Get cmd + args to launch proxy tunnel."""
    return _get_bin_cmd(TUNNEL_EXECUTABLE,
                        extra_fallbacks=extra_fallbacks)
