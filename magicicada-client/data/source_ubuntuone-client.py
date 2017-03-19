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
"""Stub for Apport"""

from __future__ import print_function, unicode_literals

import apport
import os

from apport.hookutils import attach_file_if_exists
from dirspec.basedir import xdg_cache_home, xdg_config_home

# Paths where things we might want live
u1_log_path = os.path.join(xdg_cache_home, b"ubuntuone", b"log")
u1_user_config_path = os.path.join(xdg_config_home, b"ubuntuone")
# things we may want to collect for the report
u1_client_log = os.path.join(u1_log_path, b"syncdaemon.log")
u1_except_log = os.path.join(u1_log_path, b"syncdaemon-exceptions.log")
u1_invalidnames_log = os.path.join(u1_log_path, b"syncdaemon-invalid-names.log")
u1_sd_conf = os.path.join(b"etc", b"xdg", b"ubuntuone", b"syncdaemon.conf")
u1_usersd_conf = os.path.join(u1_user_config_path, b"syncdaemon.conf")


def add_info(report):
    """add report info"""
    attach_file_if_exists(report, u1_except_log,
                                  "UbuntuOneSyncdaemonExceptionsLog")
    attach_file_if_exists(report, u1_invalidnames_log,
                                  "UbuntuOneSyncdaemonInvalidNamesLog")
    attach_file_if_exists(report, u1_usersd_conf,
                                  "UbuntuOneUserSyncdaemonConfig")
    attach_file_if_exists(report, u1_sd_conf,
                                  "UbuntuOneSyncdaemonConfig")

    if not apport.packaging.is_distro_package(report['Package'].split()[0]):
        report['ThirdParty'] = 'True'
        report['CrashDB'] = 'ubuntuone'
