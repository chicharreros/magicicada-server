# -*- coding: utf-8 -*-
#
# Copyright 2010-2012 Canonical Ltd.
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Utilities."""

from __future__ import unicode_literals

import logging
import os
import sys

from dirspec.basedir import load_config_paths
from dirspec.utils import get_program_path

from twisted.python import procutils


logger = logging.getLogger(__name__)
BIN_SUFFIX = 'bin'
DATA_SUFFIX = 'data'

QSS_MAP = dict(win32=':/windows.qss',
               darwin=':/darwin.qss',
               linux=':/linux.qss')

# Setting linux as default if we don't find the
# platform as a key in the dictionary
PLATFORM_QSS = QSS_MAP.get(sys.platform, ":/linux.qss")


def _get_dir(dir_name, dir_constant):
    """Return the absolute path to this project's 'dir_name' dir.

    Support symlinks, and priorize local (relative) 'dir_name' dir. If not
    found, return the value of the 'dir_constant'.

    """
    module = os.path.dirname(__file__)
    result = os.path.abspath(os.path.join(module, os.path.pardir,
                                          os.path.pardir, dir_name))
    logger.debug('_get_dir: trying use dir at %r (exists? %s)',
                 result, os.path.exists(result))
    if os.path.exists(result):
        logger.info('_get_dir: returning dir located at %r.', result)
        return result

    # otherwise, try to load 'dir_constant' from installation path
    try:
        __import__('ubuntuone.clientdefs', None, None, [''])
        module = sys.modules.get('ubuntuone.clientdefs')
        return getattr(module, dir_constant)
    except (ImportError, AttributeError):
        msg = '_get_dir: can not build a valid path. Giving up. ' \
              '__file__ is %r, clientdefs module not available.'
        logger.error(msg, __file__)


def get_project_dir():
    """Return the absolute path to this project's data/ dir.

    Support symlinks, and priorize local (relative) data/ dir. If not
    found, return the value of the PROJECT_DIR.

    """
    result = _get_dir(dir_name=DATA_SUFFIX, dir_constant='PROJECT_DIR')
    assert result is not None, '%r dir can not be None.' % DATA_SUFFIX
    return result


def get_data_file(*args):
    """Return the absolute path to 'args' within project data dir."""
    return os.path.join(get_project_dir(), *args)


def get_bin_dir():
    """Return the absolute path to this project's bin/ dir.

    Support symlinks, and priorize local (relative) bin/ dir. If not
    found, return the value of the BIN_DIR.

    """
    result = _get_dir(dir_name=BIN_SUFFIX, dir_constant='BIN_DIR')
    assert result is not None, '%r dir can not be None.' % BIN_SUFFIX
    logger.info('get_bin_dir: returning dir located at %r.', result)
    return result


def get_bin_cmd(program_name):
    """Return a list of arguments to launch the given executable."""
    path = get_program_path(program_name,
                            fallback_dirs=[get_bin_dir()])
    cmd_args = [path]

    # adjust cmd for platforms using buildout-generated python
    # wrappers
    if getattr(sys, 'frozen', None) is None:
        if sys.platform in ('darwin'):
            cmd_args.insert(0, 'python')
        elif sys.platform in ('win32'):
            cmd_args.insert(0, procutils.which("python.exe")[0])

    logger.debug('get_bin_cmd: returning %r', cmd_args)
    return cmd_args


def get_cert_dir():
    """Return directory containing certificate files."""

    if getattr(sys, "frozen", None) is not None:
        if sys.platform == "win32":
            ssl_cert_location = list(load_config_paths(
                    "ubuntuone"))[1]
        elif sys.platform == "darwin":
                main_app_dir = "".join(__file__.partition(".app")[:-1])
                main_app_resources_dir = os.path.join(main_app_dir,
                                                      "Contents",
                                                      "Resources")
                ssl_cert_location = main_app_resources_dir
    elif any(plat in sys.platform for plat in ("win32", "darwin")):
        pkg_dir = os.path.dirname(__file__)
        src_tree_path = os.path.dirname(os.path.dirname(pkg_dir))
        ssl_cert_location = os.path.join(src_tree_path,
                                         "data")
    else:
        ssl_cert_location = '/etc/ssl/certs'

    return ssl_cert_location
