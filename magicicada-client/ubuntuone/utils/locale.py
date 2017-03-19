# -*- coding: utf-8 -*-
#
# Copyright 2013 Canonical Ltd.
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

"""Utility modules related to locale."""

import os

# this locale is always installed in Ubuntu
SAFE_LOCALE = "en_US.UTF-8"


def is_turkish(locale_identifier):
    """Return whether the locale identifier is turkish."""
    return locale_identifier.startswith("tr_")


def fix_turkish_locale():
    """Change the LC_CTYPE when the LANG is turkish. Fixes lp:997326"""
    lang = os.environ.get("LANG", "")
    ctype = os.environ.get("LC_CTYPE", "")
    if (is_turkish(lang) and ctype == "") or is_turkish(ctype):
        os.environ["LC_CTYPE"] = SAFE_LOCALE
