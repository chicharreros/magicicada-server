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

"""Assorted constant definitions which don't fit anywhere else."""

import re

# the name of the directory u1sync uses to keep metadata about a mirror
METADATA_DIR_NAME = u".ubuntuone-sync"

# filenames to ignore
SPECIAL_FILE_RE = re.compile(".*\\.("
                             "(u1)?partial|part|"
                             "(u1)?conflict(\\.[0-9]+)?)$")
