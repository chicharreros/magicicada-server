# Copyright 2008-2015 Canonical
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/filesync-server

"""Manage database connections and stores to the storage database."""

from backends.db.store import get_filesync_store  # NOQA
from backends.db.dbtransaction import (
    get_storm_commit,
    get_storm_readonly,
    filesync_tm,
)
from backends.db.dbtransaction import retryable_transaction  # NOQA

fsync_commit = get_storm_commit(filesync_tm)
fsync_readonly = get_storm_readonly(filesync_tm)
fsync_readonly_slave = get_storm_readonly(filesync_tm, use_ro_store=True)
