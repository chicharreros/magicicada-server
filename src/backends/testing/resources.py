# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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
# For further info, check  http://launchpad.net/magicicada-server

"""Resources for use by tests."""

from __future__ import absolute_import

import os

import psycopg2
import testresources
import transaction

from backends.db.schemas import account as account_schema
from backends.db.schemas import storage as storage_schema
from backends.db.dbwatcher import DatabaseWatcher
from backends.db.store import get_filesync_store
from backends.filesync.dbmanager import filesync_tm

DEBUG_RESOURCES = bool(os.environ.get("DEBUG_RESOURCES"))


class DatabaseResource(testresources.TestResource):
    """A resource that resets a database to a known state for each test."""
    _watcher = None

    def __init__(self, dbname, schema_modules, autocommit=False,
                 tx_manager=transaction):
        super(DatabaseResource, self).__init__()
        self.dbname = dbname
        self.schema_modules = schema_modules
        self.autocommit = autocommit
        self.saw_commit = False
        self.schemas = None
        self.tx_manager = tx_manager

    def __repr__(self):
        return "<DatabaseResource %s>" % self.dbname

    @staticmethod
    def get_watcher():
        """Get the `DatabaseWatcher` instance for the `psycopg2` adapter."""
        watcher = DatabaseResource._watcher
        if watcher is None:
            DatabaseResource._watcher = watcher = (DatabaseWatcher(psycopg2))
            watcher.install()
        return watcher

    def make(self, dependent_resources=None):
        """See `TestResource`"""
        if DEBUG_RESOURCES:
            print "*** Make %s ***" % self.dbname
        watcher = self.get_watcher()
        watcher.enable(self.dbname)
        if self.schemas is None:
            self.schemas = [s.create_schema() for s in self.schema_modules]
        store = get_filesync_store()
        transaction.abort()
        for s in self.schemas:
            s.upgrade(store)
        transaction.commit()
        transaction.begin()
        for s in reversed(self.schemas):
            s.delete(store)
        transaction.commit()
        self.saw_commit = False
        watcher.hook(self.dbname, self._notify_change)
        watcher.reset(self.dbname)
        return self

    def clean(self, resource):
        """See `TestResource`"""
        assert self is resource, "Unknown resource passed to clean()"
        if DEBUG_RESOURCES:
            print "*** Clean %s ***" % self.dbname
        self.tx_manager.abort()
        # Someone committed to the database: clean it up.
        if self.saw_commit:
            store = get_filesync_store()
            for s in reversed(self.schemas):
                s.delete(store)
            transaction.commit()
        watcher = self.get_watcher()
        watcher.unhook(self.dbname, self._notify_change)
        watcher.reset(self.dbname)
        watcher.disable(self.dbname)

    def _notify_change(self, dbname, commit=False):
        """Dirty the resource if the database is accessed."""
        if DEBUG_RESOURCES:
            print "*** Change %s, commit=%r ***" % (dbname, commit)
        self.dirtied(self)
        # If this is an autocommit database, then any use of the
        # connection should be treated as a commit.
        if commit or self.autocommit:
            self.saw_commit = True

FilesyncDatabaseResource = DatabaseResource(
    dbname='filesync',
    schema_modules=[account_schema, storage_schema],
    tx_manager=filesync_tm)
