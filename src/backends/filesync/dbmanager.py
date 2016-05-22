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

"""Manage database connections and stores to the storage database."""

from __future__ import unicode_literals

from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

from backends.db.dbtransaction import retryable_transaction  # NOQA


_run_on_rollback = []


def on_rollback(func):
    _run_on_rollback.append(func)


class Atomic(transaction.Atomic):

    def run_and_clear_rollback_hooks(self):
        global _run_on_rollback
        try:
            while True:
                func = _run_on_rollback.pop(0)
                func()
        except IndexError:
            pass
        finally:
            _run_on_rollback = []

    def __exit__(self, exc_type, exc_value, traceback):
        result = super(Atomic, self).__exit__(exc_type, exc_value, traceback)
        if exc_type is not None:
            self.run_and_clear_rollback_hooks()
        return result


def atomic(using=None, savepoint=True):
    # Bare decorator: @atomic -- although the first argument is called
    # `using`, it's actually the function being decorated.
    if callable(using):
        return Atomic(transaction.DEFAULT_DB_ALIAS, savepoint)(using)
    # Decorator: @atomic(...) or context manager: with atomic(...): ...
    else:
        return Atomic(using, savepoint)


fsync_commit = atomic
fsync_readonly = atomic
fsync_readonly_slave = atomic


def get_object_or_none(qs, *args, **kwargs):
    qs = getattr(qs, 'objects', qs)
    try:
        result = qs.get(*args, **kwargs)
    except ObjectDoesNotExist:
        result = None
    return result
