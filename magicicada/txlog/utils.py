# Copyright 2008-2015 Canonical
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Database access functions."""

from django.db import transaction
from django.db.models import Q
from django.utils.timezone import now, timedelta

from magicicada.txlog.models import (
    DBWorkerLastRow,
    DBWorkerUnseen,
    TransactionLog,
)


NEW_WORKER_LAST_ROW = (0, None)
CHUNK_SIZE = 10000
UNSEEN_EXPIRES = 24 * 60 * 60


def get_last_row(worker_name):
    """Return (id, timestamp) of the last processed row for the 'worker_name'.

    If not found, get from the oldest possible row from the table.

    If still not found, return a default tuple for new workers.

    Transaction management should be performed by the caller.  Since this
    function is read-only, it may be called from code decorated with
    fsync_readonly, or as part of a block of operations decorated with
    fsync_commit.

    """
    if DBWorkerLastRow.objects.exists():
        try:
            last_row = DBWorkerLastRow.objects.get(worker_id=worker_name)
        except DBWorkerLastRow.DoesNotExist:
            last_row = DBWorkerLastRow.objects.all().order_by('txlog__id')[0]
        last_row = (last_row.txlog.id, last_row.txlog.timestamp)
    else:
        last_row = NEW_WORKER_LAST_ROW

    return last_row


def update_last_row(worker_name, txlog):
    """Update the id and timestamp of the most recently processed transation
    log entry for a given worker.

    Use the store name, rather than a store reference, to sidestep potential
    thread safety problems.

    Transaction management should be performed by the caller.  Since this
    function writes to the database, it should be called from code blocks
    decorated with fsync_commit.
    """
    last_row, created = DBWorkerLastRow.objects.get_or_create(
        worker_id=worker_name, defaults={'txlog': txlog})
    if not created:
        last_row.txlog = txlog
        last_row.save()


def get_txn_recs(num_recs, last_id=0,
                 worker_id=None, expire_secs=None,
                 num_partitions=None, partition_id=None):
    """Attempt to read num_recs records from the transaction log.

    Start from the row after last_id, plus any records whose ID is in the
    db_worker_unseen table.

    Return a list of up to num_rec dicts representing records from the
    transaction log, starting from the row after last_id, or the beginning of
    the table if last_id is None.  If num_recs records are not available, all
    remaining records will be returned.  If no new records are available, an
    empty list is returned.

    Transaction management should be performed by the caller.  Since this
    function is read-only, it may be called from code decorated with
    transaction.atomic.

    """
    if expire_secs is None:
        expire_secs = UNSEEN_EXPIRES
    txlogs = TransactionLog.objects.filter(id__gt=last_id)

    if num_partitions is not None and partition_id is not None:
        unfilter_op_types = (
            TransactionLog.OP_SHARE_ACCEPTED, TransactionLog.OP_SHARE_DELETED,
        )
        txlogs = txlogs.extra(
            where=['(MOD(owner_id, %s) = %s OR op_type IN %s)'],
            params=(num_partitions, partition_id, unfilter_op_types)
        )

    txlogs = txlogs.order_by('id')[:num_recs]

    if worker_id is not None and expire_secs:
        threshold = now() - timedelta(seconds=expire_secs)
        DBWorkerUnseen.objects.filter(
            worker_id=worker_id, created__gt=threshold)
        # XXX Unsure how these unseen relate to the txlogs gathered above

    result = []
    for record in txlogs:
        result.append(
            dict(txn_id=record.id, node_id=record.node_id,
                 owner_id=record.owner_id, volume_id=record.volume_id,
                 op_type=record.op_type, path=record.path,
                 generation=record.generation, timestamp=record.timestamp,
                 mimetype=record.mimetype, old_path=record.old_path,
                 extra_data=record.extra_data))

    return result


def ichunk(iter, chunk):
    i = 0
    while i < chunk:
        yield next(iter)
        i += 1


def delete_expired_unseen(worker_id, unseen_ids=None,
                          expire_secs=None):
    """Deletes expired unseen ids for a given worker id.

    If a list of unseen ids is given, also delete those explicitly.
    """
    if expire_secs is None:
        expire_secs = UNSEEN_EXPIRES
    threshold = now() - timedelta(seconds=expire_secs)
    unseen = DBWorkerUnseen.objects.filter(
        Q(worker_id=worker_id, created__lt=threshold) | Q(id__in=unseen_ids))
    deleted = unseen.count()
    unseen.delete()
    return deleted


@transaction.atomic
def delete_old_txlogs(timestamp_limit, quantity_limit=None):
    """Deletes the old transaction logs.

    Use the store name, rather than a store reference, to sidestep potential
    thread safety problems.

    Has to be given a datetime.datetime as a timestamp_limit; datetimes later
    than that will be filtered out, and won't be deleted.

    If quantity_limit is given, this will be the maximum number of entries to
    be deleted.
    """

    txlogs = TransactionLog.objects.filter(timestamp__lte=timestamp_limit)
    result = txlogs.count()
    if quantity_limit is not None and result > quantity_limit:
        txlogs = TransactionLog.objects.filter(
            pk__in=txlogs.values_list('pk')[:quantity_limit])
        result = quantity_limit
    txlogs.delete()
    return result


@transaction.atomic
def delete_txlogs_slice(date, quantity_limit):
    """Deletes txlogs from a certain slice, by date and quantity limit.

    Almost the same as delete_old_txlogs, except that it deletes txlogs
    precisely from the provided date (a datetime.date object). Also, the
    quantity_limit parameter is mandatory."""
    txlogs = TransactionLog.objects.filter(
        timestamp__range=(date, date + timedelta(days=1))).order_by('id')
    result = txlogs.count()
    if result > quantity_limit:
        txlogs = TransactionLog.objects.filter(
            pk__in=txlogs.values_list('pk')[:quantity_limit])
        result = quantity_limit
    txlogs.delete()
    return result


def get_row_by_time(timestamp):
    """Return the smaller txlog row id in that timestamp (or greater)."""
    txlog = TransactionLog.objects.filter(
        timestamp__gte=timestamp).order_by('id')[:1]
    if txlog.count() == 0:
        txid, tstamp = None, None
    else:
        txid, tstamp = txlog[0].id, txlog[0].timestamp
    return txid, tstamp


def keep_last_rows_for_worker_names(worker_names):
    """Clean DBWorkerLastRow that don't match the given worker names."""
    DBWorkerLastRow.objects.exclude(worker_id__in=worker_names).delete()
