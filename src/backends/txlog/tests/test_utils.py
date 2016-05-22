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

"""Tests for txlog utilities."""

from __future__ import unicode_literals

from datetime import timedelta

from django.utils.timezone import now

from backends.txlog import utils
from backends.txlog.models import DBWorkerLastRow, TransactionLog
from backends.txlog.tests.test_models import BaseTransactionLogTestCase


class TransactionLogUtilsTestCase(BaseTransactionLogTestCase):
    """Tests for the Materialised Views database access functions."""

    def _create_db_worker_last_row_entry(self, worker_name, txlog):
        """Create a new entry on the txlog_db_worker_last_row table."""
        return DBWorkerLastRow.objects.create(
            worker_id=worker_name, txlog=txlog)

    def _find_last_row_worker_names(self):
        """Find all worker names from the db_worker_last_row table."""
        return DBWorkerLastRow.objects.all().values_list(
            'worker_id', flat=True)

    def test_get_last_row_with_no_data(self):
        """Test the get_last_row function when no data is present."""
        worker_count = DBWorkerLastRow.objects.all().count()
        assert worker_count == 0, worker_count
        self.assertEqual(
            utils.NEW_WORKER_LAST_ROW, utils.get_last_row('some worker'))

    def test_get_last_row_with_other_data_returns_the_oldest_one(self):
        """get_last_row returns the row for the oldest txlog ID in the
        table, if the worker name is not found for that."""
        txlog1 = self.factory.make_transaction_log()
        txlog2 = self.factory.make_transaction_log()
        txlog3 = self.factory.make_transaction_log()

        self._create_db_worker_last_row_entry(
            self.factory.get_unique_unicode(), txlog3)
        self._create_db_worker_last_row_entry(
            self.factory.get_unique_unicode(), txlog1)
        self._create_db_worker_last_row_entry(
            self.factory.get_unique_unicode(), txlog2)

        self.assertEqual(
            (txlog1.id, txlog1.timestamp), utils.get_last_row('some worker'))

    def test_get_last_row_with_same_data_returns_the_exact_one(self):
        """Test that get_last_row returns the row for the exact txlog ID in the
        table, if the worker name is found for that."""
        txlog1 = self.factory.make_transaction_log()
        txlog2 = self.factory.make_transaction_log()
        txlog3 = self.factory.make_transaction_log()

        worker_name = self.factory.get_unique_unicode()
        self._create_db_worker_last_row_entry(worker_name, txlog3)
        self._create_db_worker_last_row_entry(
            self.factory.get_unique_unicode(), txlog1)
        self._create_db_worker_last_row_entry(
            self.factory.get_unique_unicode(), txlog2)

        self.assertEqual(
            (txlog3.id, txlog3.timestamp), utils.get_last_row(worker_name))

    def test_update_last_row_with_no_data(self):
        """Test the update_last_row function when no data is present."""
        txlog = self.factory.make_transaction_log()
        worker_name = self.factory.get_unique_unicode()
        utils.update_last_row(worker_name=worker_name, txlog=txlog)

        result = DBWorkerLastRow.objects.get(worker_id=worker_name)
        self.assertEqual((txlog.id, txlog.timestamp),
                         (result.txlog.id, result.txlog.timestamp))

    def test_update_last_row_with_data(self):
        """Test the update_last_row function when data for this worker is
        present.
        """
        txlog = self.factory.make_transaction_log()
        txlog2 = self.factory.make_transaction_log()
        worker_name = self.factory.get_unique_unicode()
        self._create_db_worker_last_row_entry(worker_name, txlog)
        utils.update_last_row(worker_name=worker_name, txlog=txlog2)

        result = DBWorkerLastRow.objects.get(worker_id=worker_name)
        self.assertEqual((txlog2.id, txlog2.timestamp),
                         (result.txlog.id, result.txlog.timestamp))

    def test_get_txn_recs_no_previous_no_txns(self):
        """Test getting a batch of transactions when we have not previously
        processed any rows and the transaction_log table is empty.
        """
        txlist = utils.get_txn_recs(num_recs=5, last_id=0)
        self.assertEqual([], txlist)

    def test_get_txn_recs_no_previous_small_result_set(self):
        """Test getting a batch of transactions when we have not previously
        processed any rows and the number of rows in the transaction_log table
        is smaller than the number requested.
        """
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=5, last_id=0)
        self.assertEqual([t.as_dict() for t in txlogs], txlist)

    def test_get_txn_recs_no_previous_exact_result_set(self):
        """Test getting a batch of transactions when we have not previously
        processed any rows and the number of rows in the transaction_log table
        is exactly the number requested.
        """
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=2, last_id=0)
        self.assertEqual([t.as_dict() for t in txlogs], txlist)

    def test_get_txn_recs_no_previous_large_result_set(self):
        """Test getting a batch of transactions when we have not previously
        processed any rows and the number of rows in the transaction_log table
        is larger than the number requested.
        """
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=1, last_id=0)
        expected = [txlogs[0].as_dict()]
        self.assertEqual(expected, txlist)

    def test_get_txn_recs_previous_no_new(self):
        """Test getting a batch of transactions when we have previously
        processed rows and there are no newer rows in the transaction_log
        table.
        """
        owner = self.make_user_without_txlog()
        self.factory.make_transaction_log(owner=owner)
        log = self.factory.make_transaction_log(owner=owner)
        txlist = utils.get_txn_recs(num_recs=1, last_id=log.id)
        self.assertEqual([], txlist)

    def test_get_txn_recs_previous_small_new(self):
        """Test getting a batch of transactions when we have previously
        processed rows and there are fewer newer rows in the transaction_log
        table than we requested.
        """
        owner = self.make_user_without_txlog()
        t1 = self.factory.make_transaction_log(owner=owner)
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=5, last_id=t1.id)
        self.assertEqual([t.as_dict() for t in txlogs], txlist)

    def test_get_txn_recs_previous_exact_new(self):
        """Test getting a batch of transactions when we have previously
        processed rows and there are the exact number of newer rows in the
        transaction_log table that we requested.
        """
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=1, last_id=txlogs[0].id)
        expected = [txlogs[1].as_dict()]
        self.assertEqual(expected, txlist)

    def test_get_txn_recs_previous_large_new(self):
        """Test getting a batch of transactions when we have previously
        processed rows and there are the more newer rows in the
        transaction_log table than we requested.
        """
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=1, last_id=txlogs[1].id)
        expected = [txlogs[2].as_dict()]
        self.assertEqual(expected, txlist)

    def test_get_txn_recs_respects_order(self):
        """Test that transaction log entries are returned in order."""
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        txlist = utils.get_txn_recs(num_recs=3, last_id=0)
        self.assertEqual([t.as_dict() for t in txlogs], txlist)

    def test_get_txn_recs_unseen(self):
        """Getting transactions with unseen ids records those as unseen.

        Querying again returns unseen transactions if they are now present.

        """
        owner = self.make_user_without_txlog()
        txlogs = [self.factory.make_transaction_log(owner=owner),
                  self.factory.make_transaction_log(owner=owner)]
        worker_id = self.factory.get_unique_unicode()
        txlist = utils.get_txn_recs(num_recs=3, worker_id=worker_id)

        self.assertEqual([t.as_dict() for t in txlogs], txlist)
        unseen = self.factory.make_transaction_log(owner=owner)
        txlist = utils.get_txn_recs(
            num_recs=3, last_id=txlogs[1].id, worker_id=worker_id)
        self.assertEqual([unseen.as_dict()], txlist)

    def test_get_txn_recs_retry_list_no_new_or_retry(self):
        """Test getting a batch of transactions when there are unseen ids
        records those as unseen. Querying again when unseen isn't available yet
        returns nothing.
        """
        owner = self.make_user_without_txlog()
        t1 = self.factory.make_transaction_log(owner=owner)
        t2 = self.factory.make_transaction_log(owner=owner)
        t3 = self.factory.make_transaction_log(owner=owner)
        t2.delete()

        worker_id = self.factory.get_unique_unicode()
        txlist = utils.get_txn_recs(num_recs=3, worker_id=worker_id)
        self.assertEqual([t1.as_dict(), t3.as_dict()], txlist)
        txlist = utils.get_txn_recs(
            num_recs=3, last_id=t3.id, worker_id=worker_id)
        self.assertEqual([], txlist)

    def test_get_txn_recs_for_partition(self):
        """Get txlogs for the provided partition ID.

        When owner_id % num_partitions == partition_id, the txlog is added to
        the result set, so that it matches the filter by partition. Also, any
        txlog that is related to sharing is also returned, no matter what the
        owner_id is.
        """
        owner = self.make_user_without_txlog()
        other = self.make_user_without_txlog()
        num_partitions = 8
        partition_id = owner.id % num_partitions

        t1 = self.factory.make_transaction_log(owner=owner)
        self.factory.make_transaction_log(owner=other)  # Different one
        t3 = self.factory.make_transaction_log(owner=owner)
        # Share txlogs, but with a different owner, are also returned.
        t4 = self.factory.make_transaction_log(
            owner=other, op_type=TransactionLog.OP_SHARE_ACCEPTED)
        t5 = self.factory.make_transaction_log(
            owner=other, op_type=TransactionLog.OP_SHARE_DELETED)

        txlogs = [t1, t3, t4, t5]
        txlist = utils.get_txn_recs(
            num_recs=5, last_id=0,
            num_partitions=num_partitions, partition_id=partition_id
        )
        self.assertEqual([t.as_dict() for t in txlogs], txlist)

    def test_maintains_newish_txlogs_when_purging(self):
        """Test that txnlogs not old enough are maintained, instead of being
        deleted."""
        owner = self.make_user_without_txlog()

        right_now = now()
        limit_datetime = right_now - timedelta(days=7)
        # Not so old
        old_datetime = limit_datetime + timedelta(seconds=1)

        expected = [
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
        ]

        removed = utils.delete_old_txlogs(timestamp_limit=limit_datetime)
        self.assertEqual(removed, 0)

        txlist = utils.get_txn_recs(num_recs=4, last_id=0)
        ids = [int(txdict['txn_id']) for txdict in txlist]
        self.assertItemsEqual(ids, [t.id for t in expected])

    def test_deletes_old_enough_txlogs(self):
        """Test that txnlogs old enough are deleted."""
        owner = self.make_user_without_txlog()

        right_now = now()
        timestamp_limit = right_now - timedelta(days=7)
        # Old enough
        old_datetime = timestamp_limit

        txlogs = [
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
        ]
        expected = [txlogs[0], txlogs[2]]

        removed = utils.delete_old_txlogs(timestamp_limit=timestamp_limit)

        txlist = utils.get_txn_recs(num_recs=len(txlogs), last_id=0)
        self.assertEqual(len(txlist), 2)
        self.assertEqual(removed, 2)
        ids = [int(txdict['txn_id']) for txdict in txlist]
        self.assertItemsEqual(ids, [t.id for t in expected])

    def test_deletes_old_txlogs_within_quantity_limit(self):
        """Test that txnlogs old enough are deleted and are within the quantity
        limit given."""

        owner = self.make_user_without_txlog()
        right_now = now()
        timestamp_limit = right_now - timedelta(days=7)
        # Old enough
        old_datetime = timestamp_limit
        quantity_limit = 2

        txlogs = [
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
            self.factory.make_transaction_log(
                owner=owner, timestamp=old_datetime),
        ]
        expected = [txlogs[0], txlogs[2], txlogs[4], ]

        removed = utils.delete_old_txlogs(timestamp_limit=timestamp_limit,
                                          quantity_limit=quantity_limit)

        txlist = utils.get_txn_recs(num_recs=len(txlogs), last_id=0)
        self.assertEqual(len(txlist), 3)
        self.assertEqual(removed, quantity_limit)
        ids = [int(txdict['txn_id']) for txdict in txlist]
        self.assertItemsEqual(ids, [t.id for t in expected])

    def test_deletes_txlogs_slice(self):
        """Delete a txlog slice by date and quantity."""

        owner = self.make_user_without_txlog()
        right_now = now()
        # Old enough
        timestamp_limit = right_now - timedelta(days=7)
        quantity_limit = 2

        txlogs = [
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=timestamp_limit),
            self.factory.make_transaction_log(owner=owner),
            self.factory.make_transaction_log(
                owner=owner, timestamp=timestamp_limit),
            self.factory.make_transaction_log(owner=owner),
        ]

        removed = utils.delete_txlogs_slice(date=right_now.date(),
                                            quantity_limit=quantity_limit)
        self.assertEqual(removed, quantity_limit)

        txlist = utils.get_txn_recs(num_recs=len(txlogs), last_id=0)
        self.assertEqual(len(txlist), 3)
        self.assertEqual(removed, quantity_limit)
        ids = [int(txdict['txn_id']) for txdict in txlist]
        expected = [txlogs[1], txlogs[3], txlogs[4]]
        self.assertItemsEqual(ids, [t.id for t in expected])

    def test_get_row_by_time_with_no_data(self):
        """Test the get_row_by_time function when no data is present."""
        txid, _ = utils.get_row_by_time(now())
        self.assertEqual(txid, None)

    def test_get_row_by_time_with_data(self):
        """Test get_row_by_time function when data is present."""
        ts = now()
        txlogs = [
            self.factory.make_transaction_log(timestamp=ts + timedelta(i, 0))
            for i in range(5)]
        tstamp = txlogs[2].timestamp
        txid, newtstamp = utils.get_row_by_time(tstamp)
        self.assertEqual(txid, txlogs[2].id)
        self.assertEqual(newtstamp, tstamp)

    def test_get_row_by_time_timestamp_twice(self):
        """Test get_row_by_time having two lines with same timestamp."""
        ts = now()
        txlogs = [
            self.factory.make_transaction_log(timestamp=ts + timedelta(i, 0))
            for i in range(5)]
        # put the timestamp of [3] into [1], the function should return the
        # id of [1]
        tstamp = txlogs[1].timestamp = txlogs[3].timestamp
        txlogs[1].save()

        txid, newtstamp = utils.get_row_by_time(tstamp)
        self.assertEqual(txid, txlogs[1].id)
        self.assertEqual(newtstamp, tstamp)

    def test_get_row_by_time_not_exact(self):
        """Test get_row_by_time not giving an exact timestamp."""
        ts = now()
        txlogs = [
            self.factory.make_transaction_log(timestamp=ts + timedelta(i, 0))
            for i in range(5)]

        # get a timestamp in the middle of [2] and [3], the function should
        # return the id of [3]
        tx2, tx3 = txlogs[2:4]
        delta = (txlogs[3].timestamp - txlogs[2].timestamp) / 2
        tstamp = txlogs[2].timestamp + delta

        txid, newtstamp = utils.get_row_by_time(tstamp)
        self.assertEqual(txid, txlogs[3].id)
        self.assertEqual(newtstamp, txlogs[3].timestamp)

    def test_get_row_by_time_nothing_found(self):
        """Test get_row_by_time with a big enough timestamp."""
        txlogs = [self.factory.make_transaction_log() for i in range(2)]
        tstamp = txlogs[-1].timestamp + timedelta(seconds=1)
        txid, newtstamp = utils.get_row_by_time(tstamp)
        self.assertEqual(txid, None)
        self.assertEqual(newtstamp, None)

    def test_cleans_last_rows_for_workers_not_in_list(self):
        """Test that keep_last_rows_for_worker_names removes all rows from
        workers not in the list of given names."""
        initial_workers = [
            'worker1',
            'worker2',
            'worker3',
            'worker4',
        ]
        kept_workers = [
            'worker1',
            'worker2',
            'worker4',
        ]
        for worker_name in initial_workers:
            txlog = self.factory.make_transaction_log()
            self._create_db_worker_last_row_entry(worker_name, txlog)

        utils.keep_last_rows_for_worker_names(kept_workers)

        actual_worker_names = self._find_last_row_worker_names()
        self.assertItemsEqual(actual_worker_names, kept_workers)

    def test_cleans_last_rows_for_workers_not_in_list_of_strings(self):
        """Test that keep_last_rows_for_worker_names removes all rows from
        workers not in the list of given names as plain strings."""
        initial_workers = [
            'worker1',
            'worker2',
            'worker3',
            'worker4',
        ]
        kept_workers = [
            'worker1',
            'worker2',
            'worker4',
        ]
        for worker_name in initial_workers:
            txlog = self.factory.make_transaction_log()
            self._create_db_worker_last_row_entry(worker_name, txlog)

        utils.keep_last_rows_for_worker_names(kept_workers)

        actual_worker_names = self._find_last_row_worker_names()
        self.assertItemsEqual(actual_worker_names, kept_workers)
