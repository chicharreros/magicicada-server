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

"""Test for the txlog models."""

from collections import OrderedDict

from magicicada.filesync.models import (
    STATUS_LIVE,
    STATUS_DEAD,
)
from magicicada.filesync.services import SystemGateway
from magicicada.testing.testcase import BaseTestCase
from magicicada.txlog.models import get_epoch_secs, TransactionLog


class BaseTransactionLogTestCase(BaseTestCase):

    def clear_txlogs(self):
        # clear current transaction logs
        TransactionLog.objects.all().delete()

    def make_user_without_txlog(self, **kwargs):
        """Custom make_user function that does not create TransactionLogs."""
        user = self.factory.make_user(**kwargs)
        self.clear_txlogs()
        return user


class TestTransactionLog(BaseTransactionLogTestCase):

    mimetype = 'image/jpeg'

    def assert_txlog_correct(self, txlog, expected):
        # self.assertEqual(txlog.extra_data_dict, expected['extra_data_dict'])
        # self.assertEqual(txlog.op_type, expected['op_type'])
        # self.assertEqual(txlog.generation, expected['generation'])
        # self.assertEqual(txlog.path., expected['path'])
        # self.assertEqual(txlog.volume_id, expected['volume_id'])
        # self.assertEqual(txlog.node_id, expected['node_id'])
        # self.assertEqual(txlog.owner_id, expected['owner_id'])
        msg = 'Value for %r must be %r (got %r instead).'
        for k, v in expected.items():
            actual = getattr(txlog, k)
            self.assertEqual(actual, v, msg % (k, v, actual))

    def test_create(self):
        self.factory.make_transaction_log()

    def test_txlog_when_creating_udf(self):
        udf = self.factory.make_user_volume()

        txlog = TransactionLog.objects.get(
            volume_id=udf.id, op_type=TransactionLog.OP_UDF_CREATED)
        self.assertTxLogDetailsMatchesUserVolumeDetails(
            txlog, udf, TransactionLog.OP_UDF_CREATED)

    def test_txlog_when_deleting_empty_udf(self):
        """When we delete an empty UDF there will be a single txlog."""
        udf = self.factory.make_user_volume()
        self.clear_txlogs()

        udf.kill()

        expected_rows = [
            self._get_dict_with_txlog_attrs_from_udf(
                udf, TransactionLog.OP_UDF_DELETED),
            self._get_dict_with_txlog_attrs_from(
                udf.root_node, TransactionLog.OP_DELETE,
                generation=udf.generation)]
        self.assertTransactionLogsMatch(expected_rows)

    def test_txlogs_when_deleting_udf_with_files(self):
        """Check that deleting a UDF creates correct transaction logs.

        We only create transaction logs for the UDF itself and the descendants
        which are either directories or files whose mimetype is in
        TransactionLog.INTERESTING_MIMETYPES.
        """
        udf = self.factory.make_user_volume()
        expected_rows = []
        for i in range(5):
            f = self.factory.make_file(
                parent=udf.root_node, mimetype=self.mimetype)
            expected_rows.append(self._get_dict_with_txlog_attrs_from(
                f, TransactionLog.OP_DELETE, generation=udf.generation))
        self.clear_txlogs()

        udf.kill()

        expected_rows += [
            self._get_dict_with_txlog_attrs_from_udf(
                udf, TransactionLog.OP_UDF_DELETED),
            self._get_dict_with_txlog_attrs_from(
                udf.root_node, TransactionLog.OP_DELETE,
                generation=udf.generation),
        ]
        self.assertTransactionLogsMatch(expected_rows)

    def test_txlogs_when_user_signs_up(self):
        """When user signs up, txlogs for new user and root UDF are created."""
        user = SystemGateway().create_or_update_user(
            username='pepe', max_storage_bytes=1234)

        udf_txlog = TransactionLog.objects.get(
            op_type=TransactionLog.OP_UDF_CREATED)
        self.assertTxLogDetailsMatchesUserVolumeDetails(
            udf_txlog, user.root_volume, TransactionLog.OP_UDF_CREATED)

        user_txlog = TransactionLog.objects.get(
            op_type=TransactionLog.OP_USER_CREATED)
        self.assertTxLogDetailsMatchesUserDetails(user, user_txlog)

    def test_txlog_when_unlinking_file(self):
        """Check that we store a TransactionLog with the file attributes."""
        node = self.factory.make_file(mimetype=self.mimetype)
        self.clear_txlogs()

        node.unlink()
        expected = [
            self._get_dict_with_txlog_attrs_from(
                node, TransactionLog.OP_DELETE)
        ]
        self.assertTransactionLogsMatch(expected)

    def test_txlog_when_unlinking_empty_directory(self):
        node = self.factory.make_directory()
        self.clear_txlogs()

        node.unlink()
        expected = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_DELETE)
        self.assertTransactionLogsMatch([expected])

    def test_txlogs_when_unlinking_tree(self):
        """Check that unlink_tree() creates correct transaction logs.

        We only create transaction logs for the directory itself and the
        descendants which are either directories or files.
        """
        # Create a directory with 5 files.
        directory = self.factory.make_directory()
        expected_rows = []
        for i in range(5):
            f = self.factory.make_file(
                parent=directory, mimetype=self.mimetype)
            e = self._get_dict_with_txlog_attrs_from(
                f, TransactionLog.OP_DELETE)
            expected_rows.append(e)
        self.clear_txlogs()
        directory.unlink_tree()

        expected_rows.append(self._get_dict_with_txlog_attrs_from(
            directory, TransactionLog.OP_DELETE))
        self.assertTransactionLogsMatch(expected_rows)

    def test_txlogs_when_unlinking_multi_level_tree(self):
        """Test that unlink_tree() creates TransactionLog entries for indirect
        descendants."""
        root = self.factory.make_directory()
        subdir = self.factory.make_directory(parent=root)
        f = self.factory.make_file(parent=subdir, mimetype=self.mimetype)
        self.clear_txlogs()

        root.unlink_tree()

        # The TransactionLog entry created will have the directory's
        # generation because in unlink_tree() we only update the directory's
        # generation and not the generation of its descendants.
        expected = [
            self._get_dict_with_txlog_attrs_from(
                node, TransactionLog.OP_DELETE) for node in [root, subdir, f]
        ]
        self.assertTransactionLogsMatch(expected)

    def test_txlog_when_moving_file(self):
        user = self.factory.make_user()
        dir1 = self.factory.make_directory(owner=user)
        dir2 = self.factory.make_directory(owner=user)
        f = self.factory.make_file(parent=dir1, mimetype=self.mimetype)
        orig_path = f.full_path
        self.clear_txlogs()

        f.move(dir2, f.name)

        expected_attrs = self._get_dict_with_txlog_attrs_from(
            f, TransactionLog.OP_MOVE, old_path=orig_path,
            extra_data_dict=TransactionLog.extra_data_new_node(f))
        self.assertTransactionLogsMatch([expected_attrs])

    def test_extra_data_new_node(self):
        """Check that extra_data_new_node includes all we need."""
        f = self.factory.make_file()
        f_extra_data = dict(
            size=f.content.size, storage_key=str(f.content.storage_key),
            public_uuid=None, content_hash=f.content_hash,
            when_created=get_epoch_secs(f.when_created),
            last_modified=get_epoch_secs(f.when_last_modified),
            kind=f.kind, volume_path=f.volume.path)
        expected = TransactionLog.extra_data_new_node(f)
        self.assertEqual(expected, f_extra_data)

    def test_record_move_for_directory(self):
        user = self.factory.make_user()
        new_parent = self.factory.make_directory(owner=user, name='new-parent')
        current = self.factory.make_directory(owner=user, name='current')
        dir1 = self.factory.make_directory(name='dir1', parent=current)
        f = self.factory.make_file(
            name='f.jpg', parent=dir1, mimetype=self.mimetype)
        f_orig_path = f.full_path
        dir_orig_path = dir1.full_path
        self.clear_txlogs()

        dir1.move(new_parent, dir1.name)
        f_extra_data = TransactionLog.extra_data_new_node(f)
        # All TransactionLog entries created will have the moved directory's
        # generation because in a move() we only update the directory's
        # generation and not the generation of its descendants.
        f_expected_attrs = self._get_dict_with_txlog_attrs_from(
            f, TransactionLog.OP_MOVE, old_path=f_orig_path,
            generation=dir1.generation, extra_data_dict=f_extra_data)
        dir_expected_attrs = self._get_dict_with_txlog_attrs_from(
            dir1, TransactionLog.OP_MOVE,
            old_path=dir_orig_path, generation=dir1.generation,
            extra_data_dict=TransactionLog.extra_data_new_node(dir1))
        self.assertTransactionLogsMatch([f_expected_attrs, dir_expected_attrs])

    def test_record_move_for_directory_with_indirect_children(self):
        # Create the following file structure:
        # root
        # |-- new-parent
        # |-- current-parent
        #     |-- dir1
        #         |-- f1.jpg
        #         |-- dir1.1
        #             |-- f11.jpg
        user = self.factory.make_user()
        parent = self.factory.make_directory(owner=user, name='current-parent')
        dir1 = self.factory.make_directory(name='dir1', parent=parent)
        dir11 = self.factory.make_directory(name='dir1.1', parent=dir1)
        f1 = self.factory.make_file(
            name='f1.jpg', parent=dir1, mimetype=self.mimetype)
        f11 = self.factory.make_file(
            name='f11.jpg', parent=dir11, mimetype=self.mimetype)
        nodes = [(dir1, dir1.full_path), (dir11, dir11.full_path),
                 (f1, f1.full_path), (f11, f11.full_path)]

        # Now move dir1 to new_parent.
        new_parent = self.factory.make_directory(owner=user, name='new-parent')
        self.clear_txlogs()

        dir1.move(new_parent, dir1.name)

        expected = [
            self._get_dict_with_txlog_attrs_from(
                node, TransactionLog.OP_MOVE,
                old_path=old_path, generation=dir1.generation,
                extra_data_dict=TransactionLog.extra_data_new_node(node))
            for node, old_path in nodes]
        self.assertTransactionLogsMatch(expected)

    def test_txlog_when_renaming_a_directory(self):
        user = self.factory.make_user()
        current_parent = self.factory.make_directory(
            owner=user, name='current-parent')
        dir1 = self.factory.make_directory(name='dir1', parent=current_parent)
        f = self.factory.make_file(
            name='f.jpg', parent=dir1, mimetype=self.mimetype)
        self.clear_txlogs()
        dir1_orig_path = dir1.full_path
        f_orig_path = f.full_path
        dir1.move(dir1.parent, 'new-name')

        # All TransactionLog entries created will have the moved directory's
        # generation because in a move() we only update the directory's
        # generation and not the generation of its descendants.
        f_expected_attrs = self._get_dict_with_txlog_attrs_from(
            f, TransactionLog.OP_MOVE, old_path=f_orig_path,
            generation=dir1.generation,
            extra_data_dict=TransactionLog.extra_data_new_node(f))
        dir_expected_attrs = self._get_dict_with_txlog_attrs_from(
            dir1, TransactionLog.OP_MOVE, old_path=dir1_orig_path,
            extra_data_dict=TransactionLog.extra_data_new_node(dir1))
        self.assertTransactionLogsMatch(
            [f_expected_attrs, dir_expected_attrs])

    def test_txlog_for_move_with_same_parent_and_name(self):
        root = self.factory.make_directory()
        f = self.factory.make_file(parent=root, mimetype=self.mimetype)

        self.assertRaises(
            ValueError, TransactionLog.record_move, f, f.name, f.parent, [])

    def test_txlog_for_share_accepted(self):
        share = self.factory.make_share(shared_to=self.factory.make_user())
        self.clear_txlogs()

        share.accept()

        expected_attrs = self._get_dict_with_txlog_attrs_from_share(
            share, TransactionLog.OP_SHARE_ACCEPTED)
        self.assertTransactionLogsMatch([expected_attrs])

    def test_txlog_for_share_deleted(self):
        share = self.factory.make_share(accepted=True)
        self.clear_txlogs()

        share.kill()

        expected_attrs = self._get_dict_with_txlog_attrs_from_share(
            share, TransactionLog.OP_SHARE_DELETED)
        self.assertTransactionLogsMatch([expected_attrs])

    def test_txlog_for_content_change(self):
        node = self.factory.make_file(mimetype=self.mimetype)
        new_content = self.factory.make_content_blob()
        self.clear_txlogs()

        node.content = new_content

        extra_data = TransactionLog.extra_data_new_node(node)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_PUT_CONTENT, extra_data_dict=extra_data)
        self.assertTransactionLogsMatch([expected_attrs])

    def test_txlog_when_publishing_directory(self):
        directory = self.factory.make_directory()
        self.clear_txlogs()

        directory.make_public()

        public_url = directory.public_url
        self.assertIsNotNone(public_url)
        extra_data = TransactionLog.extra_data_new_node(directory)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            directory, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
            extra_data_dict=extra_data)
        self.assertTransactionLogsMatch([expected_attrs])

    def test_txlog_when_unpublishing_directory(self):
        directory = self.factory.make_directory(public=True)
        self.assertIsNotNone(directory.public_uuid)
        self.assertTrue(directory.is_public)
        self.clear_txlogs()

        directory.make_private()

        extra_data = TransactionLog.extra_data_new_node(directory)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            directory, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
            extra_data_dict=extra_data)
        self.assertTransactionLogsMatch([expected_attrs])

    def test_txlog_for_public_access_change_on_interesting_file(self):
        node = self.factory.make_file(mimetype=self.mimetype)
        self.clear_txlogs()

        node.make_public()

        public_url = node.public_url
        self.assertIsNotNone(public_url)
        extra_data = TransactionLog.extra_data_new_node(node)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
            extra_data_dict=extra_data)
        self.assertTransactionLogsMatch([expected_attrs])

    def test_txlog_for_new_storageuser(self):
        user = self.factory.make_user()

        txlog = TransactionLog.objects.get(
            owner_id=user.id, op_type=TransactionLog.OP_USER_CREATED)
        self.assertTxLogDetailsMatchesUserDetails(user, txlog)

    def test_bootstrap_picks_up_only_files_owned_by_the_given_user(self):
        user = self.factory.make_user()
        photos = self._create_files_for_user(user, 'image/jpeg')
        # These files do not belong to the user we're bootstrapping now, so
        # they won't show up on the TXLog.
        self._create_files_for_user(self.factory.make_user(), 'image/jpeg')

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFiles(user, photos)

    def test_bootstrap_picks_up_only_live_files(self):
        user = self.factory.make_user()
        photos = self._create_files_for_user(user, 'image/jpeg')
        # Even though all files in this second UDF are dead, the UDF itself is
        # alive so we will have a txlog for it.
        self._create_files_for_user(user, 'image/jpeg', status=STATUS_DEAD)

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFiles(user, photos)

    def test_bootstrap_picks_up_only_files_in_live_udfs(self):
        user = self.factory.make_user()
        photo_in_root = self.factory.make_file(
            owner=user, parent=user.root_node, name='foo.jpg',
            mimetype='image/jpeg')
        dead_udf = self.factory.make_user_volume(owner=user)
        self.factory.make_file(
            owner=user, parent=dead_udf.root_node,
            name='foo-in-dead-udf.jpg', mimetype='image/jpeg')
        dead_udf.kill()
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFiles(user, [photo_in_root])

    def test_bootstrap_picks_up_only_folders_in_live_udfs(self):
        user = self.factory.make_user()
        folder_in_root = self.factory.make_directory(
            owner=user, parent=user.root_node, name='folder1', public=True)
        dead_udf = self.factory.make_user_volume(owner=user)
        self.factory.make_directory(
            owner=user, parent=dead_udf.root_node, name='folder2', public=True)
        dead_udf.kill()
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFolders(user, [folder_in_root])

    def test_bootstrap_picks_up_only_live_udfs(self):
        user = self.factory.make_user()
        live_udf = self.factory.make_user_volume(owner=user)
        live_udf2 = self.factory.make_user_volume(owner=user)
        self.factory.make_user_volume(owner=user, status=STATUS_DEAD)
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpUDFs(
            user, [user.root_node.volume, live_udf, live_udf2])

    def test_bootstrap_picks_up_public_folders(self):
        user = self.factory.make_user()
        public_dir = self.factory.make_directory(user, public=True)
        self.factory.make_directory(user)
        self.clear_txlogs()
        public_url = public_dir.public_url
        self.assertIsNotNone(public_url)

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFolders(user, [public_dir])

    def test_bootstrap_picks_up_user(self):
        user = self.make_user_without_txlog()

        TransactionLog.bootstrap(user)

        txlog = TransactionLog.objects.get(
            op_type=TransactionLog.OP_USER_CREATED)
        self.assertTxLogDetailsMatchesUserDetails(user, txlog)

    def test_bootstrap_picks_up_shares(self):
        user = self.factory.make_user()
        directory = self.factory.make_directory(user)
        share = self.factory.make_share(subtree=directory)
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        txlog = TransactionLog.objects.get(
            op_type=TransactionLog.OP_SHARE_ACCEPTED)
        expected_attrs = self._get_dict_with_txlog_attrs_from_share(
            share, TransactionLog.OP_SHARE_ACCEPTED)
        self.assert_txlog_correct(txlog, expected_attrs)

    def assertTxLogDetailsMatchesUserVolumeDetails(
            self, txlog, volume, op_type):
        """Check the given TXLog represents the creation of the given user."""
        expected_attrs = self._get_dict_with_txlog_attrs_from_udf(
            volume, op_type)
        self.assertIsNotNone(txlog)
        self.assert_txlog_correct(txlog, expected_attrs)

    def assertTxLogDetailsMatchesUserDetails(self, user, txlog):
        """Check the given TXLog represents the creation of the given user."""
        extra_data = dict(name=user.username, first_name=user.first_name,
                          last_name=user.last_name)
        expected_attrs = dict(
            owner_id=user.id, op_type=TransactionLog.OP_USER_CREATED,
            extra_data_dict=extra_data, node_id=None, volume_id=None,
            generation=None, old_path=None, mimetype=None, path=None)
        self.assertIsNotNone(txlog)
        self.assert_txlog_correct(txlog, expected_attrs)

    def assertBootstrappingPickedUpUDFs(self, user, udfs):
        txlogs = TransactionLog.objects.filter(
            owner_id=user.id, op_type=TransactionLog.OP_UDF_CREATED)
        expected = {}
        self.assertEqual(len(udfs), txlogs.count())
        for udf in udfs:
            udf_txlog = txlogs.get(volume_id=udf.id)
            when_created = get_epoch_secs(udf.when_created)
            expected = dict(
                node_id=None, volume_id=udf.id, generation=udf.generation,
                path=udf.path, mimetype=None, owner_id=udf.owner_id,
                extra_data_dict=dict(when_created=when_created),
                op_type=TransactionLog.OP_UDF_CREATED)
            self.assert_txlog_correct(udf_txlog, expected)

    def assertBootstrappingPickedUpFiles(self, user, files):
        """Check there are TXLog bootstrapping entries for the given files."""
        file_txlogs = TransactionLog.objects.filter(
            owner_id=user.id, op_type=TransactionLog.OP_PUT_CONTENT)
        expected = []
        for node in files:
            extra_data = TransactionLog.extra_data_new_node(node)
            expected.append(
                self._get_dict_with_txlog_attrs_from(
                    node, TransactionLog.OP_PUT_CONTENT,
                    generation=node.generation, extra_data_dict=extra_data))
        self.assertTransactionLogsMatch(expected, txlogs=file_txlogs)

    def assertBootstrappingPickedUpFolders(self, user, folders):
        """Check there are TXLog entries for the given folders."""
        folder_txlogs = TransactionLog.objects.filter(
            owner_id=user.id, op_type=TransactionLog.OP_PUBLIC_ACCESS_CHANGED)
        expected = []
        for folder in folders:
            extra_data = TransactionLog.extra_data_new_node(folder)
            expected.append(
                self._get_dict_with_txlog_attrs_from(
                    folder, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
                    extra_data_dict=extra_data))
        self.assertTransactionLogsMatch(expected, txlogs=folder_txlogs)

    def assertNoTransactionLogEntriesExist(self):
        self.assertEqual([], list(TransactionLog.objects.all()))

    def _get_dict_with_txlog_attrs_from_udf(self, udf, op_type):
        extra_data = None
        if op_type == TransactionLog.OP_UDF_CREATED:
            when_created = get_epoch_secs(udf.when_created)
            extra_data = dict(when_created=when_created)
        return dict(
            node_id=None, volume_id=udf.id, owner_id=udf.owner_id,
            op_type=op_type, path=udf.path, generation=udf.generation,
            mimetype=None, old_path=None, extra_data_dict=extra_data)

    def _get_dict_with_txlog_attrs_from_share(self, share, op_type):
        when_last_changed = share.when_last_changed
        extra_data = dict(
            shared_to=share.shared_to.id if share.shared_to else share.email,
            share_id=str(share.id), share_name=share.name,
            access_level=share.access,
            when_shared=get_epoch_secs(share.when_shared),
            when_last_changed=get_epoch_secs(when_last_changed))
        return self._get_dict_with_txlog_attrs_from(
            share.subtree, op_type, omit_generation=True,
            extra_data_dict=extra_data)

    def _get_dict_with_txlog_attrs_from(
            self, node, op_type, omit_generation=False, **kwargs):
        """Return a dictionary containing the attributes of the given node
        that would be stored in a TransactionLog entry.

        @param extra: A dictionary with values to be included in the returned
            dictionary.
        """
        node.refresh_from_db()
        generation = None
        if not omit_generation:
            generation = node.generation
        d = dict(
            node_id=node.id, volume_id=node.volume.id, op_type=op_type,
            owner_id=node.volume.owner.id, path=node.full_path, old_path=None,
            generation=generation, mimetype=node.mimetype or None,
            extra_data_dict={'kind': node.kind,
                             'volume_path': node.volume.path})
        d.update(kwargs)
        return d

    def assertTransactionLogsMatch(self, expected, txlogs=None):
        """Assert that the given TransactionLogs match the expected values.

        @param txlogs: A sequence of TransactionLog objects.
        @param expected: A dictionary with the IDs of the expected
            TransactionLogs as keys and dictionaries with all the attributes
            of the TransactionLog as values.
        """
        if txlogs is None:
            txlogs = TransactionLog.objects.all()
        actual = []
        for t in txlogs:
            td = t.as_dict()
            td.pop('txn_id')
            td.pop('timestamp')
            td.pop('extra_data')
            td['extra_data_dict'] = t.extra_data_dict
            actual.append(td)

        def sort_dicts(ll):
            return [OrderedDict(sorted(i for i in d.items())) for d in ll]

        self.assertItemsEqual(sort_dicts(expected), sort_dicts(actual))

    def _create_files_for_user(self, user, mimetype, status=STATUS_LIVE):
        """Create 5 files with the given mimetype for the given user."""
        files = []
        for i in range(0, 5):
            public = bool(i % 2)
            f = self.factory.make_file(
                owner=user, mimetype=mimetype, public=public, status=status)
            files.append(f)
        self.clear_txlogs()
        return files
