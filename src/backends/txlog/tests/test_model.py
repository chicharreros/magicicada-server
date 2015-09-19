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

"""Test for the txlog models."""

from __future__ import unicode_literals

from mock import patch

from backends.filesync.data.dbmanager import get_filesync_store
from backends.filesync.data.gateway import SystemGateway
from backends.filesync.data.model import (
    PublicNode, STATUS_DEAD, StorageObject, StorageUser, UserVolume)
from backends.filesync.data.testing.ormtestcase import ORMTestCase
from backends.filesync.data.utils import get_public_file_url

from backends.txlog.model import (
    get_epoch_secs,
    TransactionLog,
)


class BaseTransactionLogTestCase(ORMTestCase):

    def setUp(self):
        super(BaseTransactionLogTestCase, self).setUp()
        self._orig_make_user = self.obj_factory.make_user
        # Overwrite .obj_factory.make_user() with a custom version that
        # doesn't create TransactionLogs as that would pollute our tests.
        p = patch.object(self.obj_factory, 'make_user')
        self.addCleanup(p.stop)
        mock_make_user = p.start()
        mock_make_user.side_effect = self._make_user_without_txlog

        self.clear_txlogs()

    def clear_txlogs(self):
        # clear current transaction logs
        self.store.find(TransactionLog).remove()

    def _make_user_without_txlog(self, *args, **kwargs):
        """Custom make_user function that does not create TransactionLogs."""
        user = self._orig_make_user(*args, **kwargs)
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
        msg = 'Value for %r must be %r (for %r instead).'
        for k, v in expected.iteritems():
            actual = getattr(txlog, k)
            self.assertEqual(actual, v, msg % (k, v, actual))

    def test_create(self):
        self.obj_factory.make_transaction_log()
        self.store.commit()

    def test_txlog_when_creating_udf(self):
        udf = self.obj_factory.make_udf()

        txlog = self.store.find(TransactionLog).one()
        self.assertTxLogDetailsMatchesUserVolumeDetails(
            txlog, udf, TransactionLog.OP_UDF_CREATED)

    def test_txlog_when_deleting_empty_udf(self):
        """When we delete an empty UDF there will be a single txlog."""
        udf = self.obj_factory.make_udf()
        self.clear_txlogs()

        udf.delete()

        expected_rows = {
            # Our key here is None because OP_UDF_DELETED txlogs have no
            # node_id.
            None: self._get_dict_with_txlog_attrs_from_udf(
                udf, TransactionLog.OP_UDF_DELETED),
            udf.root_node.id: self._get_dict_with_txlog_attrs_from(
                udf.root_node, TransactionLog.OP_DELETE,
                extra=dict(generation=udf.generation))}
        self.assertStoredTransactionLogsMatch(expected_rows)

    def test_txlogs_when_deleting_udf_with_files(self):
        """Check that deleting a UDF creates correct transaction logs.

        We only create transaction logs for the UDF itself and the descendants
        which are either directories or files whose mimetype is in
        TransactionLog.INTERESTING_MIMETYPES.
        """
        udf = self.obj_factory.make_udf()
        self.clear_txlogs()

        expected_rows = {
            # Our key here is None because OP_UDF_DELETED txlogs have no
            # node_id.
            None: self._get_dict_with_txlog_attrs_from_udf(
                udf, TransactionLog.OP_UDF_DELETED),
            udf.root_node.id: self._get_dict_with_txlog_attrs_from(
                udf.root_node, TransactionLog.OP_DELETE)}

        for i in range(0, 5):
            f = self._make_file(parent=udf.root_node, mimetype=self.mimetype)
            expected_rows[f.id] = self._get_dict_with_txlog_attrs_from(
                f, TransactionLog.OP_DELETE,
                extra=dict(generation=udf.generation))

        udf.delete()

        # All TransactionLog entries created will have the UDF's generation
        # because when a UDF is deleted we only update the UDF's generation
        # and not the generation of its descendants.
        for row in expected_rows.values():
            row['generation'] = udf.generation
        self.assertStoredTransactionLogsMatch(expected_rows)

    def test_txlogs_when_user_signs_up(self):
        """Check that when a user signs up we get a txlog for the new user and
        one for their root UDF.
        """
        user_id = self.obj_factory.get_unique_integer()
        name = self.obj_factory.get_unique_unicode()
        user = SystemGateway().create_or_update_user(
            user_id, name, name, max_storage_bytes=user_id)
        udf = self.store.find(UserVolume, owner_id=user.id).one()

        udf_txlog = self.store.find(
            TransactionLog, op_type=TransactionLog.OP_UDF_CREATED).one()
        self.assertTxLogDetailsMatchesUserVolumeDetails(
            udf_txlog, udf, TransactionLog.OP_UDF_CREATED)

        user_txlog = self.store.find(
            TransactionLog, op_type=TransactionLog.OP_USER_CREATED).one()
        self.assertTxLogDetailsMatchesUserDetails(user, user_txlog)

    def test_txlog_when_unlinking_file(self):
        """Check that we store a TransactionLog with the file attributes.
        """
        node = self._make_file(mimetype=self.mimetype)
        node.unlink()
        expected = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_DELETE,
            extra=dict(extra_data_dict={'kind': 'File',
                                        'volume_path': '~/Ubuntu One'}))
        self.assertStoredTransactionLogsMatch({node.id: expected})

    def test_txlog_when_unlinking_empty_directory(self):
        node = self.obj_factory.make_directory()
        node.unlink()
        expected = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_DELETE,
            extra=dict(extra_data_dict={'kind': 'Directory',
                                        'volume_path': '~/Ubuntu One'}))
        self.assertStoredTransactionLogsMatch({node.id: expected})

    def test_txlogs_when_unlinking_tree(self):
        """Check that unlink_tree() creates correct transaction logs.

        We only create transaction logs for the directory itself and the
        descendants which are either directories or files.
        """
        # Create a directory with 5 files.
        directory = self.obj_factory.make_directory()
        expected_rows = {
            directory.id: self._get_dict_with_txlog_attrs_from(
                directory, TransactionLog.OP_DELETE,
                extra=dict(extra_data_dict={'kind': 'Directory',
                                            'volume_path': "~/Ubuntu One"}))}

        for i in range(0, 5):
            f = self._make_file(parent=directory, mimetype=self.mimetype)
            expected_rows[f.id] = self._get_dict_with_txlog_attrs_from(
                f, TransactionLog.OP_DELETE,
                extra=dict(extra_data_dict={'kind': f.kind,
                                            'volume_path': "~/Ubuntu One"}))

        directory.unlink_tree()

        # All TransactionLog entries created will have the directory's
        # generation because in unlink_tree() we only update the directory's
        # generation and not the generation of its descendants.
        for row in expected_rows.values():
            row['generation'] = directory.generation
        self.assertStoredTransactionLogsMatch(expected_rows)

    def test_txlogs_when_unlinking_multi_level_tree(self):
        """Test that unlink_tree() creates TransactionLog entries for indirect
        descendants."""
        root = self.obj_factory.make_directory()
        subdir = self.obj_factory.make_directory(parent=root)
        f = self._make_file(parent=subdir, mimetype=self.mimetype)

        root.unlink_tree()

        # The TransactionLog entry created will have the directory's
        # generation because in unlink_tree() we only update the directory's
        # generation and not the generation of its descendants.
        expected = {}
        for node in [root, subdir, f]:
            expected[node.id] = self._get_dict_with_txlog_attrs_from(
                node, TransactionLog.OP_DELETE,
                extra=dict(generation=root.generation))
        self.assertStoredTransactionLogsMatch(expected)

    def test_txlog_when_moving_file(self):
        user = self.obj_factory.make_user()
        dir1 = self.obj_factory.make_directory(user=user)
        dir2 = self.obj_factory.make_directory(user=user)
        f = self._make_file(parent=dir1, mimetype=self.mimetype)
        orig_path = f.full_path

        f.move(dir2.id, f.name)

        expected_attrs = self._get_dict_with_txlog_attrs_from(
            f, TransactionLog.OP_MOVE, extra=dict(old_path=orig_path))
        self.assertStoredTransactionLogsMatch({f.id: expected_attrs})

    def test__get_extra_data_for_new_node(self):
        """Check that _get_extra_data_for_new_node includes all we need."""
        f = self._make_file()
        f_extra_data = dict(
            size=f.content.size, storage_key=unicode(f.content.storage_key),
            publicfile_id=None, public_uuid=None, content_hash=f.content_hash,
            when_created=get_epoch_secs(f.when_created),
            last_modified=get_epoch_secs(f.when_last_modified),
            kind=f.kind, volume_path=f.volume.path)
        expected = TransactionLog._get_extra_data_for_new_node(
            f, f.volume.path)
        self.assertEqual(expected, f_extra_data)

    def test_record_move_for_directory(self):
        user = self.obj_factory.make_user()
        new_parent = self.obj_factory.make_directory(
            user=user, name='new-parent')
        current_parent = self.obj_factory.make_directory(
            user=user, name='current-parent')
        dir1 = self.obj_factory.make_directory(
            name='dir1', parent=current_parent)
        f = self._make_file(name='f.jpg', parent=dir1, mimetype=self.mimetype)
        f_orig_path = f.full_path
        dir_orig_path = dir1.full_path
        dir1.move(new_parent.id, dir1.name)
        f_extra_data = TransactionLog._get_extra_data_for_new_node(
            f, f.volume.path)
        # All TransactionLog entries created will have the moved directory's
        # generation because in a move() we only update the directory's
        # generation and not the generation of its descendants.
        f_expected_attrs = self._get_dict_with_txlog_attrs_from(
            f, TransactionLog.OP_MOVE,
            extra=dict(old_path=f_orig_path, generation=dir1.generation,
                       extra_data_dict=f_extra_data))
        dir_expected_attrs = self._get_dict_with_txlog_attrs_from(
            dir1, TransactionLog.OP_MOVE,
            extra=dict(old_path=dir_orig_path, generation=dir1.generation))
        self.assertStoredTransactionLogsMatch(
            {f.id: f_expected_attrs, dir1.id: dir_expected_attrs})

    def test_record_move_for_directory_with_indirect_children(self):
        # Create the following file structure:
        # root
        # |-- new-parent
        # |-- current-parent
        #     |-- dir1
        #         |-- f1.jpg
        #         |-- dir1.1
        #             |-- f11.jpg
        user = self.obj_factory.make_user()
        parent = self.obj_factory.make_directory(
            user=user, name='current-parent')
        dir1 = self.obj_factory.make_directory(name='dir1', parent=parent)
        dir11 = self.obj_factory.make_directory(name='dir1.1', parent=dir1)
        f1 = self._make_file(
            name='f1.jpg', parent=dir1, mimetype=self.mimetype)
        f11 = self._make_file(
            name='f11.jpg', parent=dir11, mimetype=self.mimetype)
        nodes = [(dir1, dir1.full_path), (dir11, dir11.full_path),
                 (f1, f1.full_path), (f11, f11.full_path)]

        # Now move dir1 to new_parent.
        new_parent = self.obj_factory.make_directory(
            user=user, name='new-parent')
        dir1.move(new_parent.id, dir1.name)

        expected = {}
        for node, old_path in nodes:
            extra = dict(old_path=old_path,
                         generation=dir1.generation)
            expected[node.id] = self._get_dict_with_txlog_attrs_from(
                node, TransactionLog.OP_MOVE, extra=extra)
        # And now ensure there are four TransactionLog entries stored (for
        # dir1, dir11, f1.jpg and f11.jpg) and the attributes there match the
        # current state of the nodes plus their old path (from before the
        # move). Notice that the generation is the same in all of them and is
        # equal to dir1.generation.
        self.assertStoredTransactionLogsMatch(expected)

    def test_txlog_when_renaming_a_directory(self):
        user = self.obj_factory.make_user()
        current_parent = self.obj_factory.make_directory(
            user=user, name='current-parent')
        dir1 = self.obj_factory.make_directory(
            name='dir1', parent=current_parent)
        f = self._make_file(
            name='f.jpg', parent=dir1, mimetype=self.mimetype)

        dir1_orig_path = dir1.full_path
        f_orig_path = f.full_path
        dir1.move(dir1.parent.id, 'new-name')

        # All TransactionLog entries created will have the moved directory's
        # generation because in a move() we only update the directory's
        # generation and not the generation of its descendants.
        f_expected_attrs = self._get_dict_with_txlog_attrs_from(
            f, TransactionLog.OP_MOVE,
            extra=dict(old_path=f_orig_path, generation=dir1.generation))
        dir_expected_attrs = self._get_dict_with_txlog_attrs_from(
            dir1, TransactionLog.OP_MOVE,
            extra=dict(old_path=dir1_orig_path, generation=dir1.generation))
        self.assertStoredTransactionLogsMatch(
            {f.id: f_expected_attrs, dir1.id: dir_expected_attrs})

    def test_txlog_for_move_with_same_parent_and_name(self):
        root = self.obj_factory.make_directory()
        f = self._make_file(parent=root, mimetype=self.mimetype)

        self.assertRaises(
            ValueError, TransactionLog.record_move, f, f.name, f.parent)

    def test_txlog_for_share_accepted(self):
        share = self.obj_factory.make_share()
        self._test_share_accepted_or_deleted(
            share, TransactionLog.OP_SHARE_ACCEPTED)

    def test_txlog_for_share_deleted(self):
        share = self.obj_factory.make_share()
        self._test_share_accepted_or_deleted(
            share, TransactionLog.OP_SHARE_DELETED)

    def _test_share_accepted_or_deleted(self, share, op_type):
        node = self.store.get(StorageObject, share.subtree)
        if op_type == TransactionLog.OP_SHARE_DELETED:
            share.delete()
        elif op_type == TransactionLog.OP_SHARE_ACCEPTED:
            share.accept()
        else:
            raise AssertionError("Unexpected operation type: %s" % op_type)

        expected_attrs = self._get_dict_with_txlog_attrs_from_share(
            share, node, op_type)
        self.assertStoredTransactionLogsMatch({node.id: expected_attrs})

    def test_txlog_for_content_change(self):
        node = self._make_file(mimetype=self.mimetype)
        new_content = self.obj_factory.make_content()

        node.content = new_content

        extra_data = TransactionLog._get_extra_data_for_new_node(
            node, node.volume.path)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_PUT_CONTENT,
            extra=dict(extra_data_dict=extra_data))
        self.assertStoredTransactionLogsMatch({node.id: expected_attrs})

    def test_txlog_when_publishing_directory(self):
        directory = self.obj_factory.make_directory()
        publicfile = self.store.add(
            PublicNode(directory.id, directory.owner_id))
        self.store.flush()

        directory.publicfile_id = publicfile.id

        public_url = get_public_file_url(directory)
        self.assertIsNotNone(public_url)
        extra_data = TransactionLog._get_extra_data_for_new_node(
            directory, directory.volume.path)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            directory, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
            extra=dict(extra_data_dict=extra_data))
        self.assertStoredTransactionLogsMatch({directory.id: expected_attrs})

    def test_txlog_when_unpublishing_directory(self):
        directory = self.obj_factory.make_directory()
        # Change _publicfile_id directly because if we go via the public API
        # (.publicfile_id) it'll generate a TransactionLog and that will
        # complicate the actual test.
        directory._publicfile_id = self.obj_factory.get_unique_integer()
        self.assertIsNotNone(directory.publicfile_id)
        self.assertTrue(directory.is_public)

        directory.publicfile_id = None

        extra_data = TransactionLog._get_extra_data_for_new_node(
            directory, directory.volume.path)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            directory, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
            extra=dict(extra_data_dict=extra_data))
        self.assertStoredTransactionLogsMatch({directory.id: expected_attrs})

    def test_txlog_for_public_access_change_on_interesting_file(self):
        node = self._make_file(mimetype=self.mimetype)
        publicfile = self.store.add(PublicNode(node.id, node.owner_id))
        self.store.flush()

        node.publicfile_id = publicfile.id

        public_url = get_public_file_url(node)
        self.assertIsNotNone(public_url)
        extra_data = TransactionLog._get_extra_data_for_new_node(
            node, node.volume.path)
        expected_attrs = self._get_dict_with_txlog_attrs_from(
            node, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
            extra=dict(extra_data_dict=extra_data))
        self.assertStoredTransactionLogsMatch({node.id: expected_attrs})

    def test_txlog_for_new_storageuser(self):
        user_id = self.obj_factory.get_unique_integer()
        name = self.obj_factory.get_unique_unicode()
        visible_name = self.obj_factory.get_unique_unicode()

        user = StorageUser.new(self.store, user_id, name, visible_name)

        store = get_filesync_store()
        txlog = store.find(TransactionLog, owner_id=user.id).one()
        self.assertTxLogDetailsMatchesUserDetails(user, txlog)

    def test_bootstrap_picks_up_only_files_owned_by_the_given_user(self):
        user = self.obj_factory.make_user(user_id=1)
        photos = self._create_files_for_user(user, 'image/jpeg')
        # These files do not belong to the user we're bootstrapping now, so
        # they won't show up on the TXLog.
        self._create_files_for_user(
            self.obj_factory.make_user(user_id=2), 'image/jpeg')

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFiles(photos)

    def test_bootstrap_picks_up_only_live_files(self):
        user = self.obj_factory.make_user()
        photos = self._create_files_for_user(user, 'image/jpeg')
        # Even though all files in this second UDF are dead, the UDF itself is
        # alive so we will have a txlog for it.
        self._create_files_for_user(user, 'image/jpeg', status='Dead')

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFiles(photos)

    def test_bootstrap_picks_up_only_files_in_live_udfs(self):
        user = self.obj_factory.make_user()
        root_udf = UserVolume.get_root(self.store, user.id)
        photo_in_root = self.obj_factory.make_file(
            user, root_udf.root_node, 'foo.jpg', 'image/jpeg')
        dead_udf = self.obj_factory.make_udf(user=user)
        self.obj_factory.make_file(
            user, dead_udf.root_node, 'foo-in-dead-udf.jpg',
            'image/jpeg')
        dead_udf.delete()
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFiles([photo_in_root])

    def test_bootstrap_picks_up_only_folders_in_live_udfs(self):
        user = self.obj_factory.make_user()
        root_udf = UserVolume.get_root(self.store, user.id)
        folder_in_root = self.obj_factory.make_directory(
            user, root_udf.root_node, 'folder1', public=True)
        dead_udf = self.obj_factory.make_udf(user=user)
        self.obj_factory.make_directory(
            user, dead_udf.root_node, 'folder2', public=True)
        dead_udf.delete()
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFolders([folder_in_root])

    def test_bootstrap_picks_up_only_live_udfs(self):
        user = self.obj_factory.make_user()
        root_udf = UserVolume.get_root(self.store, user.id)
        live_udf = self.obj_factory.make_udf(user=user)
        live_udf2 = self.obj_factory.make_udf(user=user)
        self.obj_factory.make_udf(user=user, status=STATUS_DEAD)
        self.clear_txlogs()

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpUDFs([root_udf, live_udf, live_udf2])

    def test_bootstrap_picks_up_public_folders(self):
        user = self.obj_factory.make_user()
        public_dir = self.obj_factory.make_directory(user, public=True)
        self.obj_factory.make_directory(user)
        self.clear_txlogs()
        public_url = get_public_file_url(public_dir)
        self.assertIsNotNone(public_url)

        TransactionLog.bootstrap(user)

        self.assertBootstrappingPickedUpFolders([public_dir])

    def test_bootstrap_picks_up_user(self):
        user = self.obj_factory.make_user()

        TransactionLog.bootstrap(user)

        txlog = get_filesync_store().find(
            TransactionLog, op_type=TransactionLog.OP_USER_CREATED).one()
        self.assertTxLogDetailsMatchesUserDetails(user, txlog)

    def test_bootstrap_picks_up_shares(self):
        user = self.obj_factory.make_user()
        directory = self.obj_factory.make_directory(user)
        share = self.obj_factory.make_share(directory)
        self.store.commit()

        TransactionLog.bootstrap(user)

        txlog = get_filesync_store().find(
            TransactionLog, op_type=TransactionLog.OP_SHARE_ACCEPTED).one()
        expected_attrs = self._get_dict_with_txlog_attrs_from_share(
            share, directory, TransactionLog.OP_SHARE_ACCEPTED)
        self.assert_txlog_correct(txlog, expected_attrs)

    def _get_dict_with_txlog_attrs_from_udf(self, udf, op_type):
        extra_data = None
        if op_type == TransactionLog.OP_UDF_CREATED:
            when_created = get_epoch_secs(udf.when_created)
            extra_data = dict(when_created=when_created)
        return dict(
            node_id=None, volume_id=udf.id, owner_id=udf.owner_id,
            op_type=op_type, extra_data_dict=extra_data,
            generation=udf.generation, path=udf.path)

    def assertTxLogDetailsMatchesUserVolumeDetails(
            self, txlog, volume, op_type):
        """Check the given TXLog represents the creation of the given user."""
        expected_attrs = self._get_dict_with_txlog_attrs_from_udf(
            volume, op_type)
        self.assertIsNotNone(txlog)
        self.assert_txlog_correct(txlog, expected_attrs)

    def assertTxLogDetailsMatchesUserDetails(self, user, txlog):
        """Check the given TXLog represents the creation of the given user."""
        extra_data = dict(name=user.username, visible_name=user.visible_name)
        expected_attrs = dict(
            owner_id=user.id, op_type=TransactionLog.OP_USER_CREATED,
            extra_data_dict=extra_data, node_id=None, volume_id=None,
            generation=None, old_path=None, mimetype=None, path=None)
        self.assertIsNotNone(txlog)
        self.assert_txlog_correct(txlog, expected_attrs)

    def assertBootstrappingPickedUpUDFs(self, udfs):
        txlogs = self.store.find(
            TransactionLog, op_type=TransactionLog.OP_UDF_CREATED)
        expected = {}
        self.assertEqual(len(udfs), txlogs.count())
        for udf in udfs:
            udf_txlog = txlogs.find(volume_id=udf.id).one()
            when_created = get_epoch_secs(udf.when_created)
            expected = dict(
                node_id=None, volume_id=udf.id, generation=udf.generation,
                path=udf.path, mimetype=None, owner_id=udf.owner_id,
                extra_data_dict=dict(when_created=when_created),
                op_type=TransactionLog.OP_UDF_CREATED)
            self.assert_txlog_correct(udf_txlog, expected)

    def assertBootstrappingPickedUpFiles(self, files):
        """Check there are TXLog bootstrapping entries for the given files."""
        file_txlogs = self.store.find(
            TransactionLog, op_type=TransactionLog.OP_PUT_CONTENT)
        expected = {}
        for node in files:
            extra_data = TransactionLog._get_extra_data_for_new_node(
                node, node.volume.path)
            expected[node.id] = self._get_dict_with_txlog_attrs_from(
                node, TransactionLog.OP_PUT_CONTENT,
                extra=dict(generation=node.generation,
                           extra_data_dict=extra_data))
        self.assertTransactionLogsMatch(file_txlogs, expected)

    def assertBootstrappingPickedUpFolders(self, folders):
        """Check there are TXLog entries for the given folders."""
        folder_txlogs = self.store.find(
            TransactionLog,
            op_type=TransactionLog.OP_PUBLIC_ACCESS_CHANGED)
        expected = {}
        for folder in folders:
            extra_data = TransactionLog._get_extra_data_for_new_node(
                folder, folder.volume.path)
            expected[folder.id] = self._get_dict_with_txlog_attrs_from(
                folder, TransactionLog.OP_PUBLIC_ACCESS_CHANGED,
                extra=dict(extra_data_dict=extra_data))
        self.assertTransactionLogsMatch(folder_txlogs, expected)

    def assertNoTransactionLogEntriesExist(self):
        self.assertEqual([], list(self.store.find(TransactionLog)))

    def _make_file(self, name=None, parent=None, mimetype=None):
        """Creates a new file with the given attributes.

        We disable txlog before creating the file and re-enable it later so
        that no entries are created when the file content is changed in
        obj_factory.make_file().  This is just to avoid poluting the
        TransactionLog table with things the tests don't really care about.
        """
        result = self.obj_factory.make_file(
            name=name, parent=parent, mimetype=mimetype)
        self.clear_txlogs()
        return result

    def _get_dict_with_txlog_attrs_from_share(self, share, node, op_type):
        when_last_changed = share.when_last_changed
        extra_data = dict(
            shared_to=share.shared_to, share_id=str(share.id),
            share_name=share.name, access_level=share.access,
            when_shared=get_epoch_secs(share.when_shared),
            when_last_changed=get_epoch_secs(when_last_changed))
        return self._get_dict_with_txlog_attrs_from(
            node, op_type, omit_generation=True,
            extra=dict(extra_data_dict=extra_data))

    def _get_dict_with_txlog_attrs_from(self, node, op_type,
                                        omit_generation=False, extra=None):
        """Return a dictionary containing the attributes of the given node
        that would be stored in a TransactionLog entry.

        @param extra: A dictionary with values to be included in the returned
            dictionary.
        """
        generation = None
        if not omit_generation:
            generation = node.generation
        d = dict(
            node_id=node.id, owner_id=node.owner_id, path=node.full_path,
            generation=generation, mimetype=node.mimetype)
        if extra is not None:
            d.update(extra)
        return d

    def assertTransactionLogsMatch(self, txlogs, expected):
        """Assert that the given TransactionLogs match the expected values.

        @param txlogs: A sequence of TransactionLog objects.
        @param expected: A dictionary with the IDs of the expected
            TransactionLogs as keys and dictionaries with all the attributes
            of the TransactionLog as values.
        """
        self.assertEqual(len(expected), txlogs.count())
        for txlog in txlogs:
            individual_attrs = expected[txlog.node_id]
            self.assert_txlog_correct(txlog, individual_attrs)

    def assertStoredTransactionLogsMatch(self, expected):
        """Check that the TransactionLogs we have in the DB are what we expect.

        @param expected: A dict mapping node IDs to TransactionLog attributes.

        We will assert that the number of TransactionLog rows we have in the
        DB is the same as the number of items in `expected` and then assert
        that every row has the attributes we expect them to have.
        """
        txlogs = self.store.find(TransactionLog)
        self.assertTransactionLogsMatch(txlogs, expected)

    def _create_files_for_user(self, user, mimetype, status='Live'):
        """Create 5 files with the given mimetype for the given user."""
        files = []
        for i in range(0, 5):
            public = bool(i % 2)
            f = self.obj_factory.make_file(
                user=user, mimetype=mimetype, public=public)
            f.status = status
            files.append(f)
        self.clear_txlogs()
        return files
