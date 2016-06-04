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

"""Model code for the Transaction Log."""

from __future__ import unicode_literals

import calendar
import json
import os

from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils.timezone import now

from magicicada.filesync.models import (
    STATUS_DEAD,
    STATUS_LIVE,
    Share,
    StorageObject,
    StorageUser,
    UserVolume,
)
from magicicada.filesync.signals import (
    content_changed,
    node_moved,
    post_unlink_tree,
    post_kill,
    public_access_changed,
)


def get_epoch_secs(dt):
    """Get the seconds since epoch"""
    return calendar.timegm(dt.timetuple())


class TransactionLog(models.Model):
    """The log of an operation performed on a node."""

    # Constants; may want to move somewhere else.
    OP_DELETE = 'delete'
    OP_MOVE = 'move'
    OP_PUT_CONTENT = 'put_content'
    OP_SHARE_ACCEPTED = 'share_accepted'
    OP_SHARE_DELETED = 'share_deleted'
    OP_PUBLIC_ACCESS_CHANGED = 'public_access_changed'
    OP_USER_CREATED = 'user_created'
    OP_UDF_CREATED = 'udf_created'
    OP_UDF_DELETED = 'udf_deleted'
    OPERATIONS = [
        OP_USER_CREATED, OP_DELETE, OP_MOVE, OP_PUT_CONTENT,
        OP_SHARE_ACCEPTED, OP_SHARE_DELETED, OP_PUBLIC_ACCESS_CHANGED,
        OP_UDF_CREATED, OP_UDF_DELETED]

    # Most operations we care about are on nodes, but this can be None for
    # things like OP_USER_CREATED.
    node_id = models.UUIDField(null=True)
    # The volume where the node is; can also be None in some cases.
    volume_id = models.UUIDField(null=True)
    # The ID of the node's owner if this is an operation on a Node, or the ID
    # of the newly created user if it's a OP_USER_CREATED.
    owner_id = models.BigIntegerField()
    op_type = models.CharField(
        max_length=256, choices=[(i, i) for i in OPERATIONS])
    path = models.TextField(null=True)
    generation = models.BigIntegerField(null=True)
    timestamp = models.DateTimeField(default=now)
    mimetype = models.TextField(null=True)
    extra_data = models.TextField(null=True)
    # Only used when representing a move.
    old_path = models.TextField(null=True)

    def __unicode__(self):
        return 'TransactionLog: owner_id %r volume_id %r op_type %r' % (
            self.owner_id, self.volume_id, self.op_type)

    @property
    def extra_data_dict(self):
        """A dictionary obtained by json.loading self.extra_data."""
        if self.extra_data is None:
            return self.extra_data
        return json.loads(self.extra_data)

    @classmethod
    def bootstrap(cls, user):
        cls.record_user_created(user)
        # Number of TransactionLog rows we inserted.
        rows = 1

        for udf in UserVolume.objects.filter(owner=user, status=STATUS_LIVE):
            cls.record_udf_created(udf)
            rows += 1
            # If this becomes a problem it can be done as a single INSERT, but
            # we'd need to duplicate the get_absolute_url() in plpython.
            for directory in udf.storageobject_set.filter(
                    kind=StorageObject.DIRECTORY, status=STATUS_LIVE,
                    public_uuid__isnull=False):
                cls.record_public_access_change(directory)
                rows += 1

        nodes = StorageObject.objects.exclude(
            kind=StorageObject.DIRECTORY).filter(
                status=STATUS_LIVE, volume__status=STATUS_LIVE,
                volume__owner__id=user.id)
        for node in nodes:
            cls.record_put_content(node)
            rows += 1

        # Cannot create TransactionLogs for Shares in a single INSERT like
        # above because TransactionLogs and Shares live in separate databases.
        shares = Share.objects.filter(
            shared_by=user, status=STATUS_LIVE, accepted=True)
        for share in shares:
            cls.record_share_accepted(share)
            rows += 1

        return rows

    @classmethod
    def record_udf_created(cls, udf):
        """Create a TransactionLog representing a new UserVolume."""
        when_created = get_epoch_secs(udf.when_created)
        extra_data = json.dumps(dict(when_created=when_created))
        txlog = cls.objects.create(
            node_id=None, owner_id=udf.owner.id, volume_id=udf.id,
            op_type=cls.OP_UDF_CREATED, path=udf.path,
            generation=udf.generation, extra_data=extra_data)
        return txlog

    @classmethod
    def record_udf_deleted(cls, udf):
        """Create TransactionLogs representing a UserVolume deleted.

        This will create one TransactionLog for the deletion of the UserVolume
        itself (op_type=OP_UDF_DELETED) and then create TransactionLogs for
        the removal of every descendant of it. The latter part is similar to
        unlinking a directory tree where the top of the tree is the
        UserVolume's root node.

        Note that when a UserVolume is deleted its generation is increased but
        the generation of its children are not, so we use the UserVolume's
        generation in all TransactionLogs created.
        """
        rows = 1
        cls.objects.create(
            node_id=None, owner_id=udf.owner.id, volume_id=udf.id,
            op_type=cls.OP_UDF_DELETED, path=udf.path,
            generation=udf.generation)
        rows += cls._record_unlink_tree(udf.root_node, udf.generation)
        return rows

    @classmethod
    def record_user_created(cls, user):
        """Create a TransactionLog entry representing a new user.

        We abuse the TransactionLog table to store the details of newly
        created users because our derived services need information about
        users as well as their files.

        A TransactionLog representing a newly created user will have
        no node_id, volume_id, generation or path. And its owner_id will be
        the ID of the newly created user.
        """
        extra_data = json.dumps(dict(
            name=user.username, first_name=user.first_name,
            last_name=user.last_name))
        txlog = cls.objects.create(
            node_id=None, owner_id=user.id, volume_id=None, path=None,
            op_type=cls.OP_USER_CREATED, extra_data=extra_data)
        return txlog

    @classmethod
    def record_public_access_change(cls, node):
        """Create a TransactionLog entry representing a change in a
        node's public accessibility.

        Currently we only record TransactionLogs for directories that are made
        public/private, so if the given node is not a directory we'll return
        None without storing a TransactionLog.

        @param node: The StorageObject that was made public/private.
        @return: The newly created TransactionLog.
        """
        extra_data = cls.extra_data_new_node(node)
        txlog = cls.objects.create(
            node_id=node.id, owner_id=node.volume.owner.id,
            volume_id=node.volume.id, op_type=cls.OP_PUBLIC_ACCESS_CHANGED,
            path=node.full_path, mimetype=node.mimetype or None,
            generation=node.generation, extra_data=json.dumps(extra_data))
        return txlog

    @classmethod
    def record_put_content(cls, node):
        """Create a TransactionLog entry representing a PUT_CONTENT operation.

        @param node: The StorageObject which points to the content uploaded.
        @return: The newly created TransactionLog.
        """
        extra_data = cls.extra_data_new_node(node)
        txlog = cls.objects.create(
            node_id=node.id, owner_id=node.volume.owner.id,
            volume_id=node.volume.id, op_type=cls.OP_PUT_CONTENT,
            path=node.full_path, mimetype=node.mimetype or None,
            generation=node.generation, extra_data=json.dumps(extra_data))
        return txlog

    @classmethod
    def extra_data_new_node(cls, node):
        """A dict containing the extra data needed to re-create this node.

        @param node: StorageObject

        This includes the kind, size, storage_key, public_uuid,
        content_hash and creation date of the given node.

        It is supposed to be included in the extra_data of all TransactionLogs
        representing operations on nodes so that the node can be created even
        if messages arrive out of order on the service workers (e.g. a move
        txlog being processed before the txlog representing the file
        creation).

        The volume_path is passed in separately since getting it now would
        require another db transaction. The transaction management for this
        method is unclear.
        """
        public_uuid = node.public_uuid
        if public_uuid is not None:
            public_uuid = unicode(public_uuid)
        when_created = get_epoch_secs(node.when_created)
        last_modified = get_epoch_secs(node.when_last_modified)
        d = dict(public_uuid=public_uuid, when_created=when_created,
                 last_modified=last_modified, kind=node.kind,
                 volume_path=node.volume.path)
        if node.kind == StorageObject.FILE:
            d['content_hash'] = (
                bytes(node.content_blob.hash) if node.content_blob else None)
            d['size'] = getattr(node.content_blob, 'size', None)
            storage_key = getattr(node.content_blob, 'storage_key', None)
            d['storage_key'] = unicode(storage_key) if storage_key else None
        return d

    @classmethod
    def record_share_accepted(cls, share):
        """Create a TransactionLog entry representing a share being accepted.

        @param share: The Share which was accepted.
        @return: The newly created TransactionLog.
        """
        cls._record_share_accepted_or_deleted(share, cls.OP_SHARE_ACCEPTED)

    @classmethod
    def record_share_deleted(cls, share):
        """Create a TransactionLog entry representing a share being deleted.

        @param share: The Share which was deleted.
        @return: The newly created TransactionLog.
        """
        cls._record_share_accepted_or_deleted(share, cls.OP_SHARE_DELETED)

    @classmethod
    def _record_share_accepted_or_deleted(cls, share, op_type):
        node = share.subtree
        when_last_changed = share.when_last_changed
        shared_to = share.shared_to.id if share.shared_to else share.email
        extra_data = dict(
            shared_to=shared_to, share_id=str(share.id),
            share_name=share.name, access_level=share.access,
            when_shared=get_epoch_secs(share.when_shared),
            when_last_changed=get_epoch_secs(when_last_changed))
        txlog = cls.objects.create(
            node_id=node.id, owner_id=node.volume.owner.id,
            volume_id=node.volume.id, op_type=op_type, path=node.full_path,
            mimetype=node.mimetype or None, generation=None,
            extra_data=json.dumps(extra_data))
        return txlog

    @classmethod
    def record_unlink(cls, node):
        """See _record_unlink."""
        cls._record_unlink(node, node.generation)

    @classmethod
    def _record_unlink(cls, node, generation):
        """Create a TransactionLog entry representing an unlink operation.

        If the given node is a file and its mimetype is not in
        INTERESTING_MIMETYPES, we do nothing.

        @param node: The StorageObject which was unlinked.
        @param generation: The generation to use in the newly created
            TransactionLog.
        @return: The newly created TransactionLog or None.
        """
        extra_data = json.dumps({
            'kind': node.kind, 'volume_path': node.volume.path})
        txlog = cls.objects.create(
            node_id=node.id, owner_id=node.volume.owner.id,
            volume_id=node.volume.id, op_type=cls.OP_DELETE,
            path=node.full_path, mimetype=node.mimetype or None,
            generation=generation, extra_data=extra_data)
        return txlog

    @classmethod
    def record_unlink_tree(cls, directory, descendants):
        """See _record_unlink_tree."""
        cls._record_unlink_tree(directory, directory.generation, descendants)

    @classmethod
    def _record_unlink_tree(cls, directory, generation, descendants=None):
        """Create TransactionLog entries representing an unlink_tree operation.

        We create one TransactionLog entry for the given directory and each of
        its descendants that is either a directory or a file with a mimetype
        in INTERESTING_MIMETYPES.

        @param directory: The StorageObject representing the directory that
            was unlinked.
        @param generation: The generation to use in all TransactionLogs
            created by this method.
        @return: The number of created TransactionLog entries.
        """
        assert directory.kind == StorageObject.DIRECTORY, (
            "The given node is not a directory.")
        cls._record_unlink(directory, generation)
        if descendants is None:
            descendants = directory.descendants
        # We use this code to explode UDF operations and in those cases we
        # will delete the root of a UDF, so we add this extra clause to
        # avoid the query above picking up the root folder as a descendant
        # of itself.
        if directory.path == '/':
            assert directory.id not in [d.id for d in descendants]
        # Here we construct the extra_data json manually because it's trivial
        # enough and the alternative would be to use a stored procedure, which
        # requires a DB patch.
        for node in descendants:
            extra_data = json.dumps(
                {'kind': node.kind, 'volume_path': node.volume.path})
            cls.objects.create(
                node_id=node.id, owner_id=node.volume.owner.id,
                volume_id=node.volume.id, op_type=cls.OP_DELETE,
                path=node.full_path, generation=node.generation,
                mimetype=node.mimetype or None, extra_data=extra_data)

        return len(descendants)

    @classmethod
    def record_move(cls, node, old_name, old_parent, descendants):
        """Create TransactionLog entries representing a move operation.

        The 'descendants' list is the list of descendants from node before
        the moving that were affected by path rename.

        """
        if node.parent == old_parent and node.name == old_name:
            raise ValueError(
                "The old name and parent are the same as the current ones.")

        old_parent_path = os.path.join(old_parent.full_path, old_name)
        new_parent_path = node.full_path
        rowcount = 0

        # First, create a TransactionLog for the actual file/directory
        # being moved.
        extra_data = cls.extra_data_new_node(node)
        cls.objects.create(
            node_id=node.id, owner_id=node.volume.owner.id,
            volume_id=node.volume.id, op_type=cls.OP_MOVE,
            path=new_parent_path, old_path=old_parent_path,
            mimetype=node.mimetype or None, generation=node.generation,
            extra_data=json.dumps(extra_data))
        rowcount += 1

        if node.is_dir:
            # Now we generate a TransactionLog for every interesting
            # descendant of the directory that is being moved.
            # We use this code to explode UDF operations and in those cases we
            # will delete the root of a UDF, so we add this extra clause to
            # avoid the query above picking up the root folder as a descendant
            # of itself.
            if node.path == '/':
                assert node.id not in [d.id for d in descendants]

            for n in descendants:
                old_path = n.full_path
                new_path = old_path.replace(old_parent_path, new_parent_path)
                extra_data = cls.extra_data_new_node(n)
                cls.objects.create(
                    node_id=n.id, owner_id=n.volume.owner.id,
                    volume_id=n.volume.id, op_type=cls.OP_MOVE,
                    path=new_path, generation=node.generation,
                    mimetype=n.mimetype or None,
                    extra_data=json.dumps(extra_data), old_path=old_path)

                rowcount += 1

        return rowcount

    def as_dict(self):
        result = dict(
            txn_id=self.id, node_id=self.node_id, volume_id=self.volume_id,
            owner_id=self.owner_id, op_type=self.op_type, path=self.path,
            generation=self.generation, timestamp=self.timestamp,
            mimetype=self.mimetype, old_path=self.old_path,
            extra_data=self.extra_data)
        return result


class DBWorkerLastRow(models.Model):

    txlog = models.ForeignKey(TransactionLog, null=True)
    worker_id = models.TextField()


class DBWorkerUnseen(models.Model):

    worker_id = models.TextField()
    created = models.DateTimeField(default=now)


@receiver(content_changed, sender=StorageObject)
def storage_object_content_changed(sender, instance, content_added, **kwargs):
    if content_added:
        TransactionLog.record_put_content(instance)


@receiver(node_moved, sender=StorageObject)
def storage_object_node_moved(
        sender, instance, old_name, old_parent, descendants, **kwargs):
    TransactionLog.record_move(instance, old_name, old_parent, descendants)


@receiver(post_save, sender=Share)
def share_post_save_handler(sender, instance, **kwargs):
    if instance.status == STATUS_DEAD:
        TransactionLog.record_share_deleted(instance)
    elif instance.accepted:
        TransactionLog.record_share_accepted(instance)


@receiver(post_save, sender=StorageUser)
def user_post_save_handler(sender, instance, created, **kwargs):
    if created:
        TransactionLog.record_user_created(instance)


@receiver(post_save, sender=UserVolume)
def user_volume_post_save_handler(sender, instance, created, **kwargs):
    if created:
        TransactionLog.record_udf_created(instance)


@receiver(post_unlink_tree, sender=StorageObject)
def storage_object_post_unlink_tree(sender, instance, descendants, **kwargs):
    TransactionLog.record_unlink_tree(instance, descendants)


@receiver(post_kill, sender=UserVolume)
def user_volume_post_kill_handler(sender, instance, **kwargs):
    TransactionLog.record_udf_deleted(instance)


@receiver(post_kill, sender=StorageObject)
def storage_object_post_kill(sender, instance, **kwargs):
    TransactionLog.record_unlink(instance)


@receiver(public_access_changed, sender=StorageObject)
def storage_object_public_access_changed(sender, instance, public, **kwargs):
    TransactionLog.record_public_access_change(instance)
