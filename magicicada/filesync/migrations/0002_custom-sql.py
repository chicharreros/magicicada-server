# Generated by Django 1.9 on 2016-01-02 16:51
# Second version: Generated by Django 4.1 on 2022-08-31 19:28

from django.db import migrations, models


# See below for the reason behind the following commented out block.
# NAME_UNIQUE_WHEN_LIVE = """
#     CREATE UNIQUE INDEX filesync_storageobject_parent_name_uniq
#         ON filesync_storageobject(parent_id, name) WHERE status = 'Live';
#     CREATE UNIQUE INDEX filesync_uservolume_owner_path_uniq
#         ON filesync_uservolume(owner_id, path) WHERE status = 'Live';
#     CREATE UNIQUE INDEX filesync_share_shared_to_name_uniq
#         ON filesync_share(shared_to_id, name) WHERE status = 'Live';
#     CREATE UNIQUE INDEX filesync_share_shared_to_shared_by_subtree_uniq
#         ON filesync_share(shared_to_id, shared_by_id, subtree_id)
#         WHERE status='Live' AND shared_to_id IS NOT NULL;
#     CREATE INDEX move_from_share_delta_idx
#         ON filesync_movefromshare (share_id, volume_id, generation, path);
# """

MOVE_FROM_SHARE = """
    CREATE VIEW share_delta_view AS
        SELECT NULL::unknown AS share_id, o.id, o.name, o.kind, o.when_created,
        o.when_last_modified, o.status, o.path, o.mimetype,
        o.public_uuid, o.generation, o.generation_created,
        o.content_blob_id, o.volume_id, o.parent_id
        FROM filesync_storageobject o
    UNION
        SELECT mfs.share_id, mfs.node_id, mfs.name, mfs.kind, mfs.when_created,
        mfs.when_last_modified, mfs.status, mfs.path, mfs.mimetype,
        mfs.public_uuid, mfs.generation, mfs.generation_created,
        mfs.content_blob_id, mfs.volume_id, mfs.old_parent_id
        FROM filesync_movefromshare mfs;
"""


class Migration(migrations.Migration):

    dependencies = [
        ('filesync', '0001_initial'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='movefromshare',
            index=models.Index(
                fields=['share_id', 'volume_id', 'generation', 'path'],
                name='move_from_share_delta_idx',
            ),
        ),
        migrations.AddConstraint(
            model_name='share',
            constraint=models.UniqueConstraint(
                condition=models.Q(('status', 'Live')),
                fields=('shared_to', 'name'),
                name='filesync_share_shared_to_name_uniq',
            ),
        ),
        migrations.AddConstraint(
            model_name='share',
            constraint=models.UniqueConstraint(
                condition=models.Q(
                    ('shared_to__isnull', False), ('status', 'Live')
                ),
                fields=('shared_to', 'shared_by', 'subtree'),
                name='filesync_share_shared_to_shared_by_subtree_uniq',
            ),
        ),
        migrations.AddConstraint(
            model_name='storageobject',
            constraint=models.UniqueConstraint(
                condition=models.Q(('status', 'Live')),
                fields=('parent', 'name'),
                name='filesync_storageobject_parent_name_uniq',
            ),
        ),
        migrations.AddConstraint(
            model_name='uservolume',
            constraint=models.UniqueConstraint(
                condition=models.Q(('status', 'Live')),
                fields=('owner', 'path'),
                name='filesync_uservolume_owner_path_uniq',
            ),
        ),
        # Previous version of this migration would create the needed INDEX
        # and UNIQUE INDEX using raw SQL. Now that we have updated to latest
        # Django (4.1 to this date), we can express the constraints directly
        # in the Meta class of each model using the `constraints` attribute.
        # migrations.RunSQL(NAME_UNIQUE_WHEN_LIVE),
        migrations.RunSQL(MOVE_FROM_SHARE),
    ]
