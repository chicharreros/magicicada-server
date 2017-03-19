# ubuntuone.syncdaemon.filesystem_manager - FSM
#
# Author: Facundo Batista <facundo@canonical.com>
#
# Copyright 2009-2012 Canonical Ltd.
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
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
"""Module that implements the File System Manager."""

from __future__ import with_statement

import os
import re
import time
import functools
import itertools
import logging
import contextlib
import errno
import stat
import uuid

from ubuntuone.clientdefs import NAME
from ubuntuone.syncdaemon import file_shelf, config
from ubuntuone.syncdaemon.volume_manager import VolumeDoesNotExist
from ubuntuone.syncdaemon.interfaces import IMarker
from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.syncdaemon.tritcask import TritcaskShelf
from ubuntuone.platform import (
    listdir,
    make_dir,
    normpath,
    move_to_trash,
    path_exists,
    remove_dir,
    remove_file,
    remove_tree,
    rename,
    recursive_move,
    set_dir_readonly,
    set_dir_readwrite,
    set_file_readonly,
    set_file_readwrite,
    stat_path,
    walk,
)
from ubuntuone.platform import open_file as os_open

METADATA_VERSION = "6"

# tritcask row types
FSM_ROW_TYPE = 0
TRASH_ROW_TYPE = 1
MOVE_LIMBO_ROW_TYPE = 2

#
# File System Manager  (FSM)
# --------------------------
#
# The FileSystemManager is the one that interacts with the filesystem, and
# keeps a storage with metadata.  This storage is verterok's FileShelf.
#
# The metadata, in disk, is a dictionary, where the keys are 'mdid's (metadata
# ids), and the values are different parameters, some of them can be modified
# from outside, and some can not.
#
# There're two very important values: path and node_id. The path is the
# pointer to where the file or directory is located in the filesystem, and
# the node_id is the unique identifier from the server. When a new file is
# created (with the .create() method), a mdid is assigned to the path and the
# share, but no node_id yet. When the server assigns the node_id, it needs to
# be set here with the .set_node_id() method.
#
# All the data can be retrieved generally using this three values (mdid, path,
# and node_id/share) using specific get_by_*() methods. For this to be fast,
# two indexes are created at init time, two dictionaries that hold the
# relationships path->mdid, and (share,node_id)->mdid.  In any case, KeyError
# is raised if an incorrect value is passed to the getters. Note that a mdid
# identifies uniquely the MD Object, like also the path; but for the node_id it
# also needs to have the share, as the same "server file" can live in different
# directories in the "client disk".
#
# Once assigned, the path, share and node_id values can not be changed. For any
# other value (except another special one, 'info', see below), three methods
# are provided to set them: set_by_*() (symmetric to the getters). These
# methods receive a first argument to indicate what is modified, and then
# several keyword arguments with all the values to be set.
#
# The 'info' is a special value set by the FileSystemManager itself, that
# records operations and changes made to each node, and as I said before,
# it can only be accesses from outside, not modified.
#
# Another method is provided to retrieve the created objects:
# get_mdobjs_by_share_id, that returns all the objects in that share and it
# path starts with the base_path argument.
#
# When asked for data, the FSM returns an object that is a thin wrapper to the
# info, only to be easily accessible, like using "mdobj.path", or
# "mdobj.info.is_partial". This object is not alive: it does not get updated
# if something changes in the metadata, and any change in the object is not
# written back to the metadata (this is by design, because of how the
# information flows in the system).
#
# As I said before, the FileSystemManager not only keeps the metadata, but also
# interacts with the filesystem itself. As such, it provides several operations
# on files and directories.
#
# In the process of downloading a file from the server, FSM handles the
# .partial files. With the .create_partial() method the system creates this
# special file where the new content will be downloaded. When it finishes ok,
# the .commit_partial() is called, and that content is moved into the old file.
# If the download fails for any reason, .remove_partial() is called and all is
# back to clean.
#
# Other services are provided:
#
#    .move_to_conflict(): moves a file or dir in problem to the same name but
# adding a .conflict to the name (if .conflict already exists, it will try with
# .conflict.1, .conflict.2, and so on).
#
#    .upload_finished(): sets a new hash in the metadata, marking that the
# new content was uploaded to the server.
#
#    .move_file(): moves a file or directory from one pathname to other.
#
#    .delete_file(): removes a file or directory from disk.
#
# Finally, the FSM has three methods that provides high level information,
# in some cases synthesising their values using some internal values:
#
#    .has_metadata(): returns True if the system has metadata for that path,
# node_id or mdid (note that we may don't have metadata even to an old mdid,
# because it was deleted in the middle)
#
#    .changed(): returns 'local', 'server', or 'none', depending of what
# changed for that node
#
#    .is_dir: returns if the node is a directory.
#
#


# fsm logger
fsm_logger = logging.getLogger('ubuntuone.SyncDaemon.fsm')
logger = functools.partial(fsm_logger.log, logging.INFO)
log_warning = functools.partial(fsm_logger.log, logging.WARNING)
log_debug = functools.partial(fsm_logger.log, logging.DEBUG)

is_forbidden = set("info path node_id share_id is_dir".split()).intersection


class InconsistencyError(Exception):
    """Inconsistency between internal records and filesystem itself."""


class Despair(Exception):
    """This should never happen, we're in an impossible condition!"""


class DirectoryNotRemovable(Exception):
    """The directory can not be emptied to delete."""


class _MDObject(object):
    """Wrapper around MD dict."""
    def __init__(self, **mdobj):
        self.__dict__.update(mdobj)

        # info is a special one
        if "info" in mdobj:
            self.info = _MDObject(**mdobj["info"])

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class ShareNodeDict(dict):
    """Cache for node_id and share."""

    def __getitem__(self, key):
        share_id, node_id = key
        if node_id is None:
            raise ValueError("The node_id can not be None")
        return dict.__getitem__(self, key)

    def __setitem__(self, key, value):
        share_id, node_id = key
        if node_id is None:
            raise ValueError("The node_id can not be None")
        return dict.__setitem__(self, key, value)

    def __contains__(self, key):
        share_id, node_id = key
        if node_id is None:
            raise ValueError("The node_id can not be None")
        return dict.__contains__(self, key)


class TrashFileShelf(file_shelf.CachedFileShelf):
    """Custom file shelf that supports share and node as keys."""

    _marker_flag = 'marker'
    _marker_len = len(_marker_flag)

    def key_file(self, key):
        """Support share and node as keys."""
        share_id, node_id = key

        # convert the markers to a string that flags them
        if IMarker.providedBy(share_id):
            share_id = str(share_id) + self._marker_flag
        if IMarker.providedBy(node_id):
            node_id = str(node_id) + self._marker_flag

        # build a string with the node_id first to have a more sparse
        # layout in disk
        key = "%s|%s" % (node_id, share_id)
        return super(TrashFileShelf, self).key_file(key)

    def keys(self):
        """Restore the share/node pair"""
        for key in super(TrashFileShelf, self).keys():
            node_id, share_id = key.split("|")
            if node_id == 'None':
                node_id = None
            elif node_id.endswith(self._marker_flag):
                node_id = MDMarker(node_id[:-self._marker_len])
            if share_id.endswith(self._marker_flag):
                share_id = MDMarker(share_id[:-self._marker_len])
            yield (share_id, node_id)


class TrashTritcaskShelf(TritcaskShelf):
    """Custom TritcaskShelf that supports share and node as keys."""

    _marker_flag = 'marker'
    _marker_len = len(_marker_flag)

    def _get_key(self, key):
        """Support share and node as keys."""
        share_id, node_id = key

        # convert the markers to a string that flags them
        if IMarker.providedBy(share_id):
            share_id = str(share_id) + self._marker_flag
        if IMarker.providedBy(node_id):
            node_id = str(node_id) + self._marker_flag

        # build a string from the (share_id, node_id)
        return "%s|%s" % (share_id, node_id)

    def __setitem__(self, key, value):
        """dict protocol."""
        raw_key = self._get_key(key)
        super(TrashTritcaskShelf, self).__setitem__(raw_key, value)

    def __getitem__(self, key):
        """dict protocol."""
        raw_key = self._get_key(key)
        return super(TrashTritcaskShelf, self).__getitem__(raw_key)

    def __delitem__(self, key):
        """dict protocol."""
        raw_key = self._get_key(key)
        return super(TrashTritcaskShelf, self).__delitem__(raw_key)

    def __contains__(self, key):
        """dict protocol."""
        raw_key = self._get_key(key)
        return super(TrashTritcaskShelf, self).__contains__(raw_key)

    def keys(self):
        """Restore the share/node pair"""
        for key in super(TrashTritcaskShelf, self).keys():
            share_id, node_id = key.split("|")
            if node_id == 'None':
                node_id = None
            elif node_id.endswith(self._marker_flag):
                node_id = MDMarker(node_id[:-self._marker_len])
            if share_id.endswith(self._marker_flag):
                share_id = MDMarker(share_id[:-self._marker_len])
            yield (share_id, node_id)


class FileSystemManager(object):
    """Keeps the files/dirs metadata and interacts with the filesystem.

    It has a FileShelf where all the metadata is stored, using 'mdid's as
    keys.  'mdid' is 'metadata id'... it's actually an uuid, but we call it
    mdid to don't get confused about names, as we also have the node_id is
    the one assigned by the server.

    At init time two indexes are built in memory:

      - idx_path: relationship path -> mdid
      - idx_node_id: relationship (share_id, node_id) -> mdid
    """

    CONFLICT_SUFFIX = '.u1conflict'
    CHANGED_LOCAL = 'LOCAL'
    CHANGED_SERVER = 'SERVER'
    CHANGED_NONE = 'NONE'

    def __init__(self, data_dir, partials_dir, vm, db):
        if not isinstance(data_dir, basestring):
            raise TypeError("data_dir should be a string instead of %s" %
                            type(data_dir))
        fsmdir = os.path.join(data_dir, 'fsm')
        self._trash_dir = os.path.join(data_dir, 'trash')
        self._movelimbo_dir = os.path.join(data_dir, 'move_limbo')
        self.partials_dir = partials_dir
        if not path_exists(self.partials_dir):
            make_dir(self.partials_dir, recursive=True)
        else:
            # ensure that we can write in the partials_dir
            set_dir_readwrite(self.partials_dir)
        self.fs = TritcaskShelf(FSM_ROW_TYPE, db)
        self.old_fs = file_shelf.CachedFileShelf(
            fsmdir, cache_size=1500, cache_compact_threshold=4)
        self.trash = TrashTritcaskShelf(TRASH_ROW_TYPE, db)
        self.move_limbo = TrashTritcaskShelf(MOVE_LIMBO_ROW_TYPE, db)
        self.shares = {}
        self.vm = vm
        self.eq = None  # this will be registered later

        # create the indexes
        self._idx_path = {}
        self._idx_node_id = ShareNodeDict()

        # get the metadata version
        self._version_file = os.path.join(data_dir, "metadata_version")
        if path_exists(self._version_file):
            with os_open(self._version_file) as fh:
                md_version = fh.read().strip()
        else:
            md_version = None

        # load the info from the metadata
        if md_version == METADATA_VERSION:
            self._load_metadata_updated()
        else:
            load_method = getattr(self, "_load_metadata_%s" % md_version)
            load_method(md_version)

        # load some config
        self.user_config = config.get_user_config()

        logger("initialized: idx_path: %s, idx_node_id: %s, shares: %s",
               len(self._idx_path), len(self._idx_node_id), len(self.shares))

    def register_eq(self, eq):
        """Registers an EventQueue here."""
        self.eq = eq

    def _safe_old_fs_iteritems(self):
        """Returns a 'safe' iterator over the items of the FileShelf.

        It's 'safe' because broken metadata objects are deleted and not
        returned.
        """
        def safeget_mdobj(mdid):
            """check if the mdobj is valid and return mdid, mdobj.
            If a KeyError is raised, returns False.
            """
            try:
                mdobj = self.old_fs[mdid]
            except KeyError:
                # oops, we have a key but don't have the value, possibly broken
                # metadata, remove it and keep going
                del self.old_fs[mdid]
                # return False, in order to be filtered later
                return False
            else:
                # check if the share exists
                try:
                    self._get_share(mdobj["share_id"])
                except VolumeDoesNotExist:
                    # oops, the share is gone!, invalidate this mdid
                    log_warning('Share %r disappeared! deleting mdid: %s',
                                mdobj['share_id'], mdid)
                    del self.old_fs[mdid]
                    return False
                else:
                    return mdid, mdobj
        safe_iteritems = itertools.imap(safeget_mdobj, self.old_fs.keys())
        # filter all False values
        return itertools.ifilter(None, safe_iteritems)

    def _fix_path_for_new_layout(self, mdobj):
        """fix the mdobj path for the new layout, only for shares root"""
        base_path, name = os.path.split(mdobj['path'])
        if base_path.startswith('/') and \
           base_path.endswith('%s/Shared With Me' % NAME):
            realpath = os.path.realpath(mdobj['path'])
            mdobj['path'] = realpath
        if (base_path.startswith('/') and base_path.endswith(NAME) and
                name == 'My Files'):
            mdobj['path'] = base_path

    def _migrate_trash_to_tritcask(self):
        """Migrate trash from FileShelf to Tritcask."""
        old_trash = TrashFileShelf(self._trash_dir, cache_size=100,
                                   cache_compact_threshold=4)
        for key, value in old_trash.iteritems():
            self.trash[key] = value
        # delete the old trash
        remove_tree(self._trash_dir)

    def _migrate_movelimbo_to_tritcask(self):
        """Migrate move limbo from FileShelf to Tritcask."""
        old_move_limbo = TrashFileShelf(self._movelimbo_dir, cache_size=100,
                                        cache_compact_threshold=4)
        for key, value in old_move_limbo.iteritems():
            self.move_limbo[key] = value
        # delete the old move limbo
        remove_tree(self._movelimbo_dir)

    def _load_metadata_None(self, old_version):
        """Loads metadata from when it wasn't even versioned."""
        logger("loading metadata from old version %r", old_version)

        for mdid, mdobj in self._safe_old_fs_iteritems():
            # assure path are bytes (new to version 2)
            try:
                mdobj["path"] = mdobj["path"].encode("utf8")
            except UnicodeDecodeError:
                # this is an invalid path, we shouldn't have it
                del self.fs[mdid]
                continue

            # fix the path
            self._fix_path_for_new_layout(mdobj)
            abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            # of course, load the metadata
            self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

            # assure we have stat info (new to version 1)
            mdobj["stat"] = get_stat(abspath)

            # convert the "yet without content" hashes to "" (new to v3)
            if mdobj["local_hash"] is None:
                mdobj["local_hash"] = ""
            if mdobj["server_hash"] is None:
                mdobj["server_hash"] = ""

            # add the generation number (new to v5)
            mdobj["generation"] = None

            # write back the object
            self.fs[mdid] = mdobj

        self._migrate_trash_to_tritcask()
        self._migrate_movelimbo_to_tritcask()
        # set new version
        with os_open(self._version_file, "w") as fh:
            fh.write(METADATA_VERSION)
            os.fsync(fh.fileno())
        # remove the old metadata
        remove_tree(self.old_fs._path)

    def _load_metadata_1(self, old_version):
        """Loads metadata from version 1."""
        logger("loading metadata from old version %r", old_version)

        for mdid, mdobj in self._safe_old_fs_iteritems():
            # assure path are bytes (new to version 2)
            try:
                mdobj["path"] = mdobj["path"].encode("utf8")
            except UnicodeDecodeError:
                # this is an invalid path, we shouldn't have it
                del self.old_fs[mdid]
                continue

            # convert the "yet without content" hashes to "" (new to v3)
            if mdobj["local_hash"] is None:
                mdobj["local_hash"] = ""
            if mdobj["server_hash"] is None:
                mdobj["server_hash"] = ""

            # fix the path
            self._fix_path_for_new_layout(mdobj)

            # add the generation number (new to v5)
            mdobj["generation"] = None

            # write back the object
            self.fs[mdid] = mdobj

            # and of course, load the metadata
            abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

        self._migrate_trash_to_tritcask()
        self._migrate_movelimbo_to_tritcask()
        # set new version
        with os_open(self._version_file, "w") as fh:
            fh.write(METADATA_VERSION)
            os.fsync(fh.fileno())
        # remove the old metadata
        remove_tree(self.old_fs._path)

    def _load_metadata_2(self, old_version):
        """Loads metadata from version 2."""
        logger("loading metadata from old version %r", old_version)

        for mdid, mdobj in self._safe_old_fs_iteritems():
            # convert the "yet without content" hashes to "" (new to v3)
            if mdobj["local_hash"] is None:
                mdobj["local_hash"] = ""
            if mdobj["server_hash"] is None:
                mdobj["server_hash"] = ""

            # fix the path
            self._fix_path_for_new_layout(mdobj)

            # add the generation number (new to v5)
            mdobj["generation"] = None

            # write back the object
            self.fs[mdid] = mdobj

            # and of course, load the metadata
            abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

        self._migrate_trash_to_tritcask()
        self._migrate_movelimbo_to_tritcask()
        # set new version
        with os_open(self._version_file, "w") as fh:
            fh.write(METADATA_VERSION)
            os.fsync(fh.fileno())
        # remove the old metadata
        remove_tree(self.old_fs._path)

    def _load_metadata_3(self, old_version):
        """Loads metadata from version 3."""
        logger("loading metadata from old version %r", old_version)

        for mdid, mdobj in self._safe_old_fs_iteritems():
            # fix the path
            self._fix_path_for_new_layout(mdobj)

            # add the generation number (new to v5)
            mdobj["generation"] = None

            # write back the object
            self.fs[mdid] = mdobj

            # and of course, load the metadata
            abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

        self._migrate_trash_to_tritcask()
        self._migrate_movelimbo_to_tritcask()
        # set new version
        with os_open(self._version_file, "w") as fh:
            fh.write(METADATA_VERSION)
            os.fsync(fh.fileno())
        # remove the old metadata
        remove_tree(self.old_fs._path)

    def _load_metadata_4(self, old_version):
        """Loads metadata from version 4."""
        logger("loading metadata from old version %r", old_version)

        for mdid, mdobj in self._safe_old_fs_iteritems():
            # add the generation number (new to v5)
            mdobj["generation"] = None

            # write back the object
            self.fs[mdid] = mdobj

            # and of course, load the metadata
            abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

        self._migrate_trash_to_tritcask()
        self._migrate_movelimbo_to_tritcask()
        # set new version
        with os_open(self._version_file, "w") as fh:
            fh.write(METADATA_VERSION)
            os.fsync(fh.fileno())
        # remove the old metadata
        remove_tree(self.old_fs._path)

    def _load_metadata_5(self, old_version):
        """Loads metadata of last version."""
        logger("loading metadata from old version %r", old_version)

        for mdid, mdobj in self._safe_old_fs_iteritems():
            abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            # write back the object
            self.fs[mdid] = mdobj
            self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

        self._migrate_trash_to_tritcask()
        self._migrate_movelimbo_to_tritcask()
        # set new version
        with os_open(self._version_file, "w") as fh:
            fh.write(METADATA_VERSION)
            os.fsync(fh.fileno())
        # remove the old metadata
        remove_tree(self.old_fs._path)

    def _load_metadata_updated(self):
        """Loads metadata of last version."""
        logger("loading updated metadata")
        for mdid, mdobj in self.fs.items():
            try:
                abspath = self.get_abspath(mdobj["share_id"], mdobj["path"])
            except VolumeDoesNotExist:
                # the share is gone!
                del self.fs[mdid]
                continue
            if abspath in self._idx_path:
                # oh, we already have this path in the idx.
                log_warning("Path already in the index: %s", abspath)
                current_mdobj = self.fs[self._idx_path[abspath]]
                if current_mdobj['info']['created'] < mdobj['info']['created']:
                    log_debug("Replacing and deleting node: %s with newer "
                              "node: %s", current_mdobj['mdid'], mdid)
                    self._idx_path[abspath] = mdid
                    # and delete the old node
                    del self.fs[current_mdobj['mdid']]
                else:
                    # do nothing if the current mdobj is newer
                    log_debug("The node: %s is newer than: %s, "
                              "leaving it alone and deleting the old one.",
                              current_mdobj['mdid'], mdid)
                    # but delete the old node
                    del self.fs[mdid]
            else:
                self._idx_path[abspath] = mdid
            if mdobj["node_id"] is not None:
                self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])] = mdid

    def create(self, path, share_id, node_id=None, is_dir=False):
        """Creates a new md object."""
        if not path.strip():
            raise ValueError("Empty paths are not allowed (got %r)" % path)

        path = normpath(path)
        if path in self._idx_path:
            raise ValueError("The path %r is already created!" % path)

        # create it
        mdid = str(uuid.uuid4())
        # make path relative to the share_id
        relpath = self._share_relative_path(share_id, path)
        newobj = dict(path=relpath, node_id=None, share_id=share_id,
                      is_dir=is_dir, local_hash="", server_hash="",
                      mdid=mdid, generation=None, crc32=None, size=None)
        newobj["info"] = dict(created=time.time(), is_partial=False)
        # only one stat, (instead of path_exists & os.stat)
        newobj["stat"] = get_stat(path)
        if node_id is not None:
            self._set_node_id(newobj, node_id, path)

        log_debug("create: path=%r mdid=%r share_id=%r node_id=%r is_dir=%r",
                  path, mdid, share_id, None, is_dir)
        self.fs[mdid] = newobj

        # adjust the index
        self._idx_path[path] = mdid

        return mdid

    def set_node_id(self, path, node_id):
        """Sets the node_id to a md object."""
        path = normpath(path)
        mdid = self._idx_path[path]
        mdobj = self.fs[mdid]
        self._set_node_id(mdobj, node_id, path)
        self.fs[mdid] = mdobj

    def _set_node_id(self, mdobj, node_id, path):
        """Set the node_id to the mdobj, but don't 'save' the mdobj"""
        if mdobj["node_id"] is not None:
            # the object is already there! it's ok if it has the same id
            if mdobj["node_id"] == node_id:
                log_warning("set_node_id (repeated!): path=%r mdid=%r "
                            "node_id=%r", path, mdobj['mdid'], node_id)
                return
            msg = "The path %r already has node_id (%r)" % (path, node_id)
            raise ValueError(msg)
        # adjust the index
        share_id = mdobj["share_id"]
        self._idx_node_id[(share_id, node_id)] = mdobj['mdid']

        # set the node_id
        mdobj["node_id"] = node_id
        mdobj["info"]["node_id_assigned"] = time.time()

        log_debug("set_node_id: path=%r mdid=%r share_id=%r node_id=%r",
                  path, mdobj['mdid'], share_id, node_id)

    def get_mdobjs_by_share_id(self, share_id, base_path=None):
        """Get all the mdobjs from a share.

        If base_path is present, only return those who start with (or
        are equal to) that path.
        """
        if base_path is None:
            base_path = self._get_share(share_id).path
        compare_path = base_path + os.path.sep

        all_mdobjs = []
        # filter by path first, so we don't touch disk
        for path, mdid in self._idx_path.iteritems():
            if path == base_path or path.startswith(compare_path):
                mdobj = self.fs[mdid]
                if mdobj["share_id"] == share_id:
                    all_mdobjs.append(_MDObject(**mdobj))

        return all_mdobjs

    def get_mdobjs_in_dir(self, base_path):
        """Return all the mdobjs which dir is base_path."""
        all_mdobjs = []
        sep = os.path.sep
        base_path += sep
        len_base = len(base_path)
        for path, mdid in self._idx_path.iteritems():
            if path[:len_base] == base_path and sep not in path[len_base:]:
                mdobj = self.fs[mdid]
                all_mdobjs.append(_MDObject(**mdobj))
        return all_mdobjs

    def get_data_for_server_rescan(self):
        """Generates all the (share, node, hash) tuples needed for rescan"""
        all_data = []
        for _, v in self.fs.items():
            if v['node_id']:
                all_data.append(
                    (v['share_id'], v['node_id'], v['server_hash']))
        return all_data

    def get_for_server_rescan_by_path(self, base_path):
        """
        Generates all the (share, node, hash) tuples, for the nodes
        starting with 'path', needed for rescan.

        """
        all_data = []
        for path, _ in self.get_paths_starting_with(base_path):
            mdid = self._idx_path[path]
            mdobj = self.fs[mdid]
            if mdobj['node_id']:
                all_data.append((mdobj['share_id'],
                                 mdobj['node_id'],
                                 mdobj['server_hash']))
        return all_data

    def get_by_mdid(self, mdid):
        """Returns the md object according to the mdid."""
        mdobj = self.fs[mdid]
        return _MDObject(**mdobj)

    def get_by_path(self, path):
        """Returns the md object according to the path."""
        path = normpath(path)
        mdid = self._idx_path[path]
        mdobj = self.fs[mdid]
        return _MDObject(**mdobj)

    def get_by_node_id(self, share_id, node_id):
        """Returns the md object according to the node_id and share_id."""
        mdid = self._idx_node_id[(share_id, node_id)]
        mdobj = self.fs[mdid]
        return _MDObject(**mdobj)

    def set_by_mdid(self, mdid, **kwargs):
        """Set some values to the md object with that mdid."""
        forbidden = is_forbidden(set(kwargs))
        if forbidden:
            raise ValueError("The following attributes can not be set "
                             "externally: %s" % forbidden)

        log_debug("set mdid=%r: %s", mdid, kwargs)
        mdobj = self.fs[mdid]
        for k, v in kwargs.items():
            mdobj[k] = v
        self.fs[mdid] = mdobj

    def set_by_path(self, path, **kwargs):
        """Set some values to the md object with that path."""
        if "mdid" in kwargs:
            raise ValueError("The mdid is forbidden to set externally")
        path = normpath(path)
        mdid = self._idx_path[path]
        self.set_by_mdid(mdid, **kwargs)

    def set_by_node_id(self, node_id, share_id, **kwargs):
        """Set some values to the md object with that node_id/share_id."""
        if "mdid" in kwargs:
            raise ValueError("The mdid is forbidden to set externally")
        mdid = self._idx_node_id[(share_id, node_id)]
        self.set_by_mdid(mdid, **kwargs)

    def move_file(self, new_share_id, path_from, path_to):
        """Move a file/dir from one point to the other."""
        path_from = normpath(path_from)
        path_to = normpath(path_to)
        mdid = self._idx_path[path_from]
        mdobj = self.fs[mdid]

        # move the file in the fs
        from_context = self._enable_share_write(mdobj['share_id'], path_from)
        to_context = self._enable_share_write(new_share_id, path_to)

        if mdobj["is_dir"]:
            expected_event = "FS_DIR_MOVE"
        else:
            expected_event = "FS_FILE_MOVE"
        try:
            with contextlib.nested(from_context, to_context):
                self.eq.add_to_mute_filter(expected_event, path_from=path_from,
                                           path_to=path_to)
                recursive_move(path_from, path_to)
        except IOError, e:
            # file was not yet created
            self.eq.rm_from_mute_filter(expected_event,
                                        path_from=path_from, path_to=path_to)
            m = "IOError %s when trying to move file/dir %r"
            log_warning(m, e, path_from)
        self.moved(new_share_id, path_from, path_to)

    def moved(self, new_share_id, path_from, path_to):
        """Change the metadata of a moved file."""
        path_from = normpath(path_from)
        path_to = normpath(path_to)
        mdid = self._idx_path.pop(path_from)
        log_debug("move_file: mdid=%r path_from=%r path_to=%r",
                  mdid, path_from, path_to)

        # if the move overwrites other file, send it to trash
        if path_to in self._idx_path:
            to_mdid = self._idx_path[path_to]
            parent_path = os.path.dirname(path_to)
            parent_mdid = self._idx_path[parent_path]
            parent_mdobj = self.fs[parent_mdid]
            self.delete_to_trash(to_mdid, parent_mdobj['node_id'])

        # adjust the metadata of "from" file
        mdobj = self.fs[mdid]
        self._idx_path[path_to] = mdid

        # change the path, make it relative to the share_id
        relpath = self._share_relative_path(new_share_id, path_to)
        mdobj["path"] = relpath
        mdobj['share_id'] = new_share_id
        mdobj["info"]["last_moved_from"] = path_from
        mdobj["info"]["last_moved_time"] = time.time()
        # we try to stat, if we fail, so what?
        try:
            mdobj["stat"] = stat_path(path_to)  # needed if not the same FS
        except OSError:
            log_warning("Got an OSError while getting the stat of %r", path_to)
        self.fs[mdid] = mdobj

        if mdobj["is_dir"]:
            # change the path for all the children of that node
            path_from = path_from + os.path.sep
            len_from = len(path_from)
            pathstofix = [x for x in self._idx_path if x.startswith(path_from)]
            for path in pathstofix:
                newpath = os.path.join(path_to, path[len_from:])

                # change in the index
                mdid = self._idx_path.pop(path)
                self._idx_path[newpath] = mdid

                # and in the object itself
                mdobj = self.fs[mdid]
                relpath = self._share_relative_path(new_share_id, newpath)
                mdobj["path"] = relpath
                self.fs[mdid] = mdobj

    def delete_metadata(self, path):
        """Delete the metadata."""
        path = normpath(path)
        mdid = self._idx_path[path]
        mdobj = self.fs[mdid]
        log_debug("delete metadata: path=%r mdid=%r", path, mdid)

        # adjust all
        del self._idx_path[path]
        if mdobj["node_id"] is not None:
            del self._idx_node_id[(mdobj["share_id"], mdobj["node_id"])]
        del self.fs[mdid]

    def _delete_dir_tree(self, path):
        """Tell if it's ok to delete a dir tree.

        Raise an exception if the directory can not be removed.
        """
        # check metadata to see if any node in LOCAL
        subtree = self.get_paths_starting_with(path, include_base=False)
        for p, is_dir in subtree:
            if self.changed(path=p) == self.CHANGED_LOCAL:
                logger("Conflicting dir on remove because %r is local", p)
                raise DirectoryNotRemovable()

        # check disk searching for previous conflicts
        for (dirpath, dirnames, filenames) in walk(path):
            for fname in filenames + dirnames:
                if fname.endswith(self.CONFLICT_SUFFIX):
                    logger("Conflicting dir on remove because of previous "
                           "conflict on: %r", os.path.join(dirpath, fname))
                    raise DirectoryNotRemovable()

        return subtree

    def delete_file(self, path):
        """Delete a file/dir and the metadata."""
        # adjust the metadata
        path = normpath(path)
        mdid = self._idx_path[path]
        mdobj = self.fs[mdid]
        log_debug("delete: path=%r mdid=%r", path, mdid)

        is_dir = self.is_dir(path=path)
        if is_dir:
            filter_event = "FS_DIR_DELETE"
        else:
            filter_event = "FS_FILE_DELETE"
        self.eq.add_to_mute_filter(filter_event, path=path)

        try:
            if is_dir:
                if listdir(path):
                    # not empty, need to check if we can delete it
                    subtree = self._delete_dir_tree(path=path)
                    for p, is_dir in subtree:
                        filter_name = (
                            "FS_DIR_DELETE" if is_dir else "FS_FILE_DELETE")
                        self.eq.add_to_mute_filter(filter_name, path=p)
                        self.delete_metadata(p)

                    with self._enable_share_write(mdobj['share_id'], path,
                                                  recursive=True):
                        if self.user_config.get_use_trash():
                            move_to_trash(path)
                        else:
                            remove_tree(path)
                else:
                    # empty, just delete it
                    with self._enable_share_write(mdobj['share_id'], path):
                        if self.user_config.get_use_trash():
                            move_to_trash(path)
                        else:
                            remove_dir(path)
            else:
                # it's a file, just delete it
                with self._enable_share_write(mdobj['share_id'], path):
                    if self.user_config.get_use_trash():
                        move_to_trash(path)
                    else:
                        remove_file(path)

        except OSError, e:
            self.eq.rm_from_mute_filter(filter_event, path=path)
            log_warning("OSError %s when trying to remove file/dir %r",
                        e, path)

        self.delete_metadata(path)

    def move_to_conflict(self, mdid):
        """Move a file/dir to its .conflict."""
        mdobj = self.fs[mdid]
        path = self.get_abspath(mdobj['share_id'], mdobj['path'])
        log_debug("move_to_conflict: path=%r mdid=%r", path, mdid)
        base_to_path = to_path = path + self.CONFLICT_SUFFIX
        ind = 0
        while path_exists(to_path):
            ind += 1
            to_path = base_to_path + "." + str(ind)
        is_dir = mdobj["is_dir"]
        if is_dir:
            expected_event = "FS_DIR_DELETE"
        else:
            expected_event = "FS_FILE_DELETE"
        with self._enable_share_write(mdobj['share_id'], path):
            try:
                self.eq.add_to_mute_filter(expected_event, path=path)
                rename(path, to_path)
                event = "FSM_DIR_CONFLICT" if is_dir else "FSM_FILE_CONFLICT"
                self.eq.push(event, old_name=path, new_name=to_path)
            except OSError, e:
                self.eq.rm_from_mute_filter(expected_event, path=path)
                if e.errno == errno.ENOENT:
                    m = "Already removed when trying to move to conflict: %r"
                    log_warning(m, path)
                else:
                    raise

        for p, is_dir in self.get_paths_starting_with(
                path, include_base=False):
            if is_dir:
                # remove inotify watch
                try:
                    self.vm.m.event_q.rm_watch(p)
                except TypeError, e:
                    # pyinotify has an ugly error management, if we can call
                    # it that, :(. We handle this here because it's possible
                    # and correct that the path is not there anymore
                    m = "Error %s when trying to remove the watch on %r"
                    log_warning(m, e, path)

            self.delete_metadata(p)
        mdobj["info"]["last_conflicted"] = time.time()
        self.fs[mdid] = mdobj

    def _check_partial(self, mdid):
        """Check consistency between internal flag and FS regarding partial"""
        # get the values
        mdobj = self.fs[mdid]
        partial_in_md = mdobj["info"]["is_partial"]
        partial_in_disk = path_exists(self._get_partial_path(mdobj))

        # check and return
        if partial_in_md != partial_in_disk:
            msg = "'partial' inconsistency for object with mdid %r!  In disk:"\
                  " %s, In MD: %s" % (mdid, partial_in_disk, partial_in_md)
            raise InconsistencyError(msg)
        return partial_in_md

    def _get_partial_path(self, mdobj, trim=None):
        """Gets the path of the .partial file for a given mdobj"""
        if trim is None and "partial_path" in mdobj["info"]:
            return mdobj["info"]["partial_path"]

        path = self.get_abspath(mdobj['share_id'], mdobj['path'])
        partial_path = os.path.join(
            self.partials_dir, mdobj['mdid'] + '.u1partial')
        dirname, filename = os.path.split(path)

        if trim is not None:
            filename = filename[:-10 * trim]
            mdobj["info"]["partial_path"] = partial_path + '.' + filename

        return partial_path + '.' + filename

    def create_partial(self, node_id, share_id):
        """Create a .partial in disk and set the flag in metadata."""
        mdid = self._idx_node_id[(share_id, node_id)]
        log_debug("create_partial: mdid=%r share_id=%r node_id=%r",
                  mdid, share_id, node_id)
        if self._check_partial(mdid):
            raise ValueError("The object with share_id %r and node_id %r is "
                             "already partial!", share_id, node_id)

        # create an empty partial and set the flag
        mdobj = self.fs[mdid]
        is_dir = mdobj["is_dir"]
        path = self.get_abspath(mdobj['share_id'], mdobj['path'])
        with self._enable_share_write(share_id, os.path.dirname(path)):
            # if we don't have the dir yet, create it
            if is_dir and not path_exists(path):
                self.eq.add_to_mute_filter("FS_DIR_CREATE", path=path)
                make_dir(path)

        mdobj["info"]["last_partial_created"] = time.time()
        mdobj["info"]["is_partial"] = True

        # create the partial path, trimming the name until fits
        # in the filesystem
        partial_path = self._get_partial_path(mdobj)
        trim = 0
        try:
            while True:
                try:
                    # don't alert EQ
                    # partials are in other directory, not watched
                    os_open(partial_path, "w").close()
                except IOError, e:
                    # linux will give you too long, windows will say invalid
                    if e.errno in (errno.ENAMETOOLONG, errno.EINVAL):
                        trim += 1
                        partial_path = self._get_partial_path(mdobj, trim=trim)
                    else:
                        raise
                else:
                    break
        finally:
            self.fs[mdid] = mdobj

    def get_partial_for_writing(self, node_id, share_id):
        """Get a write-only fd to a partial file"""
        mdid = self._idx_node_id[(share_id, node_id)]
        log_debug("get_partial_for_writing: mdid=%r share_id=%r node_id=%r",
                  mdid, share_id, node_id)

        mdobj = self.fs[mdid]
        partial_path = self._get_partial_path(mdobj)
        return os_open(partial_path, "wb")

    def get_partial(self, node_id, share_id):
        """Get a read-only fd to a partial file."""
        mdid = self._idx_node_id[(share_id, node_id)]
        if not self._check_partial(mdid):
            raise ValueError("The object with share_id %r and node_id %r is "
                             "not partial!" % (share_id, node_id))

        partial_path = self._get_partial_path(self.fs[mdid])
        fd = os_open(partial_path, "rb")
        return fd

    def commit_partial(self, node_id, share_id, local_hash):
        """Commit a file from a .partial to disk."""
        mdid = self._idx_node_id[(share_id, node_id)]
        mdobj = self.fs[mdid]
        if mdobj["is_dir"]:
            raise ValueError("Directory partials can not be commited!")
        if not self._check_partial(mdid):
            raise ValueError("The object with share_id %r and node_id %r is "
                             "not partial!" % (share_id, node_id))

        # move the .partial to the real path, and set the md info
        path = self.get_abspath(mdobj['share_id'], mdobj['path'])
        log_debug("commit_partial: path=%r mdid=%r share_id=%r node_id=%r",
                  path, mdid, share_id, node_id)

        partial_path = self._get_partial_path(mdobj)
        with self._enable_share_write(share_id, path):
            self.eq.add_to_mute_filter("FS_FILE_CREATE", path=path)
            self.eq.add_to_mute_filter("FS_FILE_CLOSE_WRITE", path=path)
            recursive_move(partial_path, path)
        mdobj["local_hash"] = local_hash
        mdobj["info"]["last_downloaded"] = time.time()
        mdobj["info"]["is_partial"] = False
        mdobj["stat"] = get_stat(path)
        self.fs[mdid] = mdobj
        self.eq.push("FSM_PARTIAL_COMMITED", share_id=share_id,
                     node_id=node_id)

    def remove_partial(self, node_id, share_id):
        """Remove a .partial in disk and set the flag in metadata."""
        mdid = self._idx_node_id[(share_id, node_id)]

        # delete the .partial, and set the md info
        mdobj = self.fs[mdid]
        path = self.get_abspath(mdobj['share_id'], mdobj['path'])
        log_debug("remove_partial: path=%r mdid=%r share_id=%r node_id=%r",
                  path, mdid, share_id, node_id)
        partial_path = self._get_partial_path(mdobj)
        try:
            # don't alert EQ, partials are in other directory, not watched
            remove_file(partial_path)
        except OSError, e:
            # we only remove it if its there.
            m = "OSError %s when trying to remove partial_path %r"
            log_warning(m, e, partial_path)
        mdobj["info"]["last_partial_removed"] = time.time()
        mdobj["info"]["is_partial"] = False
        self.fs[mdid] = mdobj

    def upload_finished(self, mdid, server_hash):
        """Set the metadata with timestamp and server hash."""
        mdobj = self.fs[mdid]
        mdobj["info"]["last_uploaded"] = time.time()
        mdobj["server_hash"] = server_hash
        self.fs[mdid] = mdobj

    def _get_mdid_from_args(self, kwargs, parent):
        """Parse the kwargs and gets the mdid."""
        if len(kwargs) == 1 and "path" in kwargs:
            path = normpath(kwargs["path"])
            return self._idx_path[path]
        if len(kwargs) == 1 and "mdid" in kwargs:
            return kwargs["mdid"]
        if len(kwargs) == 2 and "node_id" in kwargs and "share_id" in kwargs:
            return self._idx_node_id[(kwargs["share_id"], kwargs["node_id"])]
        raise TypeError("Incorrect arguments for %r: %r" % (parent, kwargs))

    def is_dir(self, **kwargs):
        """Return True if the path of a given object is a directory."""
        mdid = self._get_mdid_from_args(kwargs, "is_dir")
        mdobj = self.fs[mdid]
        return mdobj["is_dir"]

    def has_metadata(self, **kwargs):
        """Return True if there's metadata for a given object."""
        if len(kwargs) == 1 and "path" in kwargs:
            path = normpath(kwargs["path"])
            return path in self._idx_path
        if len(kwargs) == 1 and "mdid" in kwargs:
            return kwargs["mdid"] in self.fs
        if len(kwargs) == 2 and "node_id" in kwargs and "share_id" in kwargs:
            return (kwargs["share_id"], kwargs["node_id"]) in self._idx_node_id
        raise TypeError("Incorrect arguments for 'has_metadata': %r" % kwargs)

    def changed(self, **kwargs):
        """Return whether a given node has changed or not.

        The node can be defined by any of the following:
            - path
            - metadata's id (mdid)
            - node_id and share_id

        Return:
            - LOCAL if the node has local modifications that the server is
              not aware of.
            - SERVER if the node is not fully downloaded.
            - NONE the node has not changed.

        """
        # get the values
        mdid = self._get_mdid_from_args(kwargs, "changed")
        mdobj = self.fs[mdid]
        is_partial = mdobj["info"]["is_partial"]
        local_hash = mdobj.get("local_hash", False)
        server_hash = mdobj.get("server_hash", False)

        # return the status
        if local_hash == server_hash:
            if is_partial:
                return "We broke the Universe! local_hash %r, server_hash %r,"\
                       " is_partial %r" % (local_hash, server_hash, is_partial)
            else:
                return self.CHANGED_NONE
        else:
            if is_partial:
                return self.CHANGED_SERVER
            else:
                return self.CHANGED_LOCAL

    def local_changed(self, path):
        """Return whether a given node have locally changed or not.

        Return True if the node at `path' (or any of its children) has
        been locally modified.

        """
        has_changed = False
        for p, is_dir in self.get_paths_starting_with(path):
            if self.changed(path=p) == self.CHANGED_LOCAL:
                has_changed = True
                break
        return has_changed

    def dir_content(self, path):
        """Return the content of the directory in a server-comparable way."""
        path = normpath(path)
        mdid = self._idx_path[path]
        mdobj = self.fs[mdid]
        if not mdobj["is_dir"]:
            raise ValueError("You can ask dir_content only on a directory.")

        def _get_all():
            """find the mdids that match"""
            for p, m in self._idx_path.iteritems():
                if os.path.dirname(p) == path and p != path:
                    mdobj = self.fs[m]
                    yield (
                        os.path.basename(p), mdobj["is_dir"], mdobj["node_id"])

        return sorted(_get_all())

    def open_file(self, mdid):
        """Return a file like object for reading the contents of the file."""
        mdobj = self.fs[mdid]
        if mdobj["is_dir"]:
            raise ValueError("You can only open files, not directories.")

        return os_open(self.get_abspath(mdobj['share_id'], mdobj['path']),
                       'rb')

    def _share_relative_path(self, share_id, path):
        """Return the relative path from the share_id."""
        share = self._get_share(share_id)
        if path == share.path:
            # the relaitve path is the fullpath
            return share.path
        head, sep, tail = path.rpartition(share.path)
        if sep == '':
            raise ValueError("'%s' isn't a child of '%s'" % (path, share.path))
        relpath = tail.lstrip(os.path.sep)
        # remove the initial os.path.sep
        return relpath.lstrip(os.path.sep)

    def _get_share(self, id):
        """Returns the share/udf with share or volume id: id."""
        # TODO: refactor fsm to use volume instead of share
        share = self.shares.get(id, None)
        if share is None:
            share = self.vm.get_volume(id)
            self.shares[id] = share
        return share

    def get_abspath(self, share_id, path):
        """Return the absolute path: share.path + path."""
        share_path = self._get_share(share_id).path
        if share_path == path:
            # the relaitve path is the fullpath
            return share_path
        else:
            return os.path.abspath(os.path.join(share_path, path))

    def _enable_share_write(self, share_id, path, recursive=False):
        """Helper to create a EnableShareWrite context manager."""
        share = self._get_share(share_id)
        return EnableShareWrite(share, path, recursive)

    def get_paths_starting_with(self, base_path, include_base=True):
        """Return a list of paths that are starts with base_path.

        base_path should be a directory.
        If include_base, base_path is added to the resulting list.

        """
        all_paths = []

        base_mdid = self._idx_path.get(base_path)
        if base_mdid is not None and include_base:
            mdobj = self.fs[base_mdid]
            all_paths.append((base_path, mdobj['is_dir']))

        # add sep, to always match children in the tree and not partial names
        base_path += os.path.sep

        for path, mdid in self._idx_path.iteritems():
            if path.startswith(base_path):
                mdobj = self.fs[mdid]
                all_paths.append((path, mdobj['is_dir']))

        return all_paths

    def get_paths_by_pattern(self, search, ignore_shares=True):
        """Get list of paths matching 'search'. option: ignore shares to me"""
        search = '.+'.join(re.escape(search).split('\\ '))
        pattern = re.compile(search, re.IGNORECASE)

        def _get_matching():
            """Find the paths that match"""
            for p, m in self._idx_path.iteritems():
                mdobj = self.fs[m]
                # ignore shares that are not root (root is id='')
                # and ignore files not present on the server
                if ((ignore_shares and mdobj["share_id"] != '' and
                        mdobj["share_id"] in self.vm.shares) or
                        not mdobj["server_hash"]):
                    continue
                if pattern.search(p):
                    yield p

        return sorted(_get_matching())

    def delete_to_trash(self, mdid, parent_id):
        """Move the node to the trash."""
        mdobj = self.fs[mdid]
        node_id = mdobj["node_id"]
        if node_id is None:
            node_id = MDMarker(mdid)
        share_id = mdobj["share_id"]
        path = self.get_abspath(mdobj['share_id'], mdobj['path'])
        is_dir = mdobj["is_dir"]
        log_debug("delete_to_trash: mdid=%r, parent=%r, share=%r, node=%r, "
                  "path=%r is_dir=%r", mdid, parent_id, share_id, node_id,
                  path, is_dir)
        self.delete_metadata(path)
        self.trash[(share_id, node_id)] = (mdid, parent_id, path, is_dir)

    def remove_from_trash(self, share_id, node_id):
        """Delete the node from the trash."""
        log_debug("remove_from_trash: share=%r, node=%r", share_id, node_id)
        if (share_id, node_id) in self.trash:
            del self.trash[(share_id, node_id)]

    def node_in_trash(self, share_id, node_id):
        """Return if the node is in the trash."""
        return (share_id, node_id) in self.trash

    def get_iter_trash(self):
        """Return the trash element by element."""
        for (share_id, node_id), node_info in self.trash.iteritems():
            parent_id = node_info[1]
            if len(node_info) <= 2:
                # old trash, use a fake path to not block the unlink
                # that LR generates
                path = "fake_unblocking_path"
            else:
                path = node_info[2]
            if len(node_info) <= 3:
                is_dir = False
            else:
                is_dir = node_info[3]
            yield share_id, node_id, parent_id, path, is_dir

    def get_dirty_nodes(self):
        """Return the mdid of the dirty nodes, one by one."""
        for _, v in self.fs.items():
            if v.get('dirty'):
                yield _MDObject(**v)

    def add_to_move_limbo(self, share_id, node_id, old_parent_id,
                          new_parent_id, new_name, path_from, path_to):
        """Add the operation info to the move limbo."""
        log_debug("add to move limbo: share=%r, node=%r, old_parent=%r, "
                  "new_parent=%r, new_name=%r", share_id, node_id,
                  old_parent_id, new_parent_id, new_name)
        self.move_limbo[(share_id, node_id)] = (old_parent_id, new_parent_id,
                                                new_name, path_from, path_to)

    def remove_from_move_limbo(self, share_id, node_id):
        """Remove the node from the move limbo."""
        log_debug("remove from move limbo: share=%r, node=%r",
                  share_id, node_id)
        if (share_id, node_id) in self.move_limbo:
            del self.move_limbo[(share_id, node_id)]

    def get_iter_move_limbo(self):
        """Return the move limbo node by node."""
        for k, v in self.move_limbo.iteritems():
            share_id, node_id = k
            if len(v) == 3:
                # old move limbo, use fakes path to not block the move
                # that LR generates
                path_from = "fake_path_from"
                path_to = "fake_path_to"
                old_parent_id, new_parent_id, new_name = v
            else:
                old_parent_id, new_parent_id, new_name, path_from, path_to = v
            yield (share_id, node_id, old_parent_id, new_parent_id,
                   new_name, path_from, path_to)

    def make_dir(self, mdid):
        """Create the dir in disk."""
        mdobj = self.get_by_mdid(mdid)
        if not mdobj.is_dir:
            raise ValueError("make_dir must be on a file (mdid: %r)" % (mdid,))

        full_path = self.get_abspath(mdobj.share_id, mdobj.path)
        with self._enable_share_write(mdobj.share_id, full_path) as enable:
            if not enable.ro:
                self.eq.add_to_mute_filter('FS_DIR_CREATE', path=full_path)

            try:
                make_dir(full_path)
            except OSError, e:
                if not e.errno == 17:  # already exists
                    raise

            if not enable.ro:
                # add the watch: we hope the user wont have time to add a file
                # just after *we* created the directory; see bug #373940
                self.eq.add_watch(full_path)

    def dereference_ok_limbos(self, marker, value):
        """Dereference markers in the limbos with a value."""
        for (share, node), (mdid, parent, path, is_dir) in \
                self.trash.iteritems():
            if node == marker:
                del self.trash[(share, node)]
                self.trash[(share, value)] = (mdid, parent, path, is_dir)
                log_debug("dereference ok trash: share=%r  marker=%r  "
                          "new node=%r", share, marker, value)
            elif parent == marker:
                self.trash[(share, node)] = (mdid, value, path, is_dir)
                log_debug("dereference ok trash: share=%r  node=%r  marker=%r"
                          "  new parent=%r", share, node, marker, value)

        for k, v in self.move_limbo.iteritems():
            share, node = k
            old_parent, new_parent, new_name, path_from, path_to = v

            if node == marker:
                del self.move_limbo[(share, node)]
                self.move_limbo[(share, value)] = v
                log_debug("dereference ok move limbo: share=%r  marker=%r  "
                          "new node=%r", share, marker, value)
            else:
                # both parents can be the same marker at the same time
                if old_parent == marker or new_parent == marker:
                    if old_parent == marker:
                        old_parent = value
                    if new_parent == marker:
                        new_parent = value
                log_debug("dereference ok move limbo: share=%r  node=%r  "
                          "marker=%r  old_parent=%r  new_parent=%r",
                          share, node, marker, old_parent, new_parent)
                self.move_limbo[k] = (old_parent, new_parent, new_name,
                                      path_from, path_to)

    def dereference_err_limbos(self, marker):
        """Dereference markers in the limbos with an error.

        As the dependency is not valid, we just remove the item.
        """
        for (share, node), (_, parent, _, _) in self.trash.iteritems():
            if node == marker or parent == marker:
                log_debug("dereference err trash: share=%r  node=%r  "
                          "marker=%r", share, node, marker)
                del self.trash[(share, node)]

        move_items = self.move_limbo.iteritems()
        for (share, node), (old_parent, new_parent, _, _, _) in move_items:
            if node == marker or old_parent == marker or new_parent == marker:
                log_debug("dereference err move limbo: share=%r  node=%r  "
                          "marker=%r", share, node, marker)
                del self.move_limbo[(share, node)]


class EnableShareWrite(object):
    """Context manager to allow write in ro-shares."""

    def __init__(self, share, path, recursive=False):
        self.share = share
        self.path = path
        self.ro = not self.share.can_write()
        self.recursive = recursive

        # list of (path, isdir) to restore permissions
        self._changed_nodes = []

    def __enter__(self):
        """Change the nodes to be writable."""
        if not self.ro:
            return self

        # the parent should be writable for us to change path
        parent = os.path.dirname(self.path)
        parent_stat = get_stat(parent)
        if parent_stat is None:
            # if we don't have the parent yet, create it
            with EnableShareWrite(self.share, parent):
                make_dir(parent)
        set_dir_readwrite(parent)
        self._changed_nodes.append((parent, True))

        # so, change path if exists
        path_stat = get_stat(self.path)
        if path_stat is not None:
            if stat.S_ISDIR(path_stat.st_mode):
                set_dir_readwrite(self.path)
                self._changed_nodes.append((self.path, True))
            else:
                set_file_readwrite(self.path)
                self._changed_nodes.append((self.path, False))

        # if needed, change the whole subtree
        if self.recursive:
            for dirpath, dirnames, filenames in walk(self.path, topdown=False):
                for dname in dirnames:
                    path = os.path.join(dirpath, dname)
                    set_dir_readwrite(path)
                    self._changed_nodes.append((path, True))
                for fname in filenames:
                    path = os.path.join(dirpath, fname)
                    set_file_readwrite(path)
                    self._changed_nodes.append((path, False))
        return self

    def __exit__(self, *exc_info):
        """Restore node permissions.

        Note that this is done backwards, from the leaf to the root.
        """
        if not self.ro:
            return

        # restore self.path, that may not have existed at __enter__ time
        path_stat = get_stat(self.path)
        if path_stat is not None:
            if stat.S_ISDIR(path_stat.st_mode):
                set_dir_readonly(self.path)
            else:
                set_file_readonly(self.path)

        # restore all saved ones
        exists = path_exists
        for path, isdir in self._changed_nodes[::-1]:
            if exists(path):
                if isdir:
                    set_dir_readonly(path)
                else:
                    set_file_readonly(path)


def get_stat(path):
    """Return os.lstat or None if errno == ENOENT.

    os.lstat is used as we don't support symlinks
    """
    try:
        return stat_path(path)
    except OSError, e:
        if e.errno == errno.ENOENT:
            return None
        else:
            raise
