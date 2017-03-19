# -*- coding: utf-8 -*-
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
"""Module that implements the Local Rescan."""

import collections
import errno
import functools
import logging
import os
import stat

from ubuntuone.syncdaemon import volume_manager
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    ACCESS_LEVEL_RW,
)
from ubuntuone.syncdaemon.filesystem_manager import get_stat
from twisted.internet import defer, reactor

from ubuntuone.syncdaemon.interfaces import IMarker
from ubuntuone.platform import (
    access,
    is_link,
    listdir,
    path_exists,
    remove_file,
    rename,
    stat_path,
)


class ScanTransactionDirty(Exception):
    """The transaction was dirty."""


class ScanNoDirectory(Exception):
    """The whole directory went away."""

# local rescan logger
lr_logger = logging.getLogger('ubuntuone.SyncDaemon.local_rescan')
log_info = functools.partial(lr_logger.log, logging.INFO)
log_trace = functools.partial(lr_logger.log, logging.getLevelName('TRACE'))
log_debug = functools.partial(lr_logger.log, logging.DEBUG)
log_error = functools.partial(lr_logger.log, logging.ERROR)
log_warning = functools.partial(lr_logger.log, logging.WARNING)


def is_valid_name(path):
    """Tell if the name is valid.

    This checks for the bytes in the path to be utf-8 valid before let them
    get into Syncdaemon.

    There is a similar check in platform/linux/filesystem_notification.py; we
    don't use that because this is more platform independant, will all go away
    when put everything in unicode, and most importantly because don't want to
    send invalid notifications and don't write in the invalid log for *every*
    local rescan.
    """
    try:
        path.decode("utf-8")
    except UnicodeDecodeError:
        return False
    else:
        return True


class LocalRescan(object):
    """Local re-scanner.

    Compares the real disc with FSM's metadata, and pushes the changes to EQ.
    """
    def __init__(self, vm, fsm, eq, aq):
        self.vm = vm
        self.fsm = fsm
        self.eq = eq
        self.aq = aq
        self._queue = collections.deque()
        self._previous_deferred = None

    @defer.inlineCallbacks
    def start(self):
        """Start the comparison."""
        log_info("start scan all volumes")
        to_scan = self._get_volumes(all_volumes=False)
        for vol in to_scan:
            # check that the path exists in disk
            if not path_exists(vol.path):
                log_warning(
                    'Volume dissapeared: %r - %r', vol.volume_id, vol.path)
                if isinstance(vol, volume_manager.Share):
                    log_debug('Removing %r metadata', vol.volume_id)
                    self.vm.share_deleted(vol.volume_id)
                elif isinstance(vol, volume_manager.UDF):
                    log_debug('Unsubscribing %r', vol.volume_id)
                    self.vm.unsubscribe_udf(vol.volume_id)
                # if root is missing, we should crash and burn as it's
                # created on each startup!
                continue
            try:
                mdobj = self.fsm.get_by_path(vol.path)
            except KeyError:
                # this could happen in a strange corruption situation where FSM
                # lost the share information, so we remove it, because VM will
                # download it again
                self.vm.share_deleted(vol.volume_id)
            else:
                self._queue.appendleft((vol, vol.path, mdobj.mdid, False))

        # first of all, remove old partials and clean trash
        self._remove_partials()
        self._process_limbo()
        self._process_ro_shares()

        yield self._queue_scan()
        self._show_broken_nodes()

    def _remove_partials(self):
        """Remove all old .partial files.

        As LR now issues new downloads, and doesn't depend on these file to
        fix the nodes states, we just remove them to don't let garbage behind.
        """
        try:
            partials = listdir(self.fsm.partials_dir)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            # no partials dir at all
            return

        for partial in partials:
            partial_path = os.path.join(self.fsm.partials_dir, partial)
            log_debug("Removing old .partial: %r", partial_path)
            remove_file(partial_path)

    def _process_limbo(self):
        """Process the FSM limbos and send corresponding AQ orders."""
        log_info("processing trash")
        trash_log = "share_id=%r  parent_id=%r  node_id=%r  path=%r"
        for item in self.fsm.get_iter_trash():
            share_id, node_id, parent_id, path, is_dir = item
            datalog = trash_log % (share_id, parent_id, node_id, path)
            if IMarker.providedBy(node_id) or IMarker.providedBy(parent_id):
                # situation where the node is not in the server
                log_info("removing from trash: " + datalog)
                self.fsm.remove_from_trash(share_id, node_id)
                continue
            log_info("generating Unlink from trash: " + datalog)
            self.aq.unlink(share_id, parent_id, node_id, path, is_dir)

        log_info("processing move limbo")
        move_log = ("share_id=%r  node_id=%r  old_parent_id=%r  "
                    "new_parent_id=%r  new_name=%r  path_from=%r  path_to=%r")
        for data in self.fsm.get_iter_move_limbo():
            to_log = move_log % data
            (share_id, node_id, old_parent_id, new_parent_id, new_name,
             path_from, path_to) = data
            maybe_markers = (share_id, node_id, old_parent_id, new_parent_id)
            if any(IMarker.providedBy(x) for x in maybe_markers):
                # situation where the move was not ready
                log_info("removing from move limbo: " + to_log)
                self.fsm.remove_from_move_limbo(share_id, node_id)
                continue
            log_info("generating Move from limbo: " + to_log)
            self.aq.move(share_id, node_id, old_parent_id,
                         new_parent_id, new_name, path_from, path_to)

    def _process_ro_shares(self):
        """Process ro shares and reschedule interrupted downloads."""
        # to avoid the lookups in the nested for
        changed = self.fsm.changed
        CHANGED_SERVER = self.fsm.CHANGED_SERVER
        for share in self._get_volumes(all_volumes=False,
                                       access_level=ACCESS_LEVEL_RO):
            for mdobj in self.fsm.get_mdobjs_by_share_id(share.id):
                if changed(mdid=mdobj.mdid) == CHANGED_SERVER:
                    fullname = os.path.join(share.path, mdobj.path)
                    if mdobj.is_dir:
                        # old state, no sense now with generations
                        # but required for the migration path.
                        log_warning(
                            "Found a directory in SERVER: %r", fullname)
                        mdobj = self.fsm.get_by_path(fullname)
                        self.fsm.set_by_mdid(mdobj.mdid,
                                             server_hash=mdobj.local_hash)
                        self.fsm.remove_partial(mdobj.node_id, mdobj.share_id)
                    else:
                        log_debug("comp yield: file %r in SERVER", fullname)
                        self._resume_download(fullname)

    def _show_broken_nodes(self):
        """Log the broken nodes."""
        for mdobj in self.fsm.get_dirty_nodes():
            m = "Broken node: volume_id=%r node_id=%r mdid=%r path=%r"
            log_info(m, mdobj.share_id, mdobj.node_id, mdobj.mdid, mdobj.path)

    def _get_volumes(self, all_volumes=True, access_level=ACCESS_LEVEL_RW):
        """Get all the shares and udfs matching access_level to compare."""
        modify = access_level == ACCESS_LEVEL_RW
        view = access_level == ACCESS_LEVEL_RO
        for volume in self.vm.get_volumes(all_volumes=all_volumes):
            if (modify and volume.can_write()) or \
               (view and not volume.can_write()):
                yield volume

    def scan_dir(self, mdid, direct, udfmode=False):
        """Compares one directory between metadata and disk."""
        log_info("scan dir: %r  mdid: %s", direct, mdid)

        # get the share to get only a subset of mdids
        for share in self._get_volumes():
            if direct.startswith(share.path):
                break
        else:
            # not in RW shares; let's check RO shares, otherwise it's an error

            for share in self._get_volumes(access_level=ACCESS_LEVEL_RO):
                if direct.startswith(share.path):
                    return
            log_error("The received path is not in any share!")
            raise ValueError("The received path is not in any share!")

        # uglier than path_exists and isdir, but only hit the disk once
        stat_result = get_stat(direct)
        if stat_result is None:
            m = "The received path is not in disk: path %r  mdid %s"
            log_debug(m, direct, mdid)
            # it's better to delay the rescan some miliseconds, as if a
            # directory was moved, it's better to leave stuff some time to
            # settle down
            reactor.callLater(.1, self._send_scan_error, mdid, udfmode)
            return
        elif not stat.S_ISDIR(stat_result.st_mode):
            m = "The path is in disk but it's not a dir: %r" % direct
            log_error(m)
            raise ValueError(m)

        self._queue.appendleft((share, direct, mdid, udfmode))
        return self._queue_scan()

    def _send_scan_error(self, mdid, udfmode):
        """Sends the scan error event."""
        self.eq.push("LR_SCAN_ERROR", mdid=mdid, udfmode=udfmode)

    def _queue_scan(self):
        """If there's a scan in progress, queue the new one for later."""
        if self._previous_deferred is None:
            self._previous_deferred = defer.Deferred()
            self._process_next_queue(None)
        return self._previous_deferred

    def _process_next_queue(self, _):
        """Process the next item in the queue, if any."""
        log_debug("process next in queue (len %d)", len(self._queue))
        if not self._queue:
            d = self._previous_deferred
            self._previous_deferred = None
            d.callback(None)
            return

        # more to scan
        scan_info = self._queue.pop()

        @defer.inlineCallbacks
        def safe_scan():
            """Scan safely"""
            try:
                # add watches to UDF ancestors and check UDF is ok
                volume = scan_info[0]
                if isinstance(volume, volume_manager.UDF):
                    udf_ok = yield self.eq.add_watches_to_udf_ancestors(volume)
                    if not udf_ok:
                        # we need to ensure that the udf is not subscribed
                        # when an error happens while adding the parent watches
                        m = "Unsubscribing UDF %r because not in disk: %r"
                        log_info(m, volume.volume_id, volume.path)
                        self.vm.unsubscribe_udf(volume.volume_id)
                        self._process_next_queue(None)
                        return

                self._scan_tree(*scan_info)
            except Exception as e:
                self._previous_deferred.errback(e)

        reactor.callLater(0, safe_scan)

    def _get_share_info(self, path):
        """Get all the objects information for a directory path."""
        share_info = []
        for obj in self.fsm.get_mdobjs_in_dir(path):
            changd = self.fsm.changed(mdid=obj.mdid)
            share_info.append((obj.path, obj.is_dir, obj.stat, changd,
                               obj.node_id, obj.local_hash, obj.server_hash))
        return share_info

    def _scan_tree(self, share, path, mdid, udfmode):
        """Scans a whole tree, using the received path as root."""
        log_debug("_scan_tree:  share_path: %r  path: %r", share.path, path)

        def go_deeper(newdirs):
            """Explore into the subdirs."""
            for direct in newdirs:
                log_debug("explore subdir: %r", direct)
                self._queue.appendleft((share, direct, mdid, udfmode))

        def re_launch(failure):
            """Explore that directory again."""
            if failure.check(ScanTransactionDirty):
                reason = failure.getErrorMessage()
                log_debug("re queue, transaction dirty for %r, reason: %s",
                          path, reason)
                self._queue.appendleft((share, path, mdid, udfmode))
            elif failure.check(OSError, IOError):
                reason = failure.getErrorMessage()
                m = "Disk error while scanning path %r, reason: %s"
                log_debug(m, path, reason)
                if self.eq.is_frozen():
                    self.eq.freeze_rollback()
                # it's better to delay the rescan some miliseconds, as if a
                # directory was moved, it's better to leave stuff some time to
                # settle down
                reactor.callLater(.1, self._send_scan_error, mdid, udfmode)
            else:
                log_error("in the scan: %s (%s)\n%s",
                          failure.type, failure.value, failure.getTraceback())
                return failure

        d = defer.succeed((share, path, udfmode))
        d.addCallbacks(self._scan_one_dir)
        d.addCallbacks(go_deeper, re_launch)
        d.addCallback(self._process_next_queue)
        return d

    def _resume_download(self, fullname):
        """Resume an interrupted download."""
        mdobj = self.fsm.get_by_path(fullname)
        self.aq.download(mdobj.share_id, mdobj.node_id,
                         mdobj.server_hash, mdobj.mdid)

    def _resume_upload(self, fullname):
        """Resume an interrupted upload."""
        mdobj = self.fsm.get_by_path(fullname)
        upload_id = getattr(mdobj, 'upload_id', None)
        self.aq.upload(mdobj.share_id, mdobj.node_id, mdobj.server_hash,
                       mdobj.local_hash, mdobj.crc32, mdobj.size,
                       mdobj.mdid, upload_id=upload_id)

    def check_stat(self, fullname, oldstat):
        """Check stat info and return if different.

        Don't compare the full stat, only what is relevant:

        - st_ino: the data location changed in disk, may be something else
        - st_size: it changed in size, surely different content
        - st_mtime: the content could be different even having the same size
        """
        if oldstat is None:
            return True
        newstat = stat_path(fullname)
        different = (newstat.st_ino != oldstat.st_ino or
                     newstat.st_size != oldstat.st_size or
                     newstat.st_mtime != oldstat.st_mtime)
        if different:
            log_debug("stat differ for: %r  "
                      "Old: st_ino=%d st_size=%d st_mtime=%r  "
                      "New: st_ino=%d st_size=%d st_mtime=%r", fullname,
                      oldstat.st_ino, oldstat.st_size, oldstat.st_mtime,
                      newstat.st_ino, newstat.st_size, newstat.st_mtime)
        return different

    def _compare(self, dirpath, dirnames, filenames, share):
        """Compare the directories with the info that should be there."""
        log_debug("comparing directory %r", dirpath)

        # get the share info
        share_info = self._get_share_info(dirpath)
        shouldbe = self._paths_filter(share_info, dirpath, len(share.path))

        def despair(message, fullname, also_children=False, also_remove=None):
            """Something went very bad with this node, converge!"""
            # if asked, remove metadata por children
            if also_children:
                log_debug("Removing metadata for %r children", fullname)
                children = self.fsm.get_paths_starting_with(fullname, False)
                for path, is_dir in children:
                    self.fsm.delete_metadata(path)

            # remove fullname after removing its children,
            # otherwise metadata removal may fail
            log_info(message, fullname)
            rename(fullname, fullname + ".u1conflict")
            self.fsm.delete_metadata(fullname)

            # if asked, remove also that file (if still exists)
            if also_remove is not None:
                try:
                    log_info("Also remove %r", also_remove)
                    remove_file(also_remove)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        raise

        # check all directories
        to_scan_later = []
        events = []

        # check if dirpath is the share root
        if dirpath == share.path:
            fullname = share.path
            mdobj = self.fsm.get_by_path(fullname)
            changed = self.fsm.changed(mdid=mdobj.mdid)
            if changed == "SERVER":
                # download interrupted
                log_debug("checking root: %r in SERVER, fixing hash and "
                          "removing partial.", fullname)
                self.fsm.set_by_mdid(mdobj.mdid,
                                     server_hash=mdobj.local_hash)
                self.fsm.remove_partial(mdobj.node_id, mdobj.share_id)
            elif changed == "NONE":
                log_debug("checking root: %r in NONE, ok!", fullname)
            else:
                log_warning("checking root: %r in wrong changed "
                            "value '%s'", fullname, changed)

        for dname in dirnames:
            fullname = os.path.join(dirpath, dname)
            if dname in shouldbe:
                is_dir, statinfo, changed = shouldbe.pop(dname)
                if not is_dir:
                    # it's there, but it's a file!
                    log_info("comp yield: file %r became a dir!", fullname)
                    events.append(('FS_FILE_DELETE', fullname))
                    events.append(('FS_DIR_CREATE', fullname))
                elif changed == "SERVER":
                    # old state, no sense now with generations
                    log_warning("Found a directory in SERVER: %r", fullname)
                    mdobj = self.fsm.get_by_path(fullname)
                    self.fsm.set_by_mdid(mdobj.mdid,
                                         server_hash=mdobj.local_hash)
                    self.fsm.remove_partial(mdobj.node_id, mdobj.share_id)
                    to_scan_later.append(fullname)
                elif changed == "NONE":
                    # it's old, we should scan it later
                    log_trace("comp yield: dir %r will be scaned later "
                              "because it's in NONE!", fullname)
                    to_scan_later.append(fullname)
                else:
                    m = "Wrong 'changed' value for %r: " + changed
                    despair(m, fullname, also_children=True)

            else:
                # hey, it's new!
                log_debug("comp yield: directory %r is new!", fullname)
                events.append(('FS_DIR_CREATE', fullname))

        # check all files
        for fname in filenames:
            fullname = os.path.join(dirpath, fname)
            if fname in shouldbe:
                is_dir, statinfo, changed = shouldbe.pop(fname)
                if is_dir:
                    log_info("comp yield: dir %r became a file!", fullname)
                    # it's there, but it's a directory!
                    events.append(('FS_DIR_DELETE', fullname))
                    events.append(('FS_FILE_CREATE', fullname))
                    events.append(('FS_FILE_CLOSE_WRITE', fullname))
                elif changed == "LOCAL":
                    different = self.check_stat(fullname, statinfo)
                    if different:
                        # hash it to see the changes, Sync will take care
                        log_debug("comp yield: file %r in LOCAL and changed",
                                  fullname)
                        events.append(('FS_FILE_CLOSE_WRITE', fullname))
                    else:
                        # file didn't change, resume upload
                        log_debug("resuming upload because it was "
                                  "interrupted: %r", fullname)
                        self._resume_upload(fullname)
                elif changed == "NONE":
                    # what about stat info?
                    log_trace("comp yield: file %r was here, let's check stat",
                              fullname)
                    different = self.check_stat(fullname, statinfo)
                    if different:
                        log_debug("comp yield: file content changed: %r",
                                  fullname)
                        events.append(('FS_FILE_CLOSE_WRITE', fullname))
                    # no 'else' here: the file is the same as before, all ok
                elif changed == "SERVER":
                    log_debug("comp yield: file %r in SERVER", fullname)
                    different = self.check_stat(fullname, statinfo)
                    if different:
                        # hash it to see the changes, Sync will take care
                        events.append(('FS_FILE_CLOSE_WRITE', fullname))
                    else:
                        # file didn't change, resume download
                        self._resume_download(fullname)
                else:
                    m = "Wrong 'changed' value for %r: " + changed
                    despair(m, fullname)
            else:
                # hey, it's new!
                log_debug("comp yield: file %r is new!", fullname)
                events.append(('FS_FILE_CREATE', fullname))

                # even if it's empty, we signal to get the hash
                # otherwise it will never get "empty" to the server
                events.append(('FS_FILE_CLOSE_WRITE', fullname))

        # all these don't exist anymore
        for name, (is_dir, statinfo, changed) in shouldbe.iteritems():
            fullname = os.path.join(dirpath, name)
            if is_dir:
                if changed not in ("SERVER", "NONE"):
                    # bad metadata
                    m = "Bad 'changed': removing MD from dir %r and children"
                    log_debug(m, fullname)
                    children = self.fsm.get_paths_starting_with(fullname)
                    for path, is_dir in children:
                        self.fsm.delete_metadata(path)
                    continue

                log_info("comp yield: directory %r is gone!", fullname)
                # it's a directory, didn't have any info inside?
                to_inform = []

                # get all the info inside that dir
                objs = self.fsm.get_mdobjs_by_share_id(
                    share.volume_id, fullname)
                for obj in objs:
                    shrpath = obj.path
                    qparts = len(shrpath.split(os.path.sep))
                    to_inform.append((qparts, shrpath, obj.is_dir))

                # order everything from more path components to less (this
                # will assure correct upgoing walk in the tree)
                to_inform.sort(reverse=True)

                # inform deletion!
                for (_, name, is_dir) in to_inform:
                    fullname = os.path.join(share.path, name)
                    log_info("Inform deletion of stuff in dir: %r", fullname)
                    if is_dir:
                        events.append(('FS_DIR_DELETE', fullname))
                    else:
                        events.append(('FS_FILE_DELETE', fullname))
            else:
                if changed == 'SERVER':
                    # download interruped and partial lost
                    log_debug("comp yield: file %r not in disk, in SERVER "
                              "state", fullname)
                    self._resume_download(fullname)
                elif changed in ('NONE', 'LOCAL'):
                    # if it had content somewhen, now is really gone (otherwise
                    # it was never really created in the disk)
                    log_info("comp yield: file %r is gone!", fullname)
                    events.append(('FS_FILE_DELETE', fullname))
                else:
                    # bad metadata
                    m = "Bad 'changed': removing MD from file %r"
                    log_debug(m, fullname)
                    self.fsm.delete_metadata(fullname)

        return events, to_scan_later

    def _paths_filter(self, shrinfo, dirpath, len_shr_path):
        """Returns the paths that belong to this dir."""
        # paths in shares are relative, remove the first slash
        basedir = dirpath[:len_shr_path]

        # build the dict
        filesdirs = {}
        for fpath, is_dir, statinfo, changed, node_id, lhash, shash in shrinfo:
            fname = os.path.basename(fpath)
            # if without node_id, remove the metadata, and take it as new
            if node_id is None:
                fullname = os.path.join(basedir, fpath)
                m = "Deleting metadata, because of node_id=None, of %r"
                log_debug(m, fullname)
                self.fsm.delete_metadata(fullname)

            # if both hashes aren't set in a file, it's a non-content
            # situation, remove the metadata
            elif not is_dir and not lhash and not shash:
                fullname = os.path.join(basedir, fpath)
                m = "Deleting metadata, both hashes empty, of %r"
                log_debug(m, fullname)
                self.fsm.delete_metadata(fullname)

                # also set the parent hashes to "", to force a new scan
                parent = os.path.dirname(fullname)
                log_debug("Dirtying the parent hashes, path: %r", parent)
                self.fsm.set_by_path(parent, server_hash="", local_hash="")

            else:
                filesdirs[fname] = is_dir, statinfo, changed
        return filesdirs

    @defer.inlineCallbacks
    def _scan_one_dir(self, scan_info):
        """Gets one dir and compares with fsm."""
        share, dirpath, udf_mode = scan_info

        log_debug("Adding watch to %r", dirpath)
        yield self.eq.add_watch(dirpath)

        to_later = []
        self.eq.freeze_begin(dirpath)

        def scan():
            """The scan, really."""

            log_debug("scanning the dir %r", dirpath)
            dircontent = listdir(dirpath)

            # get the info from disk
            dnames = []
            fnames = []
            for something in dircontent:
                fullname = os.path.join(dirpath, something)
                stat_result = get_stat(fullname)
                if stat_result is None:
                    # gone between the listdir and now
                    continue
                if is_link(fullname):
                    log_info("Ignoring path as it's a symlink: %r", fullname)
                    continue
                if not is_valid_name(fullname):
                    m = "Ignoring path because it's invalid (non utf-8): %r"
                    log_info(m, fullname)
                    continue
                if not access(fullname):
                    log_warning("Ignoring path as we don't have enough "
                                "permissions to track it: %r", fullname)
                    continue

                if stat.S_ISDIR(stat_result.st_mode):
                    dnames.append(something)
                elif stat.S_ISREG(stat_result.st_mode):
                    fnames.append(something)
                else:
                    log_warning("Path: %r isn't a dir, file or symlink.",
                                fullname)

            events, to_scan_later = self._compare(dirpath, dnames, fnames,
                                                  share)
            to_later.extend(to_scan_later)
            return events

        delete_events = []

        def control(dirty):
            """controls that everything was ok"""
            if dirty:
                self.eq.freeze_rollback()
                raise ScanTransactionDirty("dirty!")

            # delete metadata for the filtered delete_events
            fsm = self.fsm
            for evtname, path in delete_events:
                parentpath = os.path.dirname(path)
                log_info("UDF mode! Resetting hashes to dir %r", parentpath)
                self.fsm.set_by_path(parentpath, local_hash="", server_hash="")
                if evtname == "FS_DIR_DELETE":
                    log_info("UDF mode! Removing metadata from dir %r", path)
                    tree = fsm.get_paths_starting_with(path, include_base=True)
                    for p, is_dir in tree:
                        fsm.delete_metadata(p)
                elif evtname == "FS_FILE_DELETE":
                    log_info("UDF mode! Removing metadata from file %r", path)
                    fsm.delete_metadata(path)
                else:
                    raise ValueError("Bad delete event! got %s (on %r)"
                                     % (evtname, path))

            return to_later

        def filter_delete_events(events):
            """Separate the delete events if it was an UDF."""
            for evt in events[:]:
                if evt[0] in ("FS_DIR_DELETE", "FS_FILE_DELETE"):
                    events.remove(evt)
                    delete_events.append(evt)
            return events

        d = defer.execute(scan)
        if udf_mode:
            d.addCallback(filter_delete_events)
        d.addCallback(self.eq.freeze_commit)
        d.addCallback(control)
        result = yield d
        defer.returnValue(result)
