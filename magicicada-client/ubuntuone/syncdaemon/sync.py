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
"""This is the magic."""

from __future__ import with_statement

import os
import logging
from operator import attrgetter
import sys

from ubuntuone.syncdaemon.marker import MDMarker
from ubuntuone.storageprotocol import delta
from ubuntuone.syncdaemon.fsm.fsm import \
    StateMachineRunner, StateMachine
from ubuntuone.syncdaemon import u1fsfsm
from ubuntuone.syncdaemon.logger import DebugCapture
from ubuntuone.syncdaemon.filesystem_manager import (
    DirectoryNotRemovable,
    InconsistencyError,
)
from ubuntuone.syncdaemon.volume_manager import VolumeDoesNotExist
from ubuntuone.platform import (
    stat_path,
)

empty_hash = ""


class FSKey(object):
    """Encapsulate the problem of getting the metadata with different keys."""
    __slots__ = ('fs', 'keys', 'mdid', '_changes')

    def __init__(self, fs, **keys):
        self.fs = fs
        self.keys = keys
        self.mdid = None
        self._changes = {}

    def get_mdid(self):
        """Get the metadata id."""
        if self.mdid is not None:
            return self.mdid
        if len(self.keys) == 1 and "path" in self.keys:
            mdid = self.fs._idx_path[self.keys["path"]]
        elif len(self.keys) == 1 and "mdid" in self.keys:
            mdid = self.keys["mdid"]
        elif (len(self.keys) == 2 and "node_id" in self.keys and
                "share_id" in self.keys):
            k = (self.keys["share_id"], self.keys["node_id"])
            mdid = self.fs._idx_node_id[k]
        else:
            raise KeyError("Incorrect keys: %s" % self.keys)
        if mdid is None:
            raise KeyError("cant find mdid")
        self.mdid = mdid
        return mdid

    def get(self, key):
        """Get the value for key."""
        mdid = self.get_mdid()
        if key == 'path':
            mdobj = self.fs.get_by_mdid(mdid)
            return self.fs.get_abspath(mdobj.share_id, mdobj.path)
        elif key == 'node_id':
            mdobj = self.fs.get_by_mdid(mdid)
            if mdobj.node_id is None:
                return MDMarker(mdid)
            else:
                return mdobj.node_id
        elif key == 'parent_id':
            mdobj = self.fs.get_by_mdid(mdid)
            path = self.fs.get_abspath(mdobj.share_id, mdobj.path)
            parent_path = os.path.dirname(path)
            parent = self.fs.get_by_path(parent_path)
            return parent.node_id or MDMarker(parent.mdid)
        else:
            return getattr(self.fs.get_by_mdid(mdid), key, None)

    def __getitem__(self, key):
        """Get the value for key."""
        return self.get(key)

    def set(self, **kwargs):
        """Set the values for kwargs."""
        self._changes.update(kwargs)

    def sync(self):
        """Sync the changes back to FSM."""
        if self._changes and self.has_metadata():
            self.fs.set_by_mdid(self.get_mdid(), **self._changes)
            self._changes = {}

    def has_metadata(self):
        """The State Machine value version of has_metadata."""
        try:
            return str(self.fs.has_metadata(**self.keys))[0]
        except (KeyError, TypeError):
            return 'NA'

    def is_directory(self):
        """The State Machine value version of is_dir.

        This is a string like "T" or "F", not useful as a bool.
        """
        try:
            return str(self.fs.is_dir(**self.keys))[0]
        except KeyError:
            return 'NA'

    def is_dir(self):
        """If the node is a directory or not.

        This is a direct wrapper around FSM.is_dir().
        """
        return self.fs.is_dir(**self.keys)

    def changed(self):
        """The State Machine value version of changed."""
        try:
            return self.fs.changed(**self.keys)
        except KeyError:
            return 'NA'

    def upload_finished(self, server_hash):
        """Signal that we have uploaded the file."""
        mdid = self.get_mdid()
        self.fs.upload_finished(mdid, server_hash)

    def delete_file(self):
        """Delete the file and metadata."""
        path = self["path"]
        self.fs.delete_file(path)
        self.mdid = None
        self._changes = {}

    def delete_to_trash(self):
        """Move the node to trash."""
        self.fs.delete_to_trash(self.get_mdid(), self["parent_id"])

    def remove_from_trash(self, share_id, node_id):
        """Remove the node from trash."""
        self.fs.remove_from_trash(share_id, node_id)

    def delete_metadata(self):
        """Delete the metadata."""
        path = self["path"]
        self.fs.delete_metadata(path)
        self.mdid = None
        self._changes = {}

    def move_file(self, new_share_id, new_parent_id, new_name):
        """Get the stuff we need to move the file."""
        source_path = self['path']
        parent_path = self.fs.get_by_node_id(new_share_id, new_parent_id).path
        dest_path = os.path.join(
            self.fs.get_abspath(new_share_id, parent_path),
            new_name)
        self.fs.move_file(new_share_id, source_path, dest_path)

    def moved(self, new_share_id, path_to):
        """Change the metadata of a moved file."""
        self.fs.moved(new_share_id, self['path'], path_to)
        if "path" in self.keys:
            self.keys["path"] = path_to

    def remove_partial(self):
        """Remove a partial file."""
        try:
            self.fs.remove_partial(self["node_id"], self["share_id"])
        except ValueError:
            # we had no partial, ignore
            pass

    def move_to_conflict(self):
        """Move file to conflict."""
        self.fs.move_to_conflict(self.get_mdid())

    def safe_get(self, key, default='^_^'):
        """Safe version of self.get, to be used in the FileLogger."""
        # catch all errors as we are here to help logging
        try:
            return self.get(key)
        except Exception:
            return default

    def is_subscribed(self):
        """Tell if the node is in a subscribed volume or not."""
        try:
            volume_id = self.get('share_id')
        except KeyError:
            # node still not created, can get the parent only with path
            if 'path' not in self.keys:
                raise

            # let's get the parent and its volume
            parent_path = os.path.dirname(self.keys["path"])
            parent = self.fs.get_by_path(parent_path)
            volume_id = parent.share_id

        # get the volume and return if subscribed
        volume = self.fs.vm.get_volume(volume_id)
        return volume.subscribed


def loglevel(lvl):
    """Make a function that logs at lvl log level."""
    def level_log(self, message, *args, **kwargs):
        """inner."""
        self.log(lvl, message, *args, **kwargs)
    return level_log


class FileLogger(object):
    """A logger that knows about the file and its state."""
    __slots__ = ('logger', 'key')

    def __init__(self, logger, key):
        """Create a logger for this guy"""
        self.logger = logger
        self.key = key

    def log(self, lvl, message, *args, **kwargs):
        """Log."""
        format = "%(hasmd)s:%(changed)s:%(isdir)s %(mdid)s "\
                 "[%(share_id)r::%(node_id)r] '%(path)r' | %(message)s"
        exc_info = sys.exc_info
        if self.key.has_metadata() == "T":
            # catch all errors as we are logging
            try:
                base = os.path.split(self.key.fs._get_share(
                    self.key['share_id']).path)[1]
                path = os.path.join(base, self.key.fs._share_relative_path(
                    self.key['share_id'], self.key['path']))
            except Exception:
                # error while getting the path
                self.logger.exception("Error in logger while building the "
                                      "relpath of: %r", self.key['path'])
                path = self.key.safe_get('path')
            extra = dict(message=message,
                         mdid=self.key.safe_get("mdid"),
                         path=path.replace('%', '%%'),   # escape %
                         share_id=self.key.safe_get("share_id") or 'root',
                         node_id=self.key.safe_get("node_id"),
                         hasmd=self.key.has_metadata(),
                         isdir=self.key.is_directory(),
                         changed=self.key.changed())
        else:
            extra = dict(message=message, mdid="-",
                         path="-",
                         share_id="-",
                         node_id="-",
                         hasmd="-",
                         isdir="-",
                         changed="-")
            extra.update(self.key.keys)
        message = format % extra
        if lvl == -1:
            kwargs.update({'exc_info': exc_info})
            self.logger.error(message, *args, **kwargs)
        else:
            self.logger.log(lvl, message, *args, **kwargs)

    critical = loglevel(logging.CRITICAL)
    error = loglevel(logging.ERROR)
    warning = loglevel(logging.WARNING)
    info = loglevel(logging.INFO)
    debug = loglevel(logging.DEBUG)
    exception = loglevel(-1)


class SyncStateMachineRunner(StateMachineRunner):
    """This is where all the state machine methods are."""

    def __init__(self, fsm, main, key, logger=None):
        """Create the runner."""
        super(SyncStateMachineRunner, self).__init__(fsm, logger)
        self.m = main
        self.key = key

    def on_event(self, *args, **kwargs):
        """Override on_event to capture the debug log"""
        kw = dict(
            hasmd=self.key.has_metadata(), isdir=self.key.is_directory(),
            changed=self.key.changed())
        in_state = '%(hasmd)s:%(changed)s:%(isdir)s' % kw
        is_debug = self.log.logger.isEnabledFor(logging.DEBUG)
        with DebugCapture(self.log.logger):
            func_name = super(SyncStateMachineRunner, self).on_event(*args,
                                                                     **kwargs)
            if not is_debug:
                self.log.info("Called %s (In: %s)" % (func_name, in_state))

    def signal_event_with_hash(self, event, hash, *args):
        """An event that takes a hash ocurred, build the params and signal."""
        self.on_event(event, self.build_hash_eq(hash), hash, *args)

    def validate_actual_data(self, path, oldstat):
        """Validates that the received info is not obsolete."""
        newstat = stat_path(path)
        if newstat.st_ino != oldstat.st_ino or \
           newstat.st_size != oldstat.st_size or \
           newstat.st_mtime != oldstat.st_mtime:
            self.log.debug("The received information is obsolete! New stat: "
                           "st_ino=%d  st_size=%d  st_mtime=%r",
                           newstat.st_ino, newstat.st_size, newstat.st_mtime)
            return False
        return True

    def build_hash_eq(self, hash):
        """Build the event params."""
        try:
            sh = str(self.key["server_hash"] == hash)[0]
            lh = str(self.key["local_hash"] == hash)[0]
        except KeyError:
            sh = lh = "NA"
        return dict(hash_eq_server_hash=sh, hash_eq_local_hash=lh)

    def signal_event_with_error_and_hash(self, event, error, hash, *args):
        """An event that takes a hash ocurred, build the params and signal."""
        params = self.build_error_eq(error)
        params.update(self.build_hash_eq(hash))
        self.on_event(event, params, error, hash, *args)

    def signal_event_with_error(self, event, failure, *args):
        """An event returned with error."""
        params = self.build_error_eq(failure.getErrorMessage())
        self.on_event(event, params, failure, *args)

    def build_error_eq(self, error):
        """Get the error state."""
        not_available = str(error == 'NOT_AVAILABLE')[0]
        not_authorized = str(error == 'NOT_AUTHORIZED')[0]
        return dict(not_available=not_available, not_authorized=not_authorized)

    def get_state_values(self):
        """Get the values for the current state."""
        return dict(
            has_metadata=self.key.has_metadata(),
            changed=self.key.changed(),
            is_directory=self.key.is_directory(),
        )

    def update_generation(self, volume_id, node_id, new_generation):
        """Update the generation for the node and volume."""

        # update the file
        try:
            node = self.m.fs.get_by_node_id(volume_id, node_id)
        except KeyError:
            pass
        else:
            self.m.fs.set_by_mdid(node.mdid, generation=new_generation)

        # update the volume
        try:
            volume = self.m.vm.get_volume(volume_id)
        except VolumeDoesNotExist:
            self.log.warning("Volume not found: %r", volume_id)
            return

        if volume.generation is None or new_generation is None:
            self.log.debug("Client not ready for generations! vol gen: %r, "
                           "new gen: %r", volume.generation, new_generation)
            return

        if new_generation <= volume.generation:
            self.log.info("Got smaller or equal generation (%d) than current "
                          "(%d) for volume %r", new_generation,
                          volume.generation, volume_id)

        elif new_generation == volume.generation + 1:
            # last change from ourselves was the responsible of this increment
            self.log.info("Updating current generation for volume %s to %d",
                          volume_id, new_generation)
            self.m.vm.update_generation(volume_id, new_generation)

        else:
            # there're changes that we don't know about, let's get a delta
            m = "Generation much bigger (%d) than current (%d) for volume %r"
            self.log.info(m, new_generation, volume.generation, volume_id)
            self.m.action_q.get_delta(volume_id, volume.generation)

    # EVENT HANDLERS
    def nothing(self, event, params, *args):
        """pass"""
        pass

    def new_dir(self, event, params, share_id, node_id, parent_id, name):
        """create a local file."""
        mdobj = self.m.fs.get_by_node_id(share_id, parent_id)
        path = os.path.join(self.m.fs.get_abspath(share_id, mdobj.path), name)
        mdid = self.m.fs.create(path, share_id, node_id, True)
        self.m.fs.make_dir(mdid)

    def new_dir_on_server_with_local_file(self, event, params, share_id,
                                          node_id, parent_id, name):
        """New dir on server and we have local file."""
        self.key.move_to_conflict()
        self.key.delete_metadata()
        self.new_dir(event, params, share_id, node_id, parent_id, name)

    def new_dir_on_server_with_local_dir(self, event, params, share_id,
                                         node_id, parent_id, name):
        """New dir on server and we have local dir: re-get it to converge."""
        self.m.fs.set_node_id(self.key['path'], node_id)
        self.reget_dir(event, params)

    def file_conflict(self, event, params, hash, crc32, size, stat):
        """This file is in conflict."""
        self.key.move_to_conflict()

    def local_file_conflict(self, event, params, hash):
        """This file is in conflict."""
        self.key.move_to_conflict()
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])
        self.get_file(event, params, hash)

    def new_file(self, event, params, share_id, node_id, parent_id, name):
        """create a local file."""
        mdobj = self.m.fs.get_by_node_id(share_id, parent_id)
        path = os.path.join(self.m.fs.get_abspath(share_id, mdobj.path), name)
        self.m.fs.create(path=path, share_id=share_id, node_id=node_id,
                         is_dir=False)
        self.key.set(server_hash="")
        self.key.set(local_hash="")
        self.key.sync()

    def new_file_on_server_with_local(self, event, params, share_id,
                                      node_id, parent_id, name):
        """move local file to conflict and re create"""
        self.key.move_to_conflict()
        self.key.delete_metadata()
        self.new_file(event, params, share_id, node_id, parent_id, name)

    def get_file(self, event, params, server_hash):
        """Get the contents for the file."""
        self.key.set(server_hash=server_hash)
        self.key.sync()
        share_id = self.key['share_id']
        node_id = self.key['node_id']
        mdid = self.key['mdid']
        self.m.fs.create_partial(node_id=node_id, share_id=share_id)
        self.m.action_q.download(share_id, node_id, server_hash, mdid)

    def reget_file(self, event, params, hash):
        """cancel and reget this download."""
        self.key.set(server_hash=hash)
        self.key.sync()
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.get_file(event, params, hash)

    def client_moved(self, event, params, path_from, path_to):
        """the client moved a file"""
        parent_path = os.path.dirname(path_from)
        old_parent = FSKey(self.m.fs, path=parent_path)
        old_parent_id = old_parent['node_id']
        new_path = os.path.dirname(path_to)
        new_name = os.path.basename(path_to)
        new_parent = FSKey(self.m.fs, path=new_path)
        new_parent_id = new_parent['node_id']
        share_id = self.key['share_id']
        node_id = self.key['node_id']

        # fix first the PathLockTree, so the move hooks on it's final
        # path, if any
        self.m.action_q.pathlock.fix_path(tuple(path_from.split(os.path.sep)),
                                          tuple(path_to.split(os.path.sep)))

        self.m.action_q.move(share_id, node_id, old_parent_id,
                             new_parent_id, new_name, path_from, path_to)
        self.m.fs.add_to_move_limbo(share_id, node_id, old_parent_id,
                                    new_parent_id, new_name,
                                    path_from, path_to)
        self.key.moved(share_id, path_to)

        # we only hash it if we're a file, not a directory
        if not self.key.is_dir():
            self.m.hash_q.insert(self.key['path'], self.key['mdid'])

    def server_file_changed_back(self, event, params, hash):
        """cancel and dont reget this download."""
        self.key.set(server_hash=hash)
        self.key.sync()
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()

    def commit_file(self, event, params, hash):
        """commit the new content."""
        key = self.key
        try:
            self.m.fs.commit_partial(key['node_id'], key['share_id'], hash)
        except InconsistencyError:
            # someone or something broke out partials, log in warning
            # and LR will take care and converge in the future
            self.log.warning("Lost .partial when commiting node! volume_id=%r "
                             "node_id=%r", key['share_id'], key['node_id'])

    def new_local_file(self, event, parms, path):
        """a new local file was created"""
        parent_path = os.path.dirname(path)
        parent = self.m.fs.get_by_path(parent_path)
        parent_id = parent.node_id or MDMarker(parent.mdid)
        share_id = parent.share_id
        self.m.fs.create(path=path, share_id=share_id, is_dir=False)
        self.key.set(local_hash=empty_hash)
        self.key.set(server_hash=empty_hash)
        self.key.sync()
        name = os.path.basename(path)
        mdid = self.key.get_mdid()
        marker = MDMarker(mdid)
        self.m.action_q.make_file(share_id, parent_id, name, marker, mdid)

    def release_marker_ok(self, event, parms, new_id, marker):
        """Release ok the received marker in AQ's DeferredMap."""
        self.m.action_q.uuid_map.set(marker, new_id)
        self.m.fs.dereference_ok_limbos(marker, new_id)

    def release_marker_error(self, event, parms, failure, marker):
        """Release with error the received marker in AQ's DeferredMap."""
        self.m.action_q.uuid_map.err(marker, failure)
        self.m.fs.dereference_err_limbos(marker)

    def new_local_file_created(self, event, parms, new_id, marker):
        """We got the server answer for the file creation."""
        self.m.action_q.uuid_map.set(marker, new_id)
        self.m.fs.set_node_id(self.key['path'], new_id)

    def new_server_file_having_local(self, event, parms, share_id, node_id,
                                     parent_id, name):
        """Got new file from server, we have it local but without id yet."""
        self.m.fs.set_node_id(self.key['path'], node_id)

    def new_local_dir(self, event, parms, path):
        """a new local dir was created"""
        parent_path = os.path.dirname(path)
        parent = self.m.fs.get_by_path(parent_path)
        parent_id = parent.node_id or MDMarker(parent.mdid)
        share_id = parent.share_id
        self.m.fs.create(path=path, share_id=share_id, is_dir=True)
        name = os.path.basename(path)
        mdid = self.key.get_mdid()
        marker = MDMarker(mdid)
        self.m.action_q.make_dir(share_id, parent_id, name, marker, mdid)
        self.m.lr.scan_dir(mdid, path)

    def new_local_dir_created(self, event, parms, new_id, marker):
        """Server answered that dir creation was ok."""
        self.m.action_q.uuid_map.set(marker, new_id)
        self.m.fs.set_node_id(self.key['path'], new_id)

    def calculate_hash(self, event, params):
        """calculate the hash of this."""
        self.m.hash_q.insert(self.key['path'], self.key['mdid'])

    def rescan_dir(self, event, parms, udfmode):
        """Starts the scan again on a dir."""
        self.m.lr.scan_dir(self.key['mdid'], self.key['path'], udfmode)

    def reput_file_from_local(self, event, params, hash_value):
        """Re put the file from its local state."""
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])

        mdid = self.key.get_mdid()
        local_hash = self.key['local_hash']
        previous_hash = self.key['server_hash']
        crc32 = self.key['crc32']
        size = self.key['size']
        share_id = self.key['share_id']
        node_id = self.key['node_id']
        upload_id = self.key.get('upload_id')

        self.m.action_q.upload(share_id, node_id, previous_hash, local_hash,
                               crc32, size, mdid, upload_id=upload_id)

    def put_file(self, event, params, current_hash, crc32, size, stat):
        """Upload the file to the server."""
        mdid = self.key.get_mdid()
        share_id = self.key['share_id']
        node_id = self.key['node_id']
        previous_hash = self.key['server_hash']
        upload_id = self.key.get('upload_id')
        self.key.set(
            local_hash=current_hash, stat=stat, crc32=crc32, size=size)
        self.key.sync()

        self.m.action_q.upload(share_id, node_id, previous_hash, current_hash,
                               crc32, size, mdid, upload_id=upload_id)

    def converges_to_server(self, event, params, hash, crc32, size, stat):
        """the local changes now match the server"""
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.key.set(local_hash=hash, stat=stat)
        self.key.sync()

    def reput_file_from_ok(self, event, param, hash):
        """put the file again, mark upload as ok"""
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])
        self.key.set(local_hash=hash)
        self.key.set(server_hash=hash)
        self.key.sync()
        self.m.hash_q.insert(self.key['path'], self.key['mdid'])

    def reput_file(self, event, param, current_hash, crc32, size, stat):
        """Put the file again."""
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])
        previous_hash = self.key['server_hash']

        share_id = self.key['share_id']
        node_id = self.key['node_id']
        upload_id = self.key.get('upload_id')
        self.key.set(local_hash=current_hash, stat=stat,
                     crc32=crc32, size=size)
        self.key.sync()
        mdid = self.key.get_mdid()
        self.m.action_q.upload(share_id, node_id, previous_hash, current_hash,
                               crc32, size, mdid, upload_id=upload_id)

    def server_file_now_matches(self, event, params, hash):
        """We got a server hash that matches local hash"""
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])
        self.key.set(server_hash=hash)
        self.key.sync()

    def commit_upload(self, event, params, hash):
        """Finish an upload."""
        self.key.upload_finished(hash)

    def cancel_and_commit(self, event, params, hash):
        """Finish an upload."""
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.key.upload_finished(hash)

    def delete_file(self, event, params, *args, **kwargs):
        """server file was deleted."""
        try:
            self.key.delete_file()
        except DirectoryNotRemovable:
            # directory not empty and with stuff that should not be deleted
            self.key.move_to_conflict()
            self.key.delete_metadata()
        except OSError, e:
            if e.errno == 2:
                # file gone
                pass
            else:
                raise e

    def conflict_and_delete(self, event, params, *args, **kwargs):
        """move to conflict and delete file."""
        self.key.move_to_conflict()
        self.key.delete_metadata()

    def file_gone_wile_downloading(self, event, params):
        """a file we were downloading is gone."""
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.delete_file(event, params)

    def filedir_error_in_creation(self, event, params, failure, marker):
        """Move actual content to conflict, and delete the metadata."""
        self.m.action_q.uuid_map.err(marker, failure)
        self.key.move_to_conflict()
        self.key.delete_metadata()

    def delete_on_server(self, event, params, path):
        """local file was deleted."""
        is_dir = self.key.is_dir()
        self.m.action_q.unlink(self.key['share_id'],
                               self.key['parent_id'],
                               self.key['node_id'], path, is_dir)
        self.key.delete_to_trash()

    def deleted_dir_while_downloading(self, event, params, path):
        """kill it"""
        is_dir = self.key.is_dir()
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.m.action_q.unlink(self.key['share_id'],
                               self.key['parent_id'],
                               self.key['node_id'], path, is_dir)
        self.key.delete_to_trash()

    def cancel_download_and_delete_on_server(self, event, params, path):
        """cancel_download_and_delete_on_server"""
        is_dir = self.key.is_dir()
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.m.action_q.unlink(self.key['share_id'],
                               self.key['parent_id'],
                               self.key['node_id'], path, is_dir)
        self.key.delete_to_trash()

    def cancel_upload_and_delete_on_server(self, event, params, path):
        """cancel_download_and_delete_on_server"""
        is_dir = self.key.is_dir()
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])
        self.m.action_q.unlink(self.key['share_id'],
                               self.key['parent_id'],
                               self.key['node_id'], path, is_dir)
        self.key.delete_to_trash()

    def remove_trash(self, event, params, share_id, node_id):
        """Remove the node from trash."""
        self.key.remove_from_trash(share_id, node_id)

    def clean_move_limbo(self, event, params, share_id, node_id):
        """Remove the node from move limbo."""
        self.m.fs.remove_from_move_limbo(share_id, node_id)

    def server_moved(self, event, params, share_id, node_id,
                     new_share_id, new_parent_id, new_name):
        """file was moved on the server"""
        self.key.move_file(new_share_id, new_parent_id, new_name)

    def server_moved_dirty(self, event, params, share_id, node_id,
                           new_share_id, new_parent_id, new_name):
        """file was moved on the server while downloading it"""
        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.key.move_file(new_share_id, new_parent_id, new_name)
        self.get_file(event, params, self.key['server_hash'])

    def moved_dirty_local(self, event, params, path_from, path_to):
        """file was moved while uploading it"""
        self.m.action_q.cancel_upload(share_id=self.key['share_id'],
                                      node_id=self.key['node_id'])
        self.key.set(local_hash=self.key['server_hash'])
        self.key.sync()
        self.client_moved(event, params, path_from, path_to)

    def moved_dirty_server(self, event, params, path_from, path_to):
        """file was moved while downloading it"""
        self.client_moved(event, params, path_from, path_to)

        self.m.action_q.cancel_download(share_id=self.key['share_id'],
                                        node_id=self.key['node_id'])
        self.key.remove_partial()
        self.key.set(server_hash=self.key['local_hash'])
        self.key.sync()

    def DESPAIR(self, event, params, *args, **kwargs):
        """if we got here, we are in trouble"""
        self.log.error("DESPAIR on event=%s params=%s args=%s kwargs=%s",
                       event, params, args, kwargs)

    def save_stat(self, event, params, hash, crc32, size, stat):
        """Save the stat"""
        self.key.set(stat=stat)
        self.key.sync()

    def remove_partial(self, event, params, error=None, server_hash=''):
        """remove the .partial file"""
        self.key.remove_partial()
        local_hash = self.key['local_hash']
        self.key.set(server_hash=local_hash, local_hash=local_hash)
        self.key.sync()


class Sync(object):
    """Translates from EQ events into state machine events."""
    # XXX: lucio.torre:
    # this will need some refactoring once we handle more events

    fsm = None

    def __init__(self, main):
        """create"""
        # XXX: verterok: add a custom Logger to lazyily build the LogRecord,
        # now that the DebugCapture is enabled
        self.logger = logging.getLogger('ubuntuone.SyncDaemon.sync')
        self.broken_logger = logging.getLogger(
            'ubuntuone.SyncDaemon.BrokenNodes')
        if Sync.fsm is None:
            Sync.fsm = StateMachine(u1fsfsm.state_machine)
        self.m = main
        self.m.event_q.subscribe(self)

    def mark_node_as_dirty(self, volume_id, node_id):
        """Mark the node as dirty, log, and send the event."""
        try:
            mdobj = self.m.fs.get_by_node_id(volume_id, node_id)
        except KeyError:
            # node was not created
            path = None
            mdid = None
        else:
            path = mdobj.path
            mdid = mdobj.mdid
            self.m.fs.set_by_mdid(mdobj.mdid, dirty=True)

        # send the event
        self.m.event_q.push('SYS_BROKEN_NODE', volume_id=volume_id,
                            node_id=node_id, path=path, mdid=mdid)
        m = "Broken node: volume_id=%r node_id=%r mdid=%r path=%r"
        self.broken_logger.info(m, volume_id, node_id, mdid, path)

    def _handle_SV_HASH_NEW(self, share_id, node_id, hash):
        """on SV_HASH_NEW.  No longer called by EQ, only internally."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)

        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        if hash == "":
            # Special case for hash == "", aka broken node.
            # Set the server_hash = hash to force LOCAL state
            key.set(server_hash=hash)
            key.sync()
        ssmr.signal_event_with_hash("SV_HASH_NEW", hash)

    def _handle_SV_FILE_NEW(self, share_id, node_id, parent_id, name):
        """on SV_FILE_NEW"""
        parent = FSKey(self.m.fs, share_id=share_id, node_id=parent_id)
        path = os.path.join(parent["path"], name)
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)

        # check if the node found by path has other node_id (which will
        # cause a conflict); note that we don't get the node_id from the
        # 'key' as it lies to us with the marker
        try:
            mdid = key.get_mdid()
        except KeyError:
            pass  # no md at all, didn't find any node by the path
        else:
            mdobj = self.m.fs.get_by_mdid(mdid)
            if mdobj.node_id is not None:
                if mdobj.node_id == node_id:
                    raise ValueError("Found same node_id in handle_SV_FILE_NEW"
                                     " (node_id=%s path=%r)" % (node_id, path))
                # have metadata with *other* node_id
                log.debug("Wanted to apply SV_FILE_NEW with node_id %s to node"
                          "with path %r, but found it with other id: %s",
                          node_id, path, mdobj.node_id)
                key.delete_file()
                return None

        ssmr.on_event("SV_FILE_NEW", {}, share_id, node_id, parent_id, name)
        self.m.event_q.push('SV_FILE_NEW', volume_id=share_id,
                            node_id=node_id, parent_id=parent_id, name=name)
        return self.m.fs.get_by_node_id(share_id, node_id)

    def _handle_SV_DIR_NEW(self, share_id, node_id, parent_id, name):
        """on SV_DIR_NEW"""
        parent = FSKey(self.m.fs, share_id=share_id, node_id=parent_id)
        path = os.path.join(parent["path"], name)
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("SV_DIR_NEW", {}, share_id, node_id, parent_id, name)
        self.m.event_q.push('SV_DIR_NEW', volume_id=share_id,
                            node_id=node_id, parent_id=parent_id, name=name)
        return self.m.fs.get_by_node_id(share_id, node_id)

    def _handle_SV_FILE_DELETED(self, share_id, node_id, is_dir):
        """on SV_FILE_DELETED. Not called by EQ anymore."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        try:
            path = key["path"]
        except KeyError:
            path = ""
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("SV_FILE_DELETED", {})
        self.m.event_q.push('SV_FILE_DELETED', volume_id=share_id,
                            node_id=node_id, was_dir=is_dir,
                            old_path=path)

    def handle_AQ_DOWNLOAD_FINISHED(self, share_id, node_id, server_hash):
        """on AQ_DOWNLOAD_FINISHED"""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.signal_event_with_hash("AQ_DOWNLOAD_FINISHED", server_hash)

    def handle_AQ_DOWNLOAD_ERROR(self, share_id, node_id, server_hash, error):
        """on AQ_DOWNLOAD_ERROR"""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.signal_event_with_error_and_hash("AQ_DOWNLOAD_ERROR", error,
                                              server_hash)

    def handle_AQ_DOWNLOAD_DOES_NOT_EXIST(self, share_id, node_id):
        """on AQ_DOWNLOAD_DOES_NOT_EXIST."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_DOWNLOAD_DOES_NOT_EXIST", {}, share_id, node_id)

    def handle_FS_FILE_CREATE(self, path):
        """on FS_FILE_CREATE"""
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_FILE_CREATE on path %r discarded because of "
                      "volume not subscribed", path)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("FS_FILE_CREATE", {}, path)

    def handle_FS_DIR_CREATE(self, path):
        """on FS_DIR_CREATE"""
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_DIR_CREATE on path %r discarded because of "
                      "volume not subscribed", path)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("FS_DIR_CREATE", {}, path)

    def handle_FS_FILE_DELETE(self, path):
        """on FS_FILE_DELETE"""
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_FILE_DELETE on path %r discarded because of "
                      "volume not subscribed", path)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("FS_FILE_DELETE", {}, path)

    def handle_FS_DIR_DELETE(self, path):
        """on FS_DIR_DELETE"""
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_DIR_DELETE on path %r discarded because of "
                      "volume not subscribed", path)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("FS_DIR_DELETE", {}, path)

    def handle_FS_FILE_MOVE(self, path_from, path_to):
        """on FS_FILE_MOVE"""
        key = FSKey(self.m.fs, path=path_from)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_FILE_MOVE on path %r discarded because of "
                      "volume not subscribed", path_from)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("FS_FILE_MOVE", {}, path_from, path_to)

    def handle_FS_DIR_MOVE(self, path_from, path_to):
        """on FS_DIR_MOVE"""
        key = FSKey(self.m.fs, path=path_from)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_DIR_MOVE on path %r discarded because of "
                      "volume not subscribed", path_from)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("FS_DIR_MOVE", {}, path_from, path_to)

    def handle_AQ_FILE_NEW_OK(self, volume_id, marker, new_id, new_generation):
        """On AQ_FILE_NEW_OK."""
        key = FSKey(self.m.fs, mdid=marker)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_FILE_NEW_OK", {}, new_id, marker)
        ssmr.update_generation(volume_id, new_id, new_generation)

    def handle_AQ_FILE_NEW_ERROR(self, marker, failure):
        """on AQ_FILE_NEW_ERROR"""
        key = FSKey(self.m.fs, mdid=marker)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.signal_event_with_error("AQ_FILE_NEW_ERROR", failure, marker)

    def handle_AQ_DIR_NEW_ERROR(self, marker, failure):
        """on AQ_DIR_NEW_ERROR"""
        key = FSKey(self.m.fs, mdid=marker)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.signal_event_with_error("AQ_DIR_NEW_ERROR", failure, marker)

    def handle_AQ_DIR_NEW_OK(self, volume_id, marker, new_id, new_generation):
        """On AQ_DIR_NEW_OK."""
        key = FSKey(self.m.fs, mdid=marker)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_DIR_NEW_OK", {}, new_id, marker)
        ssmr.update_generation(volume_id, new_id, new_generation)

    def handle_FS_FILE_CLOSE_WRITE(self, path):
        """on FS_FILE_CLOSE_WRITE"""
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        if not key.is_subscribed():
            log.debug("FS_FILE_CLOSE_WRITE on path %r discarded because of "
                      "volume not subscribed", path)
            return
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event('FS_FILE_CLOSE_WRITE', {})

    def handle_LR_SCAN_ERROR(self, mdid, udfmode):
        """on LR_SCAN_ERROR"""
        key = FSKey(self.m.fs, mdid=mdid)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event('LR_SCAN_ERROR', {}, udfmode)

    def handle_HQ_HASH_ERROR(self, mdid):
        """on HQ_HASH_ERROR"""
        key = FSKey(self.m.fs, mdid=mdid)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event('HQ_HASH_ERROR', {})

    def handle_HQ_HASH_NEW(self, path, hash, crc32, size, stat):
        """on HQ_HASH_NEW."""
        key = FSKey(self.m.fs, path=path)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        try:
            data_ok = ssmr.validate_actual_data(path, stat)
        except OSError, e:
            # the file went away between the moment HQ finished and now, we
            # discard the info, but needs to send to rehash.
            log.debug("Changing HQ_HASH_NEW to ERROR in %r: %s", path, e)
            ssmr.on_event('HQ_HASH_ERROR', {})
        else:
            if data_ok:
                ssmr.signal_event_with_hash("HQ_HASH_NEW", hash,
                                            crc32, size, stat)

    def handle_AQ_UPLOAD_FINISHED(self, share_id, node_id, hash,
                                  new_generation):
        """On AQ_UPLOAD_FINISHED."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.signal_event_with_hash("AQ_UPLOAD_FINISHED", hash)
        ssmr.update_generation(share_id, node_id, new_generation)

    def handle_AQ_UPLOAD_ERROR(self, share_id, node_id, error, hash):
        """on AQ_UPLOAD_ERROR"""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.signal_event_with_error_and_hash("AQ_UPLOAD_ERROR", error, hash)

    def _handle_SV_MOVED(self, share_id, node_id, new_share_id, new_parent_id,
                         new_name):
        """on SV_MOVED"""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("SV_MOVED", {}, share_id, node_id, new_share_id,
                      new_parent_id, new_name)

    def handle_AQ_UNLINK_OK(self, share_id, parent_id, node_id,
                            new_generation, was_dir, old_path):
        """On AQ_UNLINK_OK."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_UNLINK_OK", {}, share_id, node_id)
        ssmr.update_generation(share_id, node_id, new_generation)

    def handle_AQ_UNLINK_ERROR(self, share_id, parent_id, node_id, error):
        """on AQ_UNLINK_ERROR"""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_UNLINK_ERROR", {}, share_id, node_id)

    def handle_AQ_MOVE_OK(self, share_id, node_id, new_generation):
        """On AQ_MOVE_OK."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_MOVE_OK", {}, share_id, node_id)
        ssmr.update_generation(share_id, node_id, new_generation)

    def handle_AQ_MOVE_ERROR(self, share_id, node_id, old_parent_id,
                             new_parent_id, new_name, error):
        """On AQ_MOVE_ERROR."""
        key = FSKey(self.m.fs, share_id=share_id, node_id=node_id)
        log = FileLogger(self.logger, key)
        ssmr = SyncStateMachineRunner(self.fsm, self.m, key, log)
        ssmr.on_event("AQ_MOVE_ERROR", {}, share_id, node_id)

    def handle_AQ_DELTA_OK(self, volume_id, delta_content, end_generation,
                           full, free_bytes):
        """We got a new delta. Apply item by item of the delta.

        Unlike other Sync methods that just defer to Sync State Machine Runner,
        delta operations sync state in a different way. So this method has a
        lot of logic that you will not see in the other event handlers.
        """

        self.logger.info(
            "handle_AQ_DELTA_OK for volume %s. (%s items)",
            volume_id, len(delta_content))

        to_delete = []

        for dt in delta_content:
            # we only know how to update files
            try:
                if not isinstance(dt, delta.FileInfoDelta):
                    continue
                # Unicode boundary, convert dt.name
                dt_name = dt.name.encode('utf-8')
                # we only support files and directories
                if dt.file_type == delta.DIRECTORY:
                    is_dir = True
                elif dt.file_type == delta.FILE:
                    is_dir = False
                else:
                    self.logger.warn("Unknown file type: %r", dt.file_type)
                    continue

                # if the node is dead, call the remove handler and forget
                # about it
                if not dt.is_live:
                    to_delete.append(dt)
                    self._handle_SV_FILE_DELETED(dt.share_id, dt.node_id,
                                                 is_dir)
                    # nothing else should happen with this
                    continue

                # here we must call handlers for SV_HASH_NEW, SV_MOVED
                try:
                    node = self.m.fs.get_by_node_id(dt.share_id, dt.node_id)
                except KeyError:
                    # if we're deleting this node right now, just ignore it
                    # from the received delta
                    if self.m.fs.node_in_trash(dt.share_id, dt.node_id):
                        continue

                    # node not there, we must create it
                    args = (dt.share_id, dt.node_id, dt.parent_id, dt_name)
                    if is_dir:
                        node = self._handle_SV_DIR_NEW(*args)
                    else:
                        node = self._handle_SV_FILE_NEW(*args)
                    if node is None:
                        # the node was not created!
                        continue

                # if the delta is older than the node, skip!
                if node.generation > dt.generation:
                    continue

                # if the path changed, we have a move, notify it
                path_parent_name = os.path.dirname(node.path)
                abs_parent_path = self.m.fs.get_abspath(node.share_id,
                                                        path_parent_name)
                node_parent_id = self.m.fs.get_by_path(abs_parent_path).node_id
                node_name = os.path.basename(node.path)
                if dt.parent_id != node_parent_id or \
                        dt_name != node_name:
                    # this was moved, or maybe the server still didn't receive
                    # the move that happened here
                    if not self.m.action_q.node_is_with_queued_move(
                            dt.share_id, dt.node_id):
                        # signal moved
                        self._handle_SV_MOVED(
                            share_id=node.share_id, node_id=node.node_id,
                            new_share_id=dt.share_id,
                            new_parent_id=dt.parent_id, new_name=dt_name)
                    else:
                        self.logger.info("Not calling _handle_SV_MOVED for "
                                         "%s:%s due to pending move. "
                                         "(old parent = %s, new_parent = %s "
                                         "old_name = %s, new_name = %s)",
                                         node.share_id, node.node_id,
                                         node_parent_id, dt.parent_id,
                                         node_name, dt_name)

                # if its a dir, theres nothing else that we do with them except
                # creating them.
                # if its a file, we only care about the hash
                if not is_dir:
                    self._handle_SV_HASH_NEW(dt.share_id, dt.node_id,
                                             dt.content_hash)

                # node updated, update generation
                self.m.fs.set_by_mdid(node.mdid, generation=dt.generation)
            except Exception:
                # we trap all exceptions so we can continue processing deltas
                # even if something fails for one file.
                # Let's log
                self.logger.exception(
                    "Node delta for %s:%s can't be applied.",
                    dt.share_id, dt.node_id)

                # And mark the node as dirty
                self.mark_node_as_dirty(dt.share_id, dt.node_id)

        self.m.vm.update_free_space(volume_id, free_bytes)
        self.m.vm.update_generation(volume_id, end_generation)

        if not full:
            self.m.action_q.get_delta(volume_id, end_generation)

        self.logger.info(
            "handle_AQ_DELTA_OK for volume %r done at generation %s. "
            "(%s deletes)",
            volume_id, end_generation, len(to_delete))

    def handle_AQ_RESCAN_FROM_SCRATCH_OK(self, volume_id, delta_content,
                                         end_generation, free_bytes):
        """Handle rescan from scratch."""

        self.logger.info(
            "Applying rescan from scratch for volume %s. (%s items)",
            volume_id, len(delta_content))

        # remove root and apply the delta
        new_delta_content = [dt for dt in delta_content if dt.parent_id]

        self.handle_AQ_DELTA_OK(volume_id, new_delta_content, end_generation,
                                True, free_bytes)

        self.logger.info(
            "Rescan from scratch apply delta for volume %s done.",
            volume_id)
        # get all nodes sorted by path and reversed
        live_nodes = set(dt.node_id for dt in delta_content)
        all_nodes = list(self.m.fs.get_mdobjs_by_share_id(volume_id))
        all_nodes.sort(key=attrgetter("path"), reverse=True)

        # remove all nodes not in the delta
        # skip nodes that dont yet have node id, they are in process
        deletes = 0
        for node in all_nodes:
            node_id = node.node_id

            if node_id is None:
                continue

            if node_id not in live_nodes:
                self._handle_SV_FILE_DELETED(volume_id, node_id, node.is_dir)
                deletes += 1

        self.logger.info(
            "Rescan from scratch for volume %s done. (%s deletes)",
            volume_id, deletes)
