# ubuntuone.syncdaemon.hash_queue - hash queues
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
"""Module that implements the Events Nanny machinery."""

import logging


class DownloadFinishedNanny(object):
    """Supervises the download finished signals.

    It listens AQ_DOWNLOAD_COMMIT, and generates AQ_DOWNLOAD_FINISHED when
    the external world is ready for it.
    """
    def __init__(self, fsm, eq, hq):
        self.logger = logging.getLogger(
            'ubuntuone.SyncDaemon.DownloadFinishedNanny')
        self.fsm = fsm
        self.eq = eq
        self.hq = hq
        eq.subscribe(self)

        # need to use a dict, to keep how many simultaneous opens we receive
        self._opened = {}

        # we know a file is being hashed between CLOSE_WRITE and HASH results
        # (also always ask to the HQ, because a hash can be triggered by other
        # events)
        self._hashing = set()

        # keep here those events we blocked
        self._blocked = {}

    def eq_push(self, share_id, node_id, server_hash):
        """Push the event to EQ."""
        self.eq.push("AQ_DOWNLOAD_FINISHED", share_id=share_id,
                     node_id=node_id, server_hash=server_hash)

    def handle_FS_DIR_MOVE(self, path_from, path_to):
        """Receives DIR_MOVE to change paths."""
        # add a "/" to path_from, to be nice to partial names
        path_from += "/"

        def fix(d):
            """Fixes the dict."""
            for path in d:
                if path.startswith(path_from):
                    info = d.pop(path)
                    d[path_to + path[len(path_from) - 1:]] = info
        fix(self._opened)
        fix(self._blocked)

    def handle_FS_FILE_MOVE(self, path_from, path_to):
        """Receives FILE_MOVE to change paths."""
        def fix(d):
            """Fixes the dict."""
            if path_from in d:
                info = d.pop(path_from)
                d[path_to] = info
        fix(self._opened)
        fix(self._blocked)

    def handle_FS_FILE_DELETE(self, path):
        """Receives DELETE to discard possible blocks and open counts."""
        if path in self._opened:
            del self._opened[path]
        if path in self._blocked:
            del self._blocked[path]

    def handle_FS_FILE_CREATE(self, path):
        """Receives CREATE to discard possible blocks and open counts."""
        if path in self._opened:
            del self._opened[path]
        if path in self._blocked:
            del self._blocked[path]

    def handle_FS_FILE_OPEN(self, path):
        """Receives OPEN to update the opened paths."""
        self._opened[path] = self._opened.get(path, 0) + 1

    def handle_FS_FILE_CLOSE_WRITE(self, path):
        """Receives CLOSE_WRITE.

        It updates the opened paths. We don't release the event here, as
        that is done when the HQ_HASH_NEW arrives.
        """
        self._hashing.add(path)

        try:
            self._reduce_opened(path)
        except KeyError:
            # it wasn't supervised by open
            return

    def handle_FS_FILE_CLOSE_NOWRITE(self, path):
        """Receives CLOSE_NOWRITE.

        It updates the opened paths, and maybe releases a blocked event.
        """
        try:
            opened = self._reduce_opened(path)
        except KeyError:
            # it wasn't supervised
            return

        # release if not opened any more
        if not opened:
            self._release(path, "closed")

    def _reduce_opened(self, path):
        """Reduces opened in 1, deleting it from the dict if in 0."""
        opened = self._opened[path]
        opened -= 1
        if opened:
            # still opened
            self._opened[path] = opened
        else:
            # not open any more! remove the supervision
            del self._opened[path]
        return opened

    def handle_HQ_HASH_NEW(self, path, hash, crc32, size, stat):
        """Receives HASH_NEW, maybe releases a blocked event."""
        if path in self._hashing:
            self._hashing.remove(path)
        self._release(path, "hashed")

    def _release(self, path, why):
        """Release the event if it was blocked."""
        # something to release?
        if path not in self._blocked:
            return
        share_id, node_id, server_hash = self._blocked[path]

        # is it opened or being hashed?
        if path in self._opened or path in self._hashing:
            return

        # get the mdobj to retrieve further info
        try:
            mdobj = self.fsm.get_by_node_id(share_id, node_id)
        except KeyError:
            # the node is gone, just clean blocked
            del self._blocked[path]
            return

        # is it being hashed?
        abspath = self.fsm.get_abspath(share_id, mdobj.path)
        if self.hq.is_hashing(abspath, node_id):
            return

        # ok, so we unblock and release it!
        del self._blocked[path]
        self.logger.debug("Released! (%s)  path %r  share %r  "
                          "node %r  server_hash %s", why,
                          path, share_id, node_id, server_hash)
        self.eq_push(share_id, node_id, server_hash)

    def handle_AQ_DOWNLOAD_COMMIT(self, share_id, node_id, server_hash):
        """The download is ready to finish."""
        # get the mdobj from FSM
        try:
            mdobj = self.fsm.get_by_node_id(share_id, node_id)
        except KeyError:
            # the node is gone.. we just forward the message for Sync to
            # handle this
            self.logger.debug("Forwarded (no MD)  share %r  node %r",
                              share_id, node_id)
            self.eq_push(share_id, node_id, server_hash)
            return

        abspath = self.fsm.get_abspath(share_id, mdobj.path)
        if abspath in self._opened:
            self.logger.debug("Blocked! (opened)  share %r  node %r  path %r",
                              share_id, node_id, abspath)
            self._blocked[abspath] = (share_id, node_id, server_hash)
        elif self.hq.is_hashing(abspath, node_id):
            self.logger.debug("Blocked! (hashing)  share %r  node %r  path %r",
                              share_id, node_id, abspath)
            self._blocked[abspath] = (share_id, node_id, server_hash)
        else:
            self.logger.debug("Forwarded!  share %r  node %r  path %r",
                              share_id, node_id, abspath)
            self.eq_push(share_id, node_id, server_hash)
