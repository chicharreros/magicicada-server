#!/usr/bin/python
# Copyright (C) 2009-2012 Canonical Ltd.
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
"""
Dumps all the metadata.

Usage:

  dump_metadata.py <directory with vm and fsm subdirs>

"""

from __future__ import with_statement

import os
import sys

from ubuntuone.syncdaemon import (
    filesystem_manager,
    tritcask,
    volume_manager,
)
from dirspec.basedir import (
    xdg_cache_home,
    xdg_data_home,
)


class FakeVM(object):
    """Some functionality needed from VM, without starting a new world."""

    def __init__(self, data_dir, db):
        # paths
        data_dir = os.path.join(data_dir, 'vm')
        version_file = os.path.join(data_dir, '.version')

        # check version
        with open(version_file) as fh:
            version_found = fh.read()
        version_should = volume_manager.VolumeManager.METADATA_VERSION
        if  version_found is None or version_found != version_should:
            print "The VolumeManager metadata version is too old (or too new?)"
            print "      it should be:", repr(version_should)
            print "      found:", repr(version_found)
            exit(-1)

        self.shares = volume_manager.VMTritcaskShelf(volume_manager.SHARE_ROW_TYPE, db)
        self.shared = volume_manager.VMTritcaskShelf(volume_manager.SHARED_ROW_TYPE, db)
        self.udfs = volume_manager.VMTritcaskShelf(volume_manager.UDF_ROW_TYPE, db)

    def get_volume(self, vol_id):
        """Gets the volume."""
        if vol_id in self.udfs:
            return self.udfs[vol_id]
        else:
            return self.shares[vol_id]

def main(data_dir):
    """Dump the metadata to stdout."""
    # start the players
    tritcask_dir = os.path.join(data_dir, 'tritcask')
    db = tritcask.Tritcask(tritcask_dir)
    vm = FakeVM(data_dir, db)
    partials_dir = os.path.join(xdg_cache_home, 'ubuntuone', 'partials')
    fsm = filesystem_manager.FileSystemManager(data_dir, partials_dir, vm, db)

    shares = []
    root = None
    for share_id in vm.shares:
        share = vm.shares[share_id]
        if isinstance(share, volume_manager.Root):
            root = share
        else:
            shares.append(share)
    assert root is not None

    def show_data(volume_id):
        """Shows the info for the volume."""
        mdobjs = []
        for mdobj in fsm.get_mdobjs_by_share_id(volume_id):
            mdobjs.append((repr(mdobj.path), mdobj))
        mdobjs = [x[1] for x in sorted(mdobjs)]

        for mdobj in mdobjs:
            filedir = "DIR " if mdobj.is_dir else "FILE"
            print "  mdid=%r  node_id=%r crc32=%s local_hash=%s server_hash=%s %s  %r" % (
                mdobj.mdid, mdobj.node_id,
                getattr(mdobj, 'crc32', '**No crc32**'),
                getattr(mdobj, 'local_hash', '**No local_hash**'),
                getattr(mdobj, 'server_hash', '**No server_hash**'),
                filedir, mdobj.path)

    print "\nShowing Root: %r (id=%r)" % (root.path, root.id)
    show_data(root.id)

    for udf_id in vm.udfs:
        udf = vm.udfs[udf_id]
        print "\nShowing UDF: %r (id=%r)" % (udf.path, udf_id)
        show_data(udf_id)

    for share in shares:
        print "\nShowing Share: %r (id=%r)" % (share.path, share.id)
        show_data(share.id)

    print "\nShowing trash:"
    something = False
    for (vol_id, node_id), (mdid, parent_id, path, is_dir) in \
                                                        fsm.trash.iteritems():
        something = True
        print ("  mdid=%r  volume_id=%r  node_id=%r  parent_id=%r  path=%r "
               "is_dir=%r" % (mdid, share_id, node_id, parent_id, path, is_dir))
    if not something:
        print "  (empty)"

    print "\nShowing move limbo:"
    something = False
    for key, value in fsm.move_limbo.iteritems():
        something = True
        if len(value) == 3:
            # old move limbo, without paths
            print ("  volume_id=%r  node_id=%r  old_parent_id=%r  "
                   "new_parent_id=%r  new_name=%r" % (key + value))
        else:
            print ("  volume_id=%r  node_id=%r  old_parent_id=%r  "
                   "new_parent_id=%r  new_name=%r  path_from=%r  path_to=%r" %
                   (key + value))
    if not something:
        print "  (empty)"

    print "\nDone."


if __name__ == "__main__":
    if len(sys.argv) == 1:
        basedir = os.path.join(xdg_data_home, 'ubuntuone', 'syncdaemon')
    elif len(sys.argv) == 2:
        basedir = sys.argv[1]
    else:
        print __doc__
        sys.exit()

    main(basedir)
