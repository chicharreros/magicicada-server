# -*- coding: utf-8 -*-
#
# Copyright 2009-20112 Canonical Ltd.
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
"""Tests for the syncdaemon u1sdtool script."""

import os

from operator import itemgetter
from StringIO import StringIO

from twisted.internet import defer

from contrib.testing.testcase import (
    FakeCommand,
    FakeDownload,
    FakeUpload,
)
from ubuntuone.syncdaemon.vm_helper import get_udf_path
from ubuntuone.syncdaemon.volume_manager import (
    ACCESS_LEVEL_RO,
    Share,
    UDF,
)
from ubuntuone.platform.tools import (
    show_dirty_nodes,
    show_downloads,
    show_folders,
    show_free_space,
    show_path_info,
    show_shared,
    show_shares,
    show_state,
    show_uploads,
    show_waiting,
    show_waiting_content,
    show_waiting_metadata,
)
from ubuntuone.platform.tests.test_tools import TestToolsBase


class U1SDToolTests(TestToolsBase):
    """Tests for u1sdtool output"""

    def test_show_shares_empty(self):
        """test the output of --list-shared """
        out = StringIO()
        d = self.tool.get_shares()
        d.addCallback(lambda result: show_shares(result, out))

        def check(result):
            """check the output"""
            self.assertEqual('No shares\n', out.getvalue())
        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_show_shares(self):
        """test the output of --list-shared """
        out = StringIO()
        share_path = os.path.join(self.shares_dir, u"ñoño".encode('utf-8'))
        share = Share(path=share_path, name=u"ñoño", volume_id='share_id',
                      access_level=ACCESS_LEVEL_RO, other_username='fake_user',
                      other_visible_name=u"ñoño", accepted=False,
                      subscribed=False)
        yield self.main.vm.add_share(share)
        expected = (
            u"Shares list:\n id=share_id name=\xf1o\xf1o accepted=False "
            u"subscribed=False access_level=View from=fake_user\n")
        result = yield self.tool.get_shares()
        show_shares(result, out)
        self.assertEqual(out.getvalue(), expected)

    def test_show_shared_empty(self):
        """test the output of --list-shared """
        out = StringIO()
        d = self.tool.list_shared()
        d.addCallback(lambda result: show_shared(result, out))

        def check(result):
            """check the output"""
            self.assertEqual('No shared\n', out.getvalue())
        d.addCallback(check)
        return d

    def test_show_shared(self):
        """test the output of --list-shared """
        path = os.path.join(self.root_dir, u"ñoño".encode('utf-8'))
        self.fs.create(path, "")
        self.fs.set_node_id(path, "node_id")
        # helper function, pylint: disable-msg=C0111

        def fake_create_share(node_id, user, name, access_level, marker, path):
            self.main.vm.handle_AQ_CREATE_SHARE_OK(
                share_id='share_id', marker=marker)
        self.main.action_q.create_share = fake_create_share
        self.main.vm.create_share(path, 'fake_user', 'shared_name',
                                  ACCESS_LEVEL_RO)
        out = StringIO()
        expected = (
            u"Shared list:\n  id=share_id name=shared_name accepted=False "
            u"access_level=View to=fake_user path=%s\n" % path.decode('utf-8'))
        d = self.tool.list_shared()
        d.addCallback(lambda result: show_shared(result, out))

        def check(result):
            """check the output"""
            self.assertEqual(out.getvalue(), expected)
        d.addCallback(check)
        return d

    def test_show_path_info_unicode(self):
        """test the output of --info with unicode paths """
        return self.generic_test_show_path_info_unicode('utf-8')

    def test_show_path_info_unicode_pipe(self):
        """test the output of --info with unicode paths going to e.g. a pipe"""
        return self.generic_test_show_path_info_unicode(None)

    def generic_test_show_path_info_unicode(self, encoding):
        """generic test for the output of --info with unicode paths """
        path = os.path.join(self.root_dir, u"ñoño".encode('utf-8'))
        mdid = self.fs.create(path, "")
        self.fs.set_node_id(path, "uuid1")
        mdobj = self.fs.get_by_mdid(mdid)
        self.fs.create_partial(mdobj.node_id, mdobj.share_id)
        fh = self.fs.get_partial_for_writing(mdobj.node_id, mdobj.share_id)
        fh.write("foobar")
        fh.close()
        self.fs.commit_partial(mdobj.node_id, mdobj.share_id, "localhash")
        self.fs.remove_partial("uuid1", "")

        if encoding is not None:
            path = path.decode(encoding)
        else:
            path = path.decode('utf-8')

        d = self.tool.get_metadata(path)
        out = StringIO()
        out.encoding = encoding
        expected = """ File: %(path_info)s
  crc32: None
  generation: None
  info_created: %(info_created)s
  info_is_partial: %(info_is_partial)s
  info_last_downloaded: %(info_last_downloaded)s
  info_last_partial_created: %(info_last_partial_created)s
  info_last_partial_removed: %(info_last_partial_removed)s
  info_node_id_assigned: %(info_node_id_assigned)s
  is_dir: %(is_dir)s
  local_hash: %(local_hash)s
  mdid: %(mdid)s
  node_id: %(node_id)s
  path: %(path)s
  server_hash: %(server_hash)s
  share_id: %(share_id)s
  size: None
  stat: %(stat)s
"""
        # the callback, pylint: disable-msg=C0111

        def callback(result):
            if encoding is not None:
                result.update(dict(path_info=path))
            else:
                result.update(dict(path_info=path))
            for k, v in result.iteritems():
                self.assertIsInstance(v, unicode)
            value = expected % result
            self.assertEqual(out.getvalue(), value)
        # helper callback, pylint: disable-msg=C0111

        def show(result):
            show_path_info(result, path, out)
            return result
        d.addCallback(show)
        d.addCallback(callback)
        return d

    def test_show_current_transfers_empty(self):
        """test the output of --current_transfers option """
        out = StringIO()
        d = self.tool.get_current_uploads()
        d.addCallback(lambda result: show_uploads(result, out))
        d.addCallback(lambda _: self.tool.get_current_downloads())
        d.addCallback(lambda result: show_downloads(result, out))
        expected = u'Current uploads: 0\nCurrent downloads: 0\n'

        def check(result):
            """check the output"""
            self.assertEqual(out.getvalue(), expected)
        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_show_current_transfers(self):
        """Test the --current_transfers output with transfers in progress."""
        # create a download
        fake_download = FakeDownload('share_id', 'down_node_id')
        fake_download.deflated_size = 10
        fake_download.n_bytes_read = 1
        fake_download.path = "down_path"
        self.action_q.queue.waiting.append(fake_download)

        # create an upload
        fake_upload = FakeUpload('share_id', 'node_id')
        fake_upload.deflated_size = 100
        fake_upload.n_bytes_written = 10
        fake_upload.path = "up_path"
        self.action_q.queue.waiting.append(fake_upload)

        out = StringIO()
        expected = (
            u"Current uploads:\n  path: up_path\n    deflated size: 100\n    "
            u"bytes written: 10\nCurrent downloads:\n  path: down_path\n    "
            u"deflated size: 10\n    bytes read: 1\n")
        result = yield self.tool.get_current_uploads()
        show_uploads(result, out)

        result = yield self.tool.get_current_downloads()
        show_downloads(result, out)

        self.assertEqual(out.getvalue(), expected)

    def test_show_state(self):
        """test the output of --status """
        out = StringIO()
        expected = [
            "State: QUEUE_MANAGER",
            "connection: With User With Network",
            "description: processing the commands pool",
            "is_connected: True",
            "is_error: False",
            "is_online: True",
            "queues: IDLE"
        ]
        d = self.tool.get_status()
        d.addCallback(lambda result: show_state(result, out))

        def check(result):
            """check the output"""
            info = [x.strip() for x in out.getvalue().split("\n") if x.strip()]
            self.assertEqual(info, expected)
        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_show_free_space(self):
        """Test the output of --free-space"""
        share_path = os.path.join(self.main.shares_dir, 'share')
        share = Share(path=share_path, volume_id='vol_id')
        yield self.main.vm.add_share(share)
        self.main.vm.update_free_space('vol_id', 12345)

        out = StringIO()
        expected = "Free space: 12345 bytes\n"

        result = yield self.tool.free_space('vol_id')
        show_free_space(result, out)
        self.assertEqual(out.getvalue(), expected)

    @defer.inlineCallbacks
    def test_show_waiting_simple(self):
        """Test the output of --waiting-metadata"""
        # inject the fake data
        cmd1 = FakeCommand("", "node1", path='foo')
        cmd1.running = True
        cmd2 = FakeCommand("", "node2")
        cmd2.running = False
        self.action_q.queue.waiting.extend([cmd1, cmd2])

        out = StringIO()
        expected = (
            "  FakeCommand(running=True, share_id='', node_id='node1', "
            "path='foo', other='')\n"
            "  FakeCommand(running=False, share_id='', node_id='node2', "
            "other='')\n"
        )

        result = yield self.tool.waiting()
        show_waiting(result, out)
        self.assertEqual(out.getvalue(), expected)

    @defer.inlineCallbacks
    def test_show_waiting_metadata(self):
        """Test the output of --waiting-metadata"""
        # inject the fake data
        cmd1 = FakeCommand("", "node1", path='p')
        cmd2 = FakeCommand("", "node2")
        self.action_q.queue.waiting.extend([cmd1, cmd2])

        out = StringIO()
        expected = (
            "Warning: this option is deprecated! Use '--waiting' instead\n"
            "  FakeCommand(running=True, share_id='', node_id='node1', "
            "path='p', other='')\n"
            "  FakeCommand(running=True, share_id='', node_id='node2', "
            "other='')\n"
        )

        result = yield self.tool.waiting_metadata()
        show_waiting_metadata(result, out)
        self.assertEqual(out.getvalue(), expected)

    @defer.inlineCallbacks
    def test_show_waiting_content(self):
        """Test the output of --waiting-content"""
        class FakeCommand2(FakeUpload):
            """Fake command that goes in content queue."""
            def __init__(self, *args):
                FakeUpload.__init__(self, *args)
                self.path = 'other_path'

        # inject the fake data
        self.action_q.queue.waiting.extend([
                FakeUpload("", "node_id"),
                FakeCommand2("", "node_id_2"),
                FakeDownload("", "node_id_1"),

                FakeCommand2("", "node_id_3")])
        out = StringIO()
        expected = (
            u"Warning: this option is deprecated! Use '--waiting' instead\n"
            u"operation='FakeUpload' node_id='node_id' share_id='' "
            u"path='upload_path'\n"
            u"operation='FakeCommand2' node_id='node_id_2' share_id='' "
            u"path='other_path'\n"
            u"operation='FakeDownload' node_id='node_id_1' share_id='' "
            u"path='download_path'\n"
            u"operation='FakeCommand2' node_id='node_id_3' share_id='' "
            u"path='other_path'\n"
        )

        result = yield self.tool.waiting_content()
        yield show_waiting_content(result, out)
        self.assertEqual(out.getvalue(), expected)

    def test_show_folders_empty(self):
        """test the output of --list-folders """
        out = StringIO()
        d = self.tool.get_folders()
        d.addCallback(lambda result: show_folders(result, out))

        def check(result):
            """check the output"""
            self.assertEqual('No folders\n', out.getvalue())
        d.addCallback(check)
        return d

    @defer.inlineCallbacks
    def test_show_folders_subscribed(self):
        """Test the output of --list-folders."""
        out = StringIO()
        suggested_path = u"~/ñoño"
        path = get_udf_path(suggested_path)

        udf = UDF("folder_id", "node_id", suggested_path, path,
                  subscribed=True)
        yield self.main.vm.add_udf(udf)
        expected = u"Folder list:\n  id=folder_id subscribed=True " + \
                   u"path=%s\n" % path.decode('utf-8')
        result = yield self.tool.get_folders()
        show_folders(result, out)
        self.assertEqual(out.getvalue(), expected)

    @defer.inlineCallbacks
    def test_show_folders_unsubscribed(self):
        """Test the output of --list-folders with a unsubscribed folder."""
        out = StringIO()
        path = u'ñoño'.encode('utf-8')
        suggested_path = os.path.join("~", u'ñoño')

        udf = UDF("folder_id", "node_id", suggested_path, path,
                  subscribed=True)
        yield self.main.vm.add_udf(udf)
        self.main.vm.unsubscribe_udf(udf.id)
        expected = u"Folder list:\n  id=folder_id subscribed=False " + \
                   u"path=\xf1o\xf1o\n"
        result = yield self.tool.get_folders()
        show_folders(result, out)
        self.assertEqual(out.getvalue(), expected)

    @defer.inlineCallbacks
    def generic_show_dirty_nodes(self, encoding, empty=False):
        """Test dirty nodes output."""
        # create some nodes
        path1 = os.path.join(self.root_dir, u'ñoño-1'.encode('utf-8'))
        self.main.fs.create(path1, "")
        path2 = os.path.join(self.root_dir, u'ñoño-2'.encode('utf-8'))
        mdid2 = self.main.fs.create(path2, "")
        path3 = os.path.join(self.root_dir, "path3")
        self.main.fs.create(path3, "")
        path4 = os.path.join(self.root_dir, "path4")
        mdid4 = self.main.fs.create(path4, "")

        if not empty:
            # dirty some
            self.main.fs.set_by_mdid(mdid2, dirty=True)
            self.main.fs.set_by_mdid(mdid4, dirty=True)
        dirty_nodes = yield self.tool.get_dirty_nodes()
        out = StringIO()
        out.encoding = encoding
        # sort the list
        dirty_nodes.sort(key=itemgetter('mdid'))
        show_dirty_nodes(dirty_nodes, out)
        node_line_tpl = (
            "mdid: %(mdid)s volume_id: %(share_id)s node_id: %(node_id)s "
            "is_dir: %(is_dir)s path: %(path)s\n")
        if not empty:
            expected = " Dirty nodes:\n%s"
            lines = []
            for mdid in sorted([mdid4, mdid2]):
                mdobj = self.main.fs.get_by_mdid(mdid)
                d = mdobj.__dict__
                if encoding is not None:
                    d['path'] = d['path'].decode(encoding)
                else:
                    d['path'] = d['path'].decode('utf-8')
                lines.append(node_line_tpl % d)
            value = expected % ''.join(lines)
        else:
            value = " No dirty nodes.\n"
        self.assertEqual(out.getvalue(), value)

    def test_show_dirty_nodes(self):
        """Test show_dirty_nodes with unicode paths."""
        return self.generic_show_dirty_nodes("utf-8")

    def test_show_dirty_nodes_pipe(self):
        """Test show_dirty_nodes with unicode paths going to e.g: a pipe"""
        return self.generic_show_dirty_nodes(None)

    def test_show_dirty_nodes_empty(self):
        """Test show_dirty_nodes with no dirty nodes."""
        return self.generic_show_dirty_nodes(None, empty=True)
