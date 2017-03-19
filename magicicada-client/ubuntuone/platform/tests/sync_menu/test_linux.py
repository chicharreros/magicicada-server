# -*- coding: utf-8 *-*
#
# Copyright 2012 Canonical Ltd.
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
"""Test the Sync Menu."""

import time
from collections import Callable

from twisted.internet import defer
from twisted.trial.unittest import TestCase

from ubuntuone.platform import sync_menu
from ubuntuone.platform.sync_menu import linux


def fake_call_later(*args):
    """Fake reactor.callLater."""


class FakeStatusFrontend(object):
    """Fake StatusFrontend."""

    def __init__(self):
        self.recent_transfers_data = []
        self.uploading_data = []

    def recent_transfers(self):
        """Return the fake recent transfers files."""
        return self.recent_transfers_data

    def files_uploading(self):
        """Return the fake files being upload."""
        return self.uploading_data


class FakeAppLaunchContext(object):
    def set_timestamp(self, timestamp):
        self.timestamp = timestamp


class FakeGdkDisplay(object):
    """Fake Gdk.Display"""
    def get_app_launch_context(self):
        return FakeAppLaunchContext()


class FakeNullGdk(object):
    """Fake Gdk.Display with no default"""
    @staticmethod
    def get_default():
        return None


class FakeAppInfo(object):
    """Fake Gio.AppInfo"""
    instance = None
    name = ""
    desktop_id = ""
    command_line = ""
    opened_uri = ""
    launched = True
    context = None
    files = []
    flags = 0

    def __new__(cls, *args, **kwargs):
        cls.instance = super(FakeAppInfo, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self, command_line="", name="", flags=0):
        self.command_line = command_line
        self.name = name
        self.flags = flags

    @classmethod
    def launch_default_for_uri(cls, uri, context):
        cls.opened_uri = uri
        cls.context = context

    @classmethod
    def create_from_commandline(cls, command_line, name, flags):
        cls.instance.__init__(command_line, name, flags)
        return cls.instance

    def launch(self, files, context):
        self.launched = True
        self.files = files
        self.context = context


class FakeDesktopAppInfo(FakeAppInfo):
    """Fake Gio.DestkopAppInfo"""
    def __init__(self, desktop_id=""):
        super(FakeDesktopAppInfo, self).__init__()
        self.desktop_id = desktop_id

    @classmethod
    def new(cls, desktop_id):
        cls.instance.__init__(desktop_id)
        return cls.instance


class FakeSyncdaemonService(object):
    """Fake SyncdaemonService."""

    def __init__(self):
        self.connect_called = False
        self.disconnect_called = False
        self.fake_root_path = "/home/user/Magicicada"

    def connect(self):
        """Set connect to True."""
        self.connect_called = True

    def disconnect(self):
        """Set connect to True."""
        self.disconnect_called = True

    def get_rootdir(self):
        """Return a fake ubuntu one folder path."""
        return self.fake_root_path


class FakeSyncMenuApp(object):
    """Fake SyncMenu."""

    data = {}

    @classmethod
    def new(cls, *args):
        return FakeSyncMenuApp()

    @classmethod
    def clean(cls):
        """Clear the values stored in data."""
        FakeSyncMenuApp.data = {}

    def set_menu(self, server):
        """Set the menu for SyncMenu App."""
        self.data['server'] = server

    def connect(self, signal, callback):
        """Fake connect."""
        self.data['connect'] = (signal, callback)

    def set_paused(self, status):
        """Set the pause state."""
        self.data['paused'] = status


class SyncMenuDummyTestCase(TestCase):
    """Test the SyncMenu."""

    def test_dummy_support(self):
        """Check that the Dummy object can be created properly."""
        dummy = linux.DummySyncMenu('random', 'args')
        self.assertIsInstance(dummy, linux.DummySyncMenu)

    def test_dummy_has_update_transfers(self):
        """Check that the dummy has the proper methods required by the API."""
        dummy = linux.DummySyncMenu('random', 'args')
        self.assertIsInstance(dummy.update_transfers, Callable)
        self.assertIsInstance(dummy.sync_status_changed, Callable)


class SyncMenuTestCase(TestCase):
    """Test the SyncMenu."""

    skip = None if linux.use_syncmenu else "SyncMenu not installed."

    @defer.inlineCallbacks
    def setUp(self):
        yield super(SyncMenuTestCase, self).setUp()
        self.patch(linux.SyncMenu, "App", FakeSyncMenuApp)
        self.patch(linux.Gdk.Display, "get_default", FakeGdkDisplay)
        FakeSyncMenuApp.clean()
        self.syncdaemon_service = FakeSyncdaemonService()
        self.status_frontend = FakeStatusFrontend()
        self._paused = False
        self.sync_menu = sync_menu.UbuntuOneSyncMenu(
            self.status_frontend, self.syncdaemon_service)

    def test_init(self):
        """Check that the menu is properly initialized."""
        self.assertIsInstance(
            FakeSyncMenuApp.data['server'], linux.Dbusmenu.Server)
        self.assertEqual(
            self.sync_menu.open_u1.get_parent(), self.sync_menu.root_menu)
        self.assertEqual(
            self.sync_menu.go_to_web.get_parent(), self.sync_menu.root_menu)
        self.assertEqual(
            self.sync_menu.more_storage.get_parent(), self.sync_menu.root_menu)
        self.assertEqual(
            self.sync_menu.get_help.get_parent(), self.sync_menu.root_menu)
        self.assertEqual(
            self.sync_menu.transfers.get_parent(), self.sync_menu.root_menu)
        self.assertEqual(
            self.sync_menu.open_u1_folder.get_parent(),
            self.sync_menu.root_menu)
        self.assertEqual(
            self.sync_menu.share_file.get_parent(), self.sync_menu.root_menu)

        def get_prop(item):
            return item.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL)

        self.assertEqual(
            get_prop(self.sync_menu.open_u1), linux.OPEN_U1)
        self.assertEqual(
            get_prop(self.sync_menu.open_u1_folder), linux.OPEN_U1_FOLDER)
        self.assertEqual(
            get_prop(self.sync_menu.share_file), linux.SHARE_A_FILE)
        self.assertEqual(
            get_prop(self.sync_menu.go_to_web), linux.GO_TO_WEB)
        self.assertEqual(
            get_prop(self.sync_menu.transfers), linux.TRANSFERS)
        self.assertEqual(
            get_prop(self.sync_menu.more_storage), linux.MORE_STORAGE)
        self.assertEqual(
            get_prop(self.sync_menu.get_help), linux.GET_HELP)

        self.sync_menu.transfers.update_progress()
        self.assertIsInstance(
            self.sync_menu.transfers.separator, linux.Dbusmenu.Menuitem)

    def test_get_launch_context_with_display(self):
        """Check that the proper context is returned."""
        timestamp = time.time()
        context = self.sync_menu._get_launch_context(timestamp)
        self.assertEqual(timestamp, context.timestamp)

    def test_get_launch_context_with_no_display(self):
        """Check that the proper context is returned."""
        self.patch(linux.Gdk, "Display", FakeNullGdk)
        context = self.sync_menu._get_launch_context(time.time())
        self.assertEqual(context, None)

    def test_open_control_panel_by_command_line(self):
        """Check that the proper action is executed."""
        appinfo = FakeAppInfo()
        self.patch(linux.Gio, "AppInfo", appinfo)
        timestamp = time.time()
        self.sync_menu._open_control_panel_by_command_line(timestamp)

        self.assertEqual(appinfo.command_line, linux.CLIENT_COMMAND_LINE)
        self.assertEqual(appinfo.context.timestamp, timestamp)

    def test_open_control_panel_by_command_line_with_arg(self):
        """Check that the proper action is executed."""
        appinfo = FakeAppInfo()
        self.patch(linux.Gio, "AppInfo", appinfo)
        timestamp = time.time()
        arg = "--test-arg"
        self.sync_menu._open_control_panel_by_command_line(timestamp, arg)

        self.assertEqual(
            appinfo.command_line, "%s %s" % (linux.CLIENT_COMMAND_LINE, arg))
        self.assertEqual(appinfo.context.timestamp, timestamp)

    def test_open_uri(self):
        """Check that the proper action is executed."""
        appinfo = FakeAppInfo()
        self.patch(linux.Gio, "AppInfo", appinfo)
        timestamp = time.time()

        self.sync_menu._open_uri(linux.UBUNTUONE_LINK, timestamp)
        self.assertEqual(appinfo.opened_uri, linux.UBUNTUONE_LINK)
        self.assertEqual(appinfo.context.timestamp, timestamp)

    def test_open_u1(self):
        """Check that the proper action is executed."""
        appinfo = FakeDesktopAppInfo()
        timestamp = time.time()
        self.patch(linux.Gio, "DesktopAppInfo", appinfo)

        self.sync_menu.open_control_panel(timestamp=timestamp)
        self.assertEqual(appinfo.desktop_id, linux.CLIENT_DESKTOP_ID)
        self.assertTrue(appinfo.launched)
        self.assertEqual(appinfo.files, [])
        self.assertEqual(appinfo.context.timestamp, timestamp)

    def test_open_share_tab(self):
        """Check that the proper action is executed."""
        timestamp = time.time()
        data = []

        self.patch(
            self.sync_menu, "_open_control_panel_by_command_line",
            lambda t, a: data.append((t, a)))
        self.sync_menu.open_share_file_tab(timestamp=timestamp)
        self.assertEqual(data, [(timestamp, "--switch-to share_links")])

    def test_go_to_web(self):
        """Check that the proper action is executed."""
        timestamp = time.time()
        data = []

        self.patch(
            self.sync_menu, "_open_uri", lambda u, t: data.append((t, u)))
        self.sync_menu.open_go_to_web(timestamp=timestamp)
        self.assertEqual(data, [(timestamp, linux.DASHBOARD)])

    def test_open_ubuntu_one_folder(self):
        """Check that the proper action is executed."""
        timestamp = time.time()
        data = []

        self.patch(
            self.sync_menu, "_open_uri", lambda u, t: data.append((t, u)))
        self.sync_menu.open_ubuntu_one_folder(timestamp=timestamp)
        self.assertEqual(
            data,
            [(timestamp, "file://" + self.syncdaemon_service.fake_root_path)])

    def test_get_help(self):
        """Check that the proper action is executed."""
        timestamp = time.time()
        data = []

        self.patch(
            self.sync_menu, "_open_uri", lambda u, t: data.append((t, u)))
        self.sync_menu.open_web_help(timestamp=timestamp)
        self.assertEqual(data, [(timestamp, linux.HELP_LINK)])

    def test_more_storage(self):
        """Check that the proper action is executed."""
        timestamp = time.time()
        data = []

        self.patch(
            self.sync_menu, "_open_uri", lambda u, t: data.append((t, u)))
        self.sync_menu.open_get_more_storage(timestamp=timestamp)
        self.assertEqual(data, [(timestamp, linux.GET_STORAGE_LINK)])

    def test_empty_transfers(self):
        """Check that the Transfers menu is empty."""
        self.assertEqual(self.sync_menu.transfers.get_children(), [])

    def test_only_recent(self):
        """Check that only recent transfers items are loaded."""
        data = ['file1', 'file2', 'file3']
        self.status_frontend.recent_transfers_data = data
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        self.assertEqual(len(children), 4)
        data.reverse()
        for itemM, itemD in zip(children, data):
            self.assertEqual(
                itemM.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL), itemD)

    def test_only_progress(self):
        """Check that only progress items are loaded."""
        data = [
            ('file1', 3000, 400),
            ('file2', 2000, 100),
            ('file3', 5000, 4600)]
        uploading_data = {}
        for filename, size, written in data:
            uploading_data[filename] = (size, written)
        self.status_frontend.uploading_data = data
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        self.assertEqual(len(children), 4)
        data.reverse()
        for item in children:
            text = item.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL)
            if text is None:
                continue
            self.assertIn(text, uploading_data)
            size, written = uploading_data[text]
            percentage = written * 100 / size
            self.assertEqual(item.property_get_int(
                linux.SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE),
                percentage)

    def test_full_transfers(self):
        """Check that the transfers menu contains the maximum transfers."""
        # The api of recent transfers always returns a maximum of 5 items
        data_recent = ['file1', 'file2', 'file3', 'file4', 'file5']
        self.status_frontend.recent_transfers_data = \
            data_recent
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        self.assertEqual(len(children), 6)
        data_recent.reverse()
        for itemM, itemD in zip(children, data_recent):
            self.assertEqual(itemM.property_get(
                linux.Dbusmenu.MENUITEM_PROP_LABEL), itemD)

        data_current = [
            ('file0', 1200, 600),
            ('file1', 3000, 400),
            ('file2', 2000, 100),
            ('file3', 2500, 150),
            ('file4', 1000, 600),
            ('file5', 5000, 4600)]
        uploading_data = {}
        for filename, size, written in data_current:
            uploading_data[filename] = (size, written)
        self.status_frontend.uploading_data = data_current
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        # The menu should only show 5 current transfers.
        self.assertEqual(len(children), 11)
        data_current.reverse()
        for item in children[6:]:
            text = item.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL)
            self.assertIn(text, uploading_data)
            size, written = uploading_data[text]
            percentage = written * 100 / size
            self.assertEqual(item.property_get_int(
                linux.SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE),
                percentage)

    def test_mnemonics_labels(self):
        """Check that the transfers menu sanitizes the underscores."""
        data_recent = ['file_1', 'file__2']
        self.status_frontend.recent_transfers_data = \
            data_recent
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        data_recent.reverse()
        for itemM, itemD in zip(children, data_recent):
            self.assertEqual(itemM.property_get(
                linux.Dbusmenu.MENUITEM_PROP_LABEL), itemD.replace('_', '__'))

    def test_update_transfers(self):
        """Check that everything is ok when updating the transfers value."""
        data_current = [
            ('file0', 1200, 600),
            ('file1', 3000, 400),
            ('file4', 1000, 600),
            ('file5', 5000, 4600)]
        uploading_data = {}
        for filename, size, written in data_current:
            uploading_data[filename] = (size, written)
        self.status_frontend.uploading_data = data_current
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        # The menu should only show 5 current transfers.
        self.assertEqual(len(children), 5)
        data_current.reverse()
        for item in children:
            text = item.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL)
            if text is None:
                continue
            self.assertIn(text, uploading_data)
            size, written = uploading_data[text]
            percentage = written * 100 / size
            self.assertEqual(item.property_get_int(
                linux.SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE),
                percentage)

        data_recent = ['file5']
        self.status_frontend.recent_transfers_data = data_recent
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        self.assertEqual(len(children), 6)
        data_recent.reverse()
        for itemM, itemD in zip(children, data_recent):
            self.assertEqual(itemM.property_get(
                linux.Dbusmenu.MENUITEM_PROP_LABEL), itemD)

        data_current = [
            ('file0', 1200, 700),
            ('file1', 3000, 600),
            ('file4', 1000, 800)]
        uploading_data = {}
        for filename, size, written in data_current:
            uploading_data[filename] = (size, written)
        self.status_frontend.uploading_data = data_current
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        # The menu should only show 5 current transfers.
        self.assertEqual(len(children), 5)
        data_current.reverse()
        for item in children[6:]:
            text = item.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL)
            self.assertIn(text, uploading_data)
            size, written = uploading_data[text]
            percentage = written * 100 / size
            self.assertEqual(item.property_get_int(
                linux.SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE),
                percentage)

    def test_transfers_order(self):
        """Check that the proper transfers are shown first."""
        data_current = [
            ('file0', 1200, 610),
            ('file1', 3000, 400),
            ('file2', 2000, 100),
            ('file3', 2500, 150),
            ('file4', 2500, 950),
            ('file5', 3500, 550),
            ('file6', 1000, 600),
            ('file7', 5000, 4600)]
        expected = [
            ('file7', 5000, 4600),
            ('file4', 2500, 950),
            ('file0', 1200, 610),
            ('file6', 1000, 600),
            ('file5', 3500, 550)]
        self.status_frontend.uploading_data = data_current
        self.sync_menu.transfers.update_progress()
        children = self.sync_menu.transfers.get_children()
        # The menu should only show 5 current transfers and a separator item.
        self.assertEqual(len(children), 6)
        i = 0
        for item in children:
            text = item.property_get(linux.Dbusmenu.MENUITEM_PROP_LABEL)
            if text is None:
                continue
            percentage = item.property_get_int(
                linux.SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE)
            name, size, written = expected[i]
            i += 1
            percentage_expected = written * 100 / size
            self.assertEqual(text, name)
            self.assertEqual(percentage, percentage_expected)

    def test_update_transfers_delay(self):
        """Check that the timer is being handle properly."""
        self.sync_menu.next_update = time.time()
        self.sync_menu.update_transfers()
        self.sync_menu.timer = None
        self.sync_menu.next_update = time.time() * 2
        self.sync_menu.update_transfers()
        self.assertEqual(self.sync_menu.timer.delay, 3)

    def test_status_change_from_menu(self):
        """Check the behavior when the status is changed from the menu."""
        self.sync_menu.change_sync_status()
        self.assertFalse(self.sync_menu._connected)
        self.assertFalse(self.sync_menu._ignore_status_event)
        self.assertFalse(self.sync_menu._syncdaemon_service.connect_called)
        self.assertTrue(self.sync_menu._syncdaemon_service.disconnect_called)

        self.sync_menu._syncdaemon_service.disconnect_called = False
        self.sync_menu.change_sync_status()
        self.assertTrue(self.sync_menu._connected)
        self.assertFalse(self.sync_menu._ignore_status_event)
        self.assertTrue(self.sync_menu._syncdaemon_service.connect_called)
        self.assertFalse(self.sync_menu._syncdaemon_service.disconnect_called)

    def test_ignore_status(self):
        """Check that neither connect or disconnect are called."""
        self.sync_menu._ignore_status_event = True
        self.assertTrue(self.sync_menu._ignore_status_event)
        self.sync_menu.change_sync_status()
        self.assertTrue(self.sync_menu._connected)
        self.assertFalse(self.sync_menu._ignore_status_event)
        self.assertFalse(self.sync_menu._syncdaemon_service.connect_called)
        self.assertFalse(self.sync_menu._syncdaemon_service.disconnect_called)

    def test_sync_status_changed(self):
        """Check sync_status_changed behavior."""
        self.sync_menu.sync_status_changed(True)
        self.assertNotIn('paused', self.sync_menu.app.data)
        self.sync_menu.sync_status_changed(False)
        self.assertFalse(self.sync_menu._connected)
        self.assertTrue(self.sync_menu._ignore_status_event)
        self.assertTrue(self.sync_menu.app.data['paused'])
