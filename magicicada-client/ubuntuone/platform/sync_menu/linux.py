# -*- coding: utf-8 *-*
#
# Copyright 2012-2013 Canonical Ltd.
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
"""Use SyncMenu lib to integrate U1 with the Systray Sync Icon."""

import gettext
import logging
import time
from twisted.python.util import OrderedDict
from operator import itemgetter

try:
    from gi.repository import GLib as glib
    from gi.repository import (
        Dbusmenu,
        Gdk,
        Gio,
        SyncMenu,
    )
    use_syncmenu = True
except:
    use_syncmenu = False

from ubuntuone.clientdefs import GETTEXT_PACKAGE, NAME
from ubuntuone.platform.sync_menu.common import (
    UbuntuOneSyncMenu as DummySyncMenu,
)


logger = logging.getLogger("ubuntuone.platform.SyncMenu")


def Q_(string):
    return gettext.dgettext(GETTEXT_PACKAGE, string)


GET_HELP = Q_("Get Help on the Web")
GO_TO_WEB = Q_("Go to the main website")
MORE_STORAGE = Q_("Get More Space")
OPEN_U1 = Q_("Open")
OPEN_U1_FOLDER = Q_("Open the main folder")
SHARE_A_FILE = Q_("Share a File")
TRANSFERS = Q_("Current and Recent Transfers")

DELAY_BETWEEN_UPDATES = 3
UBUNTUONE_LINK = u'https://one.ubuntu.com/'
DASHBOARD = UBUNTUONE_LINK + u'dashboard/'
HELP_LINK = UBUNTUONE_LINK + u'support/'
GET_STORAGE_LINK = UBUNTUONE_LINK + u'services/add-storage/'
CLIENT_COMMAND_LINE = 'ubuntuone-control-panel-qt'
CLIENT_DESKTOP_ID = 'ubuntuone-installer.desktop'


class UbuntuOneSyncMenuLinux(object):
    """Integrate U1 with the Ubuntu Sync Menu."""

    def __init__(self, status, syncdaemon_service):
        """Initialize menu."""
        self._syncdaemon_service = syncdaemon_service
        self._connected = True
        self.timer = None
        self._ignore_status_event = False
        self.next_update = time.time()
        self.root_menu = Dbusmenu.Menuitem()

        self.open_u1 = Dbusmenu.Menuitem()
        self.open_u1.property_set(Dbusmenu.MENUITEM_PROP_LABEL, OPEN_U1)
        self.open_u1_folder = Dbusmenu.Menuitem()
        self.open_u1_folder.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL, OPEN_U1_FOLDER)
        self.share_file = Dbusmenu.Menuitem()
        self.share_file.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL, SHARE_A_FILE)

        self.go_to_web = Dbusmenu.Menuitem()
        self.go_to_web.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL, GO_TO_WEB)

        self.transfers = TransfersMenu(status)
        self.transfers.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL, TRANSFERS)

        self.more_storage = Dbusmenu.Menuitem()
        self.more_storage.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL, MORE_STORAGE)

        self.get_help = Dbusmenu.Menuitem()
        self.get_help.property_set(
            Dbusmenu.MENUITEM_PROP_LABEL, GET_HELP)

        # Connect signals
        self.open_u1.connect(
            Dbusmenu.MENUITEM_SIGNAL_ITEM_ACTIVATED, self.open_control_panel)
        self.open_u1_folder.connect(
            Dbusmenu.MENUITEM_SIGNAL_ITEM_ACTIVATED,
            self.open_ubuntu_one_folder)
        self.share_file.connect(
            Dbusmenu.MENUITEM_SIGNAL_ITEM_ACTIVATED, self.open_share_file_tab)
        self.go_to_web.connect(
            Dbusmenu.MENUITEM_SIGNAL_ITEM_ACTIVATED, self.open_go_to_web)
        self.get_help.connect(
            Dbusmenu.MENUITEM_SIGNAL_ITEM_ACTIVATED, self.open_web_help)
        self.more_storage.connect(
            Dbusmenu.MENUITEM_SIGNAL_ITEM_ACTIVATED,
            self.open_get_more_storage)

        # Add items
        self.root_menu.child_append(self.open_u1)
        self.root_menu.child_append(self.open_u1_folder)
        self.root_menu.child_append(self.share_file)
        self.root_menu.child_append(self.go_to_web)
        self.root_menu.child_append(self.transfers)
        self.root_menu.child_append(self.more_storage)
        self.root_menu.child_append(self.get_help)

        self.server = Dbusmenu.Server()
        self.server.set_root(self.root_menu)
        self.app = SyncMenu.App.new(CLIENT_DESKTOP_ID)
        self.app.set_menu(self.server)
        self.app.connect("notify::paused", self.change_sync_status)

    def sync_status_changed(self, status):
        """Listen to the changes for the sync status."""
        if status != self._connected:
            self._connected = status
            self._ignore_status_event = True
            self.app.set_paused(not self._connected)

    def change_sync_status(self, *args):
        """Triggered when the sync status is changed fromm the menu."""
        if self._ignore_status_event:
            self._ignore_status_event = False
        elif self._connected:
            self._syncdaemon_service.disconnect()
            self._connected = False
        else:
            self._syncdaemon_service.connect()
            self._connected = True

    def _get_launch_context(self, timestamp):
        """Returns the launch context for the current display"""
        dpy = Gdk.Display.get_default()

        if dpy:
            context = dpy.get_app_launch_context()
            context.set_timestamp(timestamp)
            return context

        return None

    def _open_uri(self, uri, timestamp=0):
        """Open an uri Using the default handler and the action timestamp"""
        try:
            Gio.AppInfo.launch_default_for_uri(
                uri, self._get_launch_context(timestamp))
        except glib.GError as e:
            logger.warning('Failed to open the uri %s: %s.', uri, e)

    def _open_control_panel_by_command_line(self, timestamp, args=''):
        """Open the control panel by command line"""
        flags = Gio.AppInfoCreateFlags.SUPPORTS_STARTUP_NOTIFICATION
        command_line = CLIENT_COMMAND_LINE
        if len(args):
            command_line += ' ' + args

        try:
            app = Gio.AppInfo.create_from_commandline(
                command_line, NAME, flags)

            if app:
                app.launch([], self._get_launch_context(timestamp))
        except glib.GError as e:
            logger.warning('Failed to open the control panel: %s.' % e)

    def open_control_panel(self, menuitem=None, timestamp=0):
        """Open the Control Panel."""
        app = Gio.DesktopAppInfo.new(CLIENT_DESKTOP_ID)

        if app:
            try:
                app.launch([], self._get_launch_context(timestamp))
            except glib.GError as e:
                logger.warning('Failed to open the control panel: %s.' % e)
        else:
            self._open_control_panel_by_command_line(timestamp)

    def open_ubuntu_one_folder(self, menuitem=None, timestamp=0):
        """Open the folder."""
        self._open_uri(
            "file://" + self._syncdaemon_service.get_rootdir(), timestamp)

    def open_share_file_tab(self, menuitem=None, timestamp=0):
        """Open the Control Panel in the Share Tab."""
        self._open_control_panel_by_command_line(
            timestamp, "--switch-to share_links")

    def open_go_to_web(self, menuitem=None, timestamp=0):
        """Open the Help Page"""
        self._open_uri(DASHBOARD, timestamp)

    def open_web_help(self, menuitem=None, timestamp=0):
        """Open the Help Page"""
        self._open_uri(HELP_LINK, timestamp)

    def open_get_more_storage(self, menuitem=None, timestamp=0):
        """Open the Help Page"""
        self._open_uri(GET_STORAGE_LINK, timestamp)

    def _timeout(self, result):
        """The aggregating timer has expired, so update the UI."""
        self.next_update = int(time.time()) + DELAY_BETWEEN_UPDATES
        self.transfers.update_progress()

    def update_transfers(self):
        """Set up a timer if there isn't one ticking and update the ui.

        NOOP. Left behind for API compatibility, will be removed later when
        all interaction with old syncmeny and desktop GUIs go away.
        """


class TransfersMenu(Dbusmenu.Menuitem if use_syncmenu else object):
    """Menu that handles the recent and current transfers."""

    def __init__(self, status_frontend):
        super(TransfersMenu, self).__init__()
        self.status_frontend = status_frontend
        self.uploading = {}
        self.previous_transfers = []
        self._transfers_items = {}
        self._uploading_items = {}
        self.separator = None

    def update_progress(self):
        """Update the list of recent transfers and current transfers."""
        recent_transfers = self.status_frontend.recent_transfers()
        current_transfers = self.status_frontend.files_uploading()
        current_transfers.sort(key=itemgetter(2))
        current_transfers.reverse()
        uploading_data = OrderedDict()
        for filename, size, written in current_transfers:
            uploading_data[filename] = (size, written)

        temp_transfers = {}
        if recent_transfers != self.previous_transfers:
            logger.debug("Update recent transfers with: %r", recent_transfers)
            for item_transfer in self._transfers_items:
                self.child_delete(self._transfers_items[item_transfer])
            for item in recent_transfers:
                recent_file = Dbusmenu.Menuitem()
                recent_file.property_set(
                    Dbusmenu.MENUITEM_PROP_LABEL, item.replace('_', '__'))
                self.child_add_position(recent_file, 0)
                temp_transfers[item] = recent_file
            self._transfers_items = temp_transfers

        if self.separator is None:
            self.separator = Dbusmenu.Menuitem()
            self.separator.property_set(
                Dbusmenu.MENUITEM_PROP_TYPE, Dbusmenu.CLIENT_TYPES_SEPARATOR)
            self.child_append(self.separator)

        items_added = 0
        remove = []
        for item in self._uploading_items:
            if item in uploading_data.keys():
                size, written = uploading_data[item]
                percentage = written * 100 / size
                upload_item = self._uploading_items[item]
                upload_item.property_set_int(
                    SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE,
                    percentage)
                logger.debug(
                    "Current transfer %s progress update: %r",
                    item, percentage)
                items_added += 1
            else:
                self.child_delete(self._uploading_items[item])
                remove.append(item)
        for item in remove:
            self._uploading_items.pop(item)
        if items_added < 5:
            for item in uploading_data.keys():
                if item not in self._uploading_items and items_added < 5:
                    size, written = uploading_data[item]
                    percentage = written * 100 / size
                    uploading_file = Dbusmenu.Menuitem()
                    uploading_file.property_set(
                        Dbusmenu.MENUITEM_PROP_LABEL, item.replace('_', '__'))
                    uploading_file.property_set(
                        Dbusmenu.MENUITEM_PROP_TYPE,
                        SyncMenu.PROGRESS_MENUITEM_TYPE)
                    uploading_file.property_set_int(
                        SyncMenu.PROGRESS_MENUITEM_PROP_PERCENT_DONE,
                        percentage)
                    logger.debug("Current transfer %s created", item)
                    self.child_append(uploading_file)
                    self._uploading_items[item] = uploading_file
                    items_added += 1


if use_syncmenu:
    UbuntuOneSyncMenu = UbuntuOneSyncMenuLinux
else:
    UbuntuOneSyncMenu = DummySyncMenu
