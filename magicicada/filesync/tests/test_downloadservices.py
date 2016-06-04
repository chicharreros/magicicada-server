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

"""Test downloadservices functions."""

from __future__ import unicode_literals

import uuid

from magicicada.filesync import downloadservices, services
from magicicada.filesync.models import Download
from magicicada.testing.testcase import BaseTestCase


class DownloadServicesTestCase(BaseTestCase):
    """Test DownloadServices."""

    def setUp(self):
        super(DownloadServicesTestCase, self).setUp()
        self.user = services.make_storage_user("username", 1000)
        self.volume_id = self.user.root_volume_id
        self.fpath = "/a/b/c/d/e/file.txt"
        self.dl_url = "http://downloadme"
        self.dl_key = "key"

    def get_or_make_it(self):
        """Make the download."""
        return downloadservices.get_or_make_download(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)

    def test_get_failed_downloads(self):
        """Test the get_failed_downloads() function."""
        # Create downloads
        udf1 = self.user.make_udf("~/path/name")
        d1 = downloadservices.make_download(
            self.user.id, udf1.id, "path/file", "http://example.com")
        downloadservices.download_error(
            self.user.id, d1.id, "download failed")
        user2 = services.make_storage_user("user2", 10 * 23)
        udf2 = user2.make_udf("~/path/name")
        d2 = downloadservices.make_download(
            user2.id, udf2.id, "path/file", "http://example.com")
        downloadservices.download_error(user2.id, d2.id, "download failed")
        # Finally, a failed download that will be outside the time window.
        d3 = downloadservices.make_download(
            user2.id, udf2.id, "path/file2", "http://example.com")
        downloadservices.download_error(user2.id, d3.id, "download failed")
        result = downloadservices.get_failed_downloads(
            start_date=d1.status_change_date,
            end_date=d3.status_change_date)
        download_ids = [download.id for download in result]
        self.assertTrue(d1.id in download_ids)
        self.assertTrue(d2.id in download_ids)
        self.assertFalse(d3.id in download_ids)

    def test_download_start(self):
        """Test download_start."""
        dl = self.get_or_make_it()
        downloadservices.download_start(self.user.id, dl.id)
        dl = downloadservices.get_download_by_id(self.user.id, dl.id)
        self.assertEqual(dl.status, Download.STATUS_DOWNLOADING)

    def test_download_error(self):
        """Test download_error."""
        dl = self.get_or_make_it()
        downloadservices.download_error(self.user.id, dl.id, "Kaploey")
        dl = downloadservices.get_download_by_id(self.user.id, dl.id)
        self.assertEqual(dl.status, Download.STATUS_ERROR)
        self.assertEqual(dl.error_message, "Kaploey")

    def test_download_complete(self):
        """Test download_complete."""
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = deflated_size = 300
        dl = self.get_or_make_it()
        downloadservices.download_complete(
            self.user.id, dl.id, hash, crc, size,
            deflated_size, mime, storage_key)
        dl = downloadservices.get_download_by_id(self.user.id, dl.id)
        self.assertEqual(dl.status, Download.STATUS_COMPLETE)
        f = self.user.volume().get_node_by_path(
            self.fpath, with_content=True)
        self.assertEqual(f.full_path, self.fpath)
        self.assertEqual(f.content_hash, hash)
        self.assertEqual(f.content.storage_key, storage_key)
        self.assertEqual(f.mimetype, mime)

    def test_get_or_make_download(self):
        """Test get_or_make_download."""
        dl = downloadservices.get_or_make_download(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)
        self.assertEqual(dl.owner_id, self.user.id)
        self.assertEqual(dl.volume_id, self.volume_id)
        self.assertEqual(dl.file_path, self.fpath)
        self.assertEqual(dl.download_url, self.dl_url)
        self.assertEqual(dl.download_key, unicode(repr(self.dl_key)))
        # do it again, make sure we get the same one
        dl2 = downloadservices.get_or_make_download(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)
        self.assertEqual(dl.id, dl2.id)

    def test_get_status(self):
        """Test get_status."""
        status = downloadservices.get_status(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)
        self.assertEqual(status, downloadservices.UNKNOWN)
        dl = self.get_or_make_it()
        status = downloadservices.get_status(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)
        self.assertEqual(status, Download.STATUS_QUEUED)
        # go ahead and complete it and create a file
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = deflated_size = 300
        dl = self.get_or_make_it()
        downloadservices.download_complete(
            self.user.id, dl.id, hash, crc, size,
            deflated_size, mime, storage_key)
        status = downloadservices.get_status(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)
        self.assertEqual(status, Download.STATUS_COMPLETE)
        # delete the file
        f = self.user.volume().get_node_by_path(self.fpath)
        f.delete()
        status = downloadservices.get_status(
            self.user.id, self.volume_id, self.fpath, self.dl_url, self.dl_key)
        self.assertEqual(status, downloadservices.DOWNLOADED_NOT_PRESENT)

    def test_get_status_by_id(self):
        """Test get_status."""
        status = downloadservices.get_status_by_id(self.user.id, uuid.uuid4())
        self.assertEqual(status, downloadservices.UNKNOWN)
        dl = self.get_or_make_it()
        status = downloadservices.get_status_by_id(self.user.id, dl.id)
        self.assertEqual(status, Download.STATUS_QUEUED)
        # go ahead and complete it and create a file
        mime = 'image/tif'
        hash = self.factory.get_fake_hash()
        storage_key = uuid.uuid4()
        crc = 12345
        size = deflated_size = 300
        dl = self.get_or_make_it()
        downloadservices.download_complete(
            self.user.id, dl.id, hash, crc, size,
            deflated_size, mime, storage_key)
        status = downloadservices.get_status_by_id(self.user.id, dl.id)
        self.assertEqual(status, Download.STATUS_COMPLETE)
        # delete the file
        f = self.user.volume().get_node_by_path(self.fpath)
        f.delete()
        status = downloadservices.get_status_by_id(self.user.id, dl.id)
        self.assertEqual(status, downloadservices.DOWNLOADED_NOT_PRESENT)
