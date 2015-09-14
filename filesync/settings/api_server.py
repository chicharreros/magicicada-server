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
# For further info, check  http://launchpad.net/filesync-server

import os
from django.conf import settings


def get_file_content(folder, filename):
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        filepath = os.path.join(folder, 'dev-' + filename)

    with open(filepath) as f:
        content = f.read()

    return content


CERTS_FOLDER = os.path.join(settings.BASE_DIR, 'certs')
# the `crt` key with the content of `cacert.pem` file
CRT = get_file_content(CERTS_FOLDER, 'cacert.pem')
CRT_CHAIN = None
# the `key` key with the content of `privkey.pem` file
KEY = get_file_content(CERTS_FOLDER, 'privkey.pem')
DELTA_MAX_SIZE = 1000
GC_DEBUG = True
GET_FROM_SCRATCH_LIMIT = 2000
GRACEFUL_SHUTDOWN = True
HEARTBEAT_INTERVAL = 5
IDLE_TIMEOUT = 7200
LOGGER_NAME = 'storage.server'
LOG_FILENAME = 'filesync-server.log'
MAGIC_UPLOAD_ACTIVE = True
MAX_DELTA_INFO = 20
METRICS_NAMESPACE = 'development.filesync.server'
MULTIPART_THRESHOLD = 10485760
PROTOCOL_WEAKREF = False
S3_BUCKET = 'test'
S3_FALLBACK_BUCKET = None
S3_RETRIES = 2
S3_RETRY_WAIT = 0.1
SERVERNAME = 'filesyncserver-development'
SLI_METRIC_NAMESPACE = None
STATS_LOG_INTERVAL = 0
STATUS_PORT = 21102
STORAGE_CHUNK_SIZE = 5242880
TCP_PORT = 21100
TRACE_USERS = ['test', 'etc']
UPLOAD_BUFFER_MAX_SIZE = 10485761
