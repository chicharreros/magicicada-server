# Copyright 2008-2015 Canonical
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
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

"""Script to generate supervisor config for many dev services and workers."""

import os
import socket
import sys

import _pythonpath  # NOQA

from ubuntuone.supervisor.config_helpers import generate_server_config
from utilities.utils import get_rootdir, get_tmpdir


ROOT_DIR = get_rootdir()
TMP_DIR = get_tmpdir()


FILESYNC_TEMPLATE = (
    '[program:%(instance_name)s]\n'
    'command=%(basepath)s/dev-scripts/set_rlimits.sh -d %(fs_memory_limit)s '
    '-m %(fs_memory_limit)s -v %(fs_memory_limit)s -n %(open_fds)s '
    '%(basepath)s/.env/bin/twistd --pidfile %(pid_folder)s/fsync_slave_%(instance)s.pid '
    '-n -y %(basepath)s/magicicada/server/server.tac '
    '--reactor=epoll\n'
    'environment=DJANGO_SETTINGS_MODULE="magicicada.settings",'
    'PYTHONPATH="%(pythonpath)s",'
    'FSYNC_INSTANCE_ID=%(instance)03d,'
    'CONFIG="%(basepath)s/configs/%(config)s"%(environment_vars)s\n'
    'autostart=false\n'
    'stdout_capture_maxbytes=%(stdout_capture_maxbytes)s\n'
    'stopsignal=INT\n'
)

SSL_PROXY_TEMPLATE = (
    '[program:%(instance_name)s]\n'
    'command=%(basepath)s/dev-scripts/set_rlimits.sh -d %(ssl_memory_limit)s '
    '-m %(ssl_memory_limit)s -v %(ssl_memory_limit)s -n %(open_fds)s '
    '%(basepath)s/.env/bin/twistd --pidfile %(pid_folder)s/ssl-proxy-%(instance)s.pid '
    '-n -y %(basepath)s/magicicada/server/ssl_proxy.tac '
    '--reactor=epoll\n'
    'environment=DJANGO_SETTINGS_MODULE="magicicada.settings",'
    'PYTHONPATH="%(pythonpath)s",'
    'FSYNC_INSTANCE_ID=%(instance)03d,'
    'CONFIG="%(basepath)s/configs/%(config)s",'
    'FSYNC_SERVICE_NAME="ssl-proxy"%(environment_vars)s\n'
    'autostart=false\n'
    'stdout_capture_maxbytes=%(stdout_capture_maxbytes)s\n'
    'stopsignal=INT\n'
)


TEMPLATES = {
    'filesync': {
        'name': "filesync-worker-%(instance)d",
        'config': FILESYNC_TEMPLATE,
    },
    'ssl-proxy': {
        'name': "ssl-proxy-%(instance)d",
        'config': SSL_PROXY_TEMPLATE,
    },
}

config_spec = {
    "basepath": ROOT_DIR,
    "log_folder": TMP_DIR,
    "pid_folder": TMP_DIR,
    "pythonpath": ':'.join(filter(None, sys.path)),
}

workers = {}
services = {"development": {"services": {}}}

if __name__ == '__main__':
    hostname = socket.gethostname()
    config_content = generate_server_config(
        hostname,
        services,
        config_spec,
        TEMPLATES,
        None,
        with_heartbeat=False,
        with_header=False,
    )
    with open(os.path.join(TMP_DIR, 'services-supervisor.conf'), 'w') as f:
        f.write(config_content)
