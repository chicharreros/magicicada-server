#!/usr/bin/python

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

"""Script starting the squid server."""

import os
import sys
import subprocess

import _pythonpath  # NOQA

from magicicada import settings
from utilities import utils
from utilities.localendpoints import (
    allocate_ports, register_local_port, get_local_server, get_local_port)


def development_ports():
    """Augment the configuration with branch-local port numbers."""
    settings.STATSD_SERVERS = get_local_server('statsd')
    settings.aws.S3_PORT = settings.aws.KEYSTONE_PORT = get_local_port('s4')
    settings.aws.S3_PROXY_HOST = settings.aws.KEYSTONE_PROXY_HOST = 'localhost'
    proxy_port = get_local_port('storage-proxy')
    settings.aws.S3_PROXY_PORT = settings.aws.KEYSTONE_PROXY_PORT = proxy_port


def main():
    """Start the squid service."""
    development_ports()

    service_name, config_template = sys.argv[1:3]
    squid_bin = "/usr/sbin/squid3"
    port = settings.STORAGE_PROXY_PORT
    if not port:
        port = allocate_ports()[0]
        register_local_port(service_name, port, ssl=False)

    tmp_dir = utils.get_tmpdir()
    conffile_path = os.path.join(tmp_dir, '%s.conf' % service_name)
    s3_dstssl = int(settings.aws.S3_PORT) == 443 and "ssl" or ""
    swift_dstssl = int(settings.aws.KEYSTONE_PORT) == 443 and "ssl" or ""

    with open(conffile_path, 'w') as config_out:
        with open(config_template, 'r') as config_in:
            config_out.write(config_in.read().format(
                s3_dstdomain=settings.aws.S3_HOST,
                s3_dstport=settings.aws.S3_PORT,
                s3_dstssl=s3_dstssl,
                swift_dstdomain=settings.aws.KEYSTONE_HOST,
                swift_dstport=settings.aws.KEYSTONE_PORT,
                swift_dstssl=swift_dstssl,
                service_name=service_name,
                tmpdir=tmp_dir,
                port=port))

    subprocess.call([squid_bin, '-f', conffile_path, '-z'])
    os.execvp(squid_bin, [squid_bin, '-f', conffile_path,
                          '-N', '-Y', '-C'])

if __name__ == '__main__':
    main()
