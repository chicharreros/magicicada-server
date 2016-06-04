#!/usr/bin/python -Wignore

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

"""Deployment script for loading the Magicicada Server.

Usage:

    python deploy_api_server.py
"""

import os
import atexit

from twisted.internet import reactor, defer

reactor.suggestThreadPoolSize(30)

import _pythonpath  # NOQA

from magicicada import settings
from magicicada.server import server
from utilities import utils

tmp_dir = os.path.join(utils.get_rootdir(), 'tmp')
api_port_filename = os.path.join(tmp_dir, "filesyncserver.port")


def cleanup():
    """Cleanup after ourselves"""
    filename = api_port_filename
    os.unlink(filename)
    filename = filename + ".ssl"
    os.unlink(filename)


@defer.inlineCallbacks
def main():
    """Start the server."""

    status_port = int(
        os.getenv('API_STATUS_PORT', settings.api_server.STATUS_PORT))
    service = server.create_service(status_port)

    yield service.startService()

    filename = api_port_filename
    f = open(filename, "w+")
    f.write(str(service.port))
    f.write("\n")
    f.close()

    filename = os.path.join(tmp_dir, "filesyncserver-status.port")
    f = open(filename, "w+")
    f.write(str(service.status_port))
    f.write("\n")
    f.close()

    atexit.register(cleanup)
    reactor.addSystemEventTrigger("before", "shutdown", service.stopService)

if __name__ == "__main__":
    reactor.callWhenRunning(main)
    reactor.run()
