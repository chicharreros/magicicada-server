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
# For further info, check  http://launchpad.net/filesync-server

"""Script to publish the API ports in specific files."""

import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('-d', '--dest', type=str, required=True)

    def handle(self, *args, **options):
        base_dir = options.get('dest')
        if not os.path.isdir(base_dir):
            raise CommandError(
                'Destination folder "%s" does not exist' % base_dir
            )
        ports = {
            'filesyncserver.port': settings.TCP_PORT,
            'filesyncserver.port.ssl': settings.SSL_PORT,
            'filesyncserver-status.port': settings.API_STATUS_PORT,
        }
        for fname, value in ports.items():
            with open(os.path.join(base_dir, fname), 'w') as f:
                f.write(str(value))
