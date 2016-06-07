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

"""Script to create default set of services and users in the DB for testing.

Called by the namesake in the top level utilities/ directory.
"""

from __future__ import unicode_literals

import django

from utilities.userutils import (
    add_auth_info_to_keyfile,
    delete_all_data,
)


django.setup()
SAMPLE_USERS = [
    {'username': "hola", 'password': "23456789",
     'full_name': "Hola Frijoles",
     'email': "hola@somemail.com"},
    {'username': "crazyhacker", 'password': "crazyhacker",
     'full_name': "Hacker ForLife",
     'email': "crazyhacker@somemail.com"},
    {'username': "chico", 'password': "23456789",
     'full_name': "Chico Frijoles",
     'email': "chico@somemail.com"},
    {'username': "miguel", 'password': "23456789",
     'full_name': "Miguel Hernandez",
     'email': "miguel@somemail.com"},
]


def main():
    """Preload the website with some data."""
    from magicicada.filesync import services
    # clear out existing data
    delete_all_data()
    for user_data in SAMPLE_USERS:
        username = user_data['username']
        password = user_data['password']
        email = user_data['email']
        first_name, last_name = user_data['full_name'].split()
        services.make_storage_user(
            username=username, email=email, first_name=first_name,
            last_name=last_name, password=password)
        auth_info = dict(username=username, password=password)
        add_auth_info_to_keyfile(username, auth_info)