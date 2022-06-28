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

"""Some generic utilities."""

from magicicada.filesync import services


def create_test_user(
        username='fred', email='fred@bedrock.com', first_name='Fredrick',
        last_name='Flintsone', password=None, max_storage_bytes=2 ** 20):
    """Create a user used for testing."""
    return services.make_storage_user(
        username, max_storage_bytes=max_storage_bytes, password=password,
        email=email, first_name=first_name, last_name=last_name,
        is_staff=False, is_active=True, is_superuser=False)
