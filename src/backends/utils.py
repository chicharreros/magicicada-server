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

"""Some generic utilities."""

from __future__ import unicode_literals
from django.contrib.auth.models import User

from backends.filesync import services


def create_test_user(
        username='fred', email='fred@bedrock.com', first_name='Fredrick',
        last_name='Flintsone', password=None, id=None):
    """Create a user used for testing."""
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        user = User(id=id, username=unicode(username), email=unicode(email),
                    is_staff=False, is_active=True, is_superuser=False)
        user.set_password(password)
        user.save()
    user.first_name = unicode(first_name)
    user.last_name = unicode(last_name)
    user.save()

    # refresh the user object to ensure permissions caches are reloaded
    account_user = User.objects.get(username=username)

    # create also the storage user
    visible_name = "%s %s" % (user.first_name, user.last_name)
    storage_user = services.make_storage_user(
        account_user.id, username, visible_name, 2 ** 20)

    return storage_user
