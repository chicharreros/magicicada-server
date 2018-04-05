#!/usr/bin/env python

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

"""Script to manage the users in the system."""

from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from magicicada.filesync import services


User = get_user_model()


class Command(BaseCommand):

    def create(self, username, password, email, firstname, lastname, **kwargs):
        """Create a user."""
        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        else:
            raise CommandError('There is already an user with that username')

        # let's create it
        services.make_storage_user(
            username, max_storage_bytes=2 ** 20, password=password,
            email=email, first_name=firstname, last_name=lastname)

        self.stdout.write('Success: User created ok')

    def update(
            self, username, email=None, password=None, firstname=None,
            lastname=None, **kwargs):
        """Change information for a user."""
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError('User does not exist')

        if email is not None:
            user.email = email.decode('utf8')
        if password is not None:
            user.set_password(password.decode('utf8'))
        if firstname is not None:
            user.first_name = firstname.decode('utf8')
        if lastname is not None:
            user.last_name = lastname.decode('utf8')
        user.save()

        self.stdout.write('Success: User updated ok')

    def delete(self, username, **kwargs):
        """Remove a user from the system."""
        username = username.decode('utf8')
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError('User does not exist')

        user.delete()
        self.stdout.write('Success: User deleted ok')

    def show(self, username, **kwargs):
        """Show information about a user."""
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError('User does not exist')

        self.stdout.write('Username:   %r' % user.username)
        self.stdout.write('E-mail:     %r' % user.email)
        self.stdout.write('Name:       ', user.first_name, user.last_name)
        self.stdout.write('Id:         ', user.id)
        self.stdout.write('Joined:     ', user.date_joined.ctime())
        self.stdout.write('Last Login: ', user.last_login.ctime())
        self.stdout.write('Active:     ', user.is_active)

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(help='User Management operations')

        p_create = subparsers.add_parser(
            'create', help='Create a user.', cmd=self)
        p_create.set_defaults(func=self.create)
        p_create.add_argument('username', type=unicode)
        p_create.add_argument('firstname', type=unicode)
        p_create.add_argument('lastname', type=unicode)
        p_create.add_argument('email', type=unicode)
        p_create.add_argument('password', type=unicode)

        p_update = subparsers.add_parser(
            'update', help='Change information for a user.', cmd=self)
        p_update.add_argument('username')
        p_update.set_defaults(func=self.update)
        p_update.add_argument('--email', type=unicode)
        p_update.add_argument('--firstname', type=unicode)
        p_update.add_argument('--lastname', type=unicode)
        p_update.add_argument('--password', type=unicode)

        p_delete = subparsers.add_parser(
            'delete', help='Remove a user from the system.', cmd=self)
        p_delete.set_defaults(func=self.delete)
        p_delete.add_argument('username', type=unicode)

        p_show = subparsers.add_parser(
            'show', help='Show information about an user.', cmd=self)
        p_show.set_defaults(func=self.show)
        p_show.add_argument('username', type=unicode)

    def handle(self, *args, **options):
        f = options.pop('func')
        f(**options)
