# Copyright 2015-2022 Chicharreros (https://launchpad.net/~chicharreros)
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

from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


User = get_user_model()


class NormalizeBookTitlesTests(TestCase):

    stdout = None
    stderr = None

    def call_command(self, *args, **kwargs):
        self.stdout = StringIO()
        self.stderr = StringIO()
        result = call_command(
            'user_mgr',
            *args,
            stdout=self.stdout,
            stderr=self.stderr,
            **kwargs,
        )
        return result

    def test_invalid_option(self):
        with self.assertRaises(CommandError) as ctx:
            self.call_command('--foo')

        self.assertEqual(
            str(ctx.exception), 'Error: unrecognized arguments: --foo'
        )

    def test_create_user(self):
        self.call_command(
            'create', 'username', 'firstname', 'lastname', 'email', 'password'
        )

        self.assertEqual(
            self.stdout.getvalue().strip(), 'Success: User created ok'
        )
        self.assertEqual(self.stderr.getvalue(), '')
        matches = User.objects.filter(
            username='username',
            first_name='firstname',
            last_name='lastname',
            email='email',
        )
        self.assertEqual(len(matches), 1)
