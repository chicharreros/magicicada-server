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

import django.dispatch

# Django 3.1 release notes
# Miscellaneous (https://docs.djangoproject.com/en/4.0/releases/3.1/#id2)
# The purely documentational providing_args argument for Signal is deprecated.
# If you rely on this argument as documentation, you can move the text to a
# code comment or docstring.

# providing_args=['instance', 'content_added', 'new_size', 'enforce_quota']
content_changed = django.dispatch.Signal()

# providing_args=['instance', 'old_name', 'old_parent', 'descendants']
node_moved = django.dispatch.Signal()

# providing_args=['instance']
pre_kill = django.dispatch.Signal()

# providing_args=['instance']
post_kill = django.dispatch.Signal()

# providing_args=['instance', 'descendants']
pre_unlink_tree = django.dispatch.Signal()

# providing_args=['instance', 'descendants']
post_unlink_tree = django.dispatch.Signal()

# providing_args=['instance', 'public']
public_access_changed = django.dispatch.Signal()
