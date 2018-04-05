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
# For further info, check  http://launchpad.net/magicicada-server

"""The Storage DAL test harness"""

from __future__ import unicode_literals

from magicicada.filesync import services  # NOQA
from magicicada.filesync.notifier.notifier import register_notifier_for_bus
from magicicada.filesync.notifier.testing.testcase import AccumulatingNotifyBus

nb = AccumulatingNotifyBus()
register_notifier_for_bus(nb)

print """
OH HAI HACKERS
This sets up an environment making it easy to play with the data access layer.

try this out:
bob = services.make_storage_user(
    'bob', visible_name='Bob the Builder', max_storage_bytes=30*(2**30))
tim = services.make_storage_user(
    'tim', visible_name='Tim the Enchanter', max_storage_bytes=30*(2**30))

udf = bob.make_udf("~/Documents")
dir = bob.volume(udf.id).root.make_subdirectory("Junk")
share = dir.share(tim.id, "MyJunk")
tim.get_share(share.id).accept()

file = tim.volume(share.id).root.make_file("file.txt")

# You also can see events queued for MQ:
print nb.events
"""
