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

"""Dump of different reports."""

import os
import gc

from django.conf import settings
from django.utils.timezone import now

try:
    from meliae import scanner
except ImportError:
    scanner = None


SIGMELIAE = 44


def meliae_dump():
    """Dump memory using meliae."""
    if scanner is None:
        return "Meliae not available"

    try:
        dump_dir = settings.LOG_FOLDER
        filename = os.path.join(
            dump_dir,
            'meliae-%s.json'
            % (
                now().strftime(
                    "%Y%m%d%H%M%S",
                )
            ),
        )
        gc.collect()
        scanner.dump_all_objects(filename)
    except Exception as e:
        return "Error while trying to dump memory: %s" % (e,)
    else:
        return 'Output written to: %s' % (filename,)


def gc_dump():
    """Dump GC usage."""
    try:
        dump_dir = settings.LOG_FOLDER
        tstamp = now().strftime("%Y%m%d%H%M%S")
        fname = os.path.join(dump_dir, 'gcdump-%s.txt' % (tstamp,))
        fh = open(fname, "w")

        # count
        count = gc.get_count()
        fh.write("gc.get_count():\n%s\n" % (count,))

        # garbage
        fh.write("gc.garbage:\n")
        c = 0
        for x in gc.garbage:
            c += 1
            try:
                line = repr(x)
            except Exception as e:
                line = "Error str'ing an object: " + str(e)
            fh.write(line + "\n")
        fh.close()
        m = 'GC count is %s and %d garbage items written to: %s' % (
            count,
            c,
            fname,
        )
        return m
    except Exception as e:
        return "Error while trying to dump GC: %s" % (e,)
