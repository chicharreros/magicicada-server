#!/usr/bin/env python

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

"""Given a user, create UDFs, folders and files to help with manual testing."""

from __future__ import unicode_literals

import sys
import random
import uuid

import _pythonpath  # NOQA

from twisted.python.util import makeStatBar

from magicicada.filesync.services import get_storage_user
from magicicada.filesync.tests.testcase import Factory


def utf2unicode(s):
    return unicode(s, 'utf-8', 'replace')


def make_udf(user, sample):
    """create a UDF for user using names from sample"""
    name = sample.pop()
    paths = []
    for j in range(random.randint(1, 4)):
        paths.append(sample.pop())
    udf = user.make_udf('~/' + '/'.join(paths) + '/' + name)
    return user.volume(udf.id).get_node(udf.root_id)


def main(username, sharer, wlist, num):
    """Create UDFs, folders and files for the given user using a wordlist."""
    user = get_storage_user(None, username=utf2unicode(username))
    sharer = get_storage_user(None, username=utf2unicode(sharer))
    folders = [user.root]
    names = [utf2unicode(i.strip()) for i in file(wlist) if i.strip()]
    sample = random.sample(names, num)

    if sys.stdout.isatty():
        import curses
        curses.setupterm()
        cols = curses.tigetnum('cols') - 1
        progbar = makeStatBar(cols, cols - 2)
        home = curses.tigetstr('cr')

        def progress(l):
            """progress bar writer."""
            sys.stdout.write(home + progbar((cols - 2) * (num - len(l)) / num))
            sys.stdout.flush()
    else:
        def progress(l): return

    # UDF
    udf = user.make_udf('~/abundant-files')
    folders.append(user.volume(udf.id).get_node(udf.root_id))

    # some UDFs
    for i in range(num / 100):
        progress(sample)
        folders.append(make_udf(user, sample))

    for i in range(num / 4):
        progress(sample)
        name = sample.pop()
        folders.append(random.choice(folders).make_subdirectory(name))

    sh_folders = [sharer.root]
    for i in range(num / 10):
        progress(sample)
        sh_folders.append(make_udf(sharer, sample))
    for i in range(num / 10):
        progress(sample)
        name = sample.pop()
        sh_folders.append(random.choice(sh_folders).make_subdirectory(name))
    for i in range(num / 20):
        progress(sample)
        name = sample.pop()
        filename = 'shared by ' + sharer.username
        readonly = random.choice((False, True))
        if readonly:
            name += ' (ro)'
            filename += ' (ro)'
        folder = random.choice(sh_folders).make_subdirectory(name)
        folder.make_file(filename)
        share = folder.share(user.id, folder.name, readonly)
        user.get_share(share.id).accept()

    for i in random.sample(folders, len(folders) / 4):
        progress(sample)
        name = sample.pop()
        filename = 'shared by ' + user.username
        readonly = random.choice((False, True))
        if readonly:
            name += ' (ro)'
            filename += ' (ro)'
        folder = random.choice(folders).make_subdirectory(name)
        folder.make_file(filename)
        share = folder.share(sharer.id, folder.name, readonly)
        sharer.get_share(share.id).accept()

    for i in range(num / 20):
        progress(sample)
        name = sample.pop()
        random.choice(folders).make_file(name)

    fake_hash = Factory().get_fake_hash()
    while sample:
        progress(sample)
        name = sample.pop()
        random.choice(folders).make_file_with_content(
            name, fake_hash, 12345, 100, 10000, uuid.uuid4(), 'image/tiff')

    if sys.stdout.isatty():
        sys.stdout.write(home + curses.tigetstr('el'))


if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser("%prog [options] username")
    parser.add_option("-w", "--wordlist", default="/usr/share/dict/words")
    parser.add_option("-n", "--number", help="number of words to use",
                      type="int", default=1000)
    parser.add_option("-s", "--sharer", help="username with which to share",
                      default="chico")
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error('missing username')
    main(args[0], options.sharer, options.wordlist, options.number)
