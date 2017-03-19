# tests.platform.windows.test_tools_irl
#
# Author: Manuel de la Pena <manuel@canonical.com>
#
# Copyright 2011-2012 Canonical Ltd.
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 3, as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# In addition, as a special exception, the copyright holders give
# permission to link the code of portions of this program with the
# OpenSSL library under certain conditions as described in each
# individual source file, and distribute linked combinations
# including the two.
# You must obey the GNU General Public License in all respects
# for all of the code used other than OpenSSL.  If you modify
# file(s) with this exception, you may extend this exception to your
# version of the file(s), but you are not obligated to do so.  If you
# do not wish to do so, delete this exception statement from your
# version.  If you delete this exception statement from all source
# files in the program, then also delete it here.
"""Small example of how to use the sdtools on windows."""

# we use the standard reactor on windows
from twisted.internet import reactor, defer
from ubuntuone.platform.windows import tools


@defer.inlineCallbacks
def print_test():
    """Print the current downloads."""
    sdtool = tools.SyncDaemonTool()
    yield sdtool.client.connect()
    result = yield sdtool.get_current_downloads()
    print 'Current downloads are: '
    for download in result:
        print download
    result = yield sdtool.get_current_uploads()
    print 'Current Uplaods are: '
    for upload in result:
        print upload
    print 'The current config is:'
    shares_link = yield sdtool.get_shares_dir_link()
    print '\tShares link: %s' % shares_link
    shares_dir = yield sdtool.get_shares_dir()
    print '\tShares dir: %s' % shares_dir
    root_dir = yield sdtool.get_root_dir()
    print '\tRoot dir: %s' % root_dir
    is_udf_autosubscribe_enabled = yield sdtool.is_udf_autosubscribe_enabled()
    print '\tAutosubscribe enabled: %s' % is_udf_autosubscribe_enabled
    is_share_autosubscribe_enabled = (
        yield sdtool.is_share_autosubscribe_enabled())
    print '\tAutosubscribe enabled: %s' % is_share_autosubscribe_enabled
    reactor.stop()


if __name__ == '__main__':
    reactor.callLater(0, print_test)
    reactor.run()
