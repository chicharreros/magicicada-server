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

"""An (non) RPC layer."""

import logging
import os
import time

from twisted.internet import defer, threads

from magicicada.rpcdb import backend


# log setup
logger = logging.getLogger(__name__)


class ThreadedNonRPC(object):
    """A threaded way to call endpoints, not really an RPC."""

    def __init__(self):
        super(ThreadedNonRPC, self).__init__()
        self.backend = backend.DAL()
        if int(os.getenv('MAGICICADA_DEBUG', '0')):
            self.defer = defer.maybeDeferred
        else:
            self.defer = threads.deferToThread

    @defer.inlineCallbacks
    def call(self, funcname, **kwargs):
        """Call the method in the backend."""
        user_id = kwargs.get('user_id')
        logger.info("Call to %s (user=%s) started", funcname, user_id)

        start_time = time.time()
        try:
            method = getattr(self.backend, funcname)
            result = yield self.defer(method, **kwargs)
        except Exception as exc:
            time_delta = time.time() - start_time
            logger.info(
                "Call %s (user=%s) ended with error: %s (%s) - time: %s",
                funcname,
                user_id,
                exc.__class__.__name__,
                exc,
                time_delta,
            )
            raise

        time_delta = time.time() - start_time
        logger.info(
            "Call to %s (user=%s) ended OK - time: %s",
            funcname,
            user_id,
            time_delta,
        )
        defer.returnValue(result)
