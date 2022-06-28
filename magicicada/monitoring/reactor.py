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

"""A thread that measures responsiveness of the twisted reactor."""

import logging
import os
import queue
import sys
import time
import threading
import traceback

from magicicada import metrics
from magicicada.settings import TRACE


logger = logging.getLogger(__name__)


class ReactorInspector(threading.Thread):
    """Log message with a time delta from the last call."""

    def __init__(self, reactor_call, loop_time=3):
        self.running = False
        self.stopped = False
        self.queue = queue.Queue()
        self.reactor_call = reactor_call
        self.loop_time = loop_time
        self.metrics = metrics.get_meter("reactor_inspector")
        self.last_responsive_ts = 0
        self.reactor_thread = None
        super(ReactorInspector, self).__init__()
        self.daemon = True

    def start(self):
        """Start the thread. Should be called from the reactor main thread."""
        self.reactor_thread = threading.currentThread().ident
        if not self.running:
            self.running = True
            super(ReactorInspector, self).start()

    def stop(self):
        """Stop the thread."""
        self.stopped = True
        logger.info("ReactorInspector: stopped")

    def dump_frames(self):
        """Dump frames info to log file."""
        current = threading.currentThread().ident
        frames = sys._current_frames()
        for frame_id, frame in frames.items():
            if frame_id == current:
                continue

            stack = ''.join(traceback.format_stack(frame))

            if frame_id == self.reactor_thread:
                title = "Dumping Python frame for reactor main thread"
            else:
                title = "Dumping Python frame"
            logger.debug(
                "%s %s (pid: %d):\n%s", title, frame_id, os.getpid(), stack)

    def run(self):
        """Start running the thread."""
        logger.info("ReactorInspector: started")
        msg_id = 0
        oldest_pending_request_ts = time.time()
        while not self.stopped:
            def task(msg_id=msg_id, tini=time.time()):
                """Put result in queue with initial and completed times."""
                self.queue.put((msg_id, tini, time.time()))
            self.reactor_call(task)
            time.sleep(self.loop_time)
            try:
                id_sent, tini, tsent = self.queue.get_nowait()
            except queue.Empty:
                # Oldest pending request is still out there
                delay = time.time() - oldest_pending_request_ts
                self.metrics.gauge("delay", delay)
                logger.critical(
                    "ReactorInspector: detected unresponsive! (current: %d, "
                    "pid: %d) delay: %.3f", msg_id, os.getpid(), delay)
                self.dump_frames()
            else:
                delay = tsent - tini
                self.metrics.gauge("delay", delay)
                if msg_id > id_sent:
                    logger.warning(
                        "ReactorInspector: late (current: %d, got: %d, pid: "
                        "%d, cleaning queue) delay: %.3f",
                        msg_id, id_sent, os.getpid(), delay)
                    while not self.queue.empty():
                        self.queue.get_nowait()
                    # About to start a new request with nothing pending
                    oldest_pending_request_ts = time.time()
                else:
                    assert msg_id == id_sent
                    # About to start a new request with nothing pending
                    self.last_responsive_ts = time.time()
                    oldest_pending_request_ts = self.last_responsive_ts
                    logger.log(
                        TRACE,
                        "ReactorInspector: ok (msg: %d, pid: %d) delay: %.3f",
                        msg_id, os.getpid(), delay)
            finally:
                msg_id += 1
