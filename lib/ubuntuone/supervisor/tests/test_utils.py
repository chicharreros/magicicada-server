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

"""Test for the supervisor utilities."""

import json
import time
import logging
from io import BytesIO

from supervisor.events import ProcessCommunicationEvent
from twisted.internet import defer, task, protocol

from magicicada.testing.testcase import BaseTestCase
from ubuntuone.supervisor.utils import (
    send_heartbeat,
    heartbeat_generator,
    HeartbeatWriter,
)

BEGIN_TOKEN = ProcessCommunicationEvent.BEGIN_TOKEN
END_TOKEN = ProcessCommunicationEvent.END_TOKEN


def wait_for(func, sleep=0.1, retries=10):
    """Loop and sleep until func() returns True."""
    count = 0
    while not func():
        if count == retries:
            raise RuntimeError(
                "%s still returned False after %d runs" % (func, retries)
            )
        time.sleep(sleep)
        count += 1


class HeartbeatTestCase(BaseTestCase):
    """Tests for heartbeat related utilities."""

    def test_send_heartbeat(self):
        """Test send_heartbeat function.

        This function is going to be called from Twisted, so we need to ensure
        that bytes are written to `out`, otherwise we'd get a traceback similar
        to this one:

        [twisted.internet.defer#critical] Unhandled error in Deferred:
        Traceback (most recent call last):
          File "/?/twisted/internet/protocol.py", line 509, in makeConnection
            self.connectionMade()
          File "/?/ubuntuone/supervisor/utils.py", line 78, in connectionMade
            self.loop.start(self.interval)
          File "/?/twisted/internet/task.py", line 206, in start
            self()
          File "/?/twisted/internet/task.py", line 251, in __call__
            d = maybeDeferred(self.f, *self.a, **self.kw)
        --- <exception caught here> ---
          File "/?/twisted/internet/defer.py", line 190, in maybeDeferred
            result = f(*args, **kwargs)
          File "/?/ubuntuone/supervisor/utils.py", line 71, in send
            send_heartbeat(
          File "/?/ubuntuone/supervisor/utils.py", line 32, in send_heartbeat
            out.write(ProcessCommunicationEvent.BEGIN_TOKEN.decode('utf-8'))
          File "/?/twisted/internet/_posixstdio.py", line 57, in write
            self._writer.write(data)
          File "/?/twisted/internet/process.py", line 177, in write
            abstract.FileDescriptor.write(self, data)
          File "/?/twisted/internet/abstract.py", line 356, in write
            _dataMustBeBytes(data)
          File "/?/twisted/internet/abstract.py", line 24, in _dataMustBeBytes
            raise TypeError("Data must be bytes")
        builtins.TypeError: Data must be bytes

        """
        out = BytesIO()
        send_heartbeat(out=out)
        raw_event = out.getvalue()
        self.assertTrue(raw_event.startswith(BEGIN_TOKEN))
        self.assertTrue(raw_event.endswith(END_TOKEN))
        # strip the tokens
        payload = json.loads(raw_event.strip(BEGIN_TOKEN).strip(END_TOKEN))
        self.assertEqual(payload['type'], "heartbeat")
        self.assertTrue(payload['time'] <= time.time())


class Timer(object):
    """A helper class to fake time.time()."""

    def __init__(self):
        self.current_time = 0

    def advance(self, s):
        """Advance the clock 's' seconds."""
        self.current_time += s

    def __call__(self):
        return self.current_time


class HeartbeatGeneratorTestCase(BaseTestCase):
    """Tests for HeartbeatGenerator."""

    def setUp(self):
        super(HeartbeatGeneratorTestCase, self).setUp()
        self.out = BytesIO()
        self.timer = Timer()

    def test_send_heartbeat_on_interval(self):
        """Test that we actually send the heartbeat."""
        gen = heartbeat_generator(2, out=self.out, time=self.timer)
        next(gen)
        self.assertFalse(self.out.getvalue())
        self.timer.advance(2)
        next(gen)
        output = self.out.getvalue()
        self.assertTrue(b'<!--XSUPERVISOR:BEGIN-->' in output)
        self.assertTrue(b'<!--XSUPERVISOR:END-->' in output)

    def test_not_send_heartbeat(self):
        """Test that we don't send the heartbeat."""
        gen = heartbeat_generator(2, out=self.out, time=self.timer)
        next(gen)
        self.assertFalse(self.out.getvalue())
        self.timer.advance(0.5)
        next(gen)
        self.assertFalse(self.out.getvalue())
        self.timer.advance(0.5)
        next(gen)
        self.assertFalse(self.out.getvalue())

    def test_interval_None(self):
        """Test generator with interval=None"""
        gen = heartbeat_generator(None, out=self.out, time=self.timer)
        next(gen)
        self.assertFalse(self.out.getvalue())
        self.timer.advance(5)
        next(gen)
        self.assertFalse(self.out.getvalue())
        self.timer.advance(5)


class HeartbeatWriterTest(BaseTestCase):
    """Tests for HeartbeatWriter."""

    interval = 5

    @defer.inlineCallbacks
    def setUp(self):
        yield super(HeartbeatWriterTest, self).setUp()
        self.logger = logging.Logger("HeartbeatWriter.test")
        self.handler = self.add_memento_handler(self.logger)
        self.clock = task.Clock()
        self.hw = HeartbeatWriter(
            self.interval, self.logger, reactor=self.clock
        )

    def test_send_no_transport(self):
        """Log a warning when there is no transport."""
        self.hw.send()
        self.handler.assert_warning("Can't send heartbeat without a transport")

    def test_send_loop(self):
        """Send heartbeats in the LoopingCall."""
        # first connect to something
        transport = BytesIO()
        self.clock.advance(2)
        self.hw.makeConnection(transport)
        self.clock.advance(5)
        self.clock.advance(5)
        # we should have 3 heartbeats in the transport, get them
        raw_events = transport.getvalue().split(BEGIN_TOKEN, 3)
        events = []
        for raw_event in raw_events:
            if raw_event:
                events.append(json.loads(raw_event.strip(END_TOKEN)))
        # strip the tokens
        for i, timestamp in [(0, 2), (1, 7), (2, 12)]:
            self.assertEqual(events[i]['type'], "heartbeat")
            self.assertEqual(events[i]['time'], timestamp)

    def test_send_on_connectionMade(self):
        """On connectionMade start the loop and send."""
        # first connect to something
        transport = BytesIO()
        self.clock.advance(0.1)
        self.hw.makeConnection(transport)
        self.assertTrue(self.hw.loop.running)
        raw_event = transport.getvalue()
        self.assertTrue(raw_event.startswith(BEGIN_TOKEN))
        self.assertTrue(raw_event.endswith(END_TOKEN))
        # strip the tokens
        payload = json.loads(raw_event.strip(BEGIN_TOKEN).strip(END_TOKEN))
        self.assertEqual(payload['type'], "heartbeat")
        self.assertEqual(payload['time'], self.clock.seconds())

    def test_connectionLost(self):
        """On connectionLost cleanup everything."""
        self.hw.makeConnection(None)
        called = []
        self.patch(self.hw.loop, 'stop', lambda: called.append(True))
        self.hw.connectionLost(protocol.connectionDone)
        self.handler.assert_info(
            "HeartbeatWriter connectionLost: %s" % protocol.connectionDone
        )
        self.assertTrue(called)
        self.assertEqual(self.hw.loop, None)
        self.assertEqual(self.hw.reactor, None)
        self.assertEqual(self.hw.logger, None)
