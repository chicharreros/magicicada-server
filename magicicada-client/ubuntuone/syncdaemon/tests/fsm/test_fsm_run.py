# ubuntuone.syncdaemon.fsm.tests.test_fsm_run
#
# Author: Lucio Torre <lucio.torre@canonical.com>
#
# Copyright 2009-2012 Canonical Ltd.
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
"""Tests for running fsms."""

import unittest
import os

from ubuntuone.syncdaemon.fsm import fsm


def p(name):
    """Make a full path from here."""
    if "HAS_OOFICE" in os.environ:
        return os.path.join(os.path.dirname(__file__), name+".ods")
    else:
        return os.path.join(os.path.dirname(__file__), name+".py")


class TestRun(unittest.TestCase):
    """Test fsm running."""

    def test_hello(self):
        """Test running a hello world machine."""
        f = fsm.StateMachine(p("test_run_hello"))
        f.validate()
        result = []

        def make(out, outstates):
            """Make action_func functions."""

            def maker(self, event, params):
                "inner"
                result.append(out)
                self.state = outstates[int(params["MV1"])-1]

            return maker

        class HelloRunner(fsm.StateMachineRunner):
            """Our implementation of the runner."""
            state = "H"
            H = make("h", "EEE")
            E = make("e", "LLL")
            L = make("l", "LOD")
            O = make("o", "WRR")
            W = make("w", "OOO")
            R = make("r", "LLL")
            D = make("d", ["NL"]*3)
            newline = make("\n", "HHH")

            def get_state_values(self):
                """Return the stateval of this fsm."""
                return dict(SV1=self.state)

        runner = HelloRunner(f)
        for i in [1, 1, 1, 2, 1, 2, 2, 3, 3, 1, 1]:
            runner.on_event("EVENT_1", dict(MV1=str(i)))
        self.assertEqual("helloworld\n", "".join(result))
