# ubuntuone.syncdaemon.fsm.tests.test_fsm
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
"""Tests for fsm that depend on python uno."""

import os
import unittest

from ubuntuone.syncdaemon.fsm import fsm

try:
    import uno
except ImportError:
    uno = None


def p(name):
    """Make a full path from here."""
    return os.path.join(os.path.dirname(__file__), name)


@unittest.skipIf(uno is None, 'python-uno not available')
class TestParse(unittest.TestCase):
    """Test fsm validation."""

    def test_one_event(self):
        """Test parsing a simple machine."""
        f = fsm.StateMachine(p("test_one_event.ods"))
        f.validate()

    def test_two_events(self):
        """Test parsing a machine with two events."""
        f = fsm.StateMachine(p("test_two_events.ods"))
        f.validate()

    def test_bang(self):
        """Test not event expansion."""
        f = fsm.StateMachine(p("test_bang.ods"))
        f.validate()

    def test_transition_twice(self):
        """Test error on duplicate transition."""
        f = fsm.StateMachine(p("test_transition_twice.ods"))
        self.assertRaises(fsm.ValidationFailed, f.validate)
        self.assertEqual(len(f.errors), 1)

    def test_missing_source_state(self):
        """Test incomplete state transition coverage."""
        f = fsm.StateMachine(p("test_missing_source_state.ods"))
        self.assertRaises(fsm.ValidationFailed, f.validate)
        self.assertEqual(len(f.errors), 1)

    def test_missing_param_values(self):
        """Test incomplete param transition coverage."""
        f = fsm.StateMachine(p("test_missing_param_values.ods"))
        self.assertRaises(fsm.ValidationFailed, f.validate)
        self.assertEqual(len(f.errors), 4)

    def test_two_missing_source_state(self):
        """Test incomplete state transition coverage."""
        f = fsm.StateMachine(p("test_two_missing_source_state.ods"))
        self.assertRaises(fsm.ValidationFailed, f.validate)
        self.assertEqual(len(f.errors), 2)

    def test_star_event(self):
        """Test expansion of one star in event columns."""
        f = fsm.StateMachine(p("test_star_event.ods"))
        f.validate()

    def test_two_star_event(self):
        """Test expansion of two stars in event columns."""
        f = fsm.StateMachine(p("test_two_star_event.ods"))
        f.validate()

    def test_star_param(self):
        """Test expansion of one star in param columns."""
        f = fsm.StateMachine(p("test_star_param.ods"))
        f.validate()

    def test_two_star_param(self):
        """Test expansion of two stars in param columns."""
        f = fsm.StateMachine(p("test_two_star_param.ods"))
        f.validate()

    def test_invalid(self):
        """Test expansion of two stars in param columns."""
        f = fsm.StateMachine(p("test_invalid.ods"))
        f.validate()

    def test_invalid_expand(self):
        """Test expansion of two stars in param columns."""
        f = fsm.StateMachine(p("test_invalid_expand.ods"))
        f.validate()

    def test_star_event_repeat(self):
        """Test expansion of stars that cover too much."""
        f = fsm.StateMachine(p("test_star_event_repeat.ods"))
        self.assertRaises(fsm.ValidationFailed, f.validate)
        self.assertEqual(len(f.errors), 1)

    def test_out_equal(self):
        """Test expansion of "=" in state out."""
        f = fsm.StateMachine(p("test_out_equal.ods"))
        f.validate()
        for s in f.states.values():
            for t in s.transitions.values():
                for k in t.source:
                    self.assertEqual(t.source[k], t.target[k])

    def test_out_equal_star(self):
        """Test expansion of "=" in state out."""
        f = fsm.StateMachine(p("test_out_equal_star.ods"))
        f.validate()
        for s in f.states.values():
            for t in s.transitions.values():
                for k in t.source:
                    self.assertEqual(
                        t.source[k], t.target[k],
                        "on transition %s target is %s" % (t, t.target))

    def test_equal_wrong_places(self):
        """make sure "=" are not allowed on state or params."""
        f = fsm.StateMachine(p("test_equal_wrong_place.ods"))
        self.assertRaises(fsm.ValidationFailed, f.validate)
        # this should be two errors
        # but more errors happen as there is no clear interpretation of
        # the table in this case
        self.assertEqual(len(f.errors), 5)

    def test_param_na(self):
        """Test that na param columns are ignored."""
        f = fsm.StateMachine(p("test_param_na.ods"))
        f.validate()
        self.assertEqual(f.events["EVENT_2"].transitions[0].parameters.keys(),
                         [u"MV2"],)

    def test_func_na(self):
        """Test that na param columns are ignored."""
        f = fsm.StateMachine(p("test_func_na.ods"))
        f.validate()
        # the state
        s = f.states[fsm.hash_dict(dict(SV1="T"))]
        # the transition
        t = "EVENT_1", fsm.hash_dict(dict(MV1="T", MV2="T"))
        self.assertFalse(t in s.transitions)
