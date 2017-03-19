# ubuntuone.syncdaemon.fsm.fsm - a fsm
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
"""
Will read the output produced by fsm_parser.parse or a .py serialization of
it and create and validate a state machine.
"""

import itertools

from ubuntuone.syncdaemon import logger


def hash_dict(d):
    "return a hashable representation of the dict"
    return tuple(sorted(d.items()))


class ValidationFailed(Exception):
    """signals that the specification is not correct"""


class ValidationError(object):
    """Contains validation errors"""

    def __init__(self, description):
        "create a validation error with description"
        self.description = description

    def __str__(self):
        "__str__"
        return "Validation Error: %s" % self.description


def build_combinations_from_varlist(varlist):
    """ create all posible variable values combinations

    takes a dict in the form {varname: [value, value2, *]}
    returns [{varname:value}, {varname:value2}, ...]
    """
    items = varlist.items()
    keys = [x[0] for x in items]
    values = [x[1] for x in items]

    possible_states = [dict(zip(keys, state))
                       for state in itertools.product(*values)]
    return possible_states


def expand_var_list(varlist, values):
    """ exapand a state description

    takes a {varname:value} dict and returns a list of {varname:value} but with
    stars and bangs replaced for all its possible values
    """
    myvalues = values.copy()
    for name in myvalues:
        # star may be unicode
        if str(myvalues[name]) == "*":
            myvalues[name] = varlist[name]
        elif str(myvalues[name])[0] == "!":
            l = varlist[name].copy()
            l.remove(myvalues[name][1:])
            myvalues[name] = l
        else:
            myvalues[name] = [myvalues[name]]
    return build_combinations_from_varlist(myvalues)


class StateMachineRunner(object):
    """Reads a StateMachine descriptions and executes transitions."""

    def __init__(self, fsm, log=None):
        """Create a state machine based on fsm."""
        self.fsm = fsm
        if log is None:
            self.log = logger.root_logger
        else:
            self.log = log

    def on_event(self, event_name, parameters, *args):
        """Do the transition for this event.
        Returns the function called for the action"""
        # get the state
        self.log.debug("EVENT: %s:%s with ARGS:%s" % (
            event_name, parameters, args))
        try:
            enter_state = self.get_state()
        except KeyError:
            self.log.error("cant find current state: %s" % (
                self.get_state_values()))
            raise KeyError("Incorrect In State")

        # find the transition
        try:
            transition = enter_state.get_transition(event_name, parameters)
        except KeyError:
            self.log.error("Cant find transition %s:%s" %
                           (event_name, parameters))
            return
        action_func_name = transition.action_func
        # call the action_func
        af = getattr(self, action_func_name, None)
        if af is None:
            self.log.error("cant find ACTION_FUNC: %s" % (action_func_name))
        elif af == "pass":
            self.log.debug("passing")
        else:
            self.log.info("Calling %s (got %s:%s)",
                          action_func_name, event_name, parameters)
            try:
                af(event_name, parameters, *args)
            except Exception, e:
                self.log.exception("Executing ACTION_FUNC '%s' "
                                   "gave an exception: %r" %
                                   (action_func_name, e))
                self.on_error(event_name, parameters)
                return
        # validate the end state
        try:
            out_state = self.get_state()
        except KeyError:
            self.log.error(
                "from state %s on %s:%s, cant find current out state: %s",
                enter_state.values, event_name, parameters,
                self.get_state_values())
            self.on_error(event_name, parameters)
            raise KeyError("unknown out state")

        if out_state.values != transition.target:
            self.log.error(
                "in state %s with event %s:%s, out state is: %s and should "
                "be %s", enter_state.values, event_name, parameters,
                out_state.values, transition.target)
            raise ValueError("Incorrect out state")
        self.log.debug("Called %s", action_func_name)
        return action_func_name

    def get_state(self):
        """Get the current state's object"""
        return self.fsm.get_state(self.get_state_values())

    def get_state_values(self):
        """Get the state variables values for this state.

        This has to be overridden on implementations of this class.
        """
        raise NotImplementedError()

    def on_error(self, event_name, parameters):
        """A Transition encontered an error. Cleanup.
        """


class StateMachine(object):
    """The state machine"""

    def __init__(self, input_data, event_filter=None):
        """create a fsm from filename.

        filename can be an .ods file or a dictionary
        event_filter, if not None, limits the events you want to parse.
        """
        self.errors = []
        self.event_filter = event_filter
        if isinstance(input_data, str):
            if input_data.endswith(".ods"):
                # fsm_parser depends on python-uno for reading ods documents
                # this shouldnt be called with an .ods file on production
                # environments
                from ubuntuone.syncdaemon.fsm import fsm_parser
                spec = fsm_parser.parse(input_data)
            elif input_data.endswith(".py"):
                result = {}
                exec open(input_data) in result
                spec = result["state_machine"]
            else:
                raise ValueError("Unknown input format")
        else:
            spec = input_data
        self.spec = spec
        self.events = {}
        self.states = {}
        self.state_vars = {}
        self.param_vars = {}
        self.build()

    def validate(self):
        """Raises an exception if the file had errors."""
        if self.errors:
            raise ValidationFailed("There are %s validation errors" %
                                   len(self.errors))
        return True

    def get_variable_values(self, kind, name):
        """Returns all the values a variable of kind in
        [STATE, PARAMETERS, STATE_OUT] with name name can take.
        """
        vals = set()
        for event in self.spec["events"].values():
            for state in event:
                try:
                    value = state[kind][name]
                except KeyError:
                    err = ValidationError(
                        "variable name '%s' not found in section %s" %
                        (name, kind))
                    self.errors.append(err)
                else:
                    if str(value).strip() == "=" and kind != "STATE_OUT":
                        self.errors.append(ValidationError(
                            "Cant have '=' in STATE or PARAMETERS section"))
                    if not str(value).strip() in ("*", "="):
                        if not str(value).strip()[0] == "!":
                            vals.add(value)
        return vals

    def build(self):
        """Do all the parsing and validating."""
        # build state variable posible values
        state_vars = {}
        for state_var in self.spec["state_vars"]:
            values = self.get_variable_values("STATE", state_var)
            values.update(self.get_variable_values("STATE_OUT", state_var))
            state_vars[state_var] = values

        self.state_vars = state_vars

        # build message parameter posible values
        parameters = {}
        for state_var in self.spec["parameters"]:
            values = self.get_variable_values("PARAMETERS", state_var)
            parameters[state_var] = values

        self.param_vars = parameters

        # build posible states
        possible_states = build_combinations_from_varlist(self.state_vars)
        # remove invalid
        for s in self.spec["invalid"]:
            for es in expand_var_list(self.state_vars, s):
                try:
                    possible_states.remove(es)
                except ValueError:
                    self.errors.append(
                        ValidationError(
                            "State %s already removed from invalid" % es))

        for stateval in possible_states:
            self.states[hash_dict(stateval)] = State(stateval)

        # build transitions
        for event_name, lines in self.spec["events"].items():
            if self.event_filter and event_name not in self.event_filter:
                continue
            event = Event(event_name, lines, self)
            self.events[event_name] = event
            tracker = event.get_tracker()
            for transition in event.transitions:
                # for each transition
                try:
                    state = self.states[hash_dict(transition.source)]
                except KeyError:
                    continue
                    # we dont error, so * that cover invalid states still work
                    # XXX: lucio.torre:
                    # we should check that if the transition
                    # is not expanded or all the states it covers are
                    # invalid, because this is an error
                    self.errors.append(
                        ValidationError(
                            "Transitiont on %s with %s from '%s'cant find "
                            "source state." % (transition.event,
                                               transition.parameters,
                                               transition.source)))
                    continue
                s = {}
                s.update(transition.source)
                s.update(transition.parameters)
                try:
                    tracker.remove(s)
                except ValueError:
                    self.errors.append(
                        ValidationError(
                            "For event %s, the following transition was "
                            "already covered: %s" % (event, transition)))
                else:
                    state.add_transition(transition)
            if tracker.empty():
                for s in tracker.pending:
                    self.errors.append(
                        ValidationError(
                            "The following state x parameters where not "
                            "covered for '%s': %s" % (event, s)))

    def get_state(self, vars_dict):
        """Get a state instance from a dict with {varname:value}"""
        return self.states[hash_dict(vars_dict)]


class Tracker(object):
    """Tracks a list of state_x_params combinations.

    Does the same that a list does, but its more explicit. it used to do more.
    """
    def __init__(self, state_x_params):
        """Create a tracker."""
        self.pending = state_x_params[:]

    def remove(self, case):
        """Remove a case."""
        self.pending.remove(case)

    def empty(self):
        """Check for pending cases."""
        return bool(self.pending)


class Event(object):
    """Represents events that may happen.

    Interesting properties:
    name: the name of the event
    state_vars: {varname:[value, value2, ...]} for state
    param_vars: {varname:[value, value2, ...]} for params
    transitions: all the transitions that this event produces
    draw_transitions: the transitions, but not expanded. for drawing.
    state_x_params: all the posible state_x_params this event may encounter
    """
    def __init__(self, name, lines, machine):
        state_vars = machine.state_vars
        param_vars = machine.param_vars
        self.invalid_states = machine.spec["invalid"]
        self.name = name
        self.state_vars = state_vars.copy()
        self.event_vars = param_vars.copy()
        # create transitions expanding *'s
        self.transitions = []
        # we have to remove parameters that have NA on all the rows
        invalid = set(param_vars.keys())
        # clean invalid list
        for line in lines:
            for k, v in line["PARAMETERS"].items():
                if str(v).strip() != "NA":
                    # this parameter has a value, remove from invalid list
                    if k in invalid:
                        invalid.remove(k)

        # remove invalids from lines
        for line in lines:
            for inv in invalid:
                if inv in line["PARAMETERS"]:
                    del line["PARAMETERS"][inv]

        # remove invalid from param_vars
        for inv in invalid:
            del self.event_vars[inv]

        # make list of state_x_parameters to cover
        vlist = {}
        vlist.update(self.state_vars)
        vlist.update(self.event_vars)
        self.state_x_params = build_combinations_from_varlist(vlist)
        # now we remove the lines that have been defines as invalid
        toremove = []
        for i in self.invalid_states:
            for ei in expand_var_list(state_vars, i):
                for sxp in self.state_x_params:
                    for k, v in ei.items():
                        if sxp[k] != v:
                            break
                    else:
                        if sxp not in toremove:
                            toremove.append(sxp)

        map(self.state_x_params.remove, toremove)

        # create transitions by expanding states
        for line in lines:
            state_exp = expand_var_list(state_vars, line["STATE"])
            param_exp = expand_var_list(param_vars, line["PARAMETERS"])
            for se in state_exp:
                for pe in param_exp:
                    new_line = line.copy()
                    # copy source state if dest state is '='
                    so = new_line["STATE_OUT"].copy()
                    for k in so:
                        if str(so[k]).strip() == "=":
                            so[k] = se[k]
                    new_line["STATE"] = se
                    new_line["PARAMETERS"] = pe
                    new_line["STATE_OUT"] = so

                    # here we have the expanded lines, remove from
                    # states_x_params the lines with action NA
                    if str(new_line["ACTION"]).strip() == "NA":
                        s_x_p = {}
                        s_x_p.update(new_line["STATE"])
                        s_x_p.update(new_line["PARAMETERS"])
                        if s_x_p in self.state_x_params:
                            self.state_x_params.remove(s_x_p)
                    else:
                        self.transitions.append(Transition(name, new_line))

        # create transitions by expanding states, but dont expand params
        # so we can use this transitions to draw them
        self.draw_transitions = []
        for line in lines:
            state_exp = expand_var_list(state_vars, line["STATE"])
            pe = line["PARAMETERS"]
            for se in state_exp:
                new_line = line.copy()
                # copy source state if dest state is '='
                so = new_line["STATE_OUT"].copy()
                for k in so:
                    if str(so[k]).strip() == "=":
                        so[k] = se[k]
                new_line["STATE"] = se
                new_line["PARAMETERS"] = pe
                new_line["STATE_OUT"] = so

                # here we have the expanded lines, remove from
                # states_x_params the lines with action NA
                if not str(new_line["ACTION"]).strip() == "NA":
                    self.draw_transitions.append(Transition(name, new_line))

    def __str__(self):
        """__str___"""
        return "<Event: %s>" % self.name

    def get_tracker(self):
        """Get a tracker for this state."""
        return Tracker(self.state_x_params)


class Transition(object):
    """A transition.

    For each expansion of a transition line in the original spreadsheet we
    get one of these. with the corresponding attributes for all sections
    and event name.
    """
    __slots__ = ('event', 'line', 'source',
                 'target', 'parameters', 'action_func')

    def __init__(self, event, line):
        """Create a transition for event event from line.

        line may be an expanded version of a source line.
        """
        self.event = event
        self.line = line
        self.source = line["STATE"]
        self.target = line["STATE_OUT"]
        self.parameters = line["PARAMETERS"]
        self.action_func = line["ACTION_FUNC"]

    def __str__(self):
        """___str___"""
        return "<Transition: %s: %s x %s>" % (
            self.event, self.source, self.parameters)


class State(object):
    """A State object.

    Represents a combination of state variable values.
    values: the state values
    transitions: the transitions that leave from this state
    """

    def __init__(self, values):
        """Create a state."""
        self.values = values
        self.transitions = {}

    def add_transition(self, transition):
        """Add a transition."""
        self.transitions[transition.event,
                         hash_dict(transition.parameters)] = transition

    def get_transition(self, event, parameters):
        """Get the transition for this events with these parameters."""
        return self.transitions[event, hash_dict(parameters)]

if __name__ == "__main__":
    import sys
    s = StateMachine(sys.argv[1], sys.argv[2:])
    if s.errors:
        for e in s.errors:
            print >> sys.stderr, e
        print "There are %s errors" % (len(s.errors))
        exit(1)
    else:
        print "validated ok."
