# ubuntuone.syncdaemon.fsm.fsm_parser - parse a fsm
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
if this module is imported without the HAS_OOFFICE it will do nothing

This module reads fsm specified in a openoffice spreadsheet and returns
a dictionary with the parsed machine.

The format is:
in the 'rules' sheet:
    - Row 1: Section names.
      (STATE, PARAMETERS, ACTION, COMMENT, ACTION_FUNC, STATE_OUT)
      This mark the columnswhere each section begins
    - Row 2: Variable descriptions (for STATE, PARAMETRS and STATE_OUT)
      Describes the variables
    - Row 3: Variable names (for STATE, PARAMETRS and STATE_OUT)
      The name of the variables. STATE and STATE out must have the same.

Then, one or more blocks. each block has:
Row 1, Column 1: The event name
Row 2+:
Each line is start state plus values for the parameters for the event.
Values for the variables can be:
    - text (a value)
    - '*' matches any possible value this variable may take
    - '!' + text (matches all values except text)
The possible values for a variable are taken from scanning all the blocks.
The state out values can be:
    - text (a value)
    - '=' (the same value as the input)
    - '*' (only for NA or DESPAIR lines)

If all the values for a variable in the parameters section are 'NA', then
we assume that variable does not come with this mesage.

The ACTION colum may have text or:
    - 'NA' this state_x_parameters is invalid (it wont happen)
    - 'DESPAIR' may happen but its an error we cant fix, go to despair.

COMMENTS are free text
ACTION_FUNC is the function name to call to execute the transition

The invalid sheet lists states that cannot happen.
"""

import os
import optparse
import pprint

try:
    import uno
    from com.sun.star.connection import NoConnectException
    from com.sun.star.lang import IndexOutOfBoundsException
    from com.sun.star.container import NoSuchElementException
    from com.sun.star.beans import PropertyValue
    from unohelper import systemPathToFileUrl, absolutize
except ImportError:
    has_oo_bindings = False
else:
    has_oo_bindings = True


if has_oo_bindings:
    # we have to do this because python-uno breaks mocker
    CONNECT_MSG = """
    Need to start OpenOffice! Use a command like:
        ooffice -accept="socket,host=localhost,port=2002;urp;"
    """

    class ParseError(Exception):
        """Raised when we cant parse the spreadsheet"""

    class ODSReader(object):
        """Reads fsm from spreadsheets"""

        def __init__(self, filename):
            """Create a reader"""
            local = uno.getComponentContext()
            resolver = local.ServiceManager.createInstanceWithContext(
                "com.sun.star.bridge.UnoUrlResolver", local)

            try:
                context = resolver.resolve(
                    "uno:socket,host=localhost,port=2002;"
                    "urp;StarOffice.ComponentContext")
            except NoConnectException:
                raise Exception(CONNECT_MSG)

            desktop = context.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", context)

            cwd = systemPathToFileUrl(os.getcwd())
            file_url = absolutize(
                cwd, systemPathToFileUrl(os.path.join(os.getcwd(), filename)))
            in_props = PropertyValue("Hidden", 0, True, 0),
            document = desktop.loadComponentFromURL(
                file_url, "_blank", 0, in_props)
            self.rules = document.Sheets.getByName(u'rules')
            try:
                self.invalid = document.Sheets.getByName(u'invalid')
            except NoSuchElementException:
                self.invalid = None

        def get_rules(self):
            """Get the rules page as a list of rows"""
            # first line, title
            # find the last column with data. from the second state
            # the last column in the third row (varnames)
            i = 1
            cells = [u""]
            found_state = False
            while True:
                try:
                    cell = self.rules.getCellByPosition(i, 0)
                except IndexOutOfBoundsException:
                    raise ParseError("STATE_OUT not found in headers")
                text = cell.getFormula()
                if text == "STATE_OUT":
                    if not found_state:
                        found_state = True
                else:
                    if found_state:
                        cell2 = self.rules.getCellByPosition(i, 2)
                        text2 = cell2.getFormula()
                        if not text2:
                            break
                cells.append(text)
                i += 1
            line_length = i
            iter_line = 1
            rows = [cells]

            while True:
                cells = [
                    self.rules.getCellByPosition(x, iter_line).getFormula()
                    for x in xrange(line_length)]
                if not any(cells):
                    break

                iter_line += 1
                rows.append(cells)
            return rows

        def get_invalid(self):
            """Get the invalid page as a list of rows."""
            if self.invalid is None:
                return []
            i = 0
            cells = []
            while True:
                cell = self.invalid.getCellByPosition(i, 0)
                text = cell.getFormula()
                if not text:
                    break
                cells.append(text)
                i += 1
            line_length = i
            iter_line = 1
            rows = [cells]

            while True:
                cells = [
                    self.invalid.getCellByPosition(x, iter_line).getFormula()
                    for x in xrange(line_length)]
                if not any(cells):
                    break

                iter_line += 1
                rows.append(cells)
            return rows

    def parse(filename):
        """converts the spreadsheet into a dictionary.

        It will have the following keys:
        events: a list of event dictionaries
            - state_vars: a mapping with variable name and
              possible values for state
            - state_vars: a mapping with variable name and possible values
              for params
            - invalid: the list of invalid states

        event dictionaries have the following:
            - event_name -> list of transitions

        transitions have these keys that point to the contents of
        the spreadsheet:
             - STATE
            - STATE_OUT
            - PARAMETERS
            - ACTION
            - COMMENTS
            - ACTION_FUNC
            - STATE, STATE_OUT and PARAMETERS are dictionaries of the form
              {varname:value}

        we only validate that variable cells have values and some structure
        """
        ods = ODSReader(filename)

        # get the titles and some info
        rows = ods.get_rules()

        def get_idx(name):
            'get the column where section $name starts'
            try:
                idx = rows[0].index(name)
            except ValueError:
                raise ValueError("Section '%s' not found." % name)
            return idx

        state_idx = get_idx("STATE")
        param_idx = get_idx("PARAMETERS")
        action_idx = get_idx("ACTION")
        comments_idx = get_idx("COMMENTS")
        action_func_idx = get_idx("ACTION_FUNC")
        state_out_idx = get_idx("STATE_OUT")
        row_size = len(rows[0])

        def get_var_value_from_row_part(row, start, end):
            'get the values for a row from start-stop columns'
            vars = {}
            for i in range(start, end):
                value = rows[row][i]
                if not value:
                    raise ParseError("Cell (%s,%s) needs a value" % (row, i))
                vars[rows[2][i]] = value.strip()
            return vars

        def build_state_from_row(row):
            return get_var_value_from_row_part(row, state_idx, param_idx)

        def build_params_from_row(row):
            return get_var_value_from_row_part(row, param_idx, action_idx)

        def build_state_out_from_row(row):
            return get_var_value_from_row_part(row, state_out_idx, row_size)

        # generate states_vars
        descs = rows[1][state_idx:param_idx]
        names = rows[2][state_idx:param_idx]
        state_vars = dict(zip(names, descs))
        # generate parameters
        descs = rows[1][param_idx:action_idx]
        names = rows[2][param_idx:action_idx]
        parameters = dict(zip(names, descs))
        # generate events
        events_rowno = [n for n in range(len(rows))
                        if rows[n][0] and not rows[n][1]]
        events = {}
        for event_rowno in events_rowno:
            event_name = rows[event_rowno][0]
            p = event_rowno + 1
            states = []
            while p < len(rows) and rows[p][1]:
                st = build_state_from_row(p)
                st_out = build_state_out_from_row(p)
                vars = build_params_from_row(p)
                row = rows[p]
                act = row[action_idx]
                comm = row[comments_idx]
                afunc = row[action_func_idx]
                p += 1
                states.append(dict(STATE=st, STATE_OUT=st_out, PARAMETERS=vars,
                              ACTION=act, COMMENTS=comm, ACTION_FUNC=afunc))
            events[event_name] = states

        # build invalid state list
        invalid = ods.get_invalid()
        invalid = [dict(zip(invalid[0], r)) for r in invalid[1:]]

        return dict(events=events, state_vars=state_vars,
                    parameters=parameters, invalid=invalid)


def main():
    """A simple interface to test the parser."""
    usage = "usage: %prog [options] SPREADSHEET"

    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-o", "--output", dest="output",
                      help="write result to FILE", metavar="FILE")

    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.print_help()
        print "SPREADSHEET required"
        return

    result = parse(args[0])
    if options.output:
        f = open(options.output, "w")
        data = pprint.pformat(result)
        f.write("\"\"\"This is a generated python file.\"\"\"\n"
                "state_machine = %s""" % data)
        f.close()
    else:
        pprint.pprint(result)


if __name__ == "__main__":
    main()
