# pyinotify.py - python interface to inotify
# Copyright (c) 2010 Sebastien Martini <seb@dbzteam.org>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Platform agnostic code grabed from pyinotify."""

import logging
import os
import sys


COMPATIBILITY_MODE = False
IN_ISDIR = '???'


class PyinotifyError(Exception):
    """Indicates exceptions raised by a Pyinotify class."""


class RawOutputFormat:
    """
    Format string representations.
    """
    def __init__(self, format=None):
        self.format = format or {}

    def simple(self, s, attribute):
        if isinstance(s, unicode):
            s = s.encode(sys.getfilesystemencoding(), 'replace')
        else:
            s = str(s)
        return (self.format.get(attribute, '') + s +
                self.format.get('normal', ''))

    def punctuation(self, s):
        """Punctuation color."""
        return self.simple(s, 'normal')

    def field_value(self, s):
        """Field value color."""
        return self.simple(s, 'purple')

    def field_name(self, s):
        """Field name color."""
        return self.simple(s, 'blue')

    def class_name(self, s):
        """Class name color."""
        return self.format.get('red', '') + self.simple(s, 'bold')

output_format = RawOutputFormat()


class EventsCodes:
    """
    Set of codes corresponding to each kind of events.
    Some of these flags are used to communicate with inotify, whereas
    the others are sent to userspace by inotify notifying some events.

    @cvar IN_ACCESS: File was accessed.
    @type IN_ACCESS: int
    @cvar IN_MODIFY: File was modified.
    @type IN_MODIFY: int
    @cvar IN_ATTRIB: Metadata changed.
    @type IN_ATTRIB: int
    @cvar IN_CLOSE_WRITE: Writtable file was closed.
    @type IN_CLOSE_WRITE: int
    @cvar IN_CLOSE_NOWRITE: Unwrittable file closed.
    @type IN_CLOSE_NOWRITE: int
    @cvar IN_OPEN: File was opened.
    @type IN_OPEN: int
    @cvar IN_MOVED_FROM: File was moved from X.
    @type IN_MOVED_FROM: int
    @cvar IN_MOVED_TO: File was moved to Y.
    @type IN_MOVED_TO: int
    @cvar IN_CREATE: Subfile was created.
    @type IN_CREATE: int
    @cvar IN_DELETE: Subfile was deleted.
    @type IN_DELETE: int
    @cvar IN_DELETE_SELF: Self (watched item itself) was deleted.
    @type IN_DELETE_SELF: int
    @cvar IN_MOVE_SELF: Self (watched item itself) was moved.
    @type IN_MOVE_SELF: int
    @cvar IN_UNMOUNT: Backing fs was unmounted.
    @type IN_UNMOUNT: int
    @cvar IN_Q_OVERFLOW: Event queued overflowed.
    @type IN_Q_OVERFLOW: int
    @cvar IN_IGNORED: File was ignored.
    @type IN_IGNORED: int
    @cvar IN_ONLYDIR: only watch the path if it is a directory (new
                      in kernel 2.6.15).
    @type IN_ONLYDIR: int
    @cvar IN_DONT_FOLLOW: don't follow a symlink (new in kernel 2.6.15).
                          IN_ONLYDIR we can make sure that we don't watch
                          the target of symlinks.
    @type IN_DONT_FOLLOW: int
    @cvar IN_MASK_ADD: add to the mask of an already existing watch (new
                       in kernel 2.6.14).
    @type IN_MASK_ADD: int
    @cvar IN_ISDIR: Event occurred against dir.
    @type IN_ISDIR: int
    @cvar IN_ONESHOT: Only send event once.
    @type IN_ONESHOT: int
    @cvar ALL_EVENTS: Alias for considering all of the events.
    @type ALL_EVENTS: int
    """

    # The idea here is 'configuration-as-code' - this way, we get
    # our nice class constants, but we also get nice human-friendly text
    # mappings to do lookups against as well, for free:
    FLAG_COLLECTIONS = {
        'OP_FLAGS': {
            'IN_ACCESS': 0x00000001,  # File was accessed
            'IN_MODIFY': 0x00000002,  # File was modified
            'IN_ATTRIB': 0x00000004,  # Metadata changed
            'IN_CLOSE_WRITE': 0x00000008,  # Writable file was closed
            'IN_CLOSE_NOWRITE': 0x00000010,  # Unwritable file closed
            'IN_OPEN': 0x00000020,  # File was opened
            'IN_MOVED_FROM': 0x00000040,  # File was moved from X
            'IN_MOVED_TO': 0x00000080,  # File was moved to Y
            'IN_CREATE': 0x00000100,  # Subfile was created
            'IN_DELETE': 0x00000200,  # Subfile was deleted
            'IN_DELETE_SELF': 0x00000400,  # Self was deleted
            'IN_MOVE_SELF': 0x00000800,  # Self was moved
        },
        'EVENT_FLAGS': {
            'IN_UNMOUNT': 0x00002000,  # Backing fs was unmounted
            'IN_Q_OVERFLOW': 0x00004000,  # Event queued overflowed
            'IN_IGNORED': 0x00008000,  # File was ignored
        },
        'SPECIAL_FLAGS': {
            'IN_ONLYDIR': 0x01000000,  # only watch the path if it is a dir
            'IN_DONT_FOLLOW': 0x02000000,  # don't follow a symlink
            'IN_MASK_ADD': 0x20000000,  # add to the mask of an existing watch
            'IN_ISDIR': 0x40000000,  # event occurred against dir
            'IN_ONESHOT': 0x80000000,  # only send event once
        },
    }

    def maskname(mask):
        """
        Returns the event name associated to mask. IN_ISDIR is appended to
        the result when appropriate. Note: only one event is returned, because
        only one event can be raised at a given time.

        @param mask: mask.
        @type mask: int
        @return: event name.
        @rtype: str
        """
        ms = mask
        name = '%s'
        if mask & IN_ISDIR:
            ms = mask - IN_ISDIR
            name = '%s|IN_ISDIR'
        return name % EventsCodes.ALL_VALUES[ms]

    maskname = staticmethod(maskname)


# So let's now turn the configuration into code
EventsCodes.ALL_FLAGS = {}
EventsCodes.ALL_VALUES = {}
for flagc, valc in EventsCodes.FLAG_COLLECTIONS.items():
    # Make the collections' members directly accessible through the
    # class dictionary
    setattr(EventsCodes, flagc, valc)

    # Collect all the flags under a common umbrella
    EventsCodes.ALL_FLAGS.update(valc)

    # Make the individual masks accessible as 'constants' at globals() scope
    # and masknames accessible by values.
    for name, val in valc.items():
        globals()[name] = val
        EventsCodes.ALL_VALUES[val] = name


# all 'normal' events
ALL_EVENTS = reduce(lambda x, y: x | y, EventsCodes.OP_FLAGS.values())
EventsCodes.ALL_FLAGS['ALL_EVENTS'] = ALL_EVENTS
EventsCodes.ALL_VALUES[ALL_EVENTS] = 'ALL_EVENTS'


class _Event:
    """
    Event structure, represent events raised by the system. This
    is the base class and should be subclassed.

    """
    def __init__(self, dict_):
        """
        Attach attributes (contained in dict_) to self.

        @param dict_: Set of attributes.
        @type dict_: dictionary
        """
        for tpl in dict_.items():
            setattr(self, *tpl)

    def __repr__(self):
        """
        @return: Generic event string representation.
        @rtype: str
        """
        s = ''
        for attr, value in sorted(self.__dict__.items(), key=lambda x: x[0]):
            if attr.startswith('_'):
                continue
            if attr == 'mask':
                value = hex(getattr(self, attr))
            elif isinstance(value, basestring) and not value:
                value = "''"
            s += ' %s%s%s' % (output_format.field_name(attr),
                              output_format.punctuation('='),
                              output_format.field_value(value))

        s = '%s%s%s %s' % (output_format.punctuation('<'),
                           output_format.class_name(self.__class__.__name__),
                           s,
                           output_format.punctuation('>'))
        return s

    def __str__(self):
        return repr(self)


class _RawEvent(_Event):
    """
    Raw event, it contains only the informations provided by the system.
    It doesn't infer anything.
    """
    def __init__(self, wd, mask, cookie, name):
        """
        @param wd: Watch Descriptor.
        @type wd: int
        @param mask: Bitmask of events.
        @type mask: int
        @param cookie: Cookie.
        @type cookie: int
        @param name: Basename of the file or directory against which the
                     event was raised in case where the watched directory
                     is the parent directory. None if the event was raised
                     on the watched item itself.
        @type name: string or None
        """
        # Use this variable to cache the result of str(self), this object
        # is immutable.
        self._str = None
        # name: remove trailing '\0'
        d = {'wd': wd,
             'mask': mask,
             'cookie': cookie,
             'name': name.rstrip('\0')}
        _Event.__init__(self, d)
        logging.debug(str(self))

    def __str__(self):
        if self._str is None:
            self._str = _Event.__str__(self)
        return self._str


class Event(_Event):
    """
    This class contains all the useful informations about the observed
    event. However, the presence of each field is not guaranteed and
    depends on the type of event. In effect, some fields are irrelevant
    for some kind of event (for example 'cookie' is meaningless for
    IN_CREATE whereas it is mandatory for IN_MOVE_TO).

    The possible fields are:
      - wd (int): Watch Descriptor.
      - mask (int): Mask.
      - maskname (str): Readable event name.
      - path (str): path of the file or directory being watched.
      - name (str): Basename of the file or directory against which the
              event was raised in case where the watched directory
              is the parent directory. None if the event was raised
              on the watched item itself. This field is always provided
              even if the string is ''.
      - pathname (str): Concatenation of 'path' and 'name'.
      - src_pathname (str): Only present for IN_MOVED_TO events and only in
              the case where IN_MOVED_FROM events are watched too. Holds the
              source pathname from where pathname was moved from.
      - cookie (int): Cookie.
      - dir (bool): True if the event was raised against a directory.

    """
    def __init__(self, raw):
        """
        Concretely, this is the raw event plus inferred infos.
        """
        _Event.__init__(self, raw)
        self.maskname = EventsCodes.maskname(self.mask)
        if COMPATIBILITY_MODE:
            self.event_name = self.maskname
        try:
            if self.name:
                self.pathname = os.path.abspath(os.path.join(self.path,
                                                             self.name))
            else:
                self.pathname = os.path.abspath(self.path)
        except AttributeError, err:
            # Usually it is not an error some events are perfectly valids
            # despite the lack of these attributes.
            logging.debug(err)


class ProcessEventError(PyinotifyError):
    """
    ProcessEventError Exception. Raised on ProcessEvent error.
    """
    def __init__(self, err):
        """
        @param err: Exception error description.
        @type err: string
        """
        PyinotifyError.__init__(self, err)


class _ProcessEvent:
    """
    Abstract processing event class.
    """
    def __call__(self, event):
        """
        To behave like a functor the object must be callable.
        This method is a dispatch method. Its lookup order is:
          1. process_MASKNAME method
          2. process_FAMILY_NAME method
          3. otherwise calls process_default

        @param event: Event to be processed.
        @type event: Event object
        @return: By convention when used from the ProcessEvent class:
                 - Returning False or None (default value) means keep on
                 executing next chained functors (see chain.py example).
                 - Returning True instead means do not execute next
                   processing functions.
        @rtype: bool
        @raise ProcessEventError: Event object undispatchable,
                                  unknown event.
        """
        stripped_mask = event.mask - (event.mask & IN_ISDIR)
        maskname = EventsCodes.ALL_VALUES.get(stripped_mask)
        if maskname is None:
            raise ProcessEventError("Unknown mask 0x%08x" % stripped_mask)

        # 1- look for process_MASKNAME
        meth = getattr(self, 'process_' + maskname, None)
        if meth is not None:
            return meth(event)
        # 2- look for process_FAMILY_NAME
        meth = getattr(self, 'process_IN_' + maskname.split('_')[1], None)
        if meth is not None:
            return meth(event)
        # 3- default call method process_default
        return self.process_default(event)

    def __repr__(self):
        return '<%s>' % self.__class__.__name__


class ProcessEvent(_ProcessEvent):
    """
    Process events objects, can be specialized via subclassing, thus its
    behavior can be overriden:

    Note: you should not override __init__ in your subclass instead define
    a my_init() method, this method will be called automatically from the
    constructor of this class with its optionals parameters.

      1. Provide specialized individual methods, e.g. process_IN_DELETE for
         processing a precise type of event (e.g. IN_DELETE in this case).
      2. Or/and provide methods for processing events by 'family', e.g.
         process_IN_CLOSE method will process both IN_CLOSE_WRITE and
         IN_CLOSE_NOWRITE events (if process_IN_CLOSE_WRITE and
         process_IN_CLOSE_NOWRITE aren't defined though).
      3. Or/and override process_default for catching and processing all
         the remaining types of events.
    """
    pevent = None

    def __init__(self, pevent=None, **kargs):
        """
        Enable chaining of ProcessEvent instances.

        @param pevent: Optional callable object, will be called on event
                       processing (before self).
        @type pevent: callable
        @param kargs: This constructor is implemented as a template method
                      delegating its optionals keyworded arguments to the
                      method my_init().
        @type kargs: dict
        """
        self.pevent = pevent
        self.my_init(**kargs)

    def my_init(self, **kargs):
        """
        This method is called from ProcessEvent.__init__(). This method is
        empty here and must be redefined to be useful. In effect, if you
        need to specifically initialize your subclass' instance then you
        just have to override this method in your subclass. Then all the
        keyworded arguments passed to ProcessEvent.__init__() will be
        transmitted as parameters to this method. Beware you MUST pass
        keyword arguments though.

        @param kargs: optional delegated arguments from __init__().
        @type kargs: dict
        """
        pass

    def __call__(self, event):
        stop_chaining = False
        if self.pevent is not None:
            # By default methods return None so we set as guideline
            # that methods asking for stop chaining must explicitely
            # return non None or non False values, otherwise the default
            # behavior will be to accept chain call to the corresponding
            # local method.
            stop_chaining = self.pevent(event)
        if not stop_chaining:
            return _ProcessEvent.__call__(self, event)

    def nested_pevent(self):
        return self.pevent

    def process_IN_Q_OVERFLOW(self, event):
        """
        By default this method only reports warning messages, you can
        overredide it by subclassing ProcessEvent and implement your own
        process_IN_Q_OVERFLOW method. The actions you can take on receiving
        this event is either to update the variable max_queued_events in order
        to handle more simultaneous events or to modify your code in order to
        accomplish a better filtering diminishing the number of raised events.
        Because this method is defined, IN_Q_OVERFLOW will never get
        transmitted as arguments to process_default calls.

        @param event: IN_Q_OVERFLOW event.
        @type event: dict
        """
        logging.warning('Event queue overflowed.')

    def process_default(self, event):
        """
        Default processing event method. By default does nothing. Subclass
        ProcessEvent and redefine this method in order to modify its behavior.

        @param event: Event to be processed. Can be of any type of events but
                      IN_Q_OVERFLOW events (see method process_IN_Q_OVERFLOW).
        @type event: Event instance
        """
        pass


class PrintAllEvents(ProcessEvent):
    """
    Dummy class used to print events strings representations. For instance this
    class is used from command line to print all received events to stdout.
    """
    def my_init(self, out=None):
        """
        @param out: Where events will be written.
        @type out: Object providing a valid file object interface.
        """
        if out is None:
            out = sys.stdout
        self._out = out

    def process_default(self, event):
        """
        Writes event string representation to file object provided to
        my_init().

        @param event: Event to be processed. Can be of any type of events but
                      IN_Q_OVERFLOW events (see method process_IN_Q_OVERFLOW).
        @type event: Event instance
        """
        self._out.write(str(event))
        self._out.write('\n')
        self._out.flush()


class WatchManagerError(Exception):
    """
    WatchManager Exception. Raised on error encountered on watches
    operations.

    """
    def __init__(self, msg, wmd):
        """
        @param msg: Exception string's description.
        @type msg: string
        @param wmd: This dictionary contains the wd assigned to paths of the
                    same call for which watches were successfully added.
        @type wmd: dict
        """
        self.wmd = wmd
        Exception.__init__(self, msg)
