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

"""Assorted stuff used by test_action_queue."""

import os
import shutil
import time
import uuid
from functools import partial, total_ordering
from io import BytesIO

import dbus
import dbus.service

from dbus.mainloop.glib import DBusGMainLoop
from magicicadaclient import platform
from magicicadaclient.syncdaemon.action_queue import (
    ActionQueue,
    ActionQueueCommand,
)
from magicicadaclient.syncdaemon import (
    main,
    tritcask,
    volume_manager,
)
from magicicadaclient.syncdaemon.event_queue import EventQueue
from magicicadaclient.syncdaemon.filesystem_manager import FileSystemManager
from magicicadaclient.syncdaemon.sync import Sync
from magicicadaclient.syncdaemon.marker import MDMarker
from magicicadaprotocol import request, sharersp, client
from twisted.internet import defer, reactor
from twisted.names import dns
from twisted.names.common import ResolverBase

from magicicada import settings
from magicicada.server import ssl_proxy
from magicicada.server.auth import SimpleAuthProvider
from magicicada.server.testing.testcase import (
    BaseProtocolTestCase,
    get_put_content_params,
)
from magicicada.testing.testcase import BaseTestCase


ROOT_DIR = os.getcwd()
SD_CONFIG_DIR = os.path.join(
    ROOT_DIR, '.sourcecode', 'magicicada-client', 'data'
)
SD_CONFIGS = [
    os.path.join(SD_CONFIG_DIR, 'syncdaemon.conf'),
    os.path.join(SD_CONFIG_DIR, 'syncdaemon-dev.conf'),
]
TESTS_DIR = os.getcwd() + "/tmp/sync_tests"

_marker = object()


def show_time():
    """Return current time with HH:MM:SS,xxx where xxx are msec."""
    t = time.time()
    p1 = time.strftime("%H:%M:%S", time.localtime(t))
    p2 = ("%.3f" % (t % 1))[2:]
    return "%s,%s" % (p1, p2)


class NoCloseCustomIO(BytesIO):
    """A BytesIO subclass that doesnt destroy content on close."""

    # Needed for action_queue's file management
    # if getattr(self.fileobj, 'fileno', None) is not None:
    #     # it's a real file, with a fileno! Let's sync its data out to disk
    #     os.fsync(self.fileobj.fileno())
    fileno = None

    def close(self):
        """do nothing"""
        pass


class ReallyAttentiveListener(object):
    """A listener that listens to everything and writes it down very tidily."""

    def __init__(self):
        self.q = []

    def __getattr__(self, attr):
        if attr.startswith('handle_'):
            return partial(self.write_it_down, attr[7:])
        # probably AttributeError, but just in case
        return super(ReallyAttentiveListener, self).__getattr__(attr)

    def write_it_down(self, attr, *a, **kw):
        """Write the event down."""
        self.q.append((attr, kw))

    def get_svhash_for(self, share_id, node_id):
        """
        find the latest SV_HASH_NEW for the given node
        """
        for ev, kw in reversed(self.q):
            if ev == 'SV_HASH_NEW':
                if (
                    kw.get('node_id') == node_id
                    and kw.get('share_id') == share_id
                ):
                    return kw.get('hash')
        raise ValueError("no hash for %s in %s" % (node_id, self.q))

    def get_rescan_from_scratch_for(self, volume_id):
        """Find the last AQ_RESCAN_FROM_SCRATCH_OK and return the kwargs."""
        for ev, kw in reversed(self.q):
            if ev == 'AQ_RESCAN_FROM_SCRATCH_OK':
                if kw.get('volume_id') == volume_id:
                    return kw
        raise ValueError(
            "no AQ_RESCAN_FROM_SCRATCH_OK for %s in %s" % (volume_id, self.q)
        )

    def get_id_for_marker(self, marker, default=_marker):
        """
        find the latest AQ_(FILE|DIR)_NEW_OK for the given marker
        """
        for ev, kw in reversed(self.q):
            if ev in ('AQ_FILE_NEW_OK', 'AQ_DIR_NEW_OK', 'AQ_CREATE_SHARE_OK'):
                if kw.get('marker') == marker:
                    if ev == 'AQ_CREATE_SHARE_OK':
                        return kw.get('share_id')
                    else:
                        return kw.get('new_id')
        if default is _marker:
            raise ValueError("no uuid for marker %s" % marker)
        else:
            return default


class DumbVolumeManager(volume_manager.VolumeManager):
    """A real VolumeManager but with dummy refresh_* and (a few) handle_*."""

    def refresh_shares(self):
        """Noop."""

    def refresh_volumes(self):
        """Noop."""

    def on_server_root(self, root):
        """Asociate server root and nothing more."""
        self.log.debug('on_server_root(%s)', root)
        self._set_root(root)

    def handle_AQ_LIST_VOLUMES_ERROR(self, error):
        """Noop."""

    def handle_AQ_LIST_SHARES_ERROR(self, error):
        """Noop."""

    def handle_AQ_ANSWER_SHARE_OK(self, share_id, answer):
        """Noop."""


class FakedHashQueue:
    """A fake and empty hash queue."""

    def __init__(self, event_queue=None):
        self.items = []

    def empty(self):
        return len(self.items) == 0

    def insert(self, path, mdid):
        return self.items.append((path, mdid))

    def __len__(self):
        return len(self.items)

    def shutdown(self):
        pass


class ReallyFakeMain(main.Main):
    """This main is so fake, it breaks nearly everything."""

    def __init__(self, port, root_dir, data_dir, partials_dir):
        self.root_dir = root_dir
        self.shares_dir = os.path.join(os.path.dirname(root_dir), 'shares_dir')
        self.shares_dir_link = os.path.join(root_dir, 'shares_link')
        self.data_dir = data_dir
        self.fsmdir = os.path.join(data_dir, 'fsmdir')
        self.partials_dir = partials_dir
        self.tritcask_dir = os.path.join(self.data_dir, 'tritcask')
        self.hash_q = FakedHashQueue()
        self.db = tritcask.Tritcask(self.tritcask_dir)
        self.vm = DumbVolumeManager(self)
        self.fs = FileSystemManager(
            self.fsmdir, self.partials_dir, self.vm, self.db
        )
        self.event_q = EventQueue(self.fs)
        self.event_q.subscribe(self.vm)
        self.fs.register_eq(self.event_q)
        self.sync = Sync(self)
        connection_info = [
            {
                'host': '127.0.0.1',
                'port': port,
                'use_ssl': False,
                'disable_ssl_verify': True,
            }
        ]
        self.action_q = ActionQueue(self.event_q, self, connection_info)
        self.state_manager = main.StateManager(self, handshake_timeout=30)
        self.state_manager.connection.waiting_timeout = 0.1
        self.vm.init_root()

    def server_rescan(self):
        """Fake server rescan that doesn't actually rescan anything."""
        return self.vm.server_rescan()

    def local_rescan(self):
        """Fake!"""


def failure_ignore(*failures):
    """A decorator to ignore the failure.

    It marks a test method such that failures during the test will not be
    marked as failures of the test itself, but simply ignored.
    """

    def wrapper(func):
        """The wrapper function."""
        func.failure_ignore = failures
        return func

    return wrapper


def failure_expected(failure):
    """A decorator to expect a failure.

    It marks a test method such that failures during the test will not be
    marked as failures of the test itself, but rather the opposite: it is
    the lack of the failure that is a failure.
    """

    def wrapper(func):
        """The wrapper function."""
        func.failure_expected = failure
        return func

    return wrapper


class WaitingHelpingHandler(object):
    """An auxiliary class that helps wait for events."""

    def __init__(
        self, event_queue, waiting_events, waiting_kwargs, result=None
    ):
        self.deferred = defer.Deferred()
        self.event_queue = event_queue
        self.result = result
        self.waiting_events = waiting_events
        self.waiting_kwargs = waiting_kwargs
        event_queue.subscribe(self)

    def handle_default(self, event, *args, **kwargs):
        """Got an event: fire if it's one we want"""
        if event in self.waiting_events:
            if args:
                for wv in self.waiting_kwargs.values():
                    if wv not in args:
                        return
            if kwargs:
                for wk, wv in self.waiting_kwargs.items():
                    if not (wk in kwargs and kwargs[wk] == wv):
                        return
            self.fire()

    def fire(self):
        """start fire the callback"""
        self.event_queue.unsubscribe(self)
        reactor.callLater(0, lambda: self.deferred.callback(self.result))


# The following class is a duplicated from
# lib/magicicadaclient/platform/tests/ipc/test_linux.py
# will be removed when bug #917285 is resolved
class FakeNetworkManager(dbus.service.Object):
    """A fake NetworkManager that only emits StatusChanged signal."""

    State = 3
    path = '/org/freedesktop/NetworkManager'

    def __init__(self, bus):
        self.bus = bus
        self.bus.request_name(
            'org.freedesktop.NetworkManager',
            flags=dbus.bus.NAME_FLAG_REPLACE_EXISTING
            | dbus.bus.NAME_FLAG_DO_NOT_QUEUE
            | dbus.bus.NAME_FLAG_ALLOW_REPLACEMENT,
        )
        self.busName = dbus.service.BusName(
            'org.freedesktop.NetworkManager', bus=self.bus
        )
        super(FakeNetworkManager, self).__init__(
            self.busName, object_path=self.path
        )

    def shutdown(self):
        """Shutdown the fake NetworkManager."""
        self.busName.get_bus().release_name(self.busName.get_name())
        self.remove_from_connection()

    @dbus.service.signal('org.freedesktop.NetworkManager', signature='i')
    def StateChanged(self, state):
        """Fire DBus signal StatusChanged."""

    def emit_connected(self):
        """Emits the signal StateChanged(3)."""
        self.StateChanged(70)

    def emit_disconnected(self):
        """Emits the signal StateChanged(4)."""
        self.StateChanged(20)

    @dbus.service.method(
        dbus.PROPERTIES_IFACE,
        in_signature='ss',
        out_signature='v',
        async_callbacks=('reply_handler', 'error_handler'),
    )
    def Get(self, interface, propname, reply_handler=None, error_handler=None):
        """Fake dbus's Get method to get at the State property."""
        try:
            reply_handler(getattr(self, propname, None))
        except Exception as e:
            error_handler(e)

    @dbus.service.method('org.freedesktop.NetworkManager')
    def state(self):
        """Fake the state."""
        return 70


class TestWithDatabase(BaseTestCase, BaseProtocolTestCase):
    """Hook up Trial, BaseTestCase, and our very own storage servers.

    Large chunks have been copy-pasted from
    server.testing.testcase.TestWithDatabase, hence the name.
    """

    auth_provider_class = SimpleAuthProvider
    _do_teardown_eq = False
    _ignore_cancelled_downloads = False
    failed = False
    ssl_proxy_heartbeat_interval = 0

    @defer.inlineCallbacks
    def setUp(self):
        """Setup."""
        yield super(TestWithDatabase, self).setUp()
        self.__root = None

        # Set up the main loop and bus connection
        self.loop = DBusGMainLoop(set_as_default=True)
        bus_address = os.environ.get('DBUS_SESSION_BUS_ADDRESS', None)
        self.bus = dbus.bus.BusConnection(
            address_or_type=bus_address, mainloop=self.loop
        )

        # Monkeypatch the dbus.SessionBus/SystemBus methods, to ensure we
        # always point at our own private bus instance.
        self.patch(dbus, 'SessionBus', lambda: self.bus)
        self.patch(dbus, 'SystemBus', lambda: self.bus)

        self.nm = FakeNetworkManager(self.bus)
        self.addCleanup(self.nm.shutdown)

        # start the ssl proxy
        self.ssl_service = ssl_proxy.ProxyService(
            self.ssl_cert,
            self.ssl_key,
            self.ssl_cert_chain,
            0,  # port
            "localhost",
            self.port,
            "ssl-proxy-test",
            0,
        )
        self.patch(
            settings, 'HEARTBEAT_INTERVAL', self.ssl_proxy_heartbeat_interval
        )
        yield self.ssl_service.startService()

        if os.path.exists(self.tmpdir):
            self.rmtree(self.tmpdir)

        _user_data = [
            ('jack', 'jackpass'),
            ('jane', 'janepass'),
            ('john', 'johnpass'),
        ]
        self.access_tokens = {}
        self.storage_users = {}
        for username, password in _user_data:
            self.access_tokens[username] = {
                'username': username,
                'password': password,
            }
            user = self.make_user(username=username, password=password)
            self.storage_users[username] = user

        # override and cleanup user config
        self.patch(main.config, 'get_config_files', lambda: SD_CONFIGS)
        main.config._user_config = None
        user_config = main.config.get_user_config()
        for section in user_config.sections():
            user_config.remove_section(section)
        main.config.get_user_config().set_throttling_read_limit(-1)
        main.config.get_user_config().set_throttling_write_limit(-1)
        main.config.get_user_config().set_autoconnect(False)

        yield self.client_setup()

    @property
    def tmpdir(self):
        """Override default tmpdir property."""
        return TESTS_DIR

    @defer.inlineCallbacks
    def tearDown(self):
        """Tear down."""
        yield super(TestWithDatabase, self).tearDown()
        yield self.ssl_service.stopService()
        if self._do_teardown_eq:
            yield self.eq.shutdown()
        yield self.main.state_manager.shutdown()
        yield self.main.db.shutdown()

        test_method = getattr(self, self._testMethodName)
        failure_expected = getattr(test_method, 'failure_expected', False)
        if failure_expected and failure_expected != self.failed:
            msg = "test method %r should've failed with %s and " % (
                self._testMethodName,
                failure_expected,
            )
            if self.failed:
                msg += 'instead failed with: %s' % self.failed
            else:
                msg += "didn't"
            self.fail(msg)

        if self.failed and failure_expected != self.failed:
            failure_ignore = getattr(test_method, 'failure_ignore', ())
            if self.failed and self.failed not in failure_ignore:
                msg = "test method %r failed with: %s" % (
                    self._testMethodName,
                    self.failed,
                )
                self.fail(msg)

        if os.path.exists(self.tmpdir):
            self.rmtree(self.tmpdir)

    def mktemp(self, name='temp'):
        """Customized mktemp that accepts an optional name argument."""
        tempdir = os.path.join(self.tmpdir, name)
        if os.path.exists(tempdir):
            self.rmtree(tempdir)
        os.makedirs(tempdir)
        self.addCleanup(self.rmtree, tempdir)
        return tempdir

    def rmtree(self, path):
        """Custom rmtree that handle ro parent(s) and childs."""
        # change perms to rw, so we can delete the temp dir
        if path != self.__root:
            platform.set_dir_readwrite(os.path.dirname(path))
        if not platform.can_write(path):
            platform.set_dir_readwrite(path)

        for dirpath, dirs, files in os.walk(path):
            for adir in dirs:
                adir = os.path.join(dirpath, adir)
                if not platform.can_write(adir):
                    platform.set_dir_readwrite(adir)

        shutil.rmtree(path)

    def client_setup(self):
        """Create the clients needed for the tests."""
        self._do_teardown_eq = True
        root_dir = self.mktemp('fake_root_dir')
        data_dir = self.mktemp('fake_data_dir')
        partials = self.mktemp('partials_dir')
        self.main = ReallyFakeMain(self.port, root_dir, data_dir, partials)
        self.state = self.main.state_manager
        self.eq = self.main.event_q
        self.listener = ReallyAttentiveListener()
        self.eq.subscribe(self.listener)
        self.addCleanup(self.eq.unsubscribe, self.listener)
        self.eq.subscribe(self)
        self.addCleanup(self.eq.unsubscribe, self)
        self.aq = self.main.action_q

    @property
    def ssl_port(self):
        """SSL port."""
        return self.ssl_service.port

    def nuke_client_method(
        self, method_name, callback, method_retval_cb=defer.Deferred
    ):
        """Nuke the client method, call the callback, and de-nuke it."""
        self.patch(
            self.aq.client, method_name, lambda *_, **__: method_retval_cb()
        )
        return callback()

    def wait_for(self, *waiting_events, **waiting_kwargs):
        """defer until event appears"""
        return WaitingHelpingHandler(
            self.main.event_q, waiting_events, waiting_kwargs
        ).deferred

    def handle_default(self, event, *args, **kwargs):
        """Default event handler.

        Specifically, catch every single errors and store them under the
        'failed' attribute.

        """
        if 'error' in kwargs:
            self.failed = kwargs['error']
        elif 'failure' in kwargs:
            self.failed = str(kwargs['failure'].value)

    def wait_for_nirvana(self, last_event_interval=0.5):
        """Get a deferred that will fire when there are no more
        events or transfers."""
        return self.main.wait_for_nirvana(last_event_interval)

    def connect(self, do_connect=True):
        """Encourage the AQ to connect."""
        d = self.wait_for('SYS_CONNECTION_MADE')
        self.eq.push('SYS_INIT_DONE')
        self.eq.push('SYS_LOCAL_RESCAN_DONE')
        self.eq.push(
            'SYS_USER_CONNECT', access_token=self.access_tokens['jack']
        )
        if do_connect:
            self.eq.push('SYS_NET_CONNECTED')
        return d

    def assertEvent(self, event, msg=None):
        """Check if an event happened."""
        self.assertIn(event, self.listener.q, msg)

    def assertInListenerEvents(self, event_name, event_kwargs):
        """Ensure that `event_name` was sent with `event_kwargs`."""
        self.assertIn((event_name, event_kwargs), self.listener.q)

    def assertAnyInListenerEvents(self, events_and_kwargs):
        """Ensure that `event_name` was sent with `event_kwargs`."""
        msg = 'None of %s were found in %s'
        self.assertTrue(
            any(e in self.listener.q for e in events_and_kwargs),
            msg % (events_and_kwargs, self.listener.q),
        )


class _Placeholder(object):
    """Object you can use in eq comparison w'out knowing equality with what."""

    def __init__(self, label):
        self.label = label

    def __repr__(self):
        return "<placeholder for %s>" % self.label


class _HashPlaceholder(_Placeholder):
    """A placeholder for a hash"""

    def __eq__(self, other):
        return all(
            (
                isinstance(other, str),
                other.startswith('sha1:'),
                len(other) == 45,
            )
        )


class _UUIDPlaceholder(_Placeholder):
    """A placeholder for an uuid"""

    def __init__(self, label, exceptions=()):
        super(_UUIDPlaceholder, self).__init__(label)
        self.exceptions = exceptions

    def __eq__(self, other):
        if other in self.exceptions:
            return True
        try:
            str(uuid.UUID(other))
        except ValueError:
            return False
        else:
            return True


class _TypedPlaceholder(_Placeholder):
    """A placeholder for an object of a certain type"""

    def __init__(self, label, a_type):
        super(_TypedPlaceholder, self).__init__(label)
        self.type = a_type

    def __eq__(self, other):
        return isinstance(other, self.type)


@total_ordering
class _ShareListPlaceholder(_Placeholder):
    """A placeholder for a list of shares"""

    def __init__(self, label, shares):
        super(_ShareListPlaceholder, self).__init__(label)
        self.shares = shares

    # To avoid the hassle of providing all six functions, you can implement
    # __eq__, __ne__, and only one of the ordering operators, and use the
    # functools.total_ordering() decorator to fill in the rest.

    def __eq__(self, other):
        return self.shares == other.shares

    def __ne__(self, other):
        return self.shares != other.shares

    def __le__(self, other):
        return self.shares <= other.shares


aHash = _HashPlaceholder('a hash')
anUUID = _UUIDPlaceholder('an UUID')
aShareUUID = _UUIDPlaceholder('a share UUID', ('',))
anEmptyShareList = _ShareListPlaceholder('an empty share list', [])
aShareInfo = _TypedPlaceholder('a share info', sharersp.NotifyShareHolder)
aGetContentRequest = _TypedPlaceholder(
    'a get_content request', client.GetContent
)
anAQCommand = _TypedPlaceholder('an action queue command', ActionQueueCommand)


def get_aq_params(data_len=1000, **overrides):
    data = os.urandom(data_len)
    fd = NoCloseCustomIO(data)
    params = get_put_content_params(data=data, fd=fd, **overrides)
    # adequate some key names to AQ terminology
    params['share_id'] = params.pop('share')
    params['hash'] = params.pop('new_hash')
    params['data'] = data
    return params


class TestBase(TestWithDatabase):
    """Base class for TestMeta and TestContent."""

    client = None

    @defer.inlineCallbacks
    def setUp(self):
        """Set up."""
        yield super(TestBase, self).setUp()
        yield self.connect()
        self.addCleanup(self.aq.disconnect)
        self.client = self.aq.client
        self.assertFalse(self.client.factory.connector is None)
        self.root = yield self.client.get_root()
        yield self.wait_for_nirvana(0.5)

    @defer.inlineCallbacks
    def _gmk(self, what, name, parent, default_id, path):
        """Generalized _mk* helper."""
        if path is None:
            path = name + str(uuid.uuid4())
        if parent is None:
            parent = self.root
        parent_path = self.main.fs.get_by_node_id(request.ROOT, parent).path
        mdid = self.main.fs.create(
            os.path.join(parent_path, path), request.ROOT
        )
        marker = MDMarker(mdid)
        meth = getattr(self.aq, 'make_' + what)
        meth(request.ROOT, parent, name, marker, mdid)
        yield self.wait_for(
            'AQ_FILE_NEW_OK',
            'AQ_FILE_NEW_ERROR',
            'AQ_DIR_NEW_OK',
            'AQ_DIR_NEW_ERROR',
            marker=marker,
        )

        node_id = self.listener.get_id_for_marker(marker, default_id)
        defer.returnValue((mdid, node_id))

    def _mkdir(self, name, parent=None, default_id=_marker, path=None):
        """Create a dir, optionally storing the resulting uuid."""
        return self._gmk('dir', name, parent, default_id, path)

    def _mkfile(self, name, parent=None, default_id=_marker, path=None):
        """Create a file, optionally storing the resulting uuid."""
        return self._gmk('file', name, parent, default_id, path)

    @defer.inlineCallbacks
    def _mk_file_w_content(self, filename='hola', data_len=1000):
        """Make a file and dump some content in it."""
        path = filename
        mdid, node_id = yield self._mkfile(filename, path=path)
        params = get_aq_params(node_id=node_id, mdid=mdid)
        wait_upload = self.wait_for(
            'AQ_UPLOAD_FINISHED',
            share_id=params['share_id'],
            hash=params['hash'],
            node_id=node_id,
        )
        orig_open_file = self.main.fs.open_file
        self.main.fs.open_file = lambda _: params['fd']

        self.aq.upload(
            params['share_id'],
            node_id,
            params['previous_hash'],
            params['hash'],
            params['crc32'],
            params['size'],
            mdid,
        )
        self.main.fs.open_file = orig_open_file
        yield wait_upload
        defer.returnValue(params)


class FakeResolver(ResolverBase):
    """A fake resolver that returns two fixed hosts.

    Those are fs-1.ubuntuone.com and fs-1.server.com both with port=443
    """

    def _lookup(self, name, cls, qtype, timeout):
        """do the fake lookup."""
        hostname = 'fs-%s.server.com'
        rr = dns.RRHeader(
            name=hostname % '0',
            type=qtype,
            cls=cls,
            ttl=60,
            payload=dns.Record_SRV(target=hostname % '0', port=443),
        )
        rr1 = dns.RRHeader(
            name=hostname % '1',
            type=qtype,
            cls=cls,
            ttl=60,
            payload=dns.Record_SRV(target=hostname % '1', port=443),
        )
        results = [rr, rr1]
        authority = []
        addtional = []
        return defer.succeed((results, authority, addtional))


class MethodInterferer(object):
    """Helper to nuke a client method and restore it later."""

    def __init__(self, obj, meth):
        self.obj = obj
        self.meth = meth
        self.old = None

    def insert_after(self, func):
        """Runs func after running the replaced method."""
        self.old = getattr(self.obj, self.meth)

        def middle(*args, **kwargs):
            """Helper/worker func."""
            r = self.old(*args, **kwargs)
            func(*args, **kwargs)
            return r

        setattr(self.obj, self.meth, middle)

    def insert_before(self, func):
        """Runs func before running the replaced method."""
        self.old = getattr(self.obj, self.meth)

        def middle(*args, **kwargs):
            """Helper/worker func."""
            if func(*args, **kwargs):
                return self.old(*args, **kwargs)

        setattr(self.obj, self.meth, middle)

    def nuke(self, func=None):
        """Nukes the method"""
        self.old = getattr(self.obj, self.meth)
        if func is None:

            def func(*args, **kwargs):
                return None

        setattr(self.obj, self.meth, func)

    def restore(self):
        """Restores the original method."""
        if self.old is None:
            m = "the old method is None (hint: called restore before nuke)"
            raise ValueError(m)
        setattr(self.obj, self.meth, self.old)

    def pause(self, func=None):
        """Pauses a method execution that can be played later."""
        self.old = getattr(self.obj, self.meth)
        play = defer.Deferred()

        @defer.inlineCallbacks
        def middle(*a, **k):
            """Play it in the middle."""
            if func is not None:
                func(*a, **k)
            yield play
            setattr(self.obj, self.meth, self.old)
            result = yield defer.maybeDeferred(self.old, *a, **k)
            defer.returnValue(result)

        setattr(self.obj, self.meth, middle)
        return lambda: play.callback(True)


class NukeAQClient(object):
    """Helper to nuke a client method and restore it later."""

    def __init__(self, aq, meth):
        self.aq = aq
        self.meth = meth
        self.old = None

    def nuke(self, func=None):
        """Nukes the method"""
        self.old = getattr(self.aq.client, self.meth)
        if func is None:

            def func(*args, **kwargs):
                return defer.Deferred

        setattr(self.aq.client, self.meth, func)

    def restore(self):
        """Restores the original method."""
        if self.old is None:
            m = "the old method is None (hint: called restore before nuke)"
            raise ValueError(m)
        if self.aq.client is not None:
            setattr(self.aq.client, self.meth, self.old)


class FakeGetContent(object):
    """Helper class that haves self.deferred"""

    def __init__(self, deferred, share, node, hash):
        """initialize it"""
        self.deferred = deferred
        self.share_id = share
        self.node_id = node
        self.server_hash = hash


class FakeFailure(object):
    """An object that when compared to a Failure, checks its message."""

    def __init__(self, message):
        self._message = message

    def __eq__(self, other):
        """Checks using the message of 'other' if any."""
        error_message_method = getattr(other, 'getErrorMessage', None)
        if error_message_method:
            other_message = error_message_method()
            return other_message == self._message
        else:
            return False
