# -*- coding: utf-8 -*-
#
# Copyright 2009-2015 Canonical Ltd.
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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
"""Base test cases and test utilities."""

from __future__ import with_statement

import contextlib
import itertools
import logging
import os
import shutil
import sys

from collections import defaultdict
from functools import wraps

from twisted.internet import defer, reactor
from twisted.trial.unittest import TestCase as TwistedTestCase
from ubuntuone.devtools.testcases import skipIfOS
from zope.interface import implements
from zope.interface.verify import verifyObject

from ubuntuone.syncdaemon import (
    config,
    action_queue,
    event_queue,
    filesystem_manager as fs_manager,
    interaction_interfaces,
    interfaces,
    volume_manager,
    main,
    local_rescan,
    tritcask,
    RECENT_TRANSFERS,
    UPLOADING,
)
from ubuntuone.syncdaemon import logger
from ubuntuone import platform
from ubuntuone.platform import (
    can_write,
    make_dir,
    path_exists,
    set_dir_readonly,
    set_dir_readwrite,
    stat_path,
)

logger.init()

FAKED_CREDENTIALS = {'username': 'test_username',
                     'password': 'test_password'}


@contextlib.contextmanager
def environ(env_var, new_value):
    """context manager to replace/add an environ value"""
    old_value = os.environ.get(env_var, None)
    os.environ[env_var] = new_value
    yield
    if old_value is None:
        os.environ.pop(env_var)
    else:
        os.environ[env_var] = old_value


class FakeHashQueue(object):
    """A fake hash queue"""
    def __init__(self, eq):
        self.eq = eq

    def empty(self):
        """are we empty? sure we are"""
        return True

    def shutdown(self):
        """go away? I'l barely *here*!"""
        pass

    def __len__(self):
        """ length is 0. we are empty, right?"""
        return 0

    def insert(self, path, mdid):
        """Fake insert."""
        self.eq.push('HQ_HASH_NEW', path=path, hash='',
                     crc32='', size=0, stat=stat_path(path))


class FakeMark(object):
    """A fake Mark Shuttleworth..."""
    def stop(self):
        """...that only knows how to stop"""


class FakeExternalInterface(object):
    """A fake DBusInterface..."""

    def start(self):
        """... that knows how to start."""
        return defer.succeed(None)

    def shutdown(self, with_restart=False):
        """... how to go away"""

    def _request_token(self, *args, **kwargs):
        """Return a token which is a fixed set of credentials."""
        return FAKED_CREDENTIALS


class FakeActionQueue(object):
    """Stub implementation."""

    implements(interfaces.IActionQueue)

    def __init__(self, eq, *args, **kwargs):
        """ Creates the instance """
        self.eq = self.event_queue = eq
        self.uuid_map = action_queue.DeferredMap()
        self.queue = action_queue.RequestQueue(self)
        self.pathlock = FakedObject()

        # throttling attributes
        self.readLimit = None
        self.writeLimit = None
        self.throttling_enabled = False

    def __setattr__(self, attr, value):
        """Custom __setattr__ that check the interface.

        After setting a callable attribute, verify the interface.
        """
        r = super(FakeActionQueue, self).__setattr__(attr, value)
        if callable(value):
            # check that AQ implements IActionQueue.
            verifyObject(interfaces.IActionQueue, self)
        return r

    # IMetaQueue
    def connect(self, host=None, port=None, user_ssl=False):
        """Just send connect!."""
        self.eq.push('SYS_CONNECTION_MADE')

    def enable_throttling(self):
        """We have throttling enabled now."""
        self.throttling_enabled = True

    def disable_throttling(self):
        """We have throttling disabled now."""
        self.throttling_enabled = False

    def answer_share(self, share_id, answer):
        """Send the event."""
        self.eq.push('AQ_ANSWER_SHARE_OK', share_id=share_id, answer=answer)

    def disconnect(self, *a, **k):
        """Stub implementation."""

    cancel_download = cancel_upload = download = upload = make_dir = disconnect
    make_file = move = unlink = list_shares = disconnect
    list_volumes = create_share = create_udf = inquire_free_space = disconnect
    inquire_account_info = delete_volume = change_public_access = disconnect
    query_volumes = get_delta = rescan_from_scratch = delete_share = disconnect
    node_is_with_queued_move = cleanup = get_public_files = disconnect


class FakeStatusListener(object):
    """A fake StatusListener."""

    def menu_data(self):
        """Fake menu_data."""
        return {RECENT_TRANSFERS: [], UPLOADING: []}


class FakeMonitor(object):
    """A fake FilesystemMonitor."""

    def __init__(self, eq, fs, ignore_config=None, timeout=1):
        """Do nothing."""

    def freeze_begin(self, path):
        """Succeed quietly."""

    def freeze_rollback(self):
        """Succeed quietly."""

    def freeze_commit(self, events):
        """Never report dirty commits for fake events."""
        return defer.succeed(False)

    def add_to_mute_filter(self, event, **info):
        """Do nothing."""

    def rm_from_mute_filter(self, event, **info):
        """Do nothing."""

    def add_watches_to_udf_ancestors(self, volume):
        """Just report success."""
        return defer.succeed(True)

    def add_watch(self, dirpath):
        """Just report success."""
        defer.succeed(True)

    def rm_watch(self, dirpath):
        """Just report success."""
        return defer.succeed(True)

    def shutdown(self):
        """Just report success."""
        return defer.succeed(True)


class FakeMain(main.Main):
    """ A fake Main class to setup the tests """

    _fake_AQ_class = FakeActionQueue
    _fake_AQ_params = ()
    _sync_class = None
    _monitor_class = FakeMonitor

    # don't call Main.__init__ we take care of creating a fake main and
    # all its attributes. pylint: disable=W0231
    def __init__(self, root_dir, shares_dir, data_dir, partials_dir):
        """ create the instance. """
        self.logger = logging.getLogger('ubuntuone.SyncDaemon.FakeMain')
        self.root_dir = root_dir
        self.data_dir = data_dir
        self.shares_dir = shares_dir
        self.partials_dir = partials_dir
        self.shares_dir_link = os.path.join(self.root_dir, 'Shared With Me')
        self.db = tritcask.Tritcask(os.path.join(self.data_dir, 'tritcask'))
        self.vm = volume_manager.VolumeManager(self)
        self.fs = fs_manager.FileSystemManager(
            self.data_dir, self.partials_dir, self.vm, self.db)
        self.event_q = event_queue.EventQueue(self.fs,
                                              monitor_class=self._monitor_class)
        self.fs.register_eq(self.event_q)
        self.action_q = self._fake_AQ_class(self.event_q, self,
                                            *self._fake_AQ_params)
        self.state_manager = main.StateManager(self, 2)
        if self._sync_class is not None:
            self.sync = self._sync_class(self)
        self.event_q.subscribe(self.vm)
        self.vm.init_root()
        self.hash_q = FakeHashQueue(self.event_q)
        self.mark = FakeMark()
        self.external = FakeExternalInterface()
        self.lr = local_rescan.LocalRescan(self.vm, self.fs,
                                           self.event_q, self.action_q)

        self.status_listener = FakeStatusListener()

    def _connect_aq(self, _):
        """Connect the fake action queue."""
        self.action_q.connect()

    def _disconnect_aq(self):
        """Disconnect the fake action queue."""
        self.action_q.disconnect()

    def check_version(self):
        """Check the client protocol version matches that of the server."""
        self.event_q.push('SYS_PROTOCOL_VERSION_OK')

    def authenticate(self):
        """Do the OAuth dance."""
        self.event_q.push('SYS_AUTH_OK')

    def set_capabilities(self):
        """Set the capabilities."""
        self.event_q.push('SYS_SET_CAPABILITIES_OK')

    def get_root(self, root_mdid):
        """Ask que AQ for our root's uuid."""
        return defer.succeed('root_uuid')

    def server_rescan(self):
        """Do the server rescan? naaa!"""
        self.event_q.push('SYS_SERVER_RESCAN_DONE')
        return defer.succeed('root_uuid')

    def local_rescan(self):
        """Do the local rescan? naaa!"""
        self.event_q.push('SYS_LOCAL_RESCAN_DONE')
        return defer.succeed(True)


class FakeTunnelRunner(object):
    """A fake proxy.tunnel_client.TunnelRunner."""

    def __init__(self, *args):
        """Fake a proxy tunnel."""

    def get_client(self):
        """Always return the reactor."""
        return defer.succeed(reactor)


class BaseTwistedTestCase(TwistedTestCase):
    """Base TestCase with helper methods to handle temp dir.

    This class provides:
        mktemp(name): helper to create temporary dirs
        mmtree(path): support read-only shares
        makedirs(path): support read-only shares
    """
    MAX_FILENAME = 32  # some platforms limit lengths of filenames
    tunnel_runner_class = FakeTunnelRunner

    def mktemp(self, name='temp'):
        """ Customized mktemp that accepts an optional name argument. """
        tempdir = os.path.join(self.tmpdir, name)
        if path_exists(tempdir):
            self.rmtree(tempdir)
        self.makedirs(tempdir)
        self.addCleanup(self.rmtree, tempdir)
        assert isinstance(tempdir, str)
        return tempdir

    @property
    def tmpdir(self):
        """Default tmpdir: module/class/test_method."""
        # check if we already generated the root path
        if self.__root:
            return self.__root
        base = os.path.join(self.__class__.__module__[:self.MAX_FILENAME],
                            self.__class__.__name__[:self.MAX_FILENAME],
                            self._testMethodName)
        # use _trial_temp dir, it should be TRIAL_TEMP_DIR or os.getcwd()
        # define the root temp dir of the testcase, pylint: disable=W0201
        root_tmp = os.environ.get('TRIAL_TEMP_DIR', os.getcwd())
        self.__root = os.path.join(root_tmp, '_trial_temp', base)
        self.addCleanup(self.rmtree, self.__root)
        return self.__root

    def rmtree(self, path):
        """Custom rmtree that handle ro parent(s) and childs."""
        assert isinstance(path, str)
        # on windows the paths cannot be removed because the process running
        # them has the ownership and therefore are locked.
        if not path_exists(path):
            return
        # change perms to rw, so we can delete the temp dir
        if path != self.__root:
            set_dir_readwrite(os.path.dirname(path))
        if not can_write(path):
            set_dir_readwrite(path)

        if sys.platform == 'win32':
            # path is a byte sequence encoded with utf-8. If we pass this to
            # os.walk, in windows, we'll get results encoded with mbcs
            path = path.decode('utf-8')

        for dirpath, dirs, files in os.walk(path):
            for adir in dirs:
                adir = os.path.join(dirpath, adir)
                if sys.platform == 'win32':
                    assert isinstance(adir, unicode)
                    adir = adir.encode('utf-8')
                if not can_write(adir):
                    set_dir_readwrite(adir)

        if sys.platform == 'win32':
            # in windows, we need to pass a unicode, literal path to
            # shutil.rmtree, otherwise we can't remove "deep and wide" paths
            path = u'\\\\?\\' + path.decode('utf-8')

        # Instead of ignoring the errors when removing trees, we are temporarly
        # printing a message to stdout to caught everyone's attention.
        # Once the tests are fixed in this regard, we're removing the
        # try-except block and having shutil.rmtree failing if the path
        # can not be removed.
        try:
            shutil.rmtree(path)
        except Exception, e:
            print 'ERROR!! could not recursively remove %r ' \
                  '(error is %r).' % (path, e)

    def makedirs(self, path):
        """Custom makedirs that handle ro parent."""
        parent = os.path.dirname(path)
        if path_exists(parent):
            set_dir_readwrite(parent)
        make_dir(path, recursive=True)

    @defer.inlineCallbacks
    def setUp(self):
        yield super(BaseTwistedTestCase, self).setUp()
        self.__root = None

        # Patch the user home
        self.home_dir = self.mktemp('ubuntuonehacker')
        self.patch(platform, "user_home", self.home_dir)

        # use the config from the branch
        new_get_config_files = lambda: [os.path.join(os.environ['ROOTDIR'],
                                                     'data', 'syncdaemon.conf')]
        self.patch(config, 'get_config_files', new_get_config_files)

        # fake a very basic config file with sane defaults for the tests
        config_dir = self.mktemp('config')
        self.config_file = os.path.join(config_dir, 'syncdaemon.conf')
        with open(self.config_file, 'w') as fp:
            fp.write('[bandwidth_throttling]\n')
            fp.write('on = False\n')
            fp.write('read_limit = -1\n')
            fp.write('write_limit = -1\n')
        # invalidate the current config
        config._user_config = None
        config.get_user_config(config_file=self.config_file)

        self.log = logging.getLogger("ubuntuone.SyncDaemon.TEST")
        self.log.info("starting test %s.%s", self.__class__.__name__,
                      self._testMethodName)
        self.patch(action_queue.tunnel_runner, "TunnelRunner",
                   self.tunnel_runner_class)


class FakeMainTestCase(BaseTwistedTestCase):
    """A testcase that starts up a Main instance."""

    timeout = 2

    @defer.inlineCallbacks
    def setUp(self):
        """Setup the infrastructure for the test."""
        yield super(FakeMainTestCase, self).setUp()

        self.data_dir = self.mktemp('data_dir')
        self.partials_dir = self.mktemp('partials')
        self.root_dir = self.mktemp('root_dir')
        self.shares_dir = self.mktemp('shares_dir')
        self.main = FakeMain(self.root_dir, self.shares_dir,
                             self.data_dir, self.partials_dir)
        self.addCleanup(self.main.shutdown)
        self.vm = self.main.vm
        self.fs = self.main.fs
        self.event_q = self.main.event_q
        self.action_q = self.main.action_q
        self.event_q.push('SYS_INIT_DONE')

        self._called = None

    def _set_called(self, *args, **kwargs):
        """Keep track of patched calls."""
        self._called = (args, kwargs)


class FakeVolumeManager(object):
    """ A volume manager that only knows one share, the root"""

    def __init__(self, root_path):
        """ Creates the instance"""
        self.root = volume_manager.Root(node_id="root_node_id", path=root_path)
        self.shares = {'': self.root}
        self.udfs = {}
        self.log = logging.getLogger('ubuntuone.SyncDaemon.VM-test')

    def add_share(self, share):
        """Add share to the shares dict."""
        self.shares[share.id] = share
        # if the share don't exists, create it
        if not path_exists(share.path):
            make_dir(share.path)
        # if it's a ro share, change the perms
        if not share.can_write():
            set_dir_readonly(share.path)

    def add_udf(self, udf):
        """Add udf to the udfs dict."""
        self.udfs[udf.id] = udf

    def share_deleted(self, _):
        """Do nothing."""

    def get_volume(self, id):
        """Returns a share or a UDF."""
        try:
            return self.shares[id]
        except KeyError:
            try:
                return self.udfs[id]
            except KeyError:
                raise volume_manager.VolumeDoesNotExist(id)

    def get_volumes(self, all_volumes=False):
        """Simple get_volumes for FakeVolumeManager."""
        volumes = itertools.chain(self.shares.values(), self.udfs.values())
        for volume in volumes:
            if all_volumes or volume.active:
                yield volume

    def unsubscribe_udf(self, udf_id):
        """Mark the UDF with udf_id as unsubscribed."""
        udf = self.udfs[udf_id]
        udf.subscribed = False
        self.udfs[udf_id] = udf

    def delete_volume(self, volume_id):
        """Request the deletion of a volume."""


class FakeLogger(object):
    """Helper logging class."""
    def __init__(self):
        self.logged = dict(debug=[], warning=[], info=[])

    def _log(self, log, txt, args):
        """Really logs."""
        if args:
            txt = txt % args
        log.append(txt)

    def warning(self, txt, *args):
        """WARNING logs."""
        self._log(self.logged['warning'], txt, args)

    def debug(self, txt, *args):
        """DEBUG logs."""
        self._log(self.logged['debug'], txt, args)

    def info(self, txt, *args):
        """INFO logs."""
        self._log(self.logged['info'], txt, args)


class FakeCommand(object):
    """A fake command."""

    is_runnable = True
    running = True

    def __init__(self, share_id=None, node_id=None,
                 other='', path=None, **kwargs):
        self.share_id = share_id
        self.node_id = node_id
        self.other = other
        self.path = path
        self.cancelled = False
        self.log = logging.getLogger('ubuntuone.SyncDaemon')

    @property
    def paused(self):
        """Is this command paused?"""
        return not self.running

    @property
    def uniqueness(self):
        """Fake uniqueness."""
        if self.share_id is None and self.node_id is None:
            return self
        else:
            return (self.__class__.__name__, self.share_id, self.node_id)

    def run(self):
        """Just succeed."""
        return defer.succeed(None)

    def to_dict(self):
        """Just send both values."""
        d = dict(share_id=self.share_id, node_id=self.node_id,
                 other=self.other, running=self.running)
        # some commands have path, others don't
        if self.path is not None:
            d['path'] = self.path
        return d

    def pause(self):
        """Pause running."""
        self.running = False

    def cancel(self):
        """Cancel!"""
        self.cancelled = True


class FakeUpload(FakeCommand, action_queue.Upload):
    """Fake command that inherits from Upload."""

    def __init__(self, *args):
        super(FakeUpload, self).__init__(*args)
        self.path = 'upload_path'
        self.tempfile = None


class FakeDownload(FakeCommand, action_queue.Download):
    """Fake command that inherits from Download."""

    def __init__(self, *args):
        super(FakeDownload, self).__init__(*args)
        self.path = 'download_path'


class EmptyCommand(FakeCommand):
    """A command without any attributes."""

    def __init__(self):
        """__init__ that doesn't set any attributes."""

    def to_dict(innerself):
        """We have no attributes, return an empty dict."""
        return {}


class FakedObject(object):
    """A class that records every call clients made to it."""

    def __init__(self, *args, **kwargs):
        self._called = defaultdict(list)

    def __getattribute__(self, attr_name):
        """Override so we can record calls to members."""
        try:
            result = super(FakedObject, self).__getattribute__(attr_name)
        except AttributeError:
            result = lambda *a, **kw: None
            super(FakedObject, self).__setattr__(attr_name, result)

        if attr_name == '_called':
            return result

        called = super(FakedObject, self).__getattribute__('_called')

        def wrap_me(f):
            """Wrap 'f'."""
            @wraps(f)
            def inner(*a, **kw):
                """Keep track of calls to 'f', execute it and return result."""
                called[attr_name].append((a, kw))
                return f(*a, **kw)

            return inner

        return wrap_me(result)


class FakedService(interaction_interfaces.SyncdaemonService):
    """A faked SyncdaemonService."""

    clients = (
        'config',
        'events',
        'event_listener',
        'file_system',
        'folders',
        'public_files',
        'shares',
        'status',
        'sync',
    )

    def __init__(self, main, send_events=False, interface=None):
        super(FakedService, self).__init__(main, send_events, interface)
        self.auth_credentials = ('foo', 'bar')

    def _create_children(self):
        """Override parent's method to have fakes for children."""
        for client in self.clients:
            setattr(self, client, FakedObject())


class Listener(object):
    """Helper class to gather events."""

    def __init__(self):
        self.events = []

    def handle_default(self, event_name, **kwargs):
        """Keep record of every event."""
        self.events.append((event_name, kwargs))


class DummyClass(object):
    """Dummy class, does nothing."""

    def __getattr__(self, name):
        """Any attribute is a no-op."""
        return lambda *args, **kwargs: None


skip_if_win32_and_uses_metadata_older_than_5 = \
    skipIfOS('win32',
             'In windows there is no need to migrate metadata older than v5.')


skip_if_win32_and_uses_readonly = \
    skipIfOS('win32', 'Can not test RO shares until bug #820350 is resolved.')


skip_if_win32_missing_fs_event = \
    skipIfOS('win32', 'Fails due to missing/out of order FS events, '
                      'see bug #820598.')

skip_if_darwin_missing_fs_event = \
    skipIfOS('darwin', 'Fails due to missing/out of order FS events, '
                       'see bug #820598.')
