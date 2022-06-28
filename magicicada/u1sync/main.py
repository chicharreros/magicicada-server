# Copyright 2009 Canonical Ltd.
# Copyright 2015-2018 Chicharreros (https://launchpad.net/~chicharreros)
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

"""A prototype directory sync client."""

import logging
import os
import signal
import sys
import uuid

from errno import EEXIST
from optparse import OptionParser, SUPPRESS_HELP
from queue import Queue

import gobject

import magicicadaprotocol.dircontent_pb2 as dircontent_pb2
from magicicadaprotocol.dircontent_pb2 import DIRECTORY, SYMLINK
from twisted.internet import reactor

from magicicada.u1sync import metadata
from magicicada.u1sync.client import (
    ConnectionError, AuthenticationError, NoSuchShareError,
    ForcedShutdown, Client)
from magicicada.u1sync.constants import METADATA_DIR_NAME
from magicicada.u1sync.genericmerge import show_tree, generic_merge
from magicicada.u1sync.merge import (
    SyncMerge, ClobberServerMerge, ClobberLocalMerge, merge_trees)
from magicicada.u1sync.scan import scan_directory
from magicicada.u1sync.sync import download_tree, upload_tree
from magicicada.u1sync.utils import safe_mkdir


logger = logging.getLogger(__name__)
gobject.set_application_name('u1sync')

DEFAULT_MERGE_ACTION = 'auto'
MERGE_ACTIONS = {
    # action: (merge_class, should_upload, should_download)
    'sync': (SyncMerge, True, True),
    'clobber-server': (ClobberServerMerge, True, False),
    'clobber-local': (ClobberLocalMerge, False, True),
    'upload': (SyncMerge, True, False),
    'download': (SyncMerge, False, True),
    'auto': None  # special case
}
NODE_TYPE_ENUM = dircontent_pb2._NODETYPE


def node_type_str(node_type):
    """Converts a numeric node type to a human-readable string."""
    return NODE_TYPE_ENUM.values_by_number[node_type].name


class ReadOnlyShareError(Exception):
    """Share is read-only."""


class DirectoryAlreadyInitializedError(Exception):
    """The directory has already been initialized."""


class DirectoryNotInitializedError(Exception):
    """The directory has not been initialized."""


class NoParentError(Exception):
    """A node has no parent."""


class TreesDiffer(Exception):
    """Raised when diff tree differs."""


def do_init(client, share_spec, directory, subtree_path, metadata=metadata):
    """Initializes a directory for syncing, and syncs it."""
    info = metadata.Metadata()

    if share_spec is not None:
        info.share_uuid = client.find_volume(share_spec)
    else:
        info.share_uuid = None

    if subtree_path is not None:
        info.path = subtree_path
    else:
        info.path = "/"

    logger.debug("Initializing directory...")
    safe_mkdir(directory)

    metadata_dir = os.path.join(directory, METADATA_DIR_NAME)
    try:
        os.mkdir(metadata_dir)
    except OSError as e:
        if e.errno == EEXIST:
            raise DirectoryAlreadyInitializedError(directory)
        else:
            raise

    logger.debug("Writing mirror metadata...")
    metadata.write(metadata_dir, info)

    logger.debug("Done.")


def do_sync(client, directory, action, dry_run):
    """Synchronizes a directory with the given share."""
    absolute_path = os.path.abspath(directory)
    while True:
        metadata_dir = os.path.join(absolute_path, METADATA_DIR_NAME)
        if os.path.exists(metadata_dir):
            break
        if absolute_path == "/":
            raise DirectoryNotInitializedError(directory)
        absolute_path = os.path.split(absolute_path)[0]

    logger.debug("Reading mirror metadata...")
    info = metadata.read(metadata_dir)

    top_uuid, writable = client.get_root_info(info.share_uuid)

    if info.root_uuid is None:
        info.root_uuid = client.resolve_path(info.share_uuid, top_uuid,
                                             info.path)

    if action == 'auto':
        if writable:
            action = 'sync'
        else:
            action = 'download'
    merge_type, should_upload, should_download = MERGE_ACTIONS[action]
    if should_upload and not writable:
        raise ReadOnlyShareError(info.share_uuid)

    logger.debug("Scanning directory...")
    local_tree = scan_directory(absolute_path)

    logger.debug("Fetching metadata...")
    remote_tree = client.build_tree(info.share_uuid, info.root_uuid)
    show_tree(remote_tree)

    logger.debug("Merging trees...")
    merged_tree = merge_trees(old_local_tree=info.local_tree,
                              local_tree=local_tree,
                              old_remote_tree=info.remote_tree,
                              remote_tree=remote_tree,
                              merge_action=merge_type())
    show_tree(merged_tree)

    logger.debug("Syncing content...")
    if should_download:
        info.local_tree = download_tree(merged_tree=merged_tree,
                                        local_tree=local_tree,
                                        client=client,
                                        share_uuid=info.share_uuid,
                                        path=absolute_path, dry_run=dry_run)
    else:
        info.local_tree = local_tree
    if should_upload:
        info.remote_tree = upload_tree(merged_tree=merged_tree,
                                       remote_tree=remote_tree,
                                       client=client,
                                       share_uuid=info.share_uuid,
                                       path=absolute_path, dry_run=dry_run)
    else:
        info.remote_tree = remote_tree

    if not dry_run:
        logger.debug("Updating mirror metadata...")
        metadata.write(metadata_dir, info)

    logger.debug("Done.")


def do_list_shares(client):
    """Lists available (incoming) shares."""
    shares = client.get_incoming_shares()
    for (name, id, user, accepted, access) in shares:
        if not accepted:
            status = " [not accepted]"
        else:
            status = ""
        name = name.encode("utf-8")
        user = user.encode("utf-8")
        logger.debug("%s  %s (from %s) [%s]%s", id, name, user, access, status)


def do_diff(client, share_spec, directory, subtree_path, ignore_symlinks=True):
    """Diffs a local directory with the server."""
    if share_spec is not None:
        share_uuid = client.find_volume(share_spec)
    else:
        share_uuid = None
    if subtree_path is None:
        subtree_path = '/'

    root_uuid, writable = client.get_root_info(share_uuid)
    subtree_uuid = client.resolve_path(share_uuid, root_uuid, subtree_path)
    local_tree = scan_directory(directory)
    remote_tree = client.build_tree(share_uuid, subtree_uuid)

    def pre_merge(nodes, name, partial_parent):
        """Compare nodes and show differences."""
        (local_node, remote_node) = nodes
        (parent_display_path, parent_differs) = partial_parent
        display_path = os.path.join(parent_display_path, name.encode("UTF-8"))
        differs = True
        if local_node is None:
            logger.debug("%s missing from client", display_path)
        elif remote_node is None:
            if ignore_symlinks and local_node.node_type == SYMLINK:
                differs = False
            else:
                logger.debug("%s missing from server", display_path)
        elif local_node.node_type != remote_node.node_type:
            local_type = node_type_str(local_node.node_type)
            remote_type = node_type_str(remote_node.node_type)
            logger.debug(
                "%s node types differ (client: %s, server: %s)",
                display_path, local_type, remote_type)
        elif (local_node.node_type != DIRECTORY and
                local_node.content_hash != remote_node.content_hash):
            local_content = local_node.content_hash
            remote_content = remote_node.content_hash
            logger.debug(
                "%s has different content (client: %s, server: %s)",
                display_path, local_content, remote_content)
        else:
            differs = False
        return (display_path, differs)

    def post_merge(nodes, partial_result, child_results):
        """Aggregates 'differs' flags."""
        (display_path, differs) = partial_result
        return differs or any(child_results.values())

    differs = generic_merge(trees=[local_tree, remote_tree],
                            pre_merge=pre_merge, post_merge=post_merge,
                            partial_parent=("", False), name="")
    if differs:
        raise TreesDiffer()


def do_main(argv):
    """The main user-facing portion of the script."""
    usage = (
        "Usage: %prog [options] [DIRECTORY]\n"
        "       %prog --list-shares [options]\n"
        "       %prog --init [--share=SHARE_UUID] [options] DIRECTORY\n"
        "       %prog --diff [--share=SHARE_UUID] [options] DIRECTORY")
    parser = OptionParser(usage=usage)
    parser.add_option("--port", dest="port", metavar="PORT",
                      default=443,
                      help="The port on which to connect to the server")
    parser.add_option("--host", dest="host", metavar="HOST",
                      default='fs-1.one.ubuntu.com',
                      help="The server address")

    action_list = ", ".join(sorted(MERGE_ACTIONS.keys()))
    parser.add_option("--action", dest="action", metavar="ACTION",
                      default=None,
                      help="Select a sync action (%s; default is %s)" %
                           (action_list, DEFAULT_MERGE_ACTION))
    parser.add_option("--dry-run", action="store_true", dest="dry_run",
                      default=False, help="Do a dry run without actually "
                                          "making changes")
    parser.add_option("--list-shares", action="store_const", dest="mode",
                      const="list-shares", default="sync",
                      help="List available shares")
    parser.add_option("--init", action="store_const", dest="mode",
                      const="init",
                      help="Initialize a local directory for syncing")
    parser.add_option("--no-ssl-verify", action="store_true",
                      dest="no_ssl_verify",
                      default=False, help=SUPPRESS_HELP)
    parser.add_option("--diff", action="store_const", dest="mode",
                      const="diff",
                      help="Compare tree on server with local tree "
                           "(does not require previous --init)")
    parser.add_option("--share", dest="share", metavar="SHARE_UUID",
                      default=None,
                      help="Sync the directory with a share rather than the "
                           "user's own volume")
    parser.add_option("--subtree", dest="subtree", metavar="PATH",
                      default=None,
                      help="Mirror a subset of the share or volume")

    (options, args) = parser.parse_args(args=list(argv[1:]))

    if options.share is not None and options.mode not in ("init", "diff"):
        parser.error("--share is only valid with --init or --diff")

    directory = None
    if options.mode in ("sync", "init" or "diff"):
        if len(args) > 1:
            parser.error("Too many arguments")
        elif len(args) < 1:
            if options.mode == "init" or options.mode == "diff":
                parser.error("--%s requires a directory to "
                             "be specified" % options.mode)
            else:
                directory = "."
        else:
            directory = args[0]
    if options.mode in ("init", "list-shares", "diff"):
        if options.action is not None:
            parser.error("--%s does not take the --action parameter" %
                         options.mode)
        if options.dry_run:
            parser.error("--%s does not take the --dry-run parameter" %
                         options.mode)
    if options.mode == "list-shares":
        if len(args) != 0:
            parser.error("--list-shares does not take a directory")
    if options.mode not in ("init", "diff"):
        if options.subtree is not None:
            parser.error("--%s does not take the --subtree parameter" %
                         options.mode)

    if options.action is not None and options.action not in MERGE_ACTIONS:
        parser.error("--action: Unknown action %s" % options.action)

    if options.action is None:
        options.action = DEFAULT_MERGE_ACTION

    if options.share is not None:
        try:
            uuid.UUID(options.share)
        except ValueError as e:
            parser.error("Invalid --share argument: %s" % e)
        share_spec = options.share
    else:
        share_spec = None

    client = Client(reactor=reactor)

    signal.signal(signal.SIGINT, lambda s, f: client.force_shutdown())
    signal.signal(signal.SIGTERM, lambda s, f: client.force_shutdown())

    def run_client():
        """Run the blocking client."""
        client.connect_ssl(
            options.host, int(options.port), options.no_ssl_verify)

        try:
            client.set_capabilities()

            if options.mode == "sync":
                do_sync(client=client, directory=directory,
                        action=options.action,
                        dry_run=options.dry_run)
            elif options.mode == "init":
                do_init(client=client, share_spec=share_spec,
                        directory=directory,
                        subtree_path=options.subtree)
            elif options.mode == "list-shares":
                do_list_shares(client=client)
            elif options.mode == "diff":
                do_diff(client=client, share_spec=share_spec,
                        directory=directory,
                        subtree_path=options.subtree,
                        ignore_symlinks=False)
        finally:
            client.disconnect()

    def capture_exception(queue, func):
        """Capture the exception from calling func."""
        try:
            func()
        except Exception:
            queue.put(sys.exc_info())
        else:
            queue.put(None)
        finally:
            reactor.callWhenRunning(reactor.stop)

    queue = Queue()
    reactor.callInThread(capture_exception, queue, run_client)
    reactor.run(installSignalHandlers=False)
    exc_info = queue.get(True, 0.1)
    if exc_info:
        raise exc_info[0](exc_info[1]).with_traceback(exc_info[2])


def main(*argv):
    """Top-level main function."""
    try:
        do_main(argv=argv)
    except AuthenticationError as e:
        logger.debug("Authentication failed: %s", e)
    except ConnectionError as e:
        logger.debug("Connection failed: %s", e)
    except DirectoryNotInitializedError:
        logger.debug(
            "Directory not initialized; use --init [DIRECTORY] to init it.")
    except DirectoryAlreadyInitializedError:
        logger.debug("Directory already initialized.")
    except NoSuchShareError:
        logger.debug("No matching share found.")
    except ReadOnlyShareError:
        logger.debug(
            "The selected action isn't possible on a read-only share.")
    except (ForcedShutdown, KeyboardInterrupt):
        logger.debug("Interrupted!")
    except TreesDiffer as e:
        logger.debug("Trees differ: %s.", e)
    else:
        return 0
    return 1
