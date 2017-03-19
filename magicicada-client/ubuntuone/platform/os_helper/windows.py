# -*- encoding: utf-8 -*-
#
# Copyright 2011-2012 Canonical Ltd.
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
"""Windows tools to interact with the os."""

import errno
import logging
import os
import shutil
import stat
import sys

from contextlib import contextmanager
from functools import wraps

from ntsecuritycon import (
    FILE_GENERIC_READ,
    FILE_GENERIC_WRITE,
    FILE_ALL_ACCESS,
)
import win32api
from pywintypes import error as PyWinError
from win32com.client import Dispatch
from win32com.shell import shell, shellcon
from win32file import (
    GetFileAttributesW,
    MoveFileExW,
    FILE_ATTRIBUTE_SYSTEM,
    MOVEFILE_COPY_ALLOWED,
    MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH,
)
from win32security import (
    ACL,
    ACL_REVISION,
    CONTAINER_INHERIT_ACE,
    CreateWellKnownSid,
    DACL_SECURITY_INFORMATION,
    GetFileSecurity,
    GetSecurityInfo,
    LookupAccountName,
    OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION,
    SetFileSecurity,
    SE_KERNEL_OBJECT,
    WinBuiltinAdministratorsSid,
    WinWorldSid,
)

from comtypes import shelllink
from comtypes.client import CreateObject
from comtypes.persist import IPersistFile

# ugly trick to stop pylint for complaining about WindowsError on Linux
if sys.platform != 'win32':
    WindowsError = None


logger = logging.getLogger('ubuntuone.SyncDaemon.VM')
platform = 'win32'

# missing win32file constant
INVALID_FILE_ATTRIBUTES = -1

# LONG_PATH_PREFIX will always be appended only to windows paths,
# which should always be unicode.
LONG_PATH_PREFIX = u'\\\\?\\'

EVERYONE_SID = CreateWellKnownSid(WinWorldSid)
ADMINISTRATORS_SID = CreateWellKnownSid(WinBuiltinAdministratorsSid)

# Mappping from the characters that are valid in other operating system but
#  areillegal in windows, to unicode values that look like the original chars
# and are valid in this platform.
BASE_CODE = u'\N{ZERO WIDTH SPACE}%s\N{ZERO WIDTH SPACE}'
WINDOWS_ILLEGAL_CHARS_MAP = {
    u'<': BASE_CODE % u'\N{SINGLE LEFT-POINTING ANGLE QUOTATION MARK}',
    u'>': BASE_CODE % u'\N{SINGLE RIGHT-POINTING ANGLE QUOTATION MARK}',
    u':': BASE_CODE % u'\N{RATIO}',
    u'"': BASE_CODE % u'\N{DOUBLE PRIME}',
    u'/': BASE_CODE % u'\N{FRACTION SLASH}',
    u'|': BASE_CODE % u'\N{DIVIDES}',
    u'?': BASE_CODE % u'\N{INTERROBANG}',
    u'*': BASE_CODE % u'\N{SEXTILE}',
    u'\n': BASE_CODE % u'\N{LINE SEPARATOR}'
}
# inverse map
LINUX_ILLEGAL_CHARS_MAP = {}
for key, value in WINDOWS_ILLEGAL_CHARS_MAP.iteritems():
    LINUX_ILLEGAL_CHARS_MAP[value] = key


def get_user_sid():
    process_handle = win32api.GetCurrentProcess()
    security_info = GetSecurityInfo(process_handle, SE_KERNEL_OBJECT,
                                    OWNER_SECURITY_INFORMATION)
    return security_info.GetSecurityDescriptorOwner()


USER_SID = get_user_sid()


def _int_to_bin(n):
    """Convert an int to a bin string of 32 bits."""
    return "".join([str((n >> y) & 1) for y in range(32 - 1, -1, -1)])


# Functions to be used for path validation

def _add_method_info(messages, method_name=None):
    """Loop through the messages and add the extra info."""
    updated_messages = messages.copy()
    if method_name:
        # lets update the messages to contain the method info.
        extra_info = 'Asserted in method "%s".' % method_name
        for message_name in messages:
            updated_messages[message_name] += extra_info
    return updated_messages


def assert_windows_path(path, method_name=None):
    """Check whether 'path' is a valid windows path.

    A 'valid windows path' should meet the following requirements:

    * is an unicode
    * is an absolute path
    * is a literal path (it starts with the LONG_PATH_PREFIX prefix)
    * do not contain any invalid character (see WINDOWS_ILLEGAL_CHARS_MAP)

    Opcionally the name of the method that called the assertion can be passed
    to improve the assertion message.
    """
    messages = {
        'unicode_path': 'Path %r should be unicode.',
        'long_path': 'Path %r should start with the LONG_PATH_PREFIX.',
        'illegal_path': '%r should not contain any character from' +
                        ' WINDOWS_ILLEGAL_CHARS_MAP.',
    }
    messages = _add_method_info(messages, method_name)

    assert isinstance(path, unicode), messages['unicode_path'] % path
    assert path.startswith(LONG_PATH_PREFIX), messages['long_path'] % path
    assert os.path.isabs(path.replace(LONG_PATH_PREFIX, u''))

    path = path.replace(LONG_PATH_PREFIX, u'')
    drive, path = os.path.splitdrive(path)
    assert not any(c in WINDOWS_ILLEGAL_CHARS_MAP for c in path), (
        messages['illegal_path'] % path)


def assert_syncdaemon_path(path, method_name=None):
    """Check whether 'path' is a valid syncdaemon path.

    A 'valid syncdaemon path' should meet the following requirements:

    * is a bytes sequence
    * is encoded with utf8
    * do not contain the LONG_PATH_PREFIX

    """
    messages = {
        'byte_path': 'Path %r should be a bytes sequence.',
        'utf8_path': 'Path %r should be encoded with utf8.',
        'long_path': '%r should not start with the LONG_PATH_PREFIX.',
        'unicode_chars': '%r should not contain any character from '
                         'LINUX_ILLEGAL_CHARS_MAP.',
    }
    messages = _add_method_info(messages, method_name)

    assert isinstance(path, str), messages['byte_path'] % path
    try:
        path = path.decode('utf8')
    except UnicodeDecodeError:
        raise AssertionError(messages['utf8_path'] % path)
    # path is now a unicode, we can compare against other unicodes
    assert not path.startswith(LONG_PATH_PREFIX), messages['long_path']
    assert not any(c in LINUX_ILLEGAL_CHARS_MAP for c in path), \
        messages['unicode_chars'] % path


# Functions to be used for path transformation


def _bytes_to_unicode(path):
    """Convert a bytes path to a unicode path."""
    # path is bytes, and non literal
    path = path.decode('utf8')
    drive, path = os.path.splitdrive(path)
    # remove the illegal windows chars with similar ones
    for invalid, valid in WINDOWS_ILLEGAL_CHARS_MAP.iteritems():
        path = path.replace(invalid, valid)
    path = drive + path
    return path


def get_windows_valid_path(path):
    """Get a 'syncdaemon' path and modify it so that it can be used in windows.

    There are a number of things we have to deal with to ensure that we can
    sync files with other operating systems. This method takes care of the
    following transformations:

    1. Decode 'path', which is a bytes sequence, into a unicode.

    2. Remove illegal chars: There are a number of illegal chars on windows
    that are allowed on Linux. The method removes those illegal chars and
    replaces them with unicode chars that look alike.

    3. Making the path absolute so (3) can be applied.

    4. Long paths: There is a limit of 255 chars per path on windows. This is
    solved by using literal paths (prepending LONG_PATH_PREFIX to the absolute
    path).

    """
    assert_syncdaemon_path(path)

    # grab the absolute path
    path = os.path.abspath(_bytes_to_unicode(path))
    result = LONG_PATH_PREFIX + path

    assert_windows_path(result)
    return result

get_os_valid_path = get_windows_valid_path


def _unicode_to_bytes(path):
    """Convert a unicode path to a bytes path."""
    # path is unicode and absolute
    drive, path = os.path.splitdrive(path)
    for invalid, valid in LINUX_ILLEGAL_CHARS_MAP.iteritems():
        path = path.replace(invalid, valid)

    return (drive + path).encode('utf8')


def get_syncdaemon_valid_path(path):
    """Get a 'windows' path and modify it so that it can be used in syncdaemon.

    There are a number of changes we make to allow the use of illegal chars,
    those generate a unicode path which sd does not handle. This method does
    the following:

    1. Remove the long path prefix: that's an implementation detail that should
    not be leaked to other layers.

    2. Replace unicode chars: the path may have some unicode chars used to
    replace chars that are valid in other operating systems but not in windows,
    so we need to replace those characters back to the original bytes.

    3. Return a sequence of bytes encoded with utf8.

    """
    assert_windows_path(path)

    # path is unicode, absolute and literal
    path = path.replace(LONG_PATH_PREFIX, u'')
    result = _unicode_to_bytes(path)

    assert_syncdaemon_path(result)
    return result


# Decorators to be used for path validation


def _is_valid_path(validate, path_indexes=None):
    """Decorator to validate the parameters using 'validate'.

    The paths given by the indexes from 'path_indexes' are validated using
    'validate'. If 'path_indexes' is None, only the first argument is checked.

    """

    if path_indexes is None:
        path_indexes = [0]

    def decorator(function):
        """Validate params given to 'function'."""

        @wraps(function)
        def inner(*args, **kwargs):
            """Do the validation."""
            for i in path_indexes:
                validate(args[i], method_name=function.__name__)
            return function(*args, **kwargs)

        return inner

    return decorator


def is_valid_windows_path(path_indexes=None):
    """Decorator to validate the parameters using assert_windows_path.

    The paths given by the indexes from 'path_indexes' are validated to be
    'windows' paths. If 'path_indexes' is None, only the first argument is
    checked.

    """
    return _is_valid_path(assert_windows_path, path_indexes)

is_valid_os_path = is_valid_windows_path


def is_valid_syncdaemon_path(path_indexes=None):
    """Decorator to validate the parameters using assert_syncdaemon_path.

    The paths given by the indexes from 'path_indexes' are validated to be
    'syncdaemon' paths. If 'path_indexes' is None, only the first argument is
    checked.

    """
    return _is_valid_path(assert_syncdaemon_path, path_indexes)


def assert_output_path_is_syncdaemon(function):
    """Ensure that the returned path is a syncdaemon path."""

    @wraps(function)
    def inner(*args, **kwargs):
        """Assert over the resulting path."""
        result = function(*args, **kwargs)
        assert_syncdaemon_path(result)

        return result

    return inner


def assert_output_collection_is_syncdaemon(function):
    """Ensure that the returned collection of paths are syncdaemon paths."""

    @wraps(function)
    def inner(*args, **kwargs):
        """Assert over the resulting paths."""
        result = function(*args, **kwargs)
        for path in result:
            assert_syncdaemon_path(path)

        return result

    return inner


# Decorators to be used for path transformation


def _transform_path(transformer, path_indexes=None):
    """Decorator to validate and transform path parameters.

    The paths given by the indexes from 'path_indexes' are transformed using
    'transformer'. If 'path_indexes' is None, only the first argument is
    checked.

    """

    if path_indexes is None:
        path_indexes = [0]

    def decorator(function):
        """Validate and transform params given to 'function'."""

        @wraps(function)
        def inner(*args, **kwargs):
            """Do the validation and transformation."""
            args = list(args)
            for i in path_indexes:
                args[i] = transformer(args[i])
            return function(*args, **kwargs)

        return inner

    return decorator


def windowspath(path_indexes=None):
    """Decorator to validate and transform path parameters.

    The paths given by the indexes from 'path_indexes' are validated to be
    'syncdaemon' paths,  and are also transformed to be valid 'windows' path,
    using the get_windows_valid_path transformer. If 'path_indexes' is None,
    only the first argument is checked.


    """
    return _transform_path(get_windows_valid_path, path_indexes)

os_path = windowspath


def syncdamonpath(path_indexes=None):
    """Decorator to validate and transform path parameters.

    The paths given by the indexes from 'path_indexes' are validated to be
    'syncdaemon' paths,  and are also transformed to be valid 'syncdaemon'
    path, using the get_syncdaemon_valid_path transformer. If 'path_indexes'
    is None, only the first argument is checked.


    """
    return _transform_path(get_syncdaemon_valid_path, path_indexes)


# internals

def _get_group_sid(group_name):
    """Return the SID for a group with the given name."""
    return LookupAccountName('', group_name)[0]


def _has_read_mask(number):
    """Return if the read flag is present."""
    # get the bin representation of the mask
    binary = _int_to_bin(number)
    # there is actual no documentation of this in MSDN but if bt 28 is set,
    # the mask has full access, more info can be found here:
    # http://www.iu.hio.no/cfengine/docs/cfengine-NT/node47.html
    if binary[28] == '1':
        return True
    # there is no documentation in MSDN about this, but if bit 0 and 3 are true
    # we have the read flag, more info can be found here:
    # http://www.iu.hio.no/cfengine/docs/cfengine-NT/node47.html
    return binary[0] == '1' and binary[3] == '1'


@is_valid_windows_path()
def _set_file_attributes(path, groups):
    """Set file attributes using the wind32api."""
    if not os.path.exists(path):
        raise WindowsError(errno.ENOENT, 'Path %s could not be found.' % path)

    # No need to do any specific handling for invalid characters since
    # 'path' is a valid windows path.
    security_descriptor = GetFileSecurity(path, DACL_SECURITY_INFORMATION)
    dacl = ACL()
    for group_sid, attributes in groups:
        # set the attributes of the group only if not null
        if attributes:
            dacl.AddAccessAllowedAceEx(
                ACL_REVISION, CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                attributes, group_sid)
    # the dacl has all the info of the diff groups passed in the parameters
    security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
    SetFileSecurity(path, DACL_SECURITY_INFORMATION, security_descriptor)


@windowspath()
def set_no_rights(path):
    """Set the rights for 'path' to be none.

    Set the groups to be empty which will remove all the rights of the file.

    """
    os.chmod(path, 0o000)
    groups = []
    _set_file_attributes(path, groups)


@windowspath()
def set_file_readonly(path):
    """Change path permissions to readonly in a file."""
    # we use the win32 api because chmod just sets the readonly flag and
    # we want to have more control over the permissions
    groups = [
        (ADMINISTRATORS_SID, FILE_GENERIC_READ | FILE_GENERIC_WRITE),
        (USER_SID, FILE_GENERIC_READ),
    ]
    # the above equals more or less to 0444
    _set_file_attributes(path, groups)


@windowspath()
def set_file_readwrite(path):
    """Change path permissions to readwrite in a file."""
    groups = [
        (EVERYONE_SID, FILE_GENERIC_READ),
        (ADMINISTRATORS_SID, FILE_ALL_ACCESS),
        (USER_SID, FILE_ALL_ACCESS),
    ]
    # the above equals more or less to 0774
    _set_file_attributes(path, groups)
    os.chmod(path, stat.S_IWRITE)


@windowspath()
def set_dir_readonly(path):
    """Change path permissions to readonly in a dir."""

    # XXX: THIS IS NOT WORKING PROPERLY, share dir created by tests can not be
    # removed after using set_dir_readwrite. So either set_dir_readonly or
    # set_dir_readwrite are buggy. See bug #820350.
    return

    groups = [
        (ADMINISTRATORS_SID, FILE_GENERIC_READ | FILE_GENERIC_WRITE),
        (USER_SID, FILE_GENERIC_READ),
    ]
    # the above equals more or less to 0444
    _set_file_attributes(path, groups)


@is_valid_windows_path()
def _set_dir_readwrite(path):
    """Change path permissions to readwrite in a dir.

    Helper that receives a windows path.

    """
    groups = [
        (EVERYONE_SID, FILE_GENERIC_READ),
        (ADMINISTRATORS_SID, FILE_ALL_ACCESS),
        (USER_SID, FILE_ALL_ACCESS),
    ]
    # the above equals more or less to 0774
    _set_file_attributes(path, groups)
    # remove the read only flag
    os.chmod(path, stat.S_IWRITE)


@windowspath()
def set_dir_readwrite(path):
    """Change path permissions to readwrite in a dir."""
    _set_dir_readwrite(path)


@contextmanager
@windowspath()
def allow_writes(path):
    """A very simple context manager to allow witting in RO dirs."""
    # get the old dacl of the file so that we can reset it back when done
    security_descriptor = GetFileSecurity(path, DACL_SECURITY_INFORMATION)
    old_dacl = security_descriptor.GetSecurityDescriptorDacl()
    _set_dir_readwrite(path)
    yield
    # set the old dacl back
    security_descriptor.SetSecurityDescriptorDacl(1, old_dacl, 0)
    SetFileSecurity(path, DACL_SECURITY_INFORMATION, security_descriptor)


@windowspath()
def remove_file(path):
    """Remove a file."""
    os.remove(path)


@windowspath()
def remove_tree(path):
    """Remove a dir and all its children."""
    shutil.rmtree(path)


@windowspath()
def remove_dir(path):
    """Remove a dir."""
    os.rmdir(path)


@windowspath()
def path_exists(path):
    """Return if the path exists."""
    return os.path.exists(path) or native_is_link(path)


@windowspath()
def is_dir(path):
    """Return if the path is an existing directory."""
    return os.path.isdir(path)


@windowspath()
def make_dir(path, recursive=False):
    """Make a dir, optionally creating all the middle ones."""
    if recursive:
        os.makedirs(path)
    else:
        os.mkdir(path)


@windowspath()
def open_file(path, mode='r'):
    """Open a file."""
    return open(path, mode)


@windowspath(path_indexes=[0, 1])
def rename(path_from, path_to):
    """Rename a file or directory."""
    return native_rename(path_from, path_to)


def native_rename(path_from, path_to):
    """Rename a file or directory, using native paths."""
    # No need to do any specific handling for invalid characters since
    # 'path_from' and 'path_to' are valid windows paths.
    # Also, to ensure the same behaviors as on linux, use the MoveFileExW
    # function from win32 which will allow to replace the destination path if
    # exists and the user has the proper rights. For further information, see:
    # http://msdn.microsoft.com/en-us/library/aa365240(v=vs.85).aspx
    flag = (MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH |
            MOVEFILE_REPLACE_EXISTING)
    try:
        MoveFileExW(path_from, path_to, flag)
    except PyWinError, e:
        # we need to transform a PyWinError into a OSError
        logger.exception('Got exception when trying to rename from ' +
                         '%r to %r', path_from, path_to)
        raise OSError(e.winerror, str(e))


@windowspath(path_indexes=[0, 1])
def recursive_move(path_from, path_to):
    """Perform a recursive move."""
    if not os.path.isdir(path_from):
        if os.path.isdir(path_to):
            path_to = os.path.join(path_to, os.path.basename(path_from))
        try:
            native_rename(path_from, path_to)
        except OSError, e:
            raise IOError(e.errno, str(e))
    else:
        shutil.move(path_from, path_to)


@windowspath(path_indexes=[0, 1])
def make_link(target, destination):
    """Create a link from the target in the given destination."""
    # append the correct file type
    if not destination.endswith(u'.lnk'):
        destination += u'.lnk'
    # ensure that the dir containing the link exists
    dirname = os.path.dirname(destination)
    if dirname != u'' and not os.path.exists(dirname):
        make_dir(dirname, recursive=True)

    # destination and target can't be literal paths nor contain
    # illegal chars.
    destination = destination.replace(LONG_PATH_PREFIX, u'')
    target = target.replace(LONG_PATH_PREFIX, u'')

    try:
        shortcut = CreateObject(shelllink.ShellLink)
        shortcut.SetPath(target)
        shortcut.SetWorkingDirectory(target)
        pf = shortcut.QueryInterface(IPersistFile)
        pf.Save(destination, True)
    except:
        logger.exception('make_link could not be completed for target %r, '
                         'destination %r:', target, destination)
        raise


@assert_output_path_is_syncdaemon
@windowspath()
def read_link(path):
    """Read the destination of a link."""
    # THIS SHOULD BE FIXED IN ORDER TO SUPPORT THE PROPER API
    # The workaround to support unicode paths was to use: WorkingDirectory,
    # because TargetPath or anything related was returning malformed paths.
    # The bug associated to this issue is: #907336
    # https://bugs.launchpad.net/ubuntuone-client/+bug/907336
    if not path.endswith(u'.lnk'):
        path += u'.lnk'
    shortcut = CreateObject(shelllink.ShellLink)
    pf = shortcut.QueryInterface(IPersistFile)
    pf.Load(path, True)
    target_path = shortcut.GetWorkingDirectory().encode('utf-8')
    target_path = target_path.decode('utf-8')
    result = get_syncdaemon_valid_path(LONG_PATH_PREFIX + target_path)
    return result


@windowspath()
def is_link(path):
    """Returns if a path is a link or not."""
    return native_is_link(path)


def native_is_link(path):
    """Check if a file is a link, using native paths."""
    if not path.endswith('.lnk'):
        path += '.lnk'
    return os.path.exists(path)


def native_is_system_path(path):
    """Return if the path has the sys attr."""
    attrs = GetFileAttributesW(path)
    if attrs == INVALID_FILE_ATTRIBUTES:
        return False
    return FILE_ATTRIBUTE_SYSTEM & attrs == FILE_ATTRIBUTE_SYSTEM


@windowspath()
def remove_link(path):
    """Removes a link."""
    if not path.endswith('.lnk'):
        path += '.lnk'
    if os.path.exists(path):
        os.unlink(path)


@windowspath()
def listdir(directory):
    """List a directory."""

    # The main reason why we have to append os.path.sep is the following:
    #
    # os.listdir implementation will append a unix path separator to the
    # path used for listdir, for example if we do:
    # os.litdir('C:\\Python27')
    # the path would be:
    # 'C:\\Python27/*.*'
    # the above does not generate any problems, unfortunatly the same cannot
    # be said when using literal paths, that is, paths starting with '\\?\'.
    # So, while the above works (and returns a consistent error if the path
    # does not exist), the following fails:
    # os.listdir('\\\\?\\C:\\Python27')
    # with the following exception:
    # WindowsError: [Error 123] The filename, directory name, or volume
    # label syntax is incorrect: '\\\\?\\C:\\Python27/*.*'
    # which gets fixed if os.path.sep is added, that is, if we use:
    # os.listdir('\\\\?\\C:\\Python27\\')
    if not directory.endswith(os.path.sep):
        directory += os.path.sep

    # On top of the above we have the issue in which python os.listdir does
    # return those paths that are system paths. Those paths are the ones that
    # we do not want to work with.

    return map(
        _unicode_to_bytes,
        [p for p in os.listdir(directory)
         if not native_is_system_path(os.path.join(directory, p))])


@windowspath()
def walk(path, topdown=True):
    """Walk a path.

    'path' should be a valid syncdaemon path, and the results are also valid
    syncdaemon paths.

    Use this function instead os.walk since this implementation transforms path
    so the windows literal prefix is added, and invalid characters are properly
    handled.

    """
    # Interestingly, while os.listdir DOES return the system folders, os.walk
    # does not. Nevertheless lets filter the same way in here so that if python
    # os.walk changes at some point, we do the same in BOTH methods.
    for dirpath, dirnames, filenames in os.walk(path, topdown):
        dirpath = _unicode_to_bytes(dirpath.replace(LONG_PATH_PREFIX, u''))
        if native_is_system_path(dirpath):
            continue
        dirnames = map(
            _unicode_to_bytes,
            [p for p in dirnames
             if not native_is_system_path(os.path.join(dirpath, p))])
        filenames = map(
            _unicode_to_bytes,
            [p for p in filenames
             if not native_is_system_path(os.path.join(dirpath, p))])
        yield dirpath, dirnames, filenames


@windowspath()
def access(path):
    """Return if the path is at least readable."""
    # lets consider the access on an illegal path to be a special case
    # since that will only occur in the case where the user created the path
    # for a file to be readable it has to be readable either by the user or
    # by the everyone group
    # XXX: ENOPARSE ^ (nessita)
    if not os.path.exists(path):
        return False
    security_descriptor = GetFileSecurity(path, DACL_SECURITY_INFORMATION)
    dacl = security_descriptor.GetSecurityDescriptorDacl()
    sids = []
    for index in range(0, dacl.GetAceCount()):
        # add the sid of the ace if it can read to test that we remove
        # the r bitmask and test if the bitmask is the same, if not, it means
        # we could read and removed it.
        ace = dacl.GetAce(index)
        if _has_read_mask(ace[1]):
            sids.append(ace[2])
    return (
        (USER_SID in sids or EVERYONE_SID in sids) and os.access(path, os.R_OK)
    )


@windowspath()
def can_write(path):
    """Return if the path is at least readable."""
    # lets consider the access on an illegal path to be a special case
    # since that will only occur in the case where the user created the path
    # for a file to be readable it has to be readable either by the user or
    # by the everyone group
    # XXX: ENOPARSE ^ (nessita)
    if not os.path.exists(path):
        return False
    security_descriptor = GetFileSecurity(path, DACL_SECURITY_INFORMATION)
    dacl = security_descriptor.GetSecurityDescriptorDacl()
    sids = []
    for index in range(0, dacl.GetAceCount()):
        # add the sid of the ace if it can read to test that we remove
        # the r bitmask and test if the bitmask is the same, if not, it means
        # we could read and removed it.
        ace = dacl.GetAce(index)
        if _has_read_mask(ace[1]):
            sids.append(ace[2])
    return (
        (USER_SID in sids or EVERYONE_SID in sids) and os.access(path, os.R_OK)
    )


@windowspath()
def stat_path(path, look_for_link=True):
    """Return stat info about a path."""
    # if the path end with .lnk, that means we are dealing with a link
    # and we should return the stat of the target path
    if path.endswith('.lnk'):
        shell_script = Dispatch('WScript.Shell')
        shortcut = shell_script.CreateShortCut(path)
        path = shortcut.Targetpath
    if look_for_link and os.path.exists(path + '.lnk'):
        return stat_path(path + '.lnk')

    return os.lstat(path)


@windowspath()
def move_to_trash(path):
    """Move the file or dir to trash.

    If had any error, or the system can't do it, just remove it.
    """
    # lets check if the file exists, if not raise an exception
    if not os.path.exists(path):
        raise OSError(errno.ENOENT, 'File could %r not be found.' % path)

    # the shell code does not know how to deal with long paths, lets
    # try to move it to the trash if it is short enough, else we remove it
    no_prefix_path = path.replace(LONG_PATH_PREFIX, u'')
    flags = (shellcon.FOF_ALLOWUNDO | shellcon.FOF_NOCONFIRMATION |
             shellcon.FOF_NOERRORUI | shellcon.FOF_SILENT)
    result = shell.SHFileOperation((0, shellcon.FO_DELETE,
                                    no_prefix_path, None, flags))

    # from http://msdn.microsoft.com/en-us/library/bb762164%28v=vs.85%29.aspx:

    # Returns zero if successful; otherwise nonzero. Applications normally
    # should simply check for zero or nonzero.
    # It is good practice to examine the value of the fAnyOperationsAborted
    # member of the SHFILEOPSTRUCT. SHFileOperation can return 0 for success if
    # the user cancels the operation. If you do not check fAnyOperationsAborted
    # as well as the return value, you cannot know that the function
    # accomplished the full task you asked of it and you might proceed
    # under incorrect assumptions.

    code, aborted = result
    if code != 0 or aborted:
        logger.error('Got error %r when trying to move_to_trash path %r '
                     '(removing anyways).', result, path)
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)


def set_application_name(app_name):
    """Set the app name."""
    # there is not way to do this on windows. The name will be correct when
    # executed from a bundle .exe otherwise it will be python


def is_root():
    """Return if the user is running as root."""
    # Always return False. Trying to be smart about OS versions and
    # only calling Windows APIs under certain conditions has still
    # proven not to work in some cases. Overall it should not matter
    # if we know whether we are Administrator or not on Windows.
    return False


@windowspath()
def get_path_list(path):
    """Return a list with the diff components of the path."""
    # The LONG_PATH_PREFIX should always be present since we use the
    # windowspath decorator.
    path = path.replace(LONG_PATH_PREFIX, u'')
    drive, path = os.path.splitdrive(path)
    # ensure that we do not return the windows unicode chars
    path = _unicode_to_bytes(path)
    result = [LONG_PATH_PREFIX + drive]
    result.extend(path.split(os.path.sep))
    return result


@assert_output_path_is_syncdaemon
@windowspath()
def normpath(path):
    """Normalize path, eliminating double slashes, etc."""
    # The LONG_PATH_PREFIX should always be present since we use the
    # windowspath decorator. We remove it since the system's normpath does not
    # process literal paths.
    path = path.replace(LONG_PATH_PREFIX, u'')
    result = LONG_PATH_PREFIX + os.path.normpath(path)
    result = get_syncdaemon_valid_path(result)
    return result
