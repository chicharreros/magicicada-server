#!/usr/bin/python
#
# Copyright 2013 Canonical Ltd.
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
"""Setup.py: build, distribute, clean."""

import os
import sys

try:
    from DistUtilsExtra.command import build_extra, build_i18n
    import DistUtilsExtra.auto
except ImportError:
    print >> sys.stderr, 'To build this program you need '\
                         'https://launchpad.net/python-distutils-extra'
    raise
assert DistUtilsExtra.auto.__version__ >= '2.18', \
    'needs DistUtilsExtra.auto >= 2.18'


PROJECT_NAME = 'magicicada-client'
VERSION = '1.0'

POT_FILE = 'po/%s.pot' % PROJECT_NAME
SERVICE_FILES = ['data/com.ubuntuone.Credentials.service',
                 'data/com.ubuntuone.SyncDaemon.service']
CONFIG_FILES = ['data/logging.conf']
CLIENTDEFS = 'ubuntuone/clientdefs.py'

BUILD_FILES = [CLIENTDEFS] + CONFIG_FILES
CLEANFILES = [POT_FILE, 'MANIFEST'] + BUILD_FILES + SERVICE_FILES

if int(VERSION.split('.')[1]) % 2 != 0:
    LOG_LEVEL = 'DEBUG'
    LOG_FILE_SIZE = '10485760'
else:
    LOG_LEVEL = 'INFO'
    LOG_FILE_SIZE = '1048576'


def replace_variables(files_to_replace, prefix=None, *args, **kwargs):
    """Replace the @VERSION@ in the constants file with the actual version."""
    for fname in files_to_replace:
        with open(fname + '.in') as in_file:
            content = in_file.read()
            with open(fname, 'w') as out_file:
                content = content.replace('@VERSION@', VERSION)
                content = content.replace('@PROJECT_NAME@', PROJECT_NAME)
                content = content.replace('@GETTEXT_PACKAGE@', PROJECT_NAME)
                content = content.replace('@LOG_LEVEL@', LOG_LEVEL)
                content = content.replace('@LOG_FILE_SIZE@', LOG_FILE_SIZE)
                if prefix is not None:
                    content = content.replace(
                        '@localedir@', os.path.join(prefix,
                                                    'share', 'locale'))
                    content = content.replace(
                        '@libexecdir@', os.path.join(prefix,
                                                     'lib', PROJECT_NAME))
                out_file.write(content)


class Install(DistUtilsExtra.auto.install_auto):
    """Class to install proper files."""

    def run(self):
        """Do the install.

        Read from *.service.in and generate .service files by replacing
        @prefix@ by self.prefix.

        """

        # Remove the contrib and tests packages from the packages list
        # as they are not meant to be installed to the system.
        pkgs = [x for x in self.distribution.packages if not (
            x.startswith('contrib') or x.startswith('tests'))]
        self.distribution.packages = pkgs

        # Remove the input and dev files from the data files list,
        # as they are not meant to be installed.
        data_files = [x for x in self.distribution.data_files if not (
            x[1][0].endswith('.in') or x[1][0].endswith('-dev.conf'))]
        self.distribution.data_files = data_files

        # Get just the prefix value, without the root
        prefix = self.install_data.replace(
            self.root if self.root is not None else '', '')
        replace_variables(SERVICE_FILES, prefix)
        DistUtilsExtra.auto.install_auto.run(self)
        # Replace the CLIENTDEFS paths here, so that we can do it directly in
        # the installed copy, rather than the lcoal copy. This allows us to
        # have a semi-generated version for use in tests, and a full version
        # for use in installed systems.
        with open(CLIENTDEFS) as in_file:
            content = in_file.read()
            with open(os.path.join(self.install_purelib,
                                   PROJECT_NAME,
                                   CLIENTDEFS), 'w') as out_file:
                content = content.replace(
                    '@localedir@', os.path.join(prefix, 'share', 'locale'))
                content = content.replace(
                    '@libexecdir@', os.path.join(prefix, 'lib', PROJECT_NAME))
                out_file.write(content)


class Build(build_extra.build_extra):
    """Build PyQt (.ui) files and resources."""

    description = "build PyQt GUIs (.ui) and resources (.qrc)"

    def run(self):
        """Execute the command."""
        replace_variables(BUILD_FILES)
        build_extra.build_extra.run(self)


class Clean(DistUtilsExtra.auto.clean_build_tree):
    """Class to clean up after the build."""

    def run(self):
        """Clean up the built files."""
        for built_file in CLEANFILES:
            if os.path.exists(built_file):
                os.unlink(built_file)

        DistUtilsExtra.auto.clean_build_tree.run(self)


class BuildLocale(build_i18n.build_i18n):
    """Work around a bug in DistUtilsExtra."""

    def run(self):
        """Magic."""
        build_i18n.build_i18n.run(self)
        i = 0
        for df in self.distribution.data_files:
            if df[0].startswith('etc/xdg/'):
                if sys.platform not in ('darwin', 'win32'):
                    new_df = (df[0].replace('etc/xdg/', '/etc/xdg/'), df[1])
                    self.distribution.data_files[i] = new_df
                else:
                    self.distribution.data_files.pop(i)
            i += 1


def set_py2exe_paths():
    """Set the path so that py2exe finds the required modules."""
    # Pylint does not understand same spaced imports
    import win32com
    try:
        import py2exe.mf as modulefinder
    except ImportError:
        import modulefinder

    # py2exe 0.6.4 introduced a replacement modulefinder.
    # This means we have to add package paths there,
    # not to the built-in one.  If this new modulefinder gets
    # integrated into Python, then we might be able to revert
    # this some day. If this doesn't work, try import modulefinder
    for package_path in win32com.__path__[1:]:
        modulefinder.AddPackagePath("win32com", package_path)
    for extra_mod in ["win32com.server", "win32com.client"]:
        __import__(extra_mod)
        module = sys.modules[extra_mod]
        for module_path in module.__path__[1:]:
            modulefinder.AddPackagePath(extra_mod, module_path)


cmdclass = {
    'install': Install,
    'build': Build,
    'clean': Clean,
    'build_i18n': BuildLocale,
}

bin_scripts = [
    'bin/u1sdtool',
    'bin/ubuntuone-launch',
]

libexec_scripts = [
    'bin/ubuntuone-proxy-tunnel',
    'bin/ubuntuone-syncdaemon',
]

data_files = []
scripts = []

if sys.platform == 'win32':
    set_py2exe_paths()
    extra = {
        'options': {
            'py2exe': {
                'bundle_files': 1,
                'skip_archive': 0,
                'optimize': 1,
                'dll_excludes': ["mswsock.dll", "powrprof.dll"],
            },
        },
        # add the console script so that py2exe compiles it
        'console': bin_scripts + libexec_scripts,
        'zipfile': None,
    }
else:
    data_files.extend([
        ('lib/%s' % PROJECT_NAME, libexec_scripts),
        ('share/dbus-1/services', SERVICE_FILES),
        ('/etc/xdg/ubuntuone', CONFIG_FILES + ['data/syncdaemon.conf']),
        ('/etc/apport/crashdb.conf.d', ['data/ubuntuone-client-crashdb.conf']),
        ('share/apport/package-hooks', ['data/source_ubuntuone-client.py']),
        ('share/man/man1', ['docs/man/u1sdtool.1']),
    ])
    scripts.extend(bin_scripts)
    extra = {}

DistUtilsExtra.auto.setup(
    name=PROJECT_NAME,
    version=VERSION,
    license='GPL v3',
    author='Chicharreros',
    author_email='magicicada-hackers@@lists.launchpad.net',
    description='Magicicada file synchronization client',
    url='https://launchpad.net/%s' % PROJECT_NAME,
    extra_path=PROJECT_NAME,
    scripts=scripts,
    data_files=data_files,
    cmdclass=cmdclass,
    **extra)
