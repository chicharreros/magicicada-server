# Copyright 2008-2015 Canonical
# Copyright 2015-2016 Chicharreros (https://launchpad.net/~chicharreros)
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

DJANGO_SETTINGS_MODULE ?= magicicada.settings
FLAKE8 = flake8
PYTHON = python
SRC_DIR = $(CURDIR)/magicicada
LIB_DIR = $(CURDIR)/lib
ENV = $(CURDIR)/env
PYTHONPATH := $(SRC_DIR):$(LIB_DIR):$(CURDIR):$(PYTHONPATH)
DJANGO_ADMIN = $(LIB_DIR)/django/bin/django-admin.py
DJANGO_MANAGE = $(PYTHON) manage.py

MAKEFLAGS:=$(MAKEFLAGS) --no-print-directory
# use protobuf cpp
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=cpp
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION_VERSION=2

START_SUPERVISORD = lib/ubuntuone/supervisor/start-supervisord.py

export PYTHONPATH
export DJANGO_SETTINGS_MODULE
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION
export PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION_VERSION
export ROOTDIR ?= $(CURDIR)

SOURCEDEPS_TAG = .sourcecode/sourcedeps-tag
SOURCEDEPS_DIR ?= ../sourcedeps
SOURCEDEPS_SOURCECODE_DIR = $(SOURCEDEPS_DIR)/sourcecode
TARGET_SOURCECODE_DIR = $(CURDIR)/.sourcecode

BUILD_DEPLOY_SOURCEDEPS=storm zope.interface ubuntuone-storage-protocol

TESTFLAGS=

TAR_EXTRA = --exclude 'tmp/*' --exclude tags

ifneq ($(strip $(STRIP_BZR)),)
TAR_EXTRA += --exclude .bzr
endif

include Makefile.db

sourcedeps: $(SOURCEDEPS_TAG)

clean-sourcedeps:
	rm -rf .sourcecode/*

$(SOURCEDEPS_TAG):
ifndef EXPORT_FROM_BZR
	$(MAKE) link-sourcedeps
endif
	$(MAKE) build-sourcedeps
	touch $(SOURCEDEPS_TAG)

build: link-sourcedeps build-sourcedeps version

link-sourcedeps:
	@echo "Checking out external source dependencies..."
	build/link-external-sourcecode \
		-p $(SOURCEDEPS_SOURCECODE_DIR)/ \
		-t $(TARGET_SOURCECODE_DIR) \
		-c build/config-manager.txt

# no need to link sourcedeps before building them, as rollout process
# handles config-manager.txt automatically
build-for-deployment: build-deploy-sourcedeps version

build-sourcedeps: build-deploy-sourcedeps
	@echo "Building client clientdefs.py"
	@cd .sourcecode/ubuntuone-client/ubuntuone/ && sed \
		-e 's|\@localedir\@|/usr/local/share/locale|g' \
		-e 's|\@libexecdir\@|/usr/local/libexec|g' \
		-e 's|\@GETTEXT_PACKAGE\@|ubuntuone-client|g' \
		-e 's|\@VERSION\@|0.0.0|g' < clientdefs.py.in > clientdefs.py

build-deploy-sourcedeps:
	@echo "Building Python extensions"

	@for sourcedep in $(BUILD_DEPLOY_SOURCEDEPS) ; do \
            d=".sourcecode/$$sourcedep" ; \
            if test -e "$$d/setup.py" ; then \
	        (cd "$$d" && $(PYTHON) \
	        setup.py build build_ext --inplace > /dev/null) ; \
            fi ; \
	done

	@echo "Generating twistd plugin cache"
	@$(PYTHON) -c "from twisted.plugin import IPlugin, getPlugins; list(getPlugins(IPlugin));"

tarball: build-for-deployment
	tar czf ../filesync-server.tgz $(TAR_EXTRA) .

bootstrap:
	cat dependencies.txt | sudo xargs apt-get install -y --no-install-recommends
	cat dependencies-devel.txt | sudo xargs apt-get install -y --no-install-recommends

raw-test:
	./test $(TESTFLAGS)

test: lint sourcedeps clean version start-base start-dbus raw-test stop

ci-test:
	$(MAKE) test TESTFLAGS="-1 $(TESTFLAGS)"

clean:
	rm -rf tmp/* _trial_temp

lint:
	virtualenv $(ENV)
	$(ENV)/bin/pip install flake8 rst2html5
	$(ENV)/bin/flake8 --filename='*.py' --exclude='migrations' $(SRC_DIR)
	dev-scripts/check_readme.sh

version:
	bzr version-info --format=python > lib/versioninfo.py || true

start: build start-base start-filesync-dummy-group load-sample-data publish-api-port

start-oauth: build start-base start-filesync-oauth-group load-sample-data publish-api-port

start-oauth-heapy:
	USE_HEAPY=1 $(MAKE) start-oauth

start-base:
	$(MAKE) start-db && $(MAKE) start-supervisor && $(MAKE) start-dbus || ( $(MAKE) stop ; exit 1 )

stop: stop-filesync-dummy-group stop-supervisor stop-db stop-dbus

start-dbus:
	dev-scripts/start-dbus.sh

stop-dbus:
	dev-scripts/stop-dbus.sh

start-supervisor:
	@python dev-scripts/supervisor-config-dev.py
	-@$(START_SUPERVISORD) dev-scripts/supervisor-dev.conf.tpl \

stop-supervisor:
	-@dev-scripts/supervisorctl-dev shutdown

start-%-group:
	-@dev-scripts/supervisorctl-dev start $*:

stop-%-group:
	-@dev-scripts/supervisorctl-dev stop $*:

start-%:
	-@dev-scripts/supervisorctl-dev start $*

stop-%:
	-@dev-scripts/supervisorctl-dev stop $*

publish-api-port:
	python -c 'from magicicada import settings; print >> file("tmp/filesyncserver.port", "w"), settings.api_server.TCP_PORT'
	python -c 'from magicicada import settings; print >> file("tmp/filesyncserver.port.ssl", "w"), settings.ssl_proxy.PORT'
	python -c 'from magicicada import settings; print >> file("tmp/filesyncserver-status.port", "w"), settings.api_server.STATUS_PORT'

load-sample-data:
	DJANGO_SETTINGS_MODULE=$(DJANGO_SETTINGS_MODULE) $(PYTHON) dev-scripts/load_sample_data.py

shell:
	$(DJANGO_MANAGE) shell

manage:
	$(DJANGO_MANAGE) $(ARGS)

admin:
	$(DJANGO_ADMIN) $(ARGS)

.PHONY: sourcedeps link-sourcedeps build-sourcedeps build-deploy-sourcedeps \
	build clean version lint test ci-test \
	build-for-deployment clean-sourcedeps tarball \
	start stop load-sample-data publish-api-port \
	start-supervisor stop-supervisor \
	start-dbus stop-dbus start-oauth start-oauth-heapy
