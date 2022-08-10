# Copyright 2015-2022 Chicharreros (https://launchpad.net/~chicharreros)
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
ENV = $(CURDIR)/.env
PYTHON = $(ENV)/bin/python
SRC_DIR = $(CURDIR)/magicicada
LIB_DIR = $(CURDIR)/lib
PATH := $(ENV)/bin:$(PATH)
PYTHONPATH := $(SRC_DIR):$(LIB_DIR):$(CURDIR):$(PYTHONPATH)
DJANGO_ADMIN = $(LIB_DIR)/django/bin/django-admin.py
DJANGO_MANAGE = $(PYTHON) manage.py

MAKEFLAGS:=$(MAKEFLAGS) --no-print-directory

START_SUPERVISORD = lib/ubuntuone/supervisor/start-supervisord.py
SUPERVISOR_CTL = $(ENV)/bin/supervisorctl

export PATH
export PYTHONPATH
export DJANGO_SETTINGS_MODULE
export ROOTDIR ?= $(CURDIR)

SOURCEDEPS_TAG = .sourcecode/sourcedeps-tag
TARGET_SOURCECODE_DIR = $(CURDIR)/.sourcecode
TESTFLAGS=

TAR_EXTRA = --exclude 'tmp/*' --exclude tags

include Makefile.db

sourcedeps: $(SOURCEDEPS_TAG)
	test -d $(TARGET_SOURCECODE_DIR)/magicicada-client || git clone --depth 1 --branch 2.0 https://github.com/chicharreros/magicicada-client.git $(TARGET_SOURCECODE_DIR)/magicicada-client

clean-sourcedeps:
	rm -rf .sourcecode/*

$(SOURCEDEPS_TAG):
	touch $(SOURCEDEPS_TAG)

build-clientdefs:
	@echo "Building client clientdefs.py"
	@cd $(TARGET_SOURCECODE_DIR)/magicicada-client/magicicadaclient/ && sed \
		-e 's|\@localedir\@|/usr/local/share/locale|g' \
		-e 's|\@libexecdir\@|/usr/local/libexec|g' \
		-e 's|\@GETTEXT_PACKAGE\@|ubuntuone-client|g' \
		-e 's|\@VERSION\@|0.0.0|g' < clientdefs.py.in > clientdefs.py

bootstrap:
	sudo apt update
	cat dependencies.txt dependencies-devel.txt | sudo xargs apt install -y --no-install-recommends
	$(MAKE) $(ENV)
	$(MAKE) sourcedeps build-clientdefs
	$(ENV)/bin/pip install -r $(TARGET_SOURCECODE_DIR)/magicicada-client/requirements.txt
	mkdir -p tmp

$(ENV): $(ENV)/bin/activate

# only runs when requirements.txt or requirements-devel.txt changes
$(ENV)/bin/activate: requirements.txt requirements-devel.txt
	test -d $(ENV) || virtualenv -p python2 $(ENV) --system-site-packages
	$(ENV)/bin/pip install -Ur requirements.txt
	$(ENV)/bin/pip install -Ur requirements-devel.txt
	touch $(ENV)/bin/activate

raw-test:
	$(PYTHON) test $(TESTFLAGS)

test: lint start-db start-base start-dbus raw-test stop

ci-test:
	$(MAKE) test TESTFLAGS="-1 $(TESTFLAGS)"

clean:
	rm -rf tmp/* _trial_temp $(ENV)

lint: $(ENV)
	$(ENV)/bin/flake8 --exclude='migrations' $(SRC_DIR)

start: $(ENV) start-base start-filesync-server-group publish-api-port

resume: start-base start-filesync-server-group

start-heapy:
	USE_HEAPY=1 $(MAKE) start

start-base:
	$(MAKE) start-supervisor && $(MAKE) start-dbus || ( $(MAKE) stop ; exit 1 )

stop: stop-supervisor stop-dbus

start-dbus:
	dev-scripts/start-dbus.sh

stop-dbus:
	dev-scripts/stop-dbus.sh

start-supervisor:
	$(PYTHON) dev-scripts/supervisor-config-dev.py
	-@$(START_SUPERVISORD) dev-scripts/supervisor-dev.conf.tpl

stop-supervisor:
	$(SUPERVISOR_CTL) -c $(CURDIR)/tmp/supervisor-dev.conf shutdown

start-%-group:
	$(SUPERVISOR_CTL) -c $(CURDIR)/tmp/supervisor-dev.conf start $*:

stop-%-group:
	$(SUPERVISOR_CTL) -c $(CURDIR)/tmp/supervisor-dev.conf stop $*:

start-%:
	$(SUPERVISOR_CTL) -c $(CURDIR)/tmp/supervisor-dev.conf start $*

stop-%:
	$(SUPERVISOR_CTL) -c $(CURDIR)/tmp/supervisor-dev.conf stop $*

publish-api-port:
	$(PYTHON) -c 'from magicicada import settings; print >> file("tmp/filesyncserver.port", "w"), settings.TCP_PORT'
	$(PYTHON) -c 'from magicicada import settings; print >> file("tmp/filesyncserver.port.ssl", "w"), settings.SSL_PORT'
	$(PYTHON) -c 'from magicicada import settings; print >> file("tmp/filesyncserver-status.port", "w"), settings.API_STATUS_PORT'

shell:
	$(DJANGO_MANAGE) shell

manage:
	$(DJANGO_MANAGE) $(ARGS)

admin:
	$(DJANGO_ADMIN) $(ARGS)

.PHONY: sourcedeps clean lint test ci-test clean-sourcedeps \
	start stop publish-api-port start-supervisor stop-supervisor \
	start-dbus stop-dbus start-heapy
