# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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
#
# For further info, check  http://launchpad.net/magicicada-client

ENV = $(CURDIR)/.env
PROTOCOL_DIR = $(CURDIR)/.protocol
PROTOCOL_LINK = ubuntuone/storageprotocol

deps:
	cat dependencies.txt | sudo xargs apt-get install -y --no-install-recommends
	cat dependencies-devel.txt | sudo xargs apt-get install -y --no-install-recommends

$(PROTOCOL_DIR):
	bzr branch lp:magicicada-protocol $(PROTOCOL_DIR)

$(PROTOCOL_LINK): $(PROTOCOL_DIR)
	ln -s $(PROTOCOL_DIR)/$(PROTOCOL_LINK) $(PROTOCOL_LINK)

update-protocol:
	cd $(PROTOCOL_DIR) && bzr pull && python setup.py build

bootstrap: deps $(PROTOCOL_DIR) $(PROTOCOL_LINK) update-protocol

lint:
	virtualenv $(ENV)
	$(ENV)/bin/pip install flake8
	$(ENV)/bin/flake8 --filename='*.py' --exclude='u1fsfsm.py,test_run_hello.py' ubuntuone

test: lint
	./run-tests

clean:
	rm -rf build _trial_temp $(PROTOCOL_DIR) $(PROTOCOL_LINK) $(ENV)
	find -name '*.pyc' -delete

.PHONY:
	deps update-protocol bootstrap lint test clean
