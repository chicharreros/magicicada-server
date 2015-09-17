# -*- python -*-

# Copyright 2008-2015 Canonical
# Copyright 2015 Chicharreros (https://launchpad.net/~chicharreros)
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

import os

from magicicada import settings
from twisted.application import service
from twisted.internet import reactor

import oops_timeline

from ubuntuone.storage.server import server, auth

oops_config = server.configure_oops()
# Should probably be an option to configure_oops?
oops_timeline.install_hooks(oops_config)


s3_host = settings.aws.S3_HOST
s3_ssl = settings.aws.S3_USE_SSL

# if neither env nor config has it, we try the port file
if s3_ssl:
    s3_port = os.getenv('S4SSLPORT', settings.aws.S3_PORT)
    if s3_port:
        s3_port = int(s3_port)
else:
    s3_port = os.getenv('S4PORT', settings.aws.S3_PORT)
    if s3_port:
        s3_port = int(s3_port)

s3_key = os.environ.get('S3_KEY', settings.aws.ACCESS_KEY_ID)
s3_secret = os.environ.get('S3_SECRET', settings.aws.SECRET_ACCESS_KEY)

application = service.Application('StorageServer')
storage = server.create_service(s3_host, s3_port, s3_ssl, s3_key, s3_secret,
                                s3_proxy_host=settings.aws.S3_PROXY_HOST,
                                s3_proxy_port=settings.aws.S3_PROXY_PORT,
                                auth_provider_class=auth.SimpleAuthProvider,
                                oops_config=oops_config)
storage.setServiceParent(service.IServiceCollection(application))
