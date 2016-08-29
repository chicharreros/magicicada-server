# flake8: noqa

from magicicada.settings import *

LOGGING['handlers']['server']['filename'] = os.path.join(
    LOG_FOLDER, 'filesync-server-tests.log')
