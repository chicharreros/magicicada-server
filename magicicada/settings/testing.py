# flake8: noqa

from magicicada.settings import *

LOGGING['handlers']['server']['filename'] = os.path.join(
    LOG_FOLDER, 'filesync-server-tests.log')
STORAGE_BASEDIR = os.path.join(BASE_DIR, 'tmp', 'filestorage-tests')
