# flake8: noqa

from magicicada.settings import *

for logger_name, logger_config in LOGGING['loggers'].items():
    if logger_name.startswith('magicicada'):
        logger_config['level'] = 'TRACE'

STORAGE_BASEDIR = os.path.join(BASE_DIR, 'tmp', 'filestorage-tests')
