from magicicada.settings import *  # noqa

LOGGING['handlers']['server']['filename'] = os.path.join(
    LOG_FOLDER, 'filesync-server-tests.log')
