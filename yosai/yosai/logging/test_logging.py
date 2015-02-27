from s_logging import LogManager
import logging


def logmanager_init():
    return LogManager().get_logger()


def test_logging(mylog):
    mylog.info('All systems operational')
    mylog.info('it works!', difficulty='easy')  


log = logging.getLogger()
print('before, hashandlers: ', log.hasHandlers())
test_logging(logmanager_init())
print('after, hashandlers: ', log.hasHandlers())


log = logging.getLogger()
print('before, hashandlers: ', log.hasHandlers())
test_logging(logmanager_init())
print('after, hashandlers: ', log.hasHandlers())
