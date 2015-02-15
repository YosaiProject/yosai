from s_logging import LogManager


def logmanager_init():
    return LogManager().get_logger()


def test_logging(mylog):
    mylog.info('All systems operational')
    mylog.info('it works!', difficulty='easy')  


test_logging(logmanager_init())
