from yosai import settings, LogManager


def initialize_yosai():
    log_path = settings.LOGGING_CONFIG_PATH
    logger = LogManager(log_path).get_logger()
    logger.info('Yosai Initialized')

