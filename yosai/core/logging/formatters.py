import traceback
import rapidjson
import itertools

import logging
import pytz
from datetime import datetime


BUILTIN_ATTRS = {
    'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
    'funcName', 'levelname', 'levelno', 'lineno', 'module', 'msecs',
    'message', 'msg', 'name', 'pathname', 'process', 'processName',
    'relativeCreated', 'stack_info', 'thread', 'threadName'}


class JSONFormatter(logging.Formatter):

    def formatException(self, ei):
        raw_lines = traceback.format_exception(*ei)
        filtered_lines = [filter(lambda x: x, line.strip().splitlines())
                          for line in raw_lines]
        return '|'.join(list(itertools.chain(*filtered_lines)))

    def format(self, record):
        message = record.getMessage()

        traceback = None
        if record.exc_info:
            traceback = self.formatException(record.exc_info)

        extra = self.extra_from_record(record)
        json_record = self.json_record(message, extra, record, traceback)
        self.mutate_json_record(json_record)
        return rapidjson.dumps(json_record)

    def extra_from_record(self, record):
        """Returns `extra` dict you passed to logger.

        The `extra` keyword argument is used to populate the `__dict__` of
        the `LogRecord`.

        """
        return {
            attr_name: record.__dict__[attr_name]
            for attr_name in record.__dict__
            if attr_name not in BUILTIN_ATTRS
        }

    def json_record(self, message, extra, record, traceback):
        """Prepares a JSON payload which will be logged.

        Override this method to change JSON log format.

        :param message: Log message, e.g., `logger.info(msg='Sign up')`.
        :param extra: Dictionary that was passed as `extra` param
            `logger.info('Sign up', extra={'referral_code': '52d6ce'})`.
        :param record: `LogRecord` we got from `JSONFormatter.format()`.
        :return: Dictionary which will be passed to JSON lib.

        """
        extra['message'] = message
        if 'time' not in extra:
            extra['time'] = datetime.now(pytz.utc)
        if traceback is not None:
            extra['traceback'] = traceback
        return extra

    def mutate_json_record(self, json_record):
        """Override it to convert fields of `json_record` to needed types.

        Default implementation converts `datetime` to string in ISO8601 format.

        """
        for attr_name in json_record:
            attr = json_record[attr_name]
            if isinstance(attr, datetime):
                json_record[attr_name] = attr.isoformat()
