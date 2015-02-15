import logging
import logging.config
import anyjson as json
import os
import structlog
import traceback


class LogManager(object):

    def __init__(self, json_config_path='logging.json'):
        try:
            self.load_logconfig(json_config_path)
            self.configure_structlog()
        except (AttributeError, TypeError):
            traceback.print_exc()
            raise

    def load_logconfig(self, path):
        if os.path.exists(path):
            with open(path) as conf_file:
                config = json.loads(conf_file.read())
            logging.config.dictConfig(config)
        else:
            raise AttributeError('Could not find log config file.') 

    def configure_structlog(self):
        structlog.configure(logger_factory=structlog.stdlib.LoggerFactory(),
                            wrapper_class=structlog.stdlib.BoundLogger,
                            context_class=dict,
                            cache_logger_on_first_use=True 
                            )  

    def get_logger(self, logger=None):
        return structlog.get_logger(logger)
import logging
import json
import socket
import datetime
import traceback as tb
import itertools


def _default_json_default(obj):
    """
    Coerce everything to strings.
    All objects representing time get output as ISO8601.
    """
    if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
        return obj.isoformat()
    else:
        return str(obj)


class JSONFormatter(logging.Formatter):

    def __init__(self,
                 fmt=None,
                 datefmt=None,
                 json_cls=None,
                 json_default=_default_json_default):
        """
        :param fmt: Config as a JSON string, allowed fields;
               source_host: override source host name
        :param datefmt: Date format to use (required by logging.Formatter
            interface but not used)
        :param json_cls: JSON encoder to forward to json.dumps
        :param json_default: Default JSON representation for unknown types,
                             by default coerce everything to a string
        """

        if fmt is not None:
            self._fmt = json.loads(fmt)
        else:
            self._fmt = {}
        self.json_default = json_default
        self.json_cls = json_cls
        if 'source_host' in self._fmt:
            self.source_host = self._fmt['source_host']
        else:
            try:
                self.source_host = socket.gethostname()
            except:
                self.source_host = ""
    
    def format_exception(self, ei, strip_newlines=True):
        lines = tb.format_exception(*ei)
        if strip_newlines:
            lines = [(line.rstrip().splitlines()) for line in lines]
            lines = list(itertools.chain(*lines))
        return lines

    def format(self, record):
        """
        Format a log record to JSON, if the message is a dict
        assume an empty message and use the dict as additional
        fields.
        """

        fields = record.__dict__.copy()

        if isinstance(record.msg, dict):
            fields.update(record.msg)
            fields.pop('msg')
            msg = ""
        else:
            msg = record.getMessage()

        if 'msg' in fields:
            fields.pop('msg')

        if 'exc_info' in fields:
            if fields['exc_info']:
                formatted = self.format_exception(fields['exc_info'])
                fields['exception'] = formatted
            fields.pop('exc_info')

        if 'exc_text' in fields and not fields['exc_text']:
            fields.pop('exc_text')

        logr = {} 

        logr.update({'@message': msg,
                     '@timestamp': datetime.datetime.utcnow().
                     strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                     '@source_host': self.source_host,
                     '@fields': self._build_fields(logr, fields)})

        return json.dumps(logr, default=self.json_default, cls=self.json_cls)

    def _build_fields(self, defaults, fields):
        """Return provided fields including any in defaults

        >>> f = JSONFormatter()
        # Verify that ``fields`` is used
        >>> f._build_fields({}, {'foo': 'one'}) == \
                {'foo': 'one'}
        True
        # Verify that ``@fields`` in ``defaults`` is used
        >>> f._build_fields({'@fields': {'bar': 'two'}}, {'foo': 'one'}) == \
                {'foo': 'one', 'bar': 'two'}
        True
        # Verify that ``fields`` takes precedence
        >>> f._build_fields({'@fields': {'foo': 'two'}}, {'foo': 'one'}) == \
                {'foo': 'one'}
        True
        """
        c = {}
        c.update(defaults.get('@fields', {}))
        c.update(fields.items())
        return c

