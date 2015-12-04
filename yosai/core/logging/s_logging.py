"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

import logging
import logging.config
import rapidjson 
import os
import structlog
import socket
import datetime
import traceback as tb
import itertools
from yosai.core import settings 

"""
s_logging as in STRUCTURED LOGGING
"""


class LogManager():

    def __init__(self):
        log = logging.getLogger()
        if (not log.hasHandlers()):  # validates whether configured
            print('Configuring Logging..')
            try:
                self.load_logconfig()
                self.configure_structlog()
            except (AttributeError, TypeError):
                tb.print_exc()
                raise

    def load_logconfig(self):
        config = settings.LOGGING_CONFIG

        if (config):
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


class JSONFormatter(logging.Formatter):

    def __init__(self,
                 fmt=None,
                 datefmt=None,
                 json_cls=None,
                 json_default=None):
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
            self._fmt = rapidjson.loads(fmt)
        else:
            self._fmt = {}

        self.json_default = json_default if json_default\
            else self._default_json_default()

        self.json_cls = json_cls
        if 'source_host' in self._fmt:
            self.source_host = self._fmt['source_host']
        else:
            try:
                self.source_host = socket.gethostname()
            except:
                self.source_host = ""

    def _default_json_default(obj):
        """
        Coerce everything to strings.
        All objects representing time get output as ISO8601.
        """
        if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
            return obj.isoformat()
        else:
            return str(obj)
    
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

        return rapidjson.dumps(logr, default=self.json_default, cls=self.json_cls)

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

