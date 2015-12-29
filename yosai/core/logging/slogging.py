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

from logging import config


from yosai.core.logging.formatters import (
    JSONFormatter,
)


def load_logconfig():

    default_logging = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'print_format': {
                'format': "%(asctime)s\t%(levelname)s:%(name)s\t%(message)s",
            },
            'json_format': {
                '()': JSONFormatter
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout',
                'formatter': 'print_format'},

            'debug_file_handler': {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': 'DEBUG',
                'filename': '/var/log/yosai/debug.log',
                'formatter': 'json_format',
                'maxBytes': 10485760,
                'backupCount': 20,
                'encoding': 'utf8'},

            'info_file_handler': {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': 'INFO',
                'filename': '/var/log/yosai/info.log',
                'formatter': 'json_format',
                'maxBytes': 10485760,
                'backupCount': 20,
                'encoding': 'utf8'},

            'error_file_handler': {
                'class': 'logging.handlers.RotatingFileHandler',
                'level': 'ERROR',
                'filename': '/var/log/yosai/errors.log',
                'formatter': 'json_format',
                'maxBytes': 10485760,
                'backupCount': 20,
                'encoding': 'utf8'}
        },
        'loggers': {
            'yosai_logger': {
                'level': 'DEBUG',
                'handlers': ['console'],
                'propagate': False
            }
        },
        'root': {
            'level': 'DEBUG',
            'handlers': ['console', 'debug_file_handler', 'info_file_handler',
                         'error_file_handler']
        }
    }

    config.dictConfig(default_logging)
