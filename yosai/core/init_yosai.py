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

from yosai import settings, LogManager
from yosai import DefaultSecurityManager, SecurityUtils, event_bus


def initialize_yosai():
    log_path = settings.LOGGING_CONFIG_PATH
    logger = LogManager(log_path).get_logger()
    configure_security_manager()
    logger.info('Yosai Initialized')


def configure_security_manager():
    """
    Unlike Shiro, which uses a configuration-file-based SecurityManagerFactory
    to initialize SecurityManager, yosai uses the following scripted function
    to initialize and inject components through construction.

    Injectable through construction
    ---------------------------------
       realms, event_bus, cache_manager, authenticator,
       authorizer, session_manager, remember_me_manager,
       subject_store, subject_factory
    """
    # permission resolver
    # account store
    # credentials cache handler
    # authorization info cache handler
    security_manager = DefaultSecurityManager(event_bus=event_bus)

    SecurityUtils.set_security_manager(security_manager)
