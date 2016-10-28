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

from pubsub import pub as event_bus

EVENT_TOPIC = event_bus.AUTO_TOPIC

logger = logging.getLogger(__name__)


class EventLogger:

    def __init__(self, eventbus):
        eventbus.subscribe(self.log_session_event, 'SESSION.START')
        eventbus.subscribe(self.log_session_event, 'SESSION.STOP')
        eventbus.subscribe(self.log_session_event, 'SESSION.EXPIRE')

        eventbus.subscribe(self.log_authc_event, 'AUTHENTICATION.ACCOUNT_NOT_FOUND')
        eventbus.subscribe(self.log_authc_event, 'AUTHENTICATION.PROGRESS')
        eventbus.subscribe(self.log_authc_event, 'AUTHENTICATION.SUCCEEDED')

        eventbus.subscribe(self.log_authc_event, 'AUTHENTICATION.FAILED')
        eventbus.subscribe(self.log_authz_event, 'AUTHORIZATION.GRANTED')
        eventbus.subscribe(self.log_authz_event, 'AUTHORIZATION.DENIED')
        eventbus.subscribe(self.log_authz_event, 'AUTHORIZATION.RESULTS')

    def log_authc_event(self, identifier=None, topic=EVENT_TOPIC):
        logger.info(topic.getName(), extra={'identifier': identifier})

    def log_session_event(self, items=None, topic=EVENT_TOPIC):
        try:
            identifier = items.identifiers.primary_identifier
        except AttributeError:
            identifier = None
        logger.info(topic.getName(), extra={'identifier': identifier,
                                            'session_id': items.session_id})

    def log_authz_event(self, identifiers=None, items=None, logical_operator=None,
                        topic=EVENT_TOPIC):

        idents = identifiers.__getstate__()
        log_op = logical_operator.__class__.__name__

        logger.info(topic.getName(), extra={'identifiers': idents,
                                            'items': items,
                                            'logical_operator': log_op})
