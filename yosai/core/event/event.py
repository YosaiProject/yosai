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

"""
I'm unsure as to how long I will use pypubsub for inter-application event
messaging.  So, I'm creating a proxy, EventBus, between pypubsub and
my application, allowing me to swap out the event bus implementation later
without impacting my core application modules.  The core application modules
know WHAT needs to be communicated with the bus but now HOW (EventBus
knows HOW).
"""
import pdb
import logging

from pubsub import pub

from pubsub.core import (
    ListenerMismatchError,
    SenderMissingReqdMsgDataError,
    SenderUnknownMsgDataError,
    TopicDefnError,
    TopicNameError,
)

from yosai.core import (
    EventBusTopicException,
    EventBusMessageDataException,
    EventBusSubscriptionException,
    event_abcs,
)

logger = logging.getLogger(__name__)


class DefaultEventBus(event_abcs.EventBus):
    """
    Yosai's EventBus is a proxy to pypubsub.  Its API is unique to Yosai,
    having little in common with the EventBus implementation in Shiro.

    Note:  most of the comments here are pasted from pypubsub's documentation
    """
    def __init__(self):
        self._event_bus = pub

        # The following two settings enforce topic naming convention.
        # If you want to catch topic naming exceptions, Uncomment the settings
        # and specify a source for the topic tree
        # self._event_bus.setTopicUnspecifiedFatal(True)()
        # self._event_bus.addTopicDefnProvider( kwargs_topics, pub.TOPIC_TREE_FROM_CLASS )

    def is_registered(self, listener, topic_name):
        try:
            return self._event_bus.isSubscribed(listener, topic_name)
        except TopicNameError:
            msg = "TopicNameError: Unrecognized topic naming convention"
            raise EventBusTopicException(msg)
        except TopicDefnError:
            msg = "TopicDefnError: Unregistered topic name"
            raise EventBusTopicException(msg)

    def publish(self, topic_name, **kwargs):
        """
        Sends a message to the bus

        :param topic_name: name of message topic
        :type topic_name: dotted-string or tuple
        :param kwargs: message data (must satisfy the topic’s MetadataService)
        """
        try:
            self._event_bus.sendMessage(topic_name, **kwargs)
        except SenderMissingReqdMsgDataError:
            msg = "SenderMissingReqdMsgDataError: can't send message"
            raise EventBusMessageDataException(msg)
        except SenderUnknownMsgDataError:
            msg = ("SenderUnknownMsgDataError: One of the keyword arguments "
                   "is not part of MDS")
            raise EventBusMessageDataException(msg)
        except TopicDefnError:
            msg = "TopicDefnError: Sending message to an unregistered topic name"
            raise EventBusTopicException(msg)
        return True

    def register(self, _callable, topic_name):
        """
        Subscribe listener to named topic.

        Note that if 'subscribe' notification is on, the handler's
        'notifySubscribe' method is called after subscription.

        :raises ListenerMismatchError: if listener isn’t compatible with the
                                       topic’s MDS (Metadata Service).
        :returns (pubsub.core.Listener, success): success is False if listener
                                                  is already subscribed

        """
        subscribed_listener = None
        success = None

        try:
            subscribed_listener, success =\
                self._event_bus.subscribe(_callable, topic_name)

        except ListenerMismatchError:
            msg = ("ListenerMismatchError: Invalid Listener -- callable does "
                   "not have a signature (call protocol) compatible with the "
                   "MDS of topic: {0}".format(topic_name))
            raise EventBusSubscriptionException(msg)
        except TopicDefnError:
            msg = "TopicDefnError: Unregistered topic name"
            raise EventBusTopicException(msg)
        else:  # return only if no exception raised
            return subscribed_listener, success

    def unregister(self, listener, topic_name):
        try:
            unsubscribed_listener = self._event_bus.unsubscribe(
                listener, topic_name)
        except TopicNameError:
            msg = "TopicNameError: Unrecognized eventbus topic naming convention"
            raise EventBusTopicException(msg)
        except TopicDefnError:
            msg = "TopicDefnError: Unregistered topic name"
            raise EventBusTopicException(msg)
        else:
            return unsubscribed_listener

    def unregister_all(self):
        """
        Returns the list of all listeners that were unsubscribed from the
        topic tree

        Note: this method will generate one 'unsubcribe' notification message
        for each listener unsubscribed
        """
        unsubscribed_listeners = self._event_bus.unsubAll()
        return unsubscribed_listeners


class EventLogger(event_abcs.EventBusAware):
    def __init__(self, event_bus):
        self.event_bus = event_bus

        self.event_bus.register(self.log_session_start, 'SESSION.START')
        self.event_bus.register(self.log_session_stop, 'SESSION.STOP')
        self.event_bus.register(self.log_session_expire, 'SESSION.EXPIRE')
        self.event_bus.register(self.log_authc_succeeded, 'AUTHENTICATION.SUCCEEDED')
        self.event_bus.register(self.log_authc_failed, 'AUTHENTICATION.FAILED')
        self.event_bus.register(self.log_authz_granted, 'AUTHORIZATION.GRANTED')
        self.event_bus.register(self.log_authz_denied, 'AUTHORIZATION.DENIED')
        self.event_bus.register(self.log_authz_results, 'AUTHORIZATION.RESULTS')

    @property
    def event_bus(self):
        return self._event_bus

    @event_bus.setter
    def event_bus(self, eventbus):
        self._event_bus = eventbus

    def log_authc_succeeded(self, identifiers=None):
        topic = 'AUTHENTICATION.SUCCEEDED'
        serialized = identifiers.serialize()
        logger.info(topic, extra={'identifiers': serialized})

    def log_authc_failed(self, username=None):
        topic = 'AUTHENTICATION.FAILED'
        logger.info(topic, extra={'username': username})

    def log_session_start(self, session_id=None):
        topic = 'SESSION.START'
        logger.info(topic, extra={'sessionid': session_id})

    def log_session_stop(self, items=None):
        topic = 'SESSION.STOP'
        try:
            # a session of a user who hasn't authenticated won't have idents
            idents = items.identifiers.serialize()
        except AttributeError:
            idents = None
        session_id = items.session_key.session_id
        logger.info(topic, extra={'identifiers': idents,
                                  'session_id': session_id})

    def log_session_expire(self, items=None):
        topic = 'SESSION.EXPIRE'
        try:
            # a session of a user who hasn't authenticated won't have idents
            idents = items.identifiers.serialize()
        except AttributeError:
            idents = None
        session_id = items.session_key.session_id
        logger.info(topic, extra={'identifiers': idents,
                                  'session_id': session_id})

    def log_authz_granted(self, identifiers=None, items=None, logical_operator=None):
        topic = 'AUTHORIZATION.GRANTED'

        try:
            # Permission objects are serializable
            new_items = [item.serialize() for item in items]
        except:
            # presumably roleid strings
            new_items = items

        identifiers = identifiers.serialize()
        logger.info(topic, extra={'identifiers': identifiers,
                                  'items': new_items,
                                  'logical_operator': logical_operator.__name__})

    def log_authz_denied(self, identifiers=None, items=None, logical_operator=None):
        topic = 'AUTHORIZATION.DENIED'

        try:
            # Permission objects are serializable
            new_items = [item.serialize() for item in items]
        except:
            # presumably roleid strings
            new_items = items

        identifiers = identifiers.serialize()
        logger.info(topic, extra={'identifiers': identifiers,
                                  'items': new_items,
                                  'logical_operator': logical_operator.__name__})

    def log_authz_results(self, identifiers=None, items=None):
        topic = 'AUTHORIZATION.RESULTS'
        try:
            # Permission objects are serializable
            new_items = [(item.serialize(), check) for (item, check) in items]
        except AttributeError:
            # presumably roleid strings
            new_items = items

        identifiers = identifiers.serialize()
        logger.info(topic, extra={'identifiers': identifiers,
                                  'items': new_items})



#def log_event(topicObj=pub.AUTO_TOPIC, **mesgData):
#    event_logger.log(topicObj, mesgData)

# pub.subscribe(log_event, pub.ALL_TOPICS)


event_bus = DefaultEventBus()  # pseudo-singleton

event_logger = EventLogger(event_bus)
