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
import logging
import pdb

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


def log_event(topicObj=pub.AUTO_TOPIC, **mesgData):
    """
    ordered by the likelihood of occuring:
    1) Authorization related
    2) Session related
    3) Authentication related
    """
    try:
        # tests whether its a tuple (authz results)
        serialized = [(item.serialize(), check) for (item, check)
                      in mesgData['items']]

        logger.info(topicObj.getName(), extra={'items': serialized})

    except Exception:
        try:
            # test whether its a named tuple  (session or authc)
            idents = mesgData['items'].identifiers.serialize()
            logger.info(topicObj.getName(), extra={'identifiers': idents})

        except Exception:
            logger.info(topicObj.getName(), extra={'payload': mesgData})


pub.subscribe(log_event, pub.ALL_TOPICS)

event_bus = DefaultEventBus()  # pseudo-singleton
