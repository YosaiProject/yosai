"""
I'm unsure as to how long I will use pypubsub for inter-application event
messaging.  So, I'm creating a proxy, EventBus, between pypubsub and 
my application, allowing me to swap out the event bus implementation later 
without impacting my core application modules.  The core application modules
know WHAT needs to be communicated with the bus but now HOW (EventBus
knows HOW).
"""

from pubsub import pub
from yosai import LogManager
import calendar
import time


class Event(object):
    """ 
    There is a standard structure for events communicated over the eventbus. 
    Yosai's Event design is a departure from Shiro's use of abstract and 
    hierarchical concrete Event classes, each of which essentially has
    the same characteristics and behavior.
    """

    def __init__(self, event_topic, event_type, source, **eventattrs):
        self.event_type = event_type  # ex:  AUTHENTICATION
        self.event_topic = event_topic  # ex:  AUTHENTICATION_FAILED
        self.source = source  # the object that emitted the event 
        self.timestamp = calendar.timegm(time.gmtime())  # UNIX timestamp
        self.__dict__.update(**eventattrs)  # DG:  risky?


class EventBus(object):
    """
    Yosai's EventBus is a proxy to pypubsub.  Its API is unique to Yosai,
    having little in common with the EventBus implementation in Shiro.
    """

    def __init__(self):
        self._event_bus = pub 

    def if_subscribed(self, listener, topic_name):
        return self._event_bus.ifSubscribed(listener, topic_name)

    def publish(self, topic_name, **kwargs):
        self._event_bus.sendMessage(topic_name, **kwargs) 

    def subscribe(self, _callable, topic_name):
        subscribed_listener = None
        success = None

        subscribed_listener, success =\
            self._event_bus.subscribe(_callable, topic_name)

        return subscribed_listener, success

    def unsubscribe(self, listener, topic_name):
        unsubscribed_listener = self._event_bus.unsubscribe(
            listener, topic_name)
        return unsubscribed_listener
       
    def unsub_all(self):
        unsubscribed_listeners = self._event_bus.unsubAll() 
        return unsubscribed_listeners
