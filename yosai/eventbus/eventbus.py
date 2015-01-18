"""
I'm unsure as to how long I will use pypubsub for inter-application event
messaging.  So, I'm creating a proxy, EventBus, between pypubsub and 
my application, allowing me to swap out the event bus implementation later 
without impacting my core application modules.  The core application modules
know WHAT needs to be communicated with the bus but now HOW (EventBus
knows HOW).
"""

from pubsub import pub


class EventBus(object):

    def __init__(self):
        self._event_bus = pub 

    def if_subscribed(self, listener, topic_name):
        try:
            check = self._event_bus.ifSubscribed(listener, topic_name)
        except:
            raise
        finally:
            return bool(check)

    def send_message(self, topic_name, **kwargs):
        try:
            self._event_bus.sendMessage(topic_name, **kwargs) 
        except:
            raise

    def subscribe(self, _callable, topic_name):
        subscribed_listener = None
        success = None

        try:
            subscribed_listener, success =\
                self._event_bus.subscribe(_callable, topic_name)
        except:
            raise

        finally:
            return subscribed_listener, success

    def unsubscribe(self, listener, topic_name):
        try:
            unsubscribed_listener = self._event_bus.unsubscribe(
                listener, topic_name)
        except:
            raise
        finally:
            return unsubscribed_listener
       
    def unsub_all(self):
        try:
            unsubscribed_listeners = self._event_bus.unsubAll() 
        except:
            raise
        finally:
            return unsubscribed_listeners
