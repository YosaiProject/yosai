from yosai import (
    IAccount,
)

class MockAccount(IAccount):

    def __init__(self, account_id, credentials={}, attributes={}):
        self._id = account_id
        self._credentials = credentials
        self._attributes = attributes
        
    @property 
    def id(self):
        return self._id 

    @property 
    def credentials(self):
        return self._credentials 

    @property 
    def attributes(self):
        return self._attributes 

    def __repr__(self):
        return "<MockAccount(id={0})>".format(self._id)


class MockEventBus(object):

    def if_subscribed(self, listener, topic_name):
        return True 

    def publish(self, topic_name, **kwargs):
        pass 

    def subscribe(self, _callable, topic_name):
        return _callable, True

    def unsubscribe(self, listener, topic_name):
        pass

    def unsub_all(self):
        pass

    def __repr__(self):
        return "<MockEventBus()>"
