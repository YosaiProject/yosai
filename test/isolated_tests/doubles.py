from yosai.account import (
    IAccount,
)

from yosai.authc import (
    IAuthenticationToken,
)

from yosai.realm import (
    IAccountCacheHandler,
)

from yosai.account import (
    IAccountStore,
)


class MockToken(IAuthenticationToken, object):
    @property
    def principal(self):
        pass

    @property
    def credentials(self):
        pass


class MockAccountCacheHandler(IAccountCacheHandler, object):

    def __init__(self, account):
        self.account = account
   
    def get_cached_account(self, account):
        return self.account  # always returns the initialized account 


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

    def __eq__(self, other):
        try:
            result = (self._id == other._id and 
                      self.credentials == other.credentials and
                      self.attributes == other.attributes)
        except Exception:
            return False
        return result

    def __repr__(self):
        return "<MockAccount(id={0}, credentials={1}, attributes={2})>".\
            format(self.id, self.credentials, self.attributes)


class MockAccountStore(IAccountStore, object):
    
    def __init__(self, account=MockAccount(account_id='MAS123')):
        self.account = account

    def get_account(self, authc_token):
        return self.account  # always returns the initialized account


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
