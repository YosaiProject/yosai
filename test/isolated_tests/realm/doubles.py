from yosai.realm import (
    IAccountCacheHandler,
    IAccountCacheResolver,
    IAccountCacheKeyResolver,
)

from ..doubles import (
    MockAccount,
    MockCache,
)

class MockAccountCacheHandler(IAccountCacheHandler, object):

    def __init__(self, account):
        self.account = account

    def get_cached_account(self, authc_token):
        return self.account 

    def cache_account(self, authc_token, account):
        self.account = account 

    def clear_cached_account(self, account_id):
        pass
    

class MockAccountCacheResolver(IAccountCacheResolver, object):

    def __init__(self, cache=None):
        self.cache = cache

    def get_account_cache(self, authc_token=None, account=None, 
                          account_id=None):
        return self.cache


class MockAccountCacheKeyResolver(IAccountCacheKeyResolver, object):
    
    def __init__(self, key=None):
        self.key = key

    def get_account_cache_key(self, authc_token=None, 
                              account=None, account_id=None):
        return self.key 
