from yosai.realm import (
    IAccountCacheHandler,
)

from ..doubles import (
    MockAccount,
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
    
