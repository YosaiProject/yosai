
from yosai import (
    realm_abcs,
)

from ..doubles import (
    MockAccount,
    MockCache,
)


class MockAuthorizationCacheHandler(realm_abcs.AuthorizationCacheHandler, object):

    def get_cached_authz_info(self, identifiers):
        pass 

    def cache_authz_info(self, identifiers, authz_info): 
        pass

    def clear_cached_authz_info(self, identifers):
        pass


class MockCredentialsCacheHandler(realm_abcs.CredentialsCacheHandler, object):

    def __init__(self, account):
        self.account = account

    def get_cached_credentials(self, authc_token):
        return self.account 

    def cache_credentials(self, authc_token, account):
        self.account = account 

    def clear_cached_credentials(self, account_id):
        pass


class MockCredentialsCacheResolver(realm_abcs.CacheResolver, object):

    def __init__(self, cache=None):
        self.cache = cache

    def get_cache(self, authc_token=None, account=None, account_id=None):
        return self.cache


class MockCredentialsCacheKeyResolver(realm_abcs.CacheKeyResolver, object):
    
    def __init__(self, key=None):
        self.key = key

    def get_cache_key(self, authc_token=None, account=None, account_id=None):
        return self.key 
