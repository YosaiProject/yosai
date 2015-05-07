from yosai import (
    AccountStoreRealmAuthenticationException,
    IllegalArgumentException,
    IncorrectCredentialsException, 
    LogManager, 
    PasswordMatcher,
    UsernamePasswordToken,
)

from . import (
    IRealm,
)

class AccountStoreRealm(IRealm, object):

    def __init__(self):
        # 80/20 rule:  most shiro deployments use passwords:
        self.credentials_matcher = PasswordMatcher()

    # removed the basic accessor/mutator methods (not pythonic)
    def supports(self, authc_token):
        # override the following return to False if you do not wish to support 
        # authentication from this realm
        return isinstance(authc_token, UsernamePasswordToken)

    def authenticate_account(self, authc_token):
        # EAFP replaces the need to verify whether an authc_token is supported
        try:  
            ach = self.account_cache_handler
            account = ach.get_cached_account(authc_token)
            if (account is None):
                # otherwise not cached, perform the lookup:
                account = self.account_store.get_account(authc_token)
                if (authc_token and account):
                    # log here
                    msg = ("Acquired Account [{0}] from account store".format(
                           account))
                    print(msg)
                    ach.cache_account(authc_token, account)
               
            else:
                # log here
                msg2 = ("Using cached account [{0}] for credentials "
                        "matching.".format(account))
                print(msg2)

            if (not account):
                # log here
                msg3 = ("No account found for submitted AuthenticationToken "
                        "[{1}].  Returning None.".format(authc_token))
                print(msg3)
                return None

            self.assert_credentials_match(authc_token, account)

            return account

        except:
            raise AccountStoreRealmAuthenticationException

    def assert_credentials_match(self, authc_token, account):
        cm = self.credentials_matcher
        if (not cm.credentials_match(authc_token, account)):
            # not successful - raise an exception as signal:
            # log here
            msg = ("Submitted credentials for token [" + authc_token + "] "
                   "did not match the stored credentials.")
            raise IncorrectCredentialsException(msg)

    def __setattr__(self, target, value):
        """
        Shiro validates in each mutator method whereas Yosai validates by
        default through __setattr__
        """
        if not value:
            msg = 'cannot set to empty or None'
            raise IllegalArgumentException(msg) 
        else:
            self.__dict__[target] = value

    def __getattr__(self, target):
        """
        This prevents an AttributeError from being raised.  Use with caution.
        """
        return self.__dict__.get(target, None)


class AbstractCacheHandler(object):

    def __init__(self):
        self._cache_manager = DisabledCacheManager.INSTANCE

    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        self._cache_manager = cachemanager


class DefaultAccountCacheHandler(AbstractCacheHandler):
    """ DG:  will refactor from inheritance to composition later """

    def __init__(self):
        pass

    @property
    def account_cache_key_resolver(self):
        return self._account_cache_key_resolver

    @account_cache_key_resolver.setter
    def account_cache_key_resolver(self, ack_resolver):
        self._account_cache_key_resolver = ack_resolver 

    @property
    def account_cache_resolver(self):
        return self._account_cache_resolver

    @account_cache_resolver.setter
    def account_cache_resolver(self, ac_resolver):
        self._account_cache_resolver = ac_resolver
    
    def get_cached_account(self, authc_token):
        cache = self.account_cache_resolver.get_account_cache(authc_token)
        key = self.account_cache_key_resolver.\
            get_account_cache_key(authc_token)
        return cache.get(key)
    
    def cache_account(self, authc_token, account):
        cache = self.account_cache_resolver.\
            get_account_cache(authc_token, account)
        key = self.account_cache_key_resolver.\
            get_account_cache_key(authc_token, account)
        cache.put(key, account)

    def clear_cached_account(self, account_id):
        cache = self.account_cache_resolver.get_account_cache(account_id)
        key = self.account_cache_key_resolver.get_account_cache_key(account_id)
        cache.remove(key)
