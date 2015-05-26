from yosai import (
    AccountCacheHandlerAttributException,
    AccountStoreRealmAuthenticationException,
    IllegalArgumentException,
    IncorrectCredentialsException, 
    LogManager, 
    PasswordMatcher,
    RealmMisconfiguredException,
    UsernamePasswordToken,
)

from . import (
    IAccountCacheHandler,
    IRealm,
)

class AccountStoreRealm(IRealm, object):
    """ as of Shiro rev1681068 , authorization implementation is TBD """
    
    def __init__(self):
        #  DG:  this needs to be updated so that positional arguments
        #       are used to construct the object rather than mutator methods 

        self._credentials_matcher = PasswordMatcher()  # 80/20 rule: passwords
        self.name = 'AccountStoreRealm' + str(id(self))  # DG:  replace later..
        self._account_store = None  # DG:  TBD
        self._account_cache_handler = None  # DG:  TBD
        self._authorization_cache_handler = None  # DG:  TBD

    # these accessor / mutator methods exist to prevent None assignments
    @property
    def account_store(self):
        return self._account_store

    @account_store.setter
    def account_store(self, accountstore):
        self._account_store = accountstore

    @property
    def credentials_matcher(self):
        return self._credentials_matcher

    @credentials_matcher.setter
    def credentials_matcher(self, credentialsmatcher):
        self._credentials_matcher = credentialsmatcher

    @property
    def account_cache_handler(self):
        return self._account_cache_handler

    @account_cache_handler.setter
    def account_cache_handler(self, accountcachehandler):
        self._account_cache_handler = accountcachehandler
    
    @property
    def authorization_cache_handler(self):
        return self._authorization_cache_handler

    @authorization_cache_handler.setter
    def authorization_cache_handler(self, authorizationcachehandler):
        self._authorization_cache_handler = authorizationcachehandler

    # removed the basic accessor/mutator methods (not pythonic)
    def supports(self, authc_token):
        # override the following return to False if you do not wish to support 
        # authentication from this realm
        return isinstance(authc_token, UsernamePasswordToken)

    def authenticate_account(self, authc_token):
        """ The default authentication caching policy is for 
            authenticate_account to cache account information required yet 
            initially unavailable during authentication, implying that 
            this is the first time within an acceptable caching timeframe 
            that an account is authenticated.  Naturally, an
            AccountCacheHandler must be defined in order to cache.
        """
        account = None
        ach = self.account_cache_handler
        if ach:
            account = ach.get_cached_account(authc_token)
        if (not account):
            # account not cached, so retrieve it from the account_store
            try:
                account = self.account_store.get_account(authc_token)
            except AttributeError:
                msg = ('AccountStoreRealm misconfigured.  At a minimum, '
                       'define an AccountStore. Further, define an' 
                       'AccountCacheHandler to cache an authenticated account')
                # log here (exception)
                raise RealmMisconfiguredException(msg)
            if (authc_token and account):
                msg = ("Acquired Account [{0}] from account store".format(
                       account))
                # log here (debug)
                print(msg)
                if ach:
                    ach.cache_account(authc_token, account)
           
        else:
            msg2 = ("Using cached account [{0}] for credentials "
                    "matching.".format(account))
            # log here (debug)
            print(msg2)

        if (not account):
            # log here
            msg3 = ("No account found for submitted AuthenticationToken "
                    "[{0}].  Returning None.".format(authc_token))
            print(msg3)
            return None

        self.assert_credentials_match(authc_token, account)

        return account

    def assert_credentials_match(self, authc_token, account):
        cm = self.credentials_matcher
        if (not cm.credentials_match(authc_token, account)):
            # not successful - raise an exception as signal:
            msg = ("Submitted credentials for token [" + str(authc_token) + 
                   "] did not match the stored credentials.")
            # log here
            raise IncorrectCredentialsException(msg)

class AbstractCacheHandler(object):

    def __init__(self):
        pass
        # self._cache_manager = DisabledCacheManager.INSTANCE

    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        self._cache_manager = cachemanager


class DefaultAccountCacheHandler(IAccountCacheHandler, AbstractCacheHandler):

    def __init__(self, cache_resolver, cache_key_resolver):
        # this init is new to Yosai in that it requires 2 positional arguments
        self.account_cache_key_resolver = cache_key_resolver 
        self.account_cache_resolver = cache_resolver 

    # omitted accessor / mutator methods for attributes (not pythonic)

    def get_cached_account(self, authc_token):
        self.verify_account_cache_handler_configured()
    
        cache = self.account_cache_resolver.\
            get_account_cache(token=authc_token)
        key = self.account_cache_key_resolver.\
            get_account_cache_key(token=authc_token)
        return cache.get(key)
    
    def cache_account(self, authc_token, account):
        self.verify_account_cache_handler_configured()
        cache = self.account_cache_resolver.\
            get_account_cache(token=authc_token, account=account)
        key = self.account_cache_key_resolver.\
            get_account_cache_key(token=authc_token, account=account)
        cache.put(key, account)

    def clear_cached_account(self, account_id):
        self.verify_account_cache_handler_configured()
        cache = self.account_cache_resolver.\
            get_account_cache(account_id=account_id)
        key = self.account_cache_key_resolver.\
            get_account_cache_key(account_id=account_id)
        cache.remove(key)

    # new to Yosai:
    def verify_account_cache_handler_configured(self):
        if not (self.account_cache_resolver and 
                self.account_cache_key_resolver):

            msg = 'Account cache resolvers not set'
            raise AccountCacheHandlerAttributException(msg)
