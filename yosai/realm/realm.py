from yosai import IncorrectCredentialsException, LogManager, PasswordMatcher


class AccountStoreRealm(object):

    def __init__(self):
        # 80/20 rule:  most shiro deployments use passwords:
        self._credentials_matcher = PasswordMatcher()

    @property
    def account_store(self):
        return self._account_store

    @account_store.setter
    def account_store(self, accountstore):
        try:
            assert accountstore
        except AssertionError as ex:
            print('cannot set accountstore with empty value!', ex)
        self._account_store = accountstore

    @property
    def credentials_matcher(self):
        return self._credentials_matcher

    @credentials_matcher.setter
    def credentials_matcher(self, credentialsmatcher):
        try:
            assert credentialsmatcher 
        except AssertionError as ex:
            print('cannot set credentialsmatcher with empty value!')
        self._credentials_matcher = credentialsmatcher

    @property
    def account_cache_handler(self):
        return self._account_cache_handler

    @account_cache_handler.setter
    def account_cache_handler(self, ach):
        try:
            assert ach 
        except AssertionError as ex:
            print('cannot set ach with empty value!')
        self._account_cache_handler = ach

    @property
    def authorization_cache_handler(self):
        return self._authorization_cache_handler

    @authorization_cache_handler.setter
    def authorization_cache_handler(self, authz_ch):
        try:
            assert authz_ch 
        except AssertionError as ex:
            print('cannot set authz_ch with empty value!')
        self._authorization_cache_handler = authz_ch

    def supports(self, authc_token):
        return isinstance(authc_token, UsernamePasswordToken)

    def authenticate_account(self, authc_token):
        try:
            account = self.account_cache_handler.get_cached_account(authc_token)
            if (account is None):
                # otherwise not cached, perform the lookup:
                account = self.account_store.get_account(authc_token)
                if (authc_token and account):
                    # log here
                    msg = ("Acquired Account [{0}] from account store".format(
                           account))
                    print(msg)
                    self.account_cache_handler.\
                        cache_account(authc_token, account)
               
            else:
                # log here
                msg2 = ("Using cached account [{0}] for credentials "
                        "matching.".format(account))
                print(msg2)

            if (not account):
                # log here
                msg3 = ("No account found for submitted AuthenticationToken "
                        "[{1}].  Returning None.".format(authc_token))
                return None

            self.assert_credentials_match(authc_token, account)

            return account

        except:
            raise

    def assert_credentials_match(self, authc_token, account):
        try:
            cm = self.credentials_matcher
            if (not cm.credentials_match(authc_token, account)):
                # not successful - throw an exception to indicate self:
                # log here
                msg = ("Submitted credentials for token [" + authc_token + "] "
                       "did not match the stored credentials.")
                raise IncorrectCredentialsException(msg)
        except IncorrectCredentialsException as ex:
            print('assert_credentials_match: ', ex)


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
