import pytest

from yosai import (
    AccountStoreRealm,
    CacheCredentialsException,
    ClearCacheCredentialsException,
    GetCachedCredentialsException,
    IncorrectCredentialsException,
    PasswordMatcher,
    RealmMisconfiguredException,
)
from ..doubles import (
    MockAccount,
    MockAccountStore,
    MockCache,
)

from .doubles import (
    MockCredentialsCacheHandler,
    MockCredentialsCacheResolver,
)

from unittest import mock

# -----------------------------------------------------------------------------
# AccountStoreRealm Tests
# -----------------------------------------------------------------------------
def test_asr_supports(patched_accountstore_realm,
                      mock_token, 
                      username_password_token):
    par = patched_accountstore_realm
    token = username_password_token
    mt = mock_token

    assert (par.supports(token) and not par.supports(mt))

def test_asr_authc_acct_fails_misconfigured(patched_accountstore_realm,
                                            username_password_token,
                                            monkeypatch):
    """ 
    unit tested:  authenticate_account

    test case:
    a misconfigured AccountStoreRealm will raise an exception when 
    authentication is attempted

    in this test, there is no accountstore attribute, and so the 
    exception will raise
    """
    par = patched_accountstore_realm
    token = username_password_token
    monkeypatch.setattr(par, 'credentials_cache_handler', None)
    monkeypatch.setattr(par, 'account_store', None)

    with pytest.raises(RealmMisconfiguredException):
        par.authenticate_account(token)    

def test_asr_authc_acct_with_cached_acct_succeeds(
        patched_accountstore_realm, monkeypatch, username_password_token):
    """ 
    unit tested:  authenticate_account

    test case:
    MockCredentialsCacheHandler.get_cached_credentials returns a MockAccount
    """

    par = patched_accountstore_realm
    token = username_password_token

    def do_nothing(x, y):
        pass

    monkeypatch.setattr(par, 'assert_credentials_match', do_nothing) 
    result = par.authenticate_account(token)
    assert result == MockAccount(account_id='MACH13579')


def test_asr_authc_acct_without_cached_acct_succeeds_and_caches(
        monkeypatch, username_password_token, patched_accountstore_realm):
    """
    unit tested:  authenticate_account

    test case:
    If the account isn't cached, it should be obtained from the account_store.
    Since an CredentialsCacheHandler is set, the account is cached.

    CredentialsCacheHandler.get_cached_credentials returns None
    AccountStoreRealm.assert_credentials_match returns True
    AccountStore.get_account returns a mock acount 
    """
    token = username_password_token
    pasr = patched_accountstore_realm 
    ach = pasr.credentials_cache_handler
    monkeypatch.setattr(pasr, '_credentials_cache_handler', 
                        MockCredentialsCacheHandler(account=''))

    def patched_assert_credentials_match(x=None, y=None):
        return True 
    monkeypatch.setattr(pasr, 'assert_credentials_match',
                        patched_assert_credentials_match)
    
    result = pasr.authenticate_account(token)
    ach = pasr.credentials_cache_handler  # it updated
    assert ((result.account_id == 'MAS123') and 
            ach.account == MockAccount(account_id='MAS123'))

def test_asr_authc_acct_cannot_locate_account(username_password_token, 
                                              patched_accountstore_realm, 
                                              monkeypatch):
    """ 
    unit tested:  authenticate_account
    
    test case:
    in the event that an account cannot be found (for a token's parameters)
    from an account_store, None is returned from authenticate_account
    
    CredentialsCacheHandler.get_cached_credentials returns None
    AccountStore.get_account returns None
    """
    token = username_password_token
    pasr = patched_accountstore_realm 
    pasr.credentials_cache_handler = MockCredentialsCacheHandler(account='')
    pasr.account_store = MockAccountStore(account='')
    
    def patched_assert_credentials_match(x=None, y=None):
        return True 
    monkeypatch.setattr(pasr, 'assert_credentials_match',
                        patched_assert_credentials_match)

    result = pasr.authenticate_account(token)

    assert result is None


def test_asr_acm_succeeds(username_password_token, patched_accountstore_realm, 
                          full_mock_account):
    """
    unit tested:  assert_credentials_match 
    """
    
    token = username_password_token
    pasr = patched_accountstore_realm 
   
    with mock.patch.object(PasswordMatcher, 'credentials_match') as pm_cm:
        pm_cm.return_value = True
        result = pasr.assert_credentials_match(token, full_mock_account)
        assert result is None

def test_asr_acm_fails(username_password_token, patched_accountstore_realm, 
                       full_mock_account):
    """
    unit tested:  assert_credentials_match 
    """
    
    token = username_password_token
    pasr = patched_accountstore_realm 
  
    with pytest.raises(IncorrectCredentialsException):
        with mock.patch.object(PasswordMatcher, 'credentials_match') as pm_cm:
            pm_cm.return_value = False 
            pasr.assert_credentials_match(token, full_mock_account)

    
# -----------------------------------------------------------------------------
# DefaultCredentialsCacheHandler Tests
# -----------------------------------------------------------------------------

def test_dach_gca_fails_to_obtain_cache_resolver(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token):
    """
    unit tested:  get_cached_credentials 
    """
    
    pdach = patched_default_credentials_cache_handler
    token = username_password_token

    monkeypatch.setattr(pdach, 'credentials_cache_resolver', None)

    with pytest.raises(GetCachedCredentialsException):
        pdach.get_cached_credentials(token)

def test_dach_gca_fails_to_obtain_cache_key_resolver(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token):
    """
    unit tested:  get_cached_credentials 
    """
    
    pdach = patched_default_credentials_cache_handler
    token = username_password_token

    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', None)
    
    with pytest.raises(GetCachedCredentialsException):
        pdach.get_cached_credentials(token)

def test_dach_gca_fails_to_locate_cache(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token):
    """
    unit tested:  get_cached_credentials 
    
    test case:
    by default, the MockCredentialsCacheResolver returns None 
    
    """
    
    pdach = patched_default_credentials_cache_handler
    token = username_password_token

    with pytest.raises(GetCachedCredentialsException):
        pdach.get_cached_credentials(token)


def test_dach_gca_fails_to_locate_cache_key(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, patched_mock_credentials_cache_resolver):
    """ 
    unit tested:  get_cached_credentials 
   
    test case:
    the default pdach fixture uses empty mocks, therefore both the 
        get_credentials_cache and get_credentials_cache_key return None

    the patched mock fixtures return values 
    """
    
    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    token = username_password_token
    pmacr = patched_mock_credentials_cache_resolver

    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)

    result = pdach.get_cached_credentials(token)

    assert result is None


def test_dach_gca_fails_to_locate_cached_credentials(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, patched_mock_credentials_cache_resolver,
        patched_mock_credentials_cache_key_resolver):
    """
    unit tested:  get_cached_credentials 
    """
    
    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    token = username_password_token
    pmacr = patched_mock_credentials_cache_resolver
    pmackr = patched_mock_credentials_cache_key_resolver
    monkeypatch.setattr(pmackr, 'key', 'user223344')

    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', pmackr)

    result = pdach.get_cached_credentials(token)

    assert result is None


def test_dach_gca_succeeds_in_locating_cached_credentials(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, patched_mock_credentials_cache_key_resolver):
    """
    unit tested:  get_cached_credentials 
    """
    
    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    token = username_password_token
    pmackr = patched_mock_credentials_cache_key_resolver

    # DG:  a username is presumably a good key to reference an account: 
    key = token.username
    value = MockAccount(account_id='CachedAccount12345')
    pmacr = MockCredentialsCacheResolver(MockCache({key: value}))

    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)

    # key is: 'CachedAccount12345'
    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', pmackr)

    result = pdach.get_cached_credentials(token)  # token is ignored by mock

    assert result.account_id == 'CachedAccount12345'

def test_dach_ca_fails_to_obtain_cache_resolver(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, full_mock_account):
    """
    unit tested:  cache_credentials 
    """
    
    pdach = patched_default_credentials_cache_handler
    account = full_mock_account
    token = username_password_token
    monkeypatch.setattr(pdach, 'credentials_cache_resolver', None)

    with pytest.raises(CacheCredentialsException):
        pdach.cache_credentials(authc_token=token, account=account)

def test_dach_ca_fails_to_obtain_cache_key_resolver(
        patched_default_credentials_cache_handler, monkeypatch,
        patched_mock_credentials_cache_resolver,
        username_password_token, full_mock_account):
    """
    unit tested:  cache_credentials 
    
    test case:
    the cache is obtained but the key isn't
    """

    pdach = patched_default_credentials_cache_handler
    account = full_mock_account
    token = username_password_token
    
    pmacr = patched_mock_credentials_cache_resolver
    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', None)
    
    with pytest.raises(CacheCredentialsException):
        pdach.cache_credentials(authc_token=token, account=account)

def test_dach_ca_fails_to_locate_cache( 
        patched_default_credentials_cache_handler, full_mock_account,
        username_password_token):
    """ 
    unit tested:  cache_credentials 

    test case:
    by default, the MockCredentialsCacheResolver returns None
    """
    
    pdach = patched_default_credentials_cache_handler
    account = full_mock_account
    token = username_password_token

    with pytest.raises(CacheCredentialsException):
        pdach.cache_credentials(authc_token=token, account=account)


def test_dach_ca_fails_to_locate_cache_key(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, patched_mock_credentials_cache_resolver,
        full_mock_account):
    """ 
    unit tested:  cache_credentials 
 
    test case:
    the default pdach fixture uses empty mocks, therefore both the 
    get_credentials_cache and get_credentials_cache_key return None

    the patched mock fixtures return values 
    """
    
    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    account = full_mock_account
    token = username_password_token
    pmacr = patched_mock_credentials_cache_resolver

    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)

    with pytest.raises(CacheCredentialsException):
        pdach.cache_credentials(authc_token=token, account=account)

def test_dach_ca_succeeds_in_caching_account(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, patched_mock_credentials_cache_key_resolver,
        patched_mock_credentials_cache_resolver, full_mock_account):
    """
    unit tested:  cache_credentials 
    """

    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    token = username_password_token
    account = full_mock_account  # has account_id = 8675309

    # pmackr always returns key='user123':
    pmackr = patched_mock_credentials_cache_key_resolver
    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', pmackr)

    pmacr = patched_mock_credentials_cache_resolver
    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)
    
    pdach.cache_credentials(authc_token=token, account=account)

    # returns a full MockAccount:
    result = pdach.credentials_cache_resolver.cache.get('user123')
    assert result.account_id == 8675309


def test_dach_cca_fails_to_obtain_cache_resolver(
        patched_default_credentials_cache_handler, monkeypatch, full_mock_account):
    """
    unit tested:  clear_cached_credentials 
    """

    pdach = patched_default_credentials_cache_handler
    account = full_mock_account
    monkeypatch.setattr(pdach, 'credentials_cache_resolver', None)

    with pytest.raises(ClearCacheCredentialsException):
        pdach.clear_cached_credentials(account_id=account.account_id)

def test_dach_cca_fails_to_obtain_cache_key_resolver(
        patched_default_credentials_cache_handler, monkeypatch, 
        full_mock_account, patched_mock_credentials_cache_resolver):
    """
    unit tested:  clear_cached_credentials 
    """
    
    pdach = patched_default_credentials_cache_handler
    account = full_mock_account

    pmacr = patched_mock_credentials_cache_resolver
    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', None)
    
    with pytest.raises(ClearCacheCredentialsException):
        pdach.clear_cached_credentials(account_id=account.account_id)

def test_dach_cca_fails_to_locate_cache(
        patched_default_credentials_cache_handler, full_mock_account,
        username_password_token):
    """
    unit tested:  clear_cached_credentials 
    
    by default, the MockCredentialsCacheResolver returns None
    """
    
    pdach = patched_default_credentials_cache_handler
    account = full_mock_account

    with pytest.raises(ClearCacheCredentialsException):
        pdach.clear_cached_credentials(account_id=account.account_id)

def test_dach_cca_fails_to_locate_cache_key(
        patched_default_credentials_cache_handler, monkeypatch, 
        patched_mock_credentials_cache_resolver, full_mock_account):
    """ 
    unit tested:  clear_cached_credentials 
    
    test case:
    the default pdach fixture uses empty mocks, therefore both the 
    get_credentials_cache and get_credentials_cache_key return None

    the patched mock fixtures return values 
    """
    
    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    account = full_mock_account
    pmacr = patched_mock_credentials_cache_resolver

    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)

    result = pdach.clear_cached_credentials(account_id=account.account_id)

    assert result is None


def test_dach_cca_succeeds_in_removing_cached_credentials(
        patched_default_credentials_cache_handler, monkeypatch, 
        username_password_token, patched_mock_credentials_cache_key_resolver,
        patched_mock_credentials_cache_resolver, full_mock_account):
    """
    unit tested:  clear_cached_credentials 
    """

    pdach = patched_default_credentials_cache_handler  # doesn't matter if patched
    account = full_mock_account  # has account_id = 8675309

    # pmackr always returns key='user123':
    pmackr = patched_mock_credentials_cache_key_resolver
    monkeypatch.setattr(pdach, 'credentials_cache_key_resolver', pmackr)

    # uses a MockCache:
    pmacr = patched_mock_credentials_cache_resolver
    monkeypatch.setattr(pdach, 'credentials_cache_resolver', pmacr)
    
    # returns a full MockAccount:
    result = pdach.clear_cached_credentials(account_id=account.account_id)

    assert result.account_id == 8675309

