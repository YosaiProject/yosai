import pytest

from yosai import (
    AccountStoreRealm,
    CacheAccountException,
    ClearCacheAccountException,
    GetCachedAccountException,
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
    MockAccountCacheHandler,
    MockAccountCacheResolver,
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
    monkeypatch.setattr(par, 'account_cache_handler', None)
    monkeypatch.setattr(par, 'account_store', None)

    with pytest.raises(RealmMisconfiguredException):
        par.authenticate_account(token)    

def test_asr_authc_acct_with_cached_acct_succeeds(
        patched_accountstore_realm, monkeypatch, username_password_token):
    """ 
    unit tested:  authenticate_account

    test case:
    MockAccountCacheHandler.get_cached_account returns a MockAccount
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
    Since an AccountCacheHandler is set, the account is cached.

    AccountCacheHandler.get_cached_account returns None
    AccountStoreRealm.assert_credentials_match returns True
    AccountStore.get_account returns a mock acount 
    """
    token = username_password_token
    pasr = patched_accountstore_realm 
    ach = pasr.account_cache_handler
    monkeypatch.setattr(pasr, '_account_cache_handler', 
                        MockAccountCacheHandler(account=''))

    def patched_assert_credentials_match(x=None, y=None):
        return True 
    monkeypatch.setattr(pasr, 'assert_credentials_match',
                        patched_assert_credentials_match)
    
    result = pasr.authenticate_account(token)
    ach = pasr.account_cache_handler  # it updated
    assert ((result.id == 'MAS123') and 
            ach.account == MockAccount(account_id='MAS123'))

def test_asr_authc_acct_cannot_locate_account(username_password_token, 
                                              patched_accountstore_realm, 
                                              monkeypatch):
    """ 
    unit tested:  authenticate_account
    
    test case:
    in the event that an account cannot be found (for a token's parameters)
    from an account_store, None is returned from authenticate_account
    
    AccountCacheHandler.get_cached_account returns None
    AccountStore.get_account returns None
    """
    token = username_password_token
    pasr = patched_accountstore_realm 
    pasr.account_cache_handler = MockAccountCacheHandler(account='')
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
# DefaultAccountCacheHandler Tests
# -----------------------------------------------------------------------------

def test_dach_gca_fails_to_obtain_cache_resolver(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token):
    """
    unit tested:  get_cached_account 
    """
    
    pdach = patched_default_account_cache_handler
    token = username_password_token

    monkeypatch.setattr(pdach, 'account_cache_resolver', None)

    with pytest.raises(GetCachedAccountException):
        pdach.get_cached_account(token)

def test_dach_gca_fails_to_obtain_cache_key_resolver(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token):
    """
    unit tested:  get_cached_account 
    """
    
    pdach = patched_default_account_cache_handler
    token = username_password_token

    monkeypatch.setattr(pdach, 'account_cache_key_resolver', None)
    
    with pytest.raises(GetCachedAccountException):
        pdach.get_cached_account(token)

def test_dach_gca_fails_to_locate_cache(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token):
    """
    unit tested:  get_cached_account 
    
    test case:
    by default, the MockAccountCacheResolver returns None 
    
    """
    
    pdach = patched_default_account_cache_handler
    token = username_password_token

    with pytest.raises(GetCachedAccountException):
        pdach.get_cached_account(token)


def test_dach_gca_fails_to_locate_cache_key(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_resolver):
    """ 
    unit tested:  get_cached_account 
   
    test case:
    the default pdach fixture uses empty mocks, therefore both the 
        get_account_cache and get_account_cache_key return None

    the patched mock fixtures return values 
    """
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    token = username_password_token
    pmacr = patched_mock_account_cache_resolver

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)

    result = pdach.get_cached_account(token)

    assert result is None


def test_dach_gca_fails_to_locate_cached_account(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_resolver,
        patched_mock_account_cache_key_resolver):
    """
    unit tested:  get_cached_account 
    """
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    token = username_password_token
    pmacr = patched_mock_account_cache_resolver
    pmackr = patched_mock_account_cache_key_resolver

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', pmackr)

    result = pdach.get_cached_account(token)

    assert result is None


def test_dach_gca_succeeds_in_locating_cached_account(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_key_resolver):
    """
    unit tested:  get_cached_account 
    """
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    token = username_password_token
    pmackr = patched_mock_account_cache_key_resolver

    # DG:  a username is presumably a good key to reference an account: 
    key = token.username
    value = MockAccount(account_id='CachedAccount12345')
    pmacr = MockAccountCacheResolver(MockCache({key: value}))

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)

    # key is: 'CachedAccount12345'
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', pmackr)

    result = pdach.get_cached_account(token)  # token is ignored by mock

    assert result.id == 'CachedAccount12345'

def test_dach_ca_fails_to_obtain_cache_resolver(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, full_mock_account):
    """
    unit tested:  cache_account 
    """
    
    pdach = patched_default_account_cache_handler
    account = full_mock_account
    token = username_password_token
    monkeypatch.setattr(pdach, 'account_cache_resolver', None)

    with pytest.raises(CacheAccountException):
        pdach.cache_account(authc_token=token, account=account)

def test_dach_ca_fails_to_obtain_cache_key_resolver(
        patched_default_account_cache_handler, monkeypatch,
        patched_mock_account_cache_resolver,
        username_password_token, full_mock_account):
    """
    unit tested:  cache_account 
    
    test case:
    the cache is obtained but the key isn't
    """

    pdach = patched_default_account_cache_handler
    account = full_mock_account
    token = username_password_token
    
    pmacr = patched_mock_account_cache_resolver
    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', None)
    
    with pytest.raises(CacheAccountException):
        pdach.cache_account(authc_token=token, account=account)

def test_dach_ca_fails_to_locate_cache( 
        patched_default_account_cache_handler, full_mock_account,
        username_password_token):
    """ 
    unit tested:  cache_account 

    test case:
    by default, the MockAccountCacheResolver returns None
    """
    
    pdach = patched_default_account_cache_handler
    account = full_mock_account
    token = username_password_token

    with pytest.raises(CacheAccountException):
        pdach.cache_account(authc_token=token, account=account)


def test_dach_ca_fails_to_locate_cache_key(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_resolver,
        full_mock_account):
    """ 
    unit tested:  cache_account 
 
    test case:
    the default pdach fixture uses empty mocks, therefore both the 
    get_account_cache and get_account_cache_key return None

    the patched mock fixtures return values 
    """
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    account = full_mock_account
    token = username_password_token
    pmacr = patched_mock_account_cache_resolver

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)

    with pytest.raises(CacheAccountException):
        pdach.cache_account(authc_token=token, account=account)

def test_dach_ca_succeeds_in_caching_account(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_key_resolver,
        patched_mock_account_cache_resolver, full_mock_account):
    """
    unit tested:  cache_account 
    """

    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    token = username_password_token
    account = full_mock_account  # has account_id = 8675309

    # pmackr always returns key='user123':
    pmackr = patched_mock_account_cache_key_resolver
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', pmackr)

    pmacr = patched_mock_account_cache_resolver
    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)
    
    pdach.cache_account(authc_token=token, account=account)

    # returns a full MockAccount:
    result = pdach.account_cache_resolver.cache.get('user123')
    assert result.id == 8675309


def test_dach_cca_fails_to_obtain_cache_resolver(
        patched_default_account_cache_handler, monkeypatch, full_mock_account):
    """
    unit tested:  clear_cached_account 
    """

    pdach = patched_default_account_cache_handler
    account = full_mock_account
    monkeypatch.setattr(pdach, 'account_cache_resolver', None)

    with pytest.raises(ClearCacheAccountException):
        pdach.clear_cached_account(account_id=account.id)

def test_dach_cca_fails_to_obtain_cache_key_resolver(
        patched_default_account_cache_handler, monkeypatch, 
        full_mock_account, patched_mock_account_cache_resolver):
    """
    unit tested:  clear_cached_account 
    """
    
    pdach = patched_default_account_cache_handler
    account = full_mock_account

    pmacr = patched_mock_account_cache_resolver
    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', None)
    
    with pytest.raises(ClearCacheAccountException):
        pdach.clear_cached_account(account_id=account.id)

def test_dach_cca_fails_to_locate_cache(
        patched_default_account_cache_handler, full_mock_account,
        username_password_token):
    """
    unit tested:  clear_cached_account 
    
    by default, the MockAccountCacheResolver returns None
    """
    
    pdach = patched_default_account_cache_handler
    account = full_mock_account

    with pytest.raises(ClearCacheAccountException):
        pdach.clear_cached_account(account_id=account.id)

def test_dach_cca_fails_to_locate_cache_key(
        patched_default_account_cache_handler, monkeypatch, 
        patched_mock_account_cache_resolver, full_mock_account):
    """ 
    unit tested:  clear_cached_account 
    
    test case:
    the default pdach fixture uses empty mocks, therefore both the 
    get_account_cache and get_account_cache_key return None

    the patched mock fixtures return values 
    """
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    account = full_mock_account
    pmacr = patched_mock_account_cache_resolver

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)

    result = pdach.clear_cached_account(account_id=account.id)

    assert result is None


def test_dach_cca_succeeds_in_removing_cached_account(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_key_resolver,
        patched_mock_account_cache_resolver, full_mock_account):
    """
    unit tested:  clear_cached_account 
    """

    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    account = full_mock_account  # has account_id = 8675309

    # pmackr always returns key='user123':
    pmackr = patched_mock_account_cache_key_resolver
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', pmackr)

    # uses a MockCache:
    pmacr = patched_mock_account_cache_resolver
    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)
    
    # returns a full MockAccount:
    result = pdach.clear_cached_account(account_id=account.id)

    assert result.id == 8675309

