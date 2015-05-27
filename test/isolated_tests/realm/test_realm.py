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
    upt = username_password_token
    mt = mock_token

    assert (par.supports(upt) and not par.supports(mt))

def test_asr_authc_acct_fails_misconfigured(patched_accountstore_realm,
                                            username_password_token,
                                            monkeypatch):
    """ a misconfigured AccountStoreRealm will raise an exception when 
        authentication is attempted

        in this test, there is no accountstore attribute, and so the 
        exception will raise
    """
    par = patched_accountstore_realm
    upt = username_password_token
    monkeypatch.setattr(par, 'account_cache_handler', None)
    monkeypatch.setattr(par, 'account_store', None)

    with pytest.raises(RealmMisconfiguredException):
        par.authenticate_account(upt)    

def test_asr_authc_acct_with_cached_acct_succeeds(
        patched_accountstore_realm, monkeypatch, username_password_token):
    """ MockAccountCacheHandler.get_cached_account returns a MockAccount """

    par = patched_accountstore_realm
    upt = username_password_token

    def do_nothing(x, y):
        pass

    monkeypatch.setattr(par, 'assert_credentials_match', do_nothing) 
    result = par.authenticate_account(upt)
    assert result == MockAccount(account_id='MACH13579')


def test_asr_authc_acct_without_cached_acct_succeeds_and_caches(
        monkeypatch, username_password_token, patched_accountstore_realm):
    """
    If the account isn't cached, it should be obtained from the account_store.
    Since an AccountCacheHandler is set, the account is cached.

    AccountCacheHandler.get_cached_account returns None
    AccountStoreRealm.assert_credentials_match returns True
    AccountStore.get_account returns a mock acount 
    """
    upt = username_password_token
    pasr = patched_accountstore_realm 
    ach = pasr.account_cache_handler
    monkeypatch.setattr(pasr, '_account_cache_handler', 
                        MockAccountCacheHandler(account=''))

    def patched_assert_credentials_match(x=None, y=None):
        return True 
    monkeypatch.setattr(pasr, 'assert_credentials_match',
                        patched_assert_credentials_match)
    
    result = pasr.authenticate_account(upt)
    ach = pasr.account_cache_handler  # it updated
    assert ((result.id == 'MAS123') and 
            ach.account == MockAccount(account_id='MAS123'))

def test_asr_authc_acct_cannot_locate_account(username_password_token, 
                                              patched_accountstore_realm, 
                                              monkeypatch):
    """ in the event that an account cannot be found (for a token's parameters)
        from an account_store, None is returned from authenticate_account
    
        AccountCacheHandler.get_cached_account returns None
        AccountStore.get_account returns None
    """
    upt = username_password_token
    pasr = patched_accountstore_realm 
    pasr.account_cache_handler = MockAccountCacheHandler(account='')
    pasr.account_store = MockAccountStore(account='')
    
    def patched_assert_credentials_match(x=None, y=None):
        return True 
    monkeypatch.setattr(pasr, 'assert_credentials_match',
                        patched_assert_credentials_match)

    result = pasr.authenticate_account(upt)

    assert result is None


def test_asr_acm_succeeds(username_password_token, patched_accountstore_realm, 
                          full_mock_account):
    
    upt = username_password_token
    pasr = patched_accountstore_realm 
   
    with mock.patch.object(PasswordMatcher, 'credentials_match') as pm_cm:
        pm_cm.return_value = True
        result = pasr.assert_credentials_match(upt, full_mock_account)
        assert result is None

def test_asr_acm_fails(username_password_token, patched_accountstore_realm, 
                       full_mock_account):
    
    upt = username_password_token
    pasr = patched_accountstore_realm 
  
    with pytest.raises(IncorrectCredentialsException):
        with mock.patch.object(PasswordMatcher, 'credentials_match') as pm_cm:
            pm_cm.return_value = False 
            pasr.assert_credentials_match(upt, full_mock_account)

    
# -----------------------------------------------------------------------------
# AbstractCacheHandler Tests
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# DefaultAccountCacheHandler Tests
# -----------------------------------------------------------------------------

def test_dach_gca_fails_to_obtain_cache_resolver(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token):
    
    pdach = patched_default_account_cache_handler
    upt = username_password_token

    monkeypatch.setattr(pdach, 'account_cache_resolver', None)

    with pytest.raises(GetCachedAccountException):
        pdach.get_cached_account(upt)

def test_dach_gca_fails_to_obtain_cache_key_resolver(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token):
    
    pdach = patched_default_account_cache_handler
    upt = username_password_token

    monkeypatch.setattr(pdach, 'account_cache_key_resolver', None)
    
    with pytest.raises(GetCachedAccountException):
        pdach.get_cached_account(upt)

def test_dach_gca_fails_to_locate_cache(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token):
    """ by default, the MockAccountCacheResolver returns None """
    
    pdach = patched_default_account_cache_handler
    upt = username_password_token

    with pytest.raises(GetCachedAccountException):
        pdach.get_cached_account(upt)


def test_dach_gca_fails_to_locate_cache_key(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_resolver):
    """ by default, both the get_account_cache and get_account_cache_key 
        return None, and the patched fixtures of them return values """
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    upt = username_password_token
    pmacr = patched_mock_account_cache_resolver

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)

    result = pdach.get_cached_account(upt)

    assert result is None


def test_dach_gca_fails_to_locate_cached_account(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_resolver,
        patched_mock_account_cache_key_resolver):
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    upt = username_password_token
    pmacr = patched_mock_account_cache_resolver
    pmackr = patched_mock_account_cache_key_resolver

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', pmackr)

    result = pdach.get_cached_account(upt)

    assert result is None


def test_dach_gca_succeeds_in_locating_cached_account(
        patched_default_account_cache_handler, monkeypatch, 
        username_password_token, patched_mock_account_cache_key_resolver):
    
    pdach = patched_default_account_cache_handler  # doesn't matter if patched
    upt = username_password_token
    pmackr = patched_mock_account_cache_key_resolver

    # DG:  a username is presumably a good key to reference an account: 
    key = upt.username
    value = MockAccount(account_id='CachedAccount12345')
    pmacr = MockAccountCacheResolver(MockCache({key: value}))

    monkeypatch.setattr(pdach, 'account_cache_resolver', pmacr)

    # key is: 'CachedAccount12345'
    monkeypatch.setattr(pdach, 'account_cache_key_resolver', pmackr)

    result = pdach.get_cached_account(upt)  # upt is ignored by mock

    assert result.id == 'CachedAccount12345'

"""
def test_dach_ca_fails_to_obtain_cache_resolver
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_ca_fails_to_obtain_cache_key_resolver
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_ca_fails_to_locate_cache
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_ca_fails_to_locate_cache_key
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_ca_fails_to_cache_account_with_bad_key
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_ca_fails_to_cache_account_with_bad_account
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_ca_succeeds_in_caching_account
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler

def test_dach_cca_fails_to_obtain_cache_resolver
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_cca_fails_to_obtain_cache_key_resolver
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_cca_fails_to_locate_cache
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler

def test_dach_cca_fails_to_locate_cache_key
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
def test_dach_cca_fails_to_remove_cached_account
    patched_default_account_cache_handler,
    pdach = patched_default_account_cache_handler

def test_dach_cca_succeeds_in_removing_cached_account
    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
"""
