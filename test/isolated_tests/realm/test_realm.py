import pytest
from yosai import (
    AccountStoreRealm,
    IncorrectCredentialsException,
    PasswordMatcher,
    RealmMisconfiguredException,
)
from ..doubles import (
    MockAccount,
    MockAccountStore,
)

from .doubles import (
    MockAccountCacheHandler,
)

from unittest import mock

# -----------------------------------------------------------------------------
# AccountStoreRealm Tests
# -----------------------------------------------------------------------------
def test_asr_supports(patched_accountstore_realm, mock_token, 
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

def test_asr_authc_acct_cannot_locate_account(
        monkeypatch, username_password_token, patched_accountstore_realm):
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

def test_asr_acm_succeeds(
        username_password_token, patched_accountstore_realm, full_mock_account):
    
    upt = username_password_token
    pasr = patched_accountstore_realm 
   
    with mock.patch.object(PasswordMatcher, 'credentials_match') as pm_cm:
        pm_cm.return_value = True
        result = pasr.assert_credentials_match(upt, full_mock_account)
        assert result is None

def test_asr_acm_fails(
        username_password_token, patched_accountstore_realm, full_mock_account):
    
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

def test_dach_gca_fails_to_locate_cache
def test_dach_gca_fails_to_locate_cache_key
def test_dach_gca_fails_to_locate_cached_account
def test_dach_gca_succeeds_in_locating_cached_account

    patched_default_account_cache_handler,

    pdach = patched_default_account_cache_handler
