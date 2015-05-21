import pytest
from unittest import mock

from yosai import (
    MultiRealmAuthenticationException,
    UnknownAccountException,
    UnsupportedTokenException,
)

from yosai.authc import (
    DefaultAuthenticator,
    DefaultCompositeAccount,
    UsernamePasswordToken,
)

# UsernamePasswordToken Tests
def test_upt_clear_existing_password(username_password_token):
    """ clear a password equal to 'secret' """
    upt = username_password_token
    upt.clear() 
    assert upt.password == bytearray(b'\x00\x00\x00\x00\x00\x00')  


# -----------------------------------------------------------------------------
# DefaultAuthenticator Tests
# -----------------------------------------------------------------------------
def test_da_auth_sra_unsupported_token(
        default_authenticator, mock_token, default_accountstorerealm):
    """ An AuthenticationToken of a type unsupported by the Realm raises an 
        exception
    """
    da = default_authenticator
    realm = default_accountstorerealm
    token = mock_token
    with pytest.raises(UnsupportedTokenException):
        da.authenticate_single_realm_account(realm, token) 

def test_da_authc_sra_supported_token(
        default_authenticator, first_accountstorerealm_succeeds, 
        username_password_token):
    """ a successful authentication returns an account """
    
    da = default_authenticator
    realm = first_accountstorerealm_succeeds 
    token = username_password_token
    assert da.authenticate_single_realm_account(realm, token)

def test_da_autc_mra_succeeds(
        default_authenticator, two_accountstorerealms_succeeds,
        username_password_token):

    da = default_authenticator
    realms = two_accountstorerealms_succeeds 
    token = username_password_token
    result = da.authenticate_multi_realm_account(realms, token)
    assert (result.__class__.__name__ == 'MockAccount')

def test_da_autc_mra_fails(
        default_authenticator, two_accountstorerealms_fails,
        username_password_token):

    da = default_authenticator
    realms = two_accountstorerealms_fails
    token = username_password_token

    with pytest.raises(MultiRealmAuthenticationException):
        da.authenticate_multi_realm_account(realms, token)

def test_da_authc_acct_authentication_fails(
        default_authenticator, username_password_token, monkeypatch): 
    """ when None is returned from do_authenticate_account, it means that
        something other than authentication failed, and so an exception is 
        raised """
    da = default_authenticator
    token = username_password_token
    def do_nothing(self, x=None, y=None):
        return None
    monkeypatch.setattr(da, 'do_authenticate_account', do_nothing) 
    monkeypatch.setattr(da, 'notify_failure', do_nothing) 
    monkeypatch.setattr(da, 'notify_success', do_nothing) 

    with pytest.raises(UnknownAccountException):
        da.authenticate_account(token)
