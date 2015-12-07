import pytest
from yosai.core import (
    AuthenticationException, 
    Credential,
    event_bus,
)

def test_authentication_using_accountstore_success(
        capsys, default_authenticator, valid_username_password_token):

    da = default_authenticator
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    account = da.authenticate_account(valid_username_password_token)
    out, err = capsys.readouterr()

    assert (event_detected.account == account and
            ("Could not obtain cached" in out and "No account" not in out) and
            account.account_id == valid_username_password_token.identifier)


def test_authentication_using_cache_success(
        capsys, default_authenticator, invalid_username_password_token,
        valid_username_password_token, cache_handler, thedude_credentials):

    da = default_authenticator
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    # failed first attempt is required because a successful authentication
    # wipes cache automatically:
    cred = Credential(thedude_credentials) 
    cache_handler.set(domain='credentials', identifier='thedude', value=cred)
    account = da.authenticate_account(valid_username_password_token)
    out, err = capsys.readouterr()

    assert (event_detected.account == account and
            ("Could not obtain cached" not in out) and
            account.account_id == valid_username_password_token.identifier)


# def test_do_clear_cache(account_store_realm):
#    account_store_realm.do_clear_cache('thedude')

#                          ('thedude', "get cached", "Could not obtain cached",


# def test_authentication_using_accountstore_pw_failure
# def test_authentication_using_cache_pw_failure
# def test_authentication_using_accountstore_user_not_found
#                          ('anonymous', "No account", "blabla", type(None))])
