import pytest
from yosai.core import (
    AuthenticationException,
    Credential,
    UsernamePasswordToken,
    event_bus,
)

def test_authentication_using_accountstore_success(
        capsys, default_authenticator, valid_username_password_token,
        thedude_credentials):

    da = default_authenticator
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    account = da.authenticate_account(valid_username_password_token)
    out, err = capsys.readouterr()
    assert (event_detected.account == account and
            ("Could not obtain cached" in out and "No account" not in out))


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
    cache_handler.set(domain='credentials', identifiers='thedude', value=cred)
    account = da.authenticate_account(valid_username_password_token)
    out, err = capsys.readouterr()

    assert (event_detected.account == account and
            ("Could not obtain cached" not in out) and
            account.account_id == valid_username_password_token.identifiers)


def test_authentication_using_accountstore_pw_failure(
        capsys, default_authenticator, invalid_username_password_token,
        thedude_credentials):

    da = default_authenticator
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    with pytest.raises(AuthenticationException):
        account = da.authenticate_account(invalid_username_password_token)
        out, err = capsys.readouterr()

        assert (event_detected.account == account and
                ("Could not obtain cached" in out and "No account" not in out))

def test_authentication_using_cache_pw_failure(
        capsys, default_authenticator, invalid_username_password_token,
        cache_handler, thedude_credentials):

    da = default_authenticator
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    cred = Credential(thedude_credentials)
    cache_handler.set(domain='credentials', identifiers='thedude', value=cred)

    with pytest.raises(AuthenticationException):
        da.authenticate_account(invalid_username_password_token)
        out, err = capsys.readouterr()

        assert (event_detected.authc_token == invalid_username_password_token and
                ("Could not obtain cached" not in out))


def test_authentication_using_accountstore_user_not_found(
        default_authenticator):
    da = default_authenticator
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    dumb_token = UsernamePasswordToken(username='dumb',
                                       password='token',
                                       remember_me=False,
                                       host='127.0.0.1')

    with pytest.raises(AuthenticationException):
        da.authenticate_account(dumb_token)

    assert (event_detected.authc_token == dumb_token)
