import pytest
from yosai.core import (
    AuthenticationException,
    Credential,
    SerializationManager,
    UsernamePasswordToken,
    AuthenticationException,
)


def test_authentication_using_accountstore_success(
        caplog, default_authenticator, valid_username_password_token,
        event_bus):
    da = default_authenticator
    event_detected = None

    def event_listener(identifiers=None):
        nonlocal event_detected
        event_detected = identifiers
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    account = da.authenticate_account(valid_username_password_token)
    out = caplog.text
    assert (event_detected == account.account_id and
            ("Could not obtain cached" in out and "No account" not in out))


def test_authentication_using_cache_success(
        caplog, default_authenticator, invalid_username_password_token,
        valid_username_password_token, cache_handler, event_bus):

    da = default_authenticator
    event_detected = None

    def event_listener(identifiers=None):
        nonlocal event_detected
        event_detected = identifiers
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    with pytest.raises(AuthenticationException):
        da.authenticate_account(invalid_username_password_token)

        account = da.authenticate_account(valid_username_password_token)

        out = caplog.text
        assert (event_detected == account.account_id and
                ("Could not obtain cached" not in out) and
                account.account_id == valid_username_password_token.identifier)


def test_authentication_using_accountstore_pw_failure(
        caplog, default_authenticator, invalid_username_password_token,
        event_bus):

    da = default_authenticator
    event_detected = None

    def event_listener(username=None):
        nonlocal event_detected
        event_detected = username
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    with pytest.raises(AuthenticationException):
        account = da.authenticate_account(invalid_username_password_token)

        out = caplog.text
        assert (event_detected == account.account_id and
                ("Could not obtain cached" in out and "No account" not in out))


def test_authentication_using_cache_pw_failure(
        caplog, default_authenticator, invalid_username_password_token,
        cache_handler, event_bus):

    da = default_authenticator
    event_detected = None

    def event_listener(username=None):
        nonlocal event_detected
        event_detected = username
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    cred = Credential('letsgobowlingggggg')
    cache_handler.set(domain='credentials', identifier='thedude', value=cred)

    with pytest.raises(AuthenticationException):
        da.authenticate_account(invalid_username_password_token)
        out = caplog.text

        assert (event_detected == invalid_username_password_token.username and
                ("Could not obtain cached" not in out))

    cache_handler.delete(domain='credentials', identifier='thedude')

def test_authentication_using_accountstore_user_not_found(
        default_authenticator, event_bus):
    da = default_authenticator
    event_detected = None

    def event_listener(username=None):
        nonlocal event_detected
        event_detected = username
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    dumb_token = UsernamePasswordToken(username='dumb',
                                       password='token',
                                       remember_me=False,
                                       host='127.0.0.1')

    with pytest.raises(AuthenticationException):
        da.authenticate_account(dumb_token)

    assert (event_detected == dumb_token.username)
