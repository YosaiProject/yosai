import pytest
from yosai.core import (
    AdditionalAuthenticationRequired,
    AuthenticationException,
    InvalidAuthenticationSequenceException,
    SerializationManager,
    SimpleIdentifierCollection,
    UsernamePasswordToken,
    AuthenticationException,
)


def test_single_factor_authc_userpass_using_accountstore_success(
        caplog, default_authenticator, valid_username_password_token,
        event_bus, cache_handler):
    da = default_authenticator
    event_detected = None

    def event_listener(identifier=None):
        nonlocal event_detected
        event_detected = identifier
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    account_id = da.authenticate_account(None, valid_username_password_token)
    out = caplog.text
    assert (event_detected == account_id.primary_identifier and
            ("Could not obtain cached" in out and "No account" not in out))


def test_multi_factor_authc_raises_invalid_sequence(
        default_authenticator, valid_thedude_totp_token):
    da = default_authenticator

    with pytest.raises(InvalidAuthenticationSequenceException):
        da.authenticate_account(None, valid_thedude_totp_token)


def test_multi_factor_authc_using_accountstore_success(
        caplog, default_authenticator, valid_username_password_token,
        valid_totp_token, event_bus):
    da = default_authenticator
    success_event_detected = None
    progress_event_detected = None

    def progress_event_listener(identifier=None):
        nonlocal progress_event_detected
        progress_event_detected = identifier
    event_bus.register(progress_event_listener, 'AUTHENTICATION.PROGRESS')

    def success_event_listener(identifier=None):
        nonlocal success_event_detected
        success_event_detected = identifier
    event_bus.register(success_event_listener, 'AUTHENTICATION.SUCCEEDED')

    try:
        account_id = da.authenticate_account(None, valid_username_password_token)
    except AdditionalAuthenticationRequired as exc:
        account_id = da.authenticate_account(exc.account_id, valid_totp_token)

    out = caplog.text
    assert (success_event_detected == account_id.primary_identifier and
            progress_event_detected == account_id.primary_identifier and
            ("Could not obtain cached" in out and "No account" not in out))

def test_single_factor_authc_userpass_using_cache_success(
        caplog, default_authenticator, invalid_username_password_token,
        valid_username_password_token, cache_handler, event_bus):

    da = default_authenticator
    event_detected = None

    def event_listener(identifiers=None):
        nonlocal event_detected
        event_detected = identifiers
    event_bus.register(event_listener, 'AUTHENTICATION.SUCCEEDED')

    with pytest.raises(AuthenticationException):
        da.authenticate_account(None, invalid_username_password_token)

        account = da.authenticate_account(None, valid_username_password_token)

        out = caplog.text
        assert (event_detected == account.account_id and
                ("Could not obtain cached" not in out) and
                account.account_id == valid_username_password_token.identifier)


def test_single_factor_authc_userpass_using_accountstore_failure(
        caplog, default_authenticator, invalid_username_password_token,
        event_bus):

    da = default_authenticator
    event_detected = None

    def event_listener(username=None):
        nonlocal event_detected
        event_detected = username
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    with pytest.raises(AuthenticationException):
        account = da.authenticate_account(None, invalid_username_password_token)

        out = caplog.text
        assert (event_detected == account.account_id and
                ("Could not obtain cached" in out and "No account" not in out))


def test_single_factor_authc_userpass_using_cache_failure(
        caplog, default_authenticator, invalid_username_password_token,
        cache_handler, event_bus):

    da = default_authenticator
    event_detected = None

    def event_listener(username=None):
        nonlocal event_detected
        event_detected = username
    event_bus.register(event_listener, 'AUTHENTICATION.FAILED')

    cred = 'letsgobowlingggggg'
    cache_handler.set(domain='credentials', identifier='thedude', value=cred)

    with pytest.raises(AuthenticationException):
        da.authenticate_account(None, invalid_username_password_token)
        out = caplog.text

        assert (event_detected == invalid_username_password_token.username and
                ("Could not obtain cached" not in out))

    cache_handler.delete(domain='credentials', identifier='thedude')

def test_single_factor_authc_userpass_using_accountstore_user_not_found(
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
        da.authenticate_account(None, dumb_token)

    assert (event_detected == dumb_token.username)
