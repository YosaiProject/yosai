import pytest
from unittest import mock
import collections

from yosai.core import (
    AccountException,
    AccountStoreRealm,
    AdditionalAuthenticationRequired,
    DefaultAuthenticator,
    DefaultAuthenticationAttempt,
    DefaultEventBus,
    IncorrectCredentialsException,
    InvalidAuthenticationSequenceException,
    LockedAccountException,
    SimpleIdentifierCollection,
    UsernamePasswordToken,
    TOTPToken,
    realm_abcs,
)

# -----------------------------------------------------------------------------
# UsernamePasswordToken Tests
# -----------------------------------------------------------------------------


def test_upt_identifier_raises(username_password_token):
    with pytest.raises(ValueError):
        username_password_token.identifier = None


def test_upt_credentials_setting_raise(username_password_token):
    with pytest.raises(ValueError):
        username_password_token.credentials = 12345


# -----------------------------------------------------------------------------
# TOTPToken Tests
# -----------------------------------------------------------------------------

@pytest.mark.parametrize('credential, exc_class', [(1234, AssertionError),
                                                   ('123456', TypeError)])
def test_totp_credentials_raises(totp_token, credential, exc_class):
    with pytest.raises(exc_class):
        totp_token.credentials = credential


# -----------------------------------------------------------------------------
# DefaultAuthenticator Tests
# -----------------------------------------------------------------------------

@mock.patch.object(DefaultAuthenticator, 'init_locking')
@mock.patch.object(DefaultAuthenticator, 'register_cache_clear_listener')
@mock.patch.object(DefaultAuthenticator, 'init_token_resolution')
def test_da_init_realms(da_itr, da_rccl, da_il, default_authenticator):
    da = default_authenticator
    faux_realm = type('FauxRealm', (object,), {})()
    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    da.init_realms((faux_realm, faux_authc_realm))
    da_itr.assert_called_once_with()
    da_rccl.assert_called_once_with()
    da_il.assert_called_once_with()
    assert da.realms == (faux_authc_realm,)


def test_da_init_locking(monkeypatch, default_authenticator):
    da = default_authenticator

    monkeypatch.setattr(da.authc_settings, 'account_lock_threshold', 5)
    monkeypatch.setattr(da, 'locate_locking_realm', lambda: 'locking_realm')
    da.init_locking()

    assert da.locking_realm == 'locking_realm'
    assert da.locking_limit == 5


def test_da_init_token_resolution(default_authenticator, monkeypatch):
    da = default_authenticator

    faux_realm1 = mock.create_autospec(AccountStoreRealm)
    faux_realm1.supported_authc_tokens = (UsernamePasswordToken,)
    faux_realm2 = mock.create_autospec(AccountStoreRealm)
    faux_realm2.supported_authc_tokens = (UsernamePasswordToken, TOTPToken)

    realms = (faux_realm1, faux_realm2)
    monkeypatch.setattr(da, 'realms', realms)

    result = da.init_token_resolution()
    expected = collections.defaultdict(list)
    expected[UsernamePasswordToken] = [faux_realm1, faux_realm2]
    expected[TOTPToken] = [faux_realm2]

    assert result == expected


def test_da_locate_locking_realm(default_authenticator, monkeypatch):
    da = default_authenticator

    faux_realm1 = type('FauxRealm', (object,), {})()
    faux_realm2 = type('FauxRealm', (object,), {'lock_account': lambda x: 'yes'})()

    realms = (faux_realm1, faux_realm2)
    monkeypatch.setattr(da, 'realms', realms)
    result = da.locate_locking_realm()
    assert result == faux_realm2


def test_da_authc_sra(default_authenticator):
    da = default_authenticator
    faux_realm = mock.create_autospec(AccountStoreRealm)
    da.authenticate_single_realm_account(faux_realm, 'authc_token')
    faux_realm.authenticate_account.assert_called_once_with('authc_token')


def test_da_autc_mra(default_authenticator, monkeypatch):
    """
    unit tested:  authenticate_multi_realm_account
    """
    da = default_authenticator
    monkeypatch.setattr(da.authentication_strategy, 'execute', lambda x: x)

    result = da.authenticate_multi_realm_account(('realm1', 'realm2'), 'authc_token')

    assert result == DefaultAuthenticationAttempt('authc_token', ('realm1', 'realm2'))


def test_da_authenticate_account_no_authc_identifier_raises(default_authenticator):
    da = default_authenticator

    with pytest.raises(InvalidAuthenticationSequenceException):
        da.authenticate_account(None, 'mock_token')


@mock.patch.object(DefaultAuthenticator, 'notify_event')
def test_da_authenticate_account_no_authc_identifier_assigns_raisesaccount(
        da_ne, default_authenticator, monkeypatch):
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_identifiers = mock.create_autospec(SimpleIdentifierCollection)
    mock_identifiers.primary_identifier = 'test_identifiers'
    mock_token.identifier = None
    monkeypatch.setattr(da, 'do_authenticate_account', lambda x: None)

    with pytest.raises(AccountException):
        da.authenticate_account(mock_identifiers, mock_token)
    mock_token.identifier = 'test_identifiers'
    da_ne.assert_called_once_with(mock_token.identifier, 'AUTHENTICATION.ACCOUNT_NOT_FOUND')


@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_succeeds(da_daa, da_ne, default_authenticator):
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_identifiers = mock.create_autospec(SimpleIdentifierCollection)
    mock_identifiers.primary_identifier = 'test_identifiers'
    da_daa.return_value = {'account_id': mock_identifiers}
    result = da.authenticate_account(None, mock_token)

    da_ne.assert_called_once_with('test_identifiers', 'AUTHENTICATION.SUCCEEDED')
    da_daa.assert_called_once_with(mock_token)
    assert result == mock_identifiers


@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_catches_additional(
        da_daa, da_ne, default_authenticator, monkeypatch):
    da_daa.side_effect = AdditionalAuthenticationRequired
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_challenger = mock.MagicMock()
    monkeypatch.setattr(da, 'mfa_challenger', mock_challenger, raising=False)

    with pytest.raises(AdditionalAuthenticationRequired):
        da.authenticate_account(None, mock_token)

    da_ne.assert_called_once_with('user123', 'AUTHENTICATION.PROGRESS')
    da_daa.assert_called_once_with(mock_token)
    mock_challenger.send_challenge.assert_called_once_with('user123')


@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_catches_accountexc(
        da_daa, da_ne, default_authenticator, monkeypatch):
    da_daa.side_effect = AccountException
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'

    with pytest.raises(AccountException):
        da.authenticate_account(None, mock_token)

    da_ne.assert_called_once_with('user123', 'AUTHENTICATION.ACCOUNT_NOT_FOUND')
    da_daa.assert_called_once_with(mock_token)


@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_catches_lockedexc(
        da_daa, da_ne, default_authenticator, monkeypatch):
    da_daa.side_effect = LockedAccountException
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'

    with pytest.raises(LockedAccountException):
        da.authenticate_account(None, mock_token)

    notify_events = [mock.call('user123', 'AUTHENTICATION.FAILED'),
                     mock.call('user123', 'AUTHENTICATION.ACCOUNT_LOCKED')]
    da_ne.assert_has_calls(notify_events)
    da_daa.assert_called_once_with(mock_token)


@mock.patch.object(DefaultAuthenticator, 'validate_locked')
@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_catches_incorrectexc(
        da_daa, da_ne, da_vl, default_authenticator, monkeypatch):
    da_daa.side_effect = IncorrectCredentialsException(failed_attempts=5)
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'

    with pytest.raises(IncorrectCredentialsException):
        da.authenticate_account(None, mock_token)

    da_vl.assert_called_once_with(mock_token, 5)
    da_ne.assert_called_once_with('user123', 'AUTHENTICATION.FAILED')
    da_daa.assert_called_once_with(mock_token)


@mock.patch.object(DefaultAuthenticator, 'validate_locked')
@mock.patch.object(DefaultAuthenticator, 'authenticate_single_realm_account')
def test_da_do_authc_acct_sra_succeeds(
        da_asra, da_vl, default_authenticator, sample_acct_info, monkeypatch):
    monkeypatch.delitem(sample_acct_info['authc_info'], 'totp')
    da_asra.return_value = sample_acct_info
    da = default_authenticator

    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_token.token_info = {'tier': 1, 'cred_type': 'password'}

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    token_realm_resolver = {UsernamePasswordToken: (faux_authc_realm,)}
    monkeypatch.setattr(da, 'token_realm_resolver', token_realm_resolver)
    monkeypatch.setattr(da, 'realms', (faux_authc_realm,))

    da.do_authenticate_account(mock_token)

    da_vl.assert_called_once_with(mock_token, [1477077663111])
    da_asra.assert_called_once_with(faux_authc_realm, mock_token)


def test_da_do_authc_acct_resolver_raises(default_authenticator, monkeypatch):
    da = default_authenticator

    mock_token = mock.create_autospec(TOTPToken)
    mock_token.identifier = 'user123'
    mock_token.token_info = {'tier': 2, 'cred_type': 'totp'}

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    token_realm_resolver = {UsernamePasswordToken: (faux_authc_realm,)}
    monkeypatch.setattr(da, 'token_realm_resolver', token_realm_resolver)
    monkeypatch.setattr(da, 'realms', (faux_authc_realm,))

    with pytest.raises(KeyError):
        da.do_authenticate_account(mock_token)


@mock.patch.object(DefaultAuthenticator, 'validate_locked')
@mock.patch.object(DefaultAuthenticator, 'authenticate_multi_realm_account')
def test_da_do_authc_acct_multi_realm(
        da_amra, da_vl, default_authenticator, sample_acct_info, monkeypatch):
    monkeypatch.delitem(sample_acct_info['authc_info'], 'totp')
    da_amra.return_value = sample_acct_info
    da = default_authenticator

    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_token.token_info = {'tier': 1, 'cred_type': 'password'}

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    faux_authc_realm2 = mock.create_autospec(AccountStoreRealm)
    token_realm_resolver = {UsernamePasswordToken: (faux_authc_realm,)}
    monkeypatch.setattr(da, 'token_realm_resolver', token_realm_resolver)
    monkeypatch.setattr(da, 'realms', (faux_authc_realm, faux_authc_realm2))

    da.do_authenticate_account(mock_token)

    da_vl.assert_called_once_with(mock_token, [1477077663111])
    da_amra.assert_called_once_with(da.realms, mock_token)


@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'validate_locked')
@mock.patch.object(DefaultAuthenticator, 'authenticate_single_realm_account')
def test_da_do_authc_acct_req_additional(
        da_asra, da_vl, da_ne, default_authenticator, sample_acct_info, monkeypatch):
    da_asra.return_value = sample_acct_info
    da = default_authenticator

    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_token.token_info = {'tier': 1, 'cred_type': 'password'}

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    token_realm_resolver = {UsernamePasswordToken: (faux_authc_realm,)}
    monkeypatch.setattr(da, 'token_realm_resolver', token_realm_resolver)
    monkeypatch.setattr(da, 'realms', (faux_authc_realm,))

    with pytest.raises(AdditionalAuthenticationRequired):
        da.do_authenticate_account(mock_token)

    da_vl.assert_called_once_with(mock_token, [1477077663111])
    da_asra.assert_called_once_with(faux_authc_realm, mock_token)
    da_ne.assert_called_once_with(mock_token.identifier, 'AUTHENTICATION.PROGRESS')


def test_da_clear_cache(
        default_authenticator, simple_identifier_collection, monkeypatch):
    sic = simple_identifier_collection
    da = default_authenticator

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_key'])
    st = session_tuple(sic, 'sessionkey123')

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    faux_authc_realm.name = 'AccountStoreRealm'
    monkeypatch.setattr(da, 'realms', (faux_authc_realm,))

    da.clear_cache(items=st)

    faux_authc_realm.clear_cached_authc_info.\
        assert_called_once_with(sic.from_source('AccountStoreRealm'))


def test_da_clear_cache_raises(
        default_authenticator, simple_identifier_collection, monkeypatch, caplog):
    sic = simple_identifier_collection
    da = default_authenticator

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_key'])
    st = session_tuple(sic, 'sessionkey123')

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    faux_authc_realm.name = 'AccountStoreRealm'
    faux_authc_realm.clear_cached_authc_info.side_effect = AttributeError
    monkeypatch.setattr(da, 'realms', (faux_authc_realm,))

    da.clear_cache(items=st)

    faux_authc_realm.clear_cached_authc_info.\
        assert_called_once_with(sic.from_source('AccountStoreRealm'))

    assert 'Could not clear authc_info' in caplog.text


def test_da_register_cache_clear_listener(
        default_authenticator, event_bus, monkeypatch):
    da = default_authenticator
    monkeypatch.setattr(da, 'event_bus', event_bus)

    with mock.patch.object(event_bus, 'register') as eb_r:
        eb_r.return_value = None
        with mock.patch.object(event_bus, 'is_registered') as eb_ir:
            eb_ir.return_value = None

            da.register_cache_clear_listener()

            calls = [mock.call(da.clear_cache, 'SESSION.EXPIRE'),
                     mock.call(da.clear_cache, 'SESSION.STOP')]

            eb_r.assert_has_calls(calls)
            eb_ir.assert_has_calls(calls)


def test_da_notify_event(default_authenticator, sample_acct_info, monkeypatch):
    """
    unit tested:  notify_event

    test case:
    creates an Event and publishes it to the event_bus
    """
    da = default_authenticator
    mock_event_bus = mock.create_autospec(DefaultEventBus)
    monkeypatch.setattr(da, 'event_bus', mock_event_bus)

    da.notify_event('identifier', 'SOMETHING HAPPENED')

    mock_event_bus.publish.assert_called_with('SOMETHING HAPPENED',
                                              identifier='identifier')


def test_da_notify_event_raises(default_authenticator, sample_acct_info, monkeypatch):
    da = default_authenticator

    with pytest.raises(AttributeError):
        da.notify_event('identifier', 'bla')


@mock.patch.object(DefaultAuthenticator, 'notify_event')
def test_validate_locked(da_ne, default_authenticator, monkeypatch):
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_realm = mock.create_autospec(AccountStoreRealm)
    monkeypatch.setattr(da, 'locking_limit', 3)
    monkeypatch.setattr(da, 'locking_realm', mock_realm)

    with pytest.raises(LockedAccountException):
        da.validate_locked(mock_token, [1, 2, 3, 4])
        
    mock_realm.lock_account.assert_called_once_with('user123')
    da_ne.assert_called_once_with('user123', 'AUTHENTICATION.ACCOUNT_LOCKED')

# -----------------------------------------------------------------------------
# AuthenticationSettings Tests
# -----------------------------------------------------------------------------

def test_init_algorithms(authc_settings, monkeypatch, authc_config):
    monkeypatch.setattr(authc_settings, 'authc_config', authc_config)
    result = authc_settings.init_algorithms()
    assert result == {"bcrypt_sha256": {},
                      "sha256_crypt": {
                      "sha256_crypt__default_rounds": 110000,
                      "sha256_crypt__max_rounds": 1000000,
                      "sha256_crypt__min_rounds": 1000,
                      "sha256_crypt__salt_size": 16}}
