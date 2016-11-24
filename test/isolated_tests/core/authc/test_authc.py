import pytest
from passlib.totp import MalformedTokenError
from unittest import mock
import collections

from yosai.core import (
    AccountException,
    AccountStoreRealm,
    AdditionalAuthenticationRequired,
    ConsumedTOTPToken,
    DefaultAuthenticator,
    AuthenticationAttempt,
    IncorrectCredentialsException,
    InvalidAuthenticationSequenceException,
    LockedAccountException,
    SimpleIdentifierCollection,
    UsernamePasswordToken,
    TOTPToken,
    create_totp_factory,
    event_bus,
)

from passlib.totp import TOTP

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

def test_totp_credentials_raises():
    with pytest.raises(MalformedTokenError):
        TOTPToken(1234567)


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
    monkeypatch.setattr(da, 'authentication_strategy', lambda x: x)

    result = da.authenticate_multi_realm_account(('realm1', 'realm2'), 'authc_token')

    assert result == AuthenticationAttempt('authc_token', ('realm1', 'realm2'))


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

    with pytest.raises(AdditionalAuthenticationRequired):
        da.authenticate_account(None, mock_token)

    da_ne.assert_called_once_with('user123', 'AUTHENTICATION.PROGRESS')
    da_daa.assert_called_once_with(mock_token)


@mock.patch.object(DefaultAuthenticator, 'notify_event')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_catches_additional_includes_secondfactor(
        da_daa, da_ne, default_authenticator, monkeypatch):
    sic = mock.MagicMock()
    sic.primary_identifier = 'user123'
    da_daa.side_effect = AdditionalAuthenticationRequired(sic)
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'

    mock_totptoken = mock.create_autospec(TOTPToken)

    with pytest.raises(AdditionalAuthenticationRequired):
        da.authenticate_account(None, mock_token, mock_totptoken)

    da_ne.assert_called_once_with('user123', 'AUTHENTICATION.PROGRESS')
    da_daa.assert_has_calls([mock.call(mock_token), mock.call(mock_totptoken)])


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
    monkeypatch.delitem(sample_acct_info['authc_info'], 'totp_key')
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
    monkeypatch.delitem(sample_acct_info['authc_info'], 'totp_key')
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


@mock.patch.object(DefaultAuthenticator, 'validate_locked')
@mock.patch.object(DefaultAuthenticator, 'authenticate_single_realm_account')
def test_da_do_authc_acct_req_additional(
        da_asra, da_vl, default_authenticator, sample_acct_info, monkeypatch):
    da_asra.return_value = sample_acct_info
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_token.token_info = {'tier': 1, 'cred_type': 'password'}

    faux_authc_realm = mock.create_autospec(AccountStoreRealm)
    faux_authc_realm.generate_totp_token.return_value = 'totp_token'
    token_realm_resolver = {UsernamePasswordToken: (faux_authc_realm,),
                            TOTPToken: (faux_authc_realm,)}
    monkeypatch.setattr(da, 'token_realm_resolver', token_realm_resolver)
    monkeypatch.setattr(da, 'realms', (faux_authc_realm,))
    mock_dispatcher = mock.MagicMock()
    monkeypatch.setattr(da, 'mfa_dispatcher', mock_dispatcher, raising=False)

    with pytest.raises(AdditionalAuthenticationRequired):
        da.do_authenticate_account(mock_token)

    da_vl.assert_called_once_with(mock_token, [1477077663111])
    da_asra.assert_called_once_with(faux_authc_realm, mock_token)
    mock_dispatcher.dispatch.assert_called_once_with('user123',
                                                     sample_acct_info['authc_info']['totp_key']['2fa_info'],
                                                     'totp_token')


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

    with mock.patch.object(event_bus, 'subscribe') as eb_r:
        eb_r.return_value = None
        with mock.patch.object(event_bus, 'isSubscribed') as eb_ir:
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
    mock_event_bus = mock.create_autospec(event_bus)
    monkeypatch.setattr(da, 'event_bus', mock_event_bus)

    da.notify_event('identifier', 'SOMETHING HAPPENED')

    mock_event_bus.sendMessage.assert_called_with('SOMETHING HAPPENED',
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


# -----------------------------------------------------------------------------
# PasslibVerifier Tests
# -----------------------------------------------------------------------------


def test_verify_userpass_credentials(
        passlib_verifier, username_password_token, monkeypatch):
    pv = passlib_verifier
    monkeypatch.setattr(pv, 'get_stored_credentials', lambda x, y: 'stored')
    mock_service = mock.MagicMock()
    monkeypatch.setattr(pv, 'password_cc', mock_service)
    pv.verify_credentials(username_password_token, {'totp': {}})

    mock_service.verify.assert_called_once_with(username_password_token.credentials, 'stored')


def test_verify_credentials_totp_fails(passlib_verifier, totp_token, monkeypatch):
    pv = passlib_verifier
    key = 'DP3RDO3FAAFUAFXQELW6OTB2IGM3SS6G'
    monkeypatch.setattr(pv, 'get_stored_credentials', lambda x, y: key)
    totp_factory = mock.MagicMock()
    totp_factory.verify.side_effect = ValueError
    monkeypatch.setattr(pv, 'totp_factory', totp_factory)

    with pytest.raises(IncorrectCredentialsException):
        pv.verify_credentials(totp_token, {'totp_key': {'consumed_token': None}})


def test_verify_totp_credentials(passlib_verifier, totp_token, monkeypatch):
    pv = passlib_verifier
    key = 'DP3RDO3FAAFUAFXQELW6OTB2IGM3SS6G'
    monkeypatch.setattr(pv, 'get_stored_credentials', lambda x, y: key)
    totp_factory = mock.MagicMock()
    totp_factory.verify.return_value = 'result'
    monkeypatch.setattr(pv, 'totp_factory', totp_factory)

    with pytest.raises(ConsumedTOTPToken) as exc:
        pv.verify_credentials(totp_token, {'totp_key': {'consumed_token': None}})
        assert exc.totp_match == 'result'

    totp_factory.verify.assert_called_once_with(totp_token.credentials, key)


def test_verify_credentials_noresult_raises_incorrect(
        passlib_verifier, username_password_token, monkeypatch):
    pv = passlib_verifier
    monkeypatch.setattr(pv, 'get_stored_credentials', lambda x, y: 'stored')

    with pytest.raises(IncorrectCredentialsException):
        pv.verify_credentials(username_password_token, 'authc_info')


@mock.patch.object(TOTP, 'using')
def test_create_totp_factory(totp_using, passlib_verifier):
    totp_using.return_value = 'factory'
    mock_settings = mock.MagicMock()
    mock_settings.totp_context = {'secrets': {'one': 'one'}}
    result = create_totp_factory(authc_settings=mock_settings)

    assert result == 'factory'
    totp_using.assert_called_once_with(secrets={'one': 'one'})
