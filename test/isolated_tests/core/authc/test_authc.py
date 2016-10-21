import pytest
from unittest import mock
import collections

from yosai.core import (
    AccountException,
    AccountStoreRealm,
    AuthenticationException,
    DefaultAuthenticator,
    DefaultAuthenticationAttempt,
    DefaultEventBus,
    InvalidAuthenticationSequenceException,
    MultiRealmAuthenticationException,
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


@mock.patch.object(DefaultAuthenticator, 'notify_account_not_found')
def test_da_authenticate_account_no_authc_identifier_assigns_raisesaccount(
        da_nanf, default_authenticator, monkeypatch):
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_identifiers = mock.create_autospec(SimpleIdentifierCollection)
    mock_identifiers.primary_identifier = 'test_identifiers'
    mock_token.identifier = None
    monkeypatch.setattr(da, 'do_authenticate_account', lambda x: None)

    with pytest.raises(AccountException):
        da.authenticate_account(mock_identifiers, mock_token)
    mock_token.identifier = 'test_identifiers'
    da_nanf.assert_called_once_with(mock_token.identifier)


@mock.patch.object(DefaultAuthenticator, 'notify_success')
@mock.patch.object(DefaultAuthenticator, 'do_authenticate_account')
def test_da_authenticate_account_succeeds(da_daa, da_ns, default_authenticator):
    da = default_authenticator
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.identifier = 'user123'
    mock_identifiers = mock.create_autospec(SimpleIdentifierCollection)
    mock_identifiers.primary_identifier = 'test_identifiers'
    da_daa.return_value = {'account_id': mock_identifiers}
    result = da.authenticate_account(None, mock_token)

    da_ns.assert_called_once_with('test_identifiers')
    da_daa.assert_called_once_with(mock_token)
    assert result == mock_identifiers


    #assert authc_token.identifier == 'test_identifiers'
    # assert authc_token.token_info == {'tier': 1, 'cred_type': 'password'}

    #da = default_authenticator
#def test_da_authenticate_account_catches_additional(default_authenticator):
    #da = default_authenticator
#def test_da_authenticate_account_catches_accountexc(default_authenticator):
    #da = default_authenticator
#def test_da_authenticate_account_catches_lockedexc(default_authenticator):
    #da = default_authenticator
#def test_da_authenticate_account_catches_incorrectexc(default_authenticator):
    #da = default_authenticator




def test_da_authc_acct_authentication_fails(
        default_authenticator, username_password_token, monkeypatch):
    """
    unit tested:  authenticate_account

    when None is returned from do_authenticate_account, it means that
    something other than authentication failed, and so an exception is
    raised
    """
    da = default_authenticator
    token = username_password_token

    def do_nothing(x, y):
        pass

    monkeypatch.setattr(da, 'do_authenticate_account', do_nothing)
    monkeypatch.setattr(da, 'notify_failure', do_nothing)
    monkeypatch.setattr(da, 'notify_success', do_nothing)

    with pytest.raises(AuthenticationException):
        da.authenticate_account(token)


def test_da_authc_acct_authentication_raises_unknown_exception(
        default_authenticator, username_password_token, monkeypatch):
    """
    unit tested:  authenticate_account

    an unexpected exception will be wrapped by an AuthenticationException
    """
    da = default_authenticator
    token = username_password_token

    def raise_typeerror():
        raise TypeError

    def do_nothing(x, y):
        pass

    monkeypatch.setattr(da, 'do_authenticate_account', raise_typeerror)
    monkeypatch.setattr(da, 'notify_failure', do_nothing)
    monkeypatch.setattr(da, 'notify_success', do_nothing)

    with pytest.raises(AuthenticationException) as exc_info:
        da.authenticate_account(token)

    assert 'unexpected' in str(exc_info.value)


def test_da_authc_acct_authentication_succeeds(
        default_authenticator, username_password_token, monkeypatch,
        full_mock_account):
    """
    unit tested:  authenticate_account

    when an Account is returned from do_authenticate_account, it means that
    authentication succeeded
    """
    da = default_authenticator
    token = username_password_token

    def get_mock_account(self, x=None):
        return full_mock_account

    monkeypatch.setattr(da, 'do_authenticate_account', get_mock_account)
    monkeypatch.setattr(da, 'notify_failure', lambda x: None)
    monkeypatch.setattr(da, 'notify_success', lambda x: None)

    result = da.authenticate_account(token)

    assert isinstance(result, full_mock_account.__class__)



def test_da_do_authc_acct_with_realm(
        default_authenticator, username_password_token,
        one_accountstorerealm_succeeds, monkeypatch):
    """
    unit tested:  authenticate_account

    when the DefaultAuthenticator is missing a realms attribute, an
    exception will raise in do_authenticate_account
    """

    da = default_authenticator
    token = username_password_token

    da.realms = one_accountstorerealm_succeeds

    def say_nothing(x, y):
        return 'nothing'

    monkeypatch.setattr(da, 'authenticate_single_realm_account', say_nothing)
    result = da.do_authenticate_account(token)
    assert result == 'nothing'


def test_da_do_authc_acct_with_realms(
        default_authenticator, username_password_token,
        two_accountstorerealms_succeeds, monkeypatch):
    """
    unit tested:  authenticate_account
    """
    da = default_authenticator
    token = username_password_token

    da.realms = two_accountstorerealms_succeeds

    def say_something(self, x=None, y=None):
        return 'something'

    monkeypatch.setattr(da, 'authenticate_multi_realm_account', say_something)
    result = da.do_authenticate_account(token)
    assert result == 'something'


def test_da_do_authc_acct_without_realm(
        default_authenticator, username_password_token):
    """
    unit tested:  authenticate_account

    when the DefaultAuthenticator is missing a realms attribute, an
    exception will raise in do_authenticate_account
    """

    da = default_authenticator
    token = username_password_token

    with pytest.raises(AuthenticationException):
        da.do_authenticate_account(token)


def test_da_clear_cache(
        default_authenticator, simple_identifier_collection, full_mock_account):
    sic = simple_identifier_collection
    da = default_authenticator

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_key'])
    st = session_tuple(sic, 'sessionkey123')

    with mock.patch.object(AccountStoreRealm, 'clear_cached_credentials') as ccc:
        ccc.return_value = None

        da.clear_cache(items=st)

        ccc.assert_called_once_with(sic.from_source('AccountStoreRealm'))


def test_da_register_cache_clear_listener(default_authenticator, event_bus):
    da = default_authenticator

    with mock.patch.object(event_bus, 'register') as eb_r:
        eb_r.return_value = None
        with mock.patch.object(event_bus, 'is_registered') as eb_ir:
            eb_ir.return_value = None

            da.register_cache_clear_listener()

            calls = [mock.call(da.clear_cache, 'SESSION.EXPIRE'),
                     mock.call(da.clear_cache, 'SESSION.STOP')]

            eb_r.assert_has_calls(calls)
            eb_ir.assert_has_calls(calls)


def test_da_notify_success(default_authenticator, full_mock_account, event_bus):
    """
    unit tested:  notify_success

    test case:
    creates an Event and publishes it to the event_bus
    """
    da = default_authenticator
    fma = full_mock_account

    with mock.patch.object(event_bus, 'publish') as eb_pub:
        eb_pub.return_value = None

        da.notify_success(fma)

        assert eb_pub.call_args == mock.call('AUTHENTICATION.SUCCEEDED',
                                             identifiers=fma.account_id)


def test_da_notify_success_raises(
        default_authenticator, monkeypatch, full_mock_account):
    """
    unit tested:  notify_success

    test case:
    creates an Event, tries publishes it to the event_bus,
    but fails and so raises an exception
    """
    da = default_authenticator

    monkeypatch.setattr(da, '_event_bus', None)

    with pytest.raises(ValueError):
        da.notify_success(full_mock_account)


def test_da_notify_failure(
        default_authenticator, username_password_token, monkeypatch):
    """
    unit tested:  notify_failure

    test case:
    creates an Event and publishes it to the event_bus
    """
    da = default_authenticator
    authc_token = username_password_token

    with mock.patch.object(DefaultEventBus, 'publish') as eb_pub:
        eb_pub.return_value = None

        da.notify_failure(authc_token, 'throwable')

        assert eb_pub.call_args == mock.call('AUTHENTICATION.FAILED',
                                             username=authc_token.username)


def test_da_notify_falure_raises(default_authenticator, monkeypatch):
    """
    unit tested:  notify_failure

    test case:
    creates an Event, tries publishes it to the event_bus,
    but fails and so raises an exception
    """
    da = default_authenticator

    monkeypatch.setattr(da, '_event_bus', None)

    with pytest.raises(ValueError):
        da.notify_failure('token', 'throwable')


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
