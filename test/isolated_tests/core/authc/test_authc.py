import pytest
from unittest import mock
import collections

from yosai.core import (
    AccountStoreRealm,
    AuthenticationException,
    AuthenticationEventException,
    DefaultEventBus,
    InvalidTokenPasswordException,
    MultiRealmAuthenticationException,
    UnsupportedTokenException,
    DefaultAuthenticator,
    DefaultCompositeAccount,
    UnauthenticatedException,
    UsernamePasswordToken,
    requires_authentication,
    requires_user,
    requires_guest,
    event_bus
)

# -----------------------------------------------------------------------------
# UsernamePasswordToken Tests
# -----------------------------------------------------------------------------
def test_upt_clear_existing_passwords_succeeds(username_password_token):
    """ clear a password bytearray equal to 'secret' """
    upt = username_password_token
    upt.clear()
    assert upt.password == bytearray(b'\x00\x00\x00\x00\x00\x00')

def test_upt_clear_existing_passwords_fails(
        username_password_token, monkeypatch):
    """ clear a password string equal to 'secret' raises an exception """
    upt = username_password_token
    monkeypatch.setattr(upt, '_password', 'secret')
    with pytest.raises(InvalidTokenPasswordException):
        upt.clear()


# -----------------------------------------------------------------------------
# DefaultAuthenticator Tests
# -----------------------------------------------------------------------------

def test_da_realms_setter(default_authenticator, default_accountstorerealm):
    faux_realm = type('FauxRealm', (object,), {})()
    asr = default_accountstorerealm
    da = default_authenticator
    da.realms = (faux_realm, asr)
    assert da._realms == (asr,)

def test_da_auth_sra_unsupported_token(
        default_authenticator, mock_token, default_accountstorerealm):
    """
    unit tested:  authenticate_single_realm_account

    An AuthenticationToken of a type unsupported by the Realm raises an
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
    """
    unit tested:  authenticate_single_realm_account

    a successful authentication returns an account
    """

    da = default_authenticator
    realm = first_accountstorerealm_succeeds
    token = username_password_token
    assert da.authenticate_single_realm_account(realm, token)


def test_da_autc_mra_succeeds(
        default_authenticator, two_accountstorerealms_succeeds,
        username_password_token):
    """
    unit tested:  authenticate_multi_realm_account
    """

    da = default_authenticator
    realms = two_accountstorerealms_succeeds
    token = username_password_token
    result = da.authenticate_multi_realm_account(realms, token)
    assert (result.__class__.__name__ == 'MockAccount')


def test_da_autc_mra_fails(
        default_authenticator, two_accountstorerealms_fails,
        username_password_token):
    """
    unit tested:  authenticate_multi_realm_account
    """

    da = default_authenticator
    realms = two_accountstorerealms_fails
    token = username_password_token

    with pytest.raises(MultiRealmAuthenticationException):
        da.authenticate_multi_realm_account(realms, token)


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


def test_da_register_cache_clear_listener(default_authenticator):
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


def test_da_notify_success(default_authenticator, full_mock_account):
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

    with pytest.raises(AuthenticationEventException):
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

    with pytest.raises(AuthenticationEventException):
        da.notify_failure('token', 'throwable')

# -----------------------------------------------------------------------------
# Decorator Tests
# -----------------------------------------------------------------------------

def test_requires_authentication_succeeds(
        monkeypatch, mock_subject, mock_secutil, yosai):
    """
    unit tested:  requires_authentication

    test case:
    a decorated method that requires authentication succeds to authenticate and
    then is called
    """
    csu = yosai

    @requires_authentication
    def do_something():
        return "something was done"

    with csu:
        monkeypatch.setattr(csu.subject, '_authenticated', True)
        result = do_something()

        assert result == "something was done"


def test_requires_authentication_raises(monkeypatch, mock_subject, yosai,
                                        yosai):

    """
    unit tested:  requires_authentication

    test case:
    a decorated method that requires authentication rails to authenticate and
    raises
    """
    csu = yosai

    @requires_authentication
    def do_something():
        return "something was done"

    with pytest.raises(UnauthenticatedException):
        with csu:
            do_something()


def test_requires_user_succeeds(monkeypatch, mock_subject,
                                yosai):
    """
    unit tested:  requires_user

    test case:
    a decorated method that requires a 'User-Subject' succeeds to obtain
    a User status and then is called
    """
    csu = yosai

    @requires_user
    def do_something():
        return "something was done"

    with csu:
        monkeypatch.setattr(csu.subject, '_identifiers', True)
        result = do_something()

        assert result == "something was done"


def test_requires_user_raises(monkeypatch, mock_subject,
                              yosai):
    """
    unit tested:  requires_user

    test case:
    a decorated method that requires a 'User-Subject' fails to obtain
    a User status and raises
    """
    csu = yosai

    @requires_user
    def do_something():
        return "something was done"

    with pytest.raises(UnauthenticatedException):
        with csu:
            do_something()


def test_requires_guest_succeeds(monkeypatch, mock_subject,
                                 yosai):
    """
    unit tested:

    test case:
    a decorated method that requires a 'Guest-Subject' status succeeds in
    finding one
    """
    csu = yosai

    @requires_guest
    def do_something():
        return "something was done"

    with csu:
        monkeypatch.setattr(csu.subject, '_identifiers', None) 
        result = do_something()

        assert result == "something was done"


def test_requires_guest_raises(monkeypatch, mock_subject, yosai):
    """
    unit tested:

    test case:
    a decorated method that requires a 'Guest-Subject' status fails to find
    one, raising
    """
    csu = yosai

    @requires_guest
    def do_something():
        return "something was done"

    with pytest.raises(UnauthenticatedException):
        with csu:
            monkeypatch.setattr(csu.subject, '_identifiers', True) 
            do_something()
