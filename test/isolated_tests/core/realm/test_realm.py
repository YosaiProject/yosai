import pytest

from yosai.core import (
    AccountStoreRealm,
    ConsumedTOTPToken,
    IncorrectCredentialsException,
    PasslibVerifier,
    TOTPToken,
    UsernamePasswordToken,
)
from unittest import mock

# -----------------------------------------------------------------------------
# AccountStoreRealm Tests
# -----------------------------------------------------------------------------

def test_supports(account_store_realm, monkeypatch, username_password_token):
    asr = account_store_realm
    monkeypatch.setattr(asr, 'token_resolver', {UsernamePasswordToken: 'bla'})
    assert asr.supports(username_password_token)


def test_asr_init_token_resolution(
        account_store_realm, monkeypatch, username_password_token):
    asr = account_store_realm
    mock_verifier = mock.MagicMock()
    mock_verifier.supported_tokens = [UsernamePasswordToken]
    monkeypatch.setattr(asr, 'authc_verifiers', (mock_verifier,))
    result = asr.init_token_resolution()
    assert result[UsernamePasswordToken] == mock_verifier


def test_asr_do_clear_cache(account_store_realm):
    """
    unit tested:  do_clear_cache

    test case:
    in turn calls the clear cache methods for credentials and authz info
    """
    asr = account_store_realm
    with mock.patch.object(AccountStoreRealm, 'clear_cached_authc_info') as ccc:
        ccc.return_value = None

        with mock.patch.object(AccountStoreRealm,
                               'clear_cached_authorization_info') as ccai:
            ccai.return_value = None

            asr.do_clear_cache('identifier')

            ccc.assert_called_once_with('identifier')
            ccai.assert_called_once_with('identifier')


def test_asr_clear_cached_authc_info(account_store_realm, monkeypatch):
    """
    unit tested: clear_cached_authc_info

    test case:
    delegates to cch.clear_cache
    """
    asr = account_store_realm
    monkeypatch.setattr(asr, 'cache_handler', mock.Mock())
    asr.clear_cached_authc_info('identifier')
    asr.cache_handler.delete.assert_called_once_with('authentication:AccountStoreRealm',
                                                     'identifier')


def test_asr_clear_cached_authorization_info(
        account_store_realm, monkeypatch):
    """
    unit tested: clear_cached_authorization_info

    test case:
    delegates to ach.clear_cache
    """
    asr = account_store_realm
    monkeypatch.setattr(asr, 'cache_handler', mock.Mock())
    asr.clear_cached_authorization_info('identifier')
    asr.cache_handler.delete.assert_called_once_with('authorization:AccountStoreRealm',
                                                     'identifier')


def test_lock_account(account_store_realm, monkeypatch):
    asr = account_store_realm
    mock_lock = mock.MagicMock()
    monkeypatch.setattr(asr.account_store, 'lock_account', mock_lock)
    asr.lock_account('identifier')
    assert mock_lock.called


def test_unlock_account(account_store_realm, monkeypatch):
    asr = account_store_realm
    mock_lock = mock.MagicMock()
    monkeypatch.setattr(asr.account_store, 'unlock_account', mock_lock)
    asr.unlock_account('identifier')
    assert mock_lock.called


def test_asr_get_authc_info_from_cache(
        account_store_realm, monkeypatch):
    asr = account_store_realm
    mock_cache = mock.MagicMock()
    mock_cache.get_or_create.return_value = {'authc_info': 'bla'}
    monkeypatch.setattr(asr, 'cache_handler', mock_cache)
    result = asr.get_authentication_info('identifier')
    assert (result['account_id'].primary_identifier == 'identifier' and
            result['authc_info'] == 'bla')


def test_asr_get_authc_info_without_cache_and_from_accountstore(
        account_store_realm, monkeypatch):
    asr = account_store_realm
    monkeypatch.setattr(asr, 'cache_handler', None)
    monkeypatch.setattr(asr.account_store,
                        'get_authc_info',
                        lambda x: {'authc_info': 'authc_info'})
    result = asr.get_authentication_info('identifier')
    assert result['authc_info'] == 'authc_info'


def test_asr_get_authc_info_cannot_locate(account_store_realm, monkeypatch):
    asr = account_store_realm
    monkeypatch.setattr(asr, 'cache_handler', None)
    monkeypatch.setattr(asr.account_store, 'get_authc_info', lambda x: None)

    with pytest.raises(ValueError):
        asr.get_authentication_info('identifier')


def test_asr_authenticate_account_invalidtoken(account_store_realm):
    asr = account_store_realm

    with pytest.raises(AttributeError):
        asr.authenticate_account('invalid_token')


@mock.patch.object(AccountStoreRealm, 'clear_cached_authc_info')
@mock.patch.object(AccountStoreRealm, 'assert_credentials_match')
@mock.patch.object(AccountStoreRealm, 'get_authentication_info')
def test_asr_authenticate_account_succeeds(
        mock_gc, mock_acm, mock_ccc, account_store_realm,
        monkeypatch, sample_acct_info, username_password_token):
    """
    - obtains identitier from token
    - get_authc_info returns a mock_account
    - assert_credentials_match doesn't raise
    """
    mock_gc.return_value = sample_acct_info
    asr = account_store_realm
    monkeypatch.setattr(asr, 'token_resolver', {UsernamePasswordToken: 'verifier'})
    account = asr.authenticate_account(username_password_token)
    mock_acm.assert_called_once_with('verifier', username_password_token, sample_acct_info)
    assert account == sample_acct_info


def test_update_failed_attempt(
        account_store_realm, monkeypatch, username_password_token,
        sample_acct_info):

    asr = account_store_realm
    mock_token_info = {'cred_type': 'password'}
    monkeypatch.setattr(username_password_token, 'token_info', mock_token_info, raising=False)
    mock_ch = mock.MagicMock()
    monkeypatch.setattr(asr, 'cache_handler', mock_ch)
    asr.update_failed_attempt(username_password_token, sample_acct_info)
    mock_ch.set.assert_called_once_with(domain='authentication:' + asr.name,
                                        identifier=username_password_token.identifier,
                                        value=sample_acct_info)
    assert len(sample_acct_info['authc_info']['password']['failed_attempts']) == 2


def test_asr_acm_succeeds(account_store_realm, sample_acct_info):
    """
    unit tested:  assert_credentials_match

    test case:
    when credentials match, nothing is returned nor any exceptions raise
    """
    asr = account_store_realm
    mock_verifier = mock.create_autospec(PasslibVerifier)
    mock_authc_token = mock.MagicMock()
    mock_authc_token.token_info = {'cred_type': 'password'}
    asr.assert_credentials_match(mock_verifier, mock_authc_token, sample_acct_info)
    mock_verifier.verify_credentials.\
        assert_called_once_with(mock_authc_token, sample_acct_info['authc_info'])


@mock.patch.object(AccountStoreRealm, 'update_failed_attempt')
def test_asr_acm_raises(mock_ufa, account_store_realm, sample_acct_info,
                        username_password_token, monkeypatch):
    """
    unit tested:  assert_credentials_match

    test case:
    when credentials fail to match, an exception is raised
    """
    asr = account_store_realm
    upt = username_password_token
    mock_token_info = {'cred_type': 'password'}
    monkeypatch.setattr(upt, 'token_info', mock_token_info, raising=False)
    updated_acct = sample_acct_info
    updated_acct['authc_info']['password']['failed_attempts'] = [1, 2, 3]
    mock_ufa.return_value = updated_acct

    mock_verifier = mock.create_autospec(PasslibVerifier)
    mock_verifier.verify_credentials.side_effect = IncorrectCredentialsException

    with pytest.raises(IncorrectCredentialsException) as exc:
        asr.assert_credentials_match(mock_verifier, upt, sample_acct_info)

    assert exc.value.failed_attempts == [1, 2, 3]
    mock_ufa.assert_called_once_with(upt, sample_acct_info)


def test_asr_acm_consumed_token(account_store_realm, sample_acct_info,
                                monkeypatch):
    asr = account_store_realm
    mock_token = mock.create_autospec(TOTPToken)
    mock_token.token_info = {'cred_type': 'totp_key'}
    mock_token.identifier = 'identifier'
    monkeypatch.setitem(sample_acct_info['authc_info'], 'totp_key', dict())

    mock_verifier = mock.create_autospec(PasslibVerifier)
    mock_verifier.verify_credentials.side_effect = ConsumedTOTPToken

    mock_ch = mock.MagicMock()
    monkeypatch.setattr(asr, 'cache_handler', mock_ch)

    asr.assert_credentials_match(mock_verifier, mock_token, sample_acct_info)

    mock_ch.set.assert_called_once_with(domain='authentication:'+ asr.name,
                                        identifier=mock_token.identifier,
                                        value=sample_acct_info)


def test_asr_get_authz_info_from_cache(
        account_store_realm, monkeypatch, simple_identifier_collection):

    sic = simple_identifier_collection
    asr = account_store_realm

    mock_cache = mock.Mock()
    mock_cache.get_or_create.return_value = {'authz_info': 'cached_authz_info'}
    monkeypatch.setattr(asr, 'cache_handler', mock_cache)

    result = asr.get_authorization_info(sic)

    assert (result['account_id'] == sic and
            result['authz_info'] == 'cached_authz_info')


def test_asr_get_authz_info_without_cache_from_accountstore(
        account_store_realm, monkeypatch, simple_identifier_collection,
        sample_acct_info):
    asr = account_store_realm
    sic = simple_identifier_collection
    monkeypatch.setattr(asr, 'cache_handler', None)
    monkeypatch.setattr(asr.account_store, 'get_authz_info', lambda x: sample_acct_info)
    result = asr.get_authorization_info(sic)
    assert result['authz_info'] == 'authz_info'


def test_asr_get_authz_info_cannot_locate(
        account_store_realm, monkeypatch, simple_identifier_collection):
    asr = account_store_realm
    sic = simple_identifier_collection
    monkeypatch.setattr(asr, 'cache_handler', None)
    monkeypatch.setattr(asr.account_store, 'get_authz_info', lambda x: None)

    with pytest.raises(ValueError):
        asr.get_authorization_info(sic)


def test_asr_is_permitted_yields(
        account_store_realm, monkeypatch, simple_identifier_collection,
        sample_acct_info):
    """
    unit tested:  is_permitted

    test case:
    - gets authorization info
    - yields from the permission_verifier, one permission at a time
    """
    asr = account_store_realm
    sic = simple_identifier_collection

    def mock_yielder(authz_info, input):
        yield ('permission', True)

    monkeypatch.setattr(asr, 'get_authorization_info', lambda x: sample_acct_info)
    monkeypatch.setattr(asr.permission_verifier, 'is_permitted', mock_yielder)

    results = list(asr.is_permitted(sic, ['domain:action']))
    assert results == [('permission', True)]


def test_asr_is_permitted_no_account_obtained(
        account_store_realm, monkeypatch, simple_identifier_collection):
    """
    unit tested:  is_permitted

    test case:
    - no account can be obtained from  get_authorization_info
    - yields False for each permission requested
    """
    asr = account_store_realm
    sic = simple_identifier_collection

    monkeypatch.setattr(asr, 'get_authorization_info', lambda x: None)

    results = list(asr.is_permitted(sic, ['domain1:action1', 'domain2:action1']))
    assert results == [('domain1:action1', False), ('domain2:action1', False)]


def test_asr_has_role_yields(
        account_store_realm, monkeypatch, simple_identifier_collection,
        sample_acct_info):
    """
    unit tested:  has_role

    test case:
    - gets authorization info
    - yields from the role_verifier, one role at a time
    """
    asr = account_store_realm
    sic = simple_identifier_collection

    def mock_yielder(authz_info, input):
        yield ('roleid1', False)

    monkeypatch.setattr(asr, 'get_authorization_info', lambda x: sample_acct_info)
    monkeypatch.setattr(asr.role_verifier, 'has_role', mock_yielder)

    results = list(asr.has_role(sic, {'roleid1'}))
    assert results == [('roleid1', False)]


def test_asr_has_role_no_account_obtained(
        account_store_realm, monkeypatch, simple_identifier_collection):
    """
    unit tested:  has_role

    test case:
    - no account can be obtained from  get_authorization_info
    - yields False for each role requested
    """
    asr = account_store_realm
    sic = simple_identifier_collection

    monkeypatch.setattr(asr, 'get_authorization_info', lambda x: None)

    results = list(asr.has_role(sic, ['role1', 'role2']))
    assert results == [('role1', False), ('role2', False)]
