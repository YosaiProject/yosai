import pytest

from yosai import (
    IllegalStateException,
    MissingCredentialsException,
    PasswordMatcherInvalidAccountException,
    PasswordMatcherInvalidTokenException,
    AllowAllCredentialsMatcher,
    PasswordMatcher,
    SimpleCredentialsMatcher,
)

# -----------------------------------------------------------------------------
# PasswordMatcher Tests
# -----------------------------------------------------------------------------
# no need to unit-test credentials_match since its tests are implicit
def test_dpm_ensure_password_service_succeeds(default_password_matcher):
    """ by default, password_service should be set """
    assert default_password_matcher.ensure_password_service()

def test_dpm_ensure_password_service_fails(default_password_matcher, monkeypatch):
    monkeypatch.setattr(default_password_matcher, 'password_service', None)
    with pytest.raises(IllegalStateException):
        assert default_password_matcher.ensure_password_service()

def test_dpm_get_submitted_password_succeeds(
        default_password_matcher, username_password_token):
    dpm = default_password_matcher
    assert dpm.get_submitted_password(username_password_token)

def test_dpm_get_submitted_password_fails(
        default_password_matcher, username_password_token, monkeypatch):
    dpm = default_password_matcher
    token = username_password_token
    monkeypatch.delattr(token, '_credentials')
    with pytest.raises(PasswordMatcherInvalidTokenException):
        dpm.get_submitted_password(username_password_token)

def test_dpm_get_stored_password_succeeds(
        default_password_matcher, full_mock_account):
    dpm = default_password_matcher
    assert dpm.get_stored_password(full_mock_account)

def test_dpm_get_stored_password_fails(
        default_password_matcher, full_mock_account, monkeypatch):
    dpm = default_password_matcher
    monkeypatch.delattr(full_mock_account, '_credentials')
    with pytest.raises(PasswordMatcherInvalidAccountException):
        dpm.get_stored_password(full_mock_account)

# -----------------------------------------------------------------------------
# SimpleCredentialsMatcher Tests
# -----------------------------------------------------------------------------

def test_scm_get_credentials_succeeds(
        default_simple_credentials_matcher, full_mock_account):
    """ verify normal behavior """ 
    dscm = default_simple_credentials_matcher 
    fma = full_mock_account
    assert dscm.get_credentials(fma) == fma.credentials

def test_scm_get_credentials_fails(
        default_simple_credentials_matcher, full_mock_account, monkeypatch):
    """ a credential source without credentials raises an exception """
    dscm = default_simple_credentials_matcher 
    fma = full_mock_account
    monkeypatch.delattr(fma, '_credentials')
    with pytest.raises(MissingCredentialsException):
        dscm.get_credentials(fma)
        
def test_scm_equals_using_two_strings(default_simple_credentials_matcher):
    """ strings are converted to bytearrays and then compared for equality """
    dscm = default_simple_credentials_matcher 
    a = 'grapesofwrath'
    b = 'eastofeden'
    c = 'ofmiceandmen'
    d = 'ofmiceandmen'
    assert (dscm.equals(a, b) is False and dscm.equals(c, d) is True)

def test_scm_equals_two_bytearrays(default_simple_credentials_matcher):
    dscm = default_simple_credentials_matcher 
    a = bytearray('grapesofwrath', 'utf-8') 
    b = bytearray('eastofeden', 'utf-8')
    c = bytearray('ofmiceandmen', 'utf-8')
    d = bytearray('ofmiceandmen', 'utf-8')
    assert (dscm.equals(a, b) is False and dscm.equals(c, d) is True)

def test_scm_equals_using_onestring_onebytearray(
        default_simple_credentials_matcher):
    dscm = default_simple_credentials_matcher 
    a = 'grapesofwrath'
    b = bytearray('eastofeden', 'utf-8')
    c = 'ofmiceandmen'
    d = bytearray('ofmiceandmen', 'utf-8')
    assert (dscm.equals(a, b) is False and dscm.equals(c, d) is True)

def test_scm_equals_using_onebytearray_onestring(
        default_simple_credentials_matcher):
    dscm = default_simple_credentials_matcher 
    a = bytearray('grapesofwrath', 'utf-8') 
    b = 'eastofeden'
    c = bytearray('ofmiceandmen', 'utf-8')
    d = 'ofmiceandmen'
    assert (dscm.equals(a, b) is False and dscm.equals(c, d) is True)

def test_scm_credentials_match_succeeds(
    default_simple_credentials_matcher, username_password_token, 
        full_mock_account, monkeypatch):
    dscm = default_simple_credentials_matcher 
    upt = username_password_token
    fma = full_mock_account
    monkeypatch.setattr(upt, '_credentials', 'ofmiceandmen')
    monkeypatch.setattr(fma, '_credentials', 'ofmiceandmen')
    assert dscm.credentials_match(upt, fma)

def test_scm_credentials_match_fails(
    default_simple_credentials_matcher, username_password_token, 
        full_mock_account, monkeypatch):
    dscm = default_simple_credentials_matcher 
    upt = username_password_token
    fma = full_mock_account
    monkeypatch.delattr(upt, '_credentials')
    monkeypatch.setattr(fma, '_credentials', 'ofmiceandmen')
    with pytest.raises(MissingCredentialsException):
        dscm.credentials_match(upt, fma)
