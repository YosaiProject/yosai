import pytest
from unittest import mock

from yosai import (
    MissingPrivateSaltException,
    PasswordMatchException,
    PepperPasswordException,
)

from yosai.authc import (
    AuthenticationSettings,
    CryptContextFactory,
    DefaultAuthcService,
    DefaultHashService,
    DefaultPasswordService,
)

# -----------------------------------------------------------------------------
# DefaultAuthcService Tests
# -----------------------------------------------------------------------------
def test_pepper_password_fails(default_authc_service):

    """
    A private salt must be concatenated with a cleartext password, else raising
    an exception if such concatenation fails
    """
    das = default_authc_service

    with pytest.raises(PepperPasswordException):
        das.pepper_password(bytearray('testing', 'utf-8')) 

def test_pepper_password_succeeds(default_authc_service):
    """
    A private salt must concatenate with a cleartext password
    """
    das = default_authc_service
    assert das.pepper_password('testing')

# -----------------------------------------------------------------------------
# DefaultHashService Tests
# -----------------------------------------------------------------------------
def test_confirm_hash_ciphertext(default_hash_service):
    """
    the result should include a bytearray of the hash
    """
    dhs = default_hash_service
    result = dhs.compute_hash('testing')
    assert isinstance(result['ciphertext'], bytearray)

def test_confirm_hash_config(default_hash_service):
    dhs = default_hash_service
    result = dhs.compute_hash('testing')
    assert isinstance(result['config'], dict) 

# DefaultPasswordService Tests
def test_passwords_match_raises(default_password_service):
    dps = default_password_service
    with pytest.raises(PasswordMatchException):
        dps.passwords_match('testing', ['raisetheroof']) 

def test_passwords_match_succeeds(default_password_service,
                                  default_encrypted_password, monkeypatch):
    monkeypatch.setattr(default_password_service, 'private_salt', 'privatesalt')
    dps = default_password_service
    assert dps.passwords_match('withcleartext', default_encrypted_password)
