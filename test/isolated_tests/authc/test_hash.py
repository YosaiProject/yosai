import pytest
from unittest import mock

from yosai.core import (
    InvalidTokenPasswordException,
    MissingPrivateSaltException,
    PasswordMatchException,
    PepperPasswordException,
    AuthenticationSettings,
    CryptContextFactory,
    AbstractAuthcService,
    DefaultHashService,
    DefaultPasswordService,
)

# -----------------------------------------------------------------------------
# AbstractAuthcService Tests
# -----------------------------------------------------------------------------
def test_clear_source_succeeds(abstract_authc_service, monkeypatch):
    """ clear_source wipes out the bytearray in memory """
    aas = abstract_authc_service
    test_source = bytearray('secret', 'utf-8')
    aas.clear_source(test_source)
    assert test_source == bytearray(b'\x00\x00\x00\x00\x00\x00')  

def test_clear_source_fails(abstract_authc_service, monkeypatch):
    """ 
    clear_source wipes out the bytearray in memory, raising an exception
    when passed an immutable object (a string)
    """
    aas = abstract_authc_service
    
    with pytest.raises(InvalidTokenPasswordException):
        aas.clear_source('secret')
    
def test_pepper_password_fails(abstract_authc_service):

    """
    A private salt must be concatenated with a bytearray password, else raising
    an exception if such concatenation fails
    """
    aas = abstract_authc_service

    with pytest.raises(PepperPasswordException):
        aas.pepper_password('testing')

def test_pepper_password_succeeds(abstract_authc_service):
    """
    A private salt must concatenate with a cleartext password
    """
    aas = abstract_authc_service
    assert aas.pepper_password(bytearray('testing', 'utf-8')) 

# -----------------------------------------------------------------------------
# DefaultHashService Tests
# -----------------------------------------------------------------------------
def test_confirm_hash_ciphertext(default_hash_service):
    """
    the result should include a bytearray of the hash
    """
    dhs = default_hash_service
    result = dhs.compute_hash(bytearray('testing', 'utf-8'))
    assert isinstance(result['ciphertext'], bytearray)

def test_confirm_hash_config(default_hash_service):
    dhs = default_hash_service
    result = dhs.compute_hash(bytearray('testing', 'utf-8'))
    assert isinstance(result['config'], dict) 

# DefaultPasswordService Tests
def test_passwords_match_raises(default_password_service):
    dps = default_password_service
    with pytest.raises(PasswordMatchException):
        dps.passwords_match(bytearray('testing', 'utf-8'), ['raisetheroof']) 

def test_passwords_match_succeeds(default_password_service,
                                  default_encrypted_password, monkeypatch):
    monkeypatch.setattr(default_password_service, 'private_salt', 
                        bytearray('privatesalt', 'utf-8'))
    dps = default_password_service
    assert dps.passwords_match(bytearray('withcleartext', 'utf-8'),
                               default_encrypted_password)
