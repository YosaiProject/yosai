import pytest
from unittest import mock
from passlib.context import CryptContext

from yosai import (
    CryptContextException,
    MissingHashAlgorithmException,
    MissingPrivateSaltException,
    settings,
)

from yosai.authc import (
    AuthenticationSettings,
    CryptContextFactory,
)

# AuthenticationSettings Tests
def test_settings_missing_private_salt(monkeypatch, authc_config):
    """
    The default security policy requires use of a private salt.  In the event
    that a private salt isn't defined within settings, init raises an 
    exception 
    """
    monkeypatch.delitem(authc_config, 'private_salt')
    monkeypatch.setattr(settings, 'AUTHC_CONFIG', authc_config) 
    with pytest.raises(MissingPrivateSaltException):
        AuthenticationSettings()

def test_get_config_where_algorithms_contains_algo(patched_authc_settings):
    assert patched_authc_settings.get_config('sha256_crypt')

def test_get_config_where_algorithms_no_algo(patched_authc_settings):
    assert not patched_authc_settings.get_config('sha256_cryp') 

def test_get_config_where_algorithms_doesnt_exist(patched_authc_settings,
                                                  monkeypatch):
    monkeypatch.setattr(patched_authc_settings, 'algorithms', None)
    assert not patched_authc_settings.get_config('sha256_crypt') 


# CryptContextFactory Tests
def test_generate_context_empty_string_algorithm(patched_cryptcontext_factory,
                                                 monkeypatch):
    """
    the algorithm parameter can't be None, but if its empty an exception
    should raise
    """
    pccf = patched_cryptcontext_factory
    with pytest.raises(MissingHashAlgorithmException):
        pccf.generate_context(algorithm='')

def test_generate_context_without_authc_items(patched_cryptcontext_factory,
                                              monkeypatch):
    """
    verify that the dictionary comprehension manages an empty dict correctly
    """
    pccf = patched_cryptcontext_factory
    with mock.patch.object(AuthenticationSettings, 'get_config') as auths:
        auths.return_value = {}
        result = pccf.generate_context(algorithm='bcrypt_sha256')
        assert len(result) == 1

def test_generate_context_with_authc_items(patched_cryptcontext_factory):
    """
    verify that the dictionary comprehension manages a full dict correctly
    """
    pccf = patched_cryptcontext_factory
    result = pccf.generate_context(algorithm='sha256_crypt')
    assert len(result) > 1

def test_create_crypt_context_with_algorithm(patched_cryptcontext_factory):
    """
    calling method with an algorithm argument should succeed
    """
    pccf = patched_cryptcontext_factory
    result = pccf.create_crypt_context(algorithm='bcrypt_sha256')
    assert isinstance(result, CryptContext)

def test_create_crypt_context_without_algorithm(patched_cryptcontext_factory):
    """
    calling method without an algorithm argument reverts to default algorithm
    """
    pccf = patched_cryptcontext_factory
    result = pccf.create_crypt_context(algorithm='').to_dict()
    assert result['schemes'] == ['bcrypt_sha256']

def test_create_crypt_with_unrec_context_arg(patched_cryptcontext_factory):
    """
    passing an unrecognized algo context argument to the cryptcontext init
    should raise an exception
    """
    pccf = patched_cryptcontext_factory
    with mock.patch.object(CryptContextFactory, 'generate_context') as gc:
        gc.return_value = {'schemes': ['bcrypt_sha256'],
                           'bcrypt_sha256__bla': 'bla'}
        with pytest.raises(CryptContextException):
            pccf.create_crypt_context()

def test_create_crypt_with_unsup_hash_algorithm(patched_cryptcontext_factory):
    """
    passlib raises an exception for unsupported hash algo
    """
    pccf = patched_cryptcontext_factory
    with pytest.raises(CryptContextException):
        pccf.create_crypt_context(algorithm='blabla')
