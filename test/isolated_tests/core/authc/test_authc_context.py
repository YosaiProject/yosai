import pytest
from unittest import mock
from passlib.context import CryptContext

from yosai.core import (
    CryptContextException,
    MissingHashAlgorithmException,
    MissingPrivateSaltException,
    AuthenticationSettings,
    CryptContextFactory,
)

# -----------------------------------------------------------------------------
# AuthenticationSettings Tests
# -----------------------------------------------------------------------------

def test_get_config_where_algorithms_contains_algo(patched_authc_settings):
    assert patched_authc_settings.get_config('sha256_crypt')

def test_get_config_where_algorithms_no_algo(patched_authc_settings):
    assert not patched_authc_settings.get_config('sha256_cryp')

def test_get_config_where_algorithms_doesnt_exist(patched_authc_settings,
                                                  monkeypatch):
    monkeypatch.setattr(patched_authc_settings, 'algorithms', None)
    assert not patched_authc_settings.get_config('sha256_crypt')

# -----------------------------------------------------------------------------
# CryptContextFactory Tests
# -----------------------------------------------------------------------------
def test_generate_context_empty_string_algorithm(cryptcontext_factory,
                                                 monkeypatch):
    """
    test case:
    the algorithm parameter can't be None, but if its empty an exception
    should raise
    """
    ccf = cryptcontext_factory
    with pytest.raises(MissingHashAlgorithmException):
        ccf.generate_context(algorithm='')

def test_generate_context_without_authc_items(cryptcontext_factory,
                                              monkeypatch):
    """
    test case:
    verify that the dictionary comprehension manages an empty dict correctly
    """
    ccf = cryptcontext_factory
    with mock.patch.object(AuthenticationSettings, 'get_config') as auths:
        auths.return_value = {}
        result = ccf.generate_context(algorithm='bcrypt_sha256')
        assert len(result) == 1

def test_generate_context_with_authc_items(cryptcontext_factory):
    """
    test case:
    verify that the dictionary comprehension manages a full dict correctly
    """
    ccf = cryptcontext_factory
    result = ccf.generate_context(algorithm='sha256_crypt')
    assert len(result) > 1

def test_create_crypt_context_with_algorithm(cryptcontext_factory):
    """
    test case:
    calling method with an algorithm argument should succeed
    """
    ccf = cryptcontext_factory
    result = ccf.create_crypt_context(algorithm='bcrypt_sha256')
    assert isinstance(result, CryptContext)

def test_create_crypt_context_without_algorithm(cryptcontext_factory):
    """
    test case:
    calling method without an algorithm argument reverts to default algorithm
    """
    ccf = cryptcontext_factory
    result = ccf.create_crypt_context(algorithm='').to_dict()
    assert result['schemes'] == ['bcrypt_sha256']

def test_create_crypt_with_unrec_context_arg(cryptcontext_factory):
    """
    test case:
    passing an unrecognized algo context argument to the cryptcontext init
    should raise an exception
    """
    ccf = cryptcontext_factory
    with mock.patch.object(CryptContextFactory, 'generate_context') as gc:
        gc.return_value = {'schemes': ['bcrypt_sha256'],
                           'bcrypt_sha256__bla': 'bla'}
        with pytest.raises(CryptContextException):
            ccf.create_crypt_context()

def test_create_crypt_with_unsup_hash_algorithm(cryptcontext_factory):
    """
    test case:
    passlib raises an exception for unsupported hash algo
    """
    ccf = cryptcontext_factory
    with pytest.raises(CryptContextException):
        ccf.create_crypt_context(algorithm='blabla')
