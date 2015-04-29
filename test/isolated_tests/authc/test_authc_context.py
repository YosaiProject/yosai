import pytest
from unittest import mock

from yosai import (
    MissingPrivateSaltException,
    settings,
)

from yosai.authc import (
    AuthenticationSettings,
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

def test_get_config_where_algorithms_contains_algo():
    pass

def test_get_config_where_algorithms_doesnt_contain_algo():
    pass

def test_get_config_where_algorithms_doesnt_exist():
    pass

# CryptContextFactory Tests
def test_generate_context_empty_string_algorithm():
    """
    the algorithm parameter can't be None, but if its empty an exception
    should raise
    """
    # mock authc_settings get_config

def test_generate_context_with_algorithm_without_items():
    """
    verify that the dictionary comprehension manages an empty dict correctly
    """
    # mock authc_settings get_config
    pass

def test_generate_context_with_algorithm_with_items():
    """
    verify that the dictionary comprehension manages a full dict correctly
    """
    # mock authc_settings get_config
    pass

def test_create_crypt_context_with_algorithm():
    """
    calling method with an algorithm argument should succeed
    """
    # mock authc_settings default_algorithm
    pass

def test_create_crypt_context_without_algorithm():
    """
    calling method without an algorithm argument reverts to default algorithm
    """
    # mock authc_settings default_algorithm
    pass

def test_create_crypt_with_unrecognized_context_arg():
    """
    passing an unrecognized algo context argument to the cryptcontext init
    should raise an exception
    """
    pass

def test_create_crypt_with_unsupported_hash_algorithm():
    """
    passlib raises an exception for unsupported hash algo
    """
    pass
