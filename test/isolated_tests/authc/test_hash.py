import pytest
from unittest import mock

from yosai import (
    DefaultHashService,
    InvalidArgumentException,
)

def test_init_private_salt_exception(authc_config, monkeypatch):
    """ initialize without a private_salt defined in the authc_config """    
    monkeypatch.setattr("yosai.authc.hash.AUTHC_CONFIG", authc_config) 
    monkeypatch.delitem(authc_config, 'private_salt')
    with pytest.raises(InvalidArgumentException):
        DefaultHashService() 

def test_private_salt_mutator_none_validation(default_hash_service):
    # private_salt cannot be None
    with pytest.raises(InvalidArgumentException):
        default_hash_service.private_salt = None

def test_private_salt_mutator_nonstring_validation(default_hash_service):
    # private_salt cannot be None
    with pytest.raises(InvalidArgumentException):
        default_hash_service.private_salt = 12 

def test_get_algorithm_name_wo_algo(hash_request, monkeypatch, 
                                    patched_default_hash_service):
    # deletes bcrypt_sha256
    monkeypatch.delattr(hash_request, 'algorithm_name')
   
    assert patched_default_hash_service.get_algorithm_name(hash_request) == \
        'sha256_crypt'

def test_get_algorithm_name(hash_request, default_hash_service):
    assert default_hash_service.get_algorithm_name(hash_request) == \
        'bcrypt_sha256'

def test_get_iterations_wo_rounds(hash_request, monkeypatch,
                                  patched_default_hash_service):
    monkeypatch.setattr(hash_request, 'algorithm_name', 'sha256_crypt')

    assert patched_default_hash_service.get_iterations(hash_request) == 110000 
         

#    T:  assert that with a hash request missing an iterations attribute (None) the method returns an iterations value of the default algorithm

#    T:  assert that with a hash request missing an iterations attribute (None) the method returns an iterations value of the default algorithm, but the default algorithm is missing

#    T:  assert that with a hash request missing an iterations attribute (None) the method obtains a default algorithm but the default context does not have a default_rounds attribute defined, returning None instead


