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
                                    default_hash_service, crypt_context):
    monkeypatch.delattr(hash_request, 'algorithm_name')
    monkeypatch.setattr(default_hash_service, 'default_context', crypt_context) 
    assert default_hash_service.get_algorithm_name(hash_request) == \
        'sha256_crypt'

def test_get_algorithm_name(hash_request, default_hash_service):
    assert default_hash_service.get_algorithm_name(hash_request) == \
        'bcrypt_sha256'


test_get_iterations(request)
    M:  uses hash request mock
    T:  assert that with a hash request missing an iterations attribute (None)
        the method returns an iterations value of the default algorithm
    T:  assert that with a hash request missing an iterations attribute (None)
        the method returns an iterations value of the default algorithm, 
        but the default algorithm is missing
    T:  assert that with a hash request missing an iterations attribute (None) 
        the method obtains a default algorithm but the default context does not
        have a default_rounds attribute defined, returning None instead


test_generate_crypt_context(request):
    M:  uses a hash request mock
    T:  assert that with a well defined hash request mock, which includes
        iterations, returns a CryptContext object configured as per the request
        mock specifications
    T:  assert that with a well defined hash request mock, which excludes
        iterations, returns a CryptContext object configured as per the request
        mock specifications
    T:  assert that a request that contains an unrecognized hash algorithm
        raises a CryptContextException

def test_compute_hash_without_params(default_hash_service):
    assert default_hash_service.compute_hash(None) == None
    
def test_compute_hash_without_hashsource(hash_request, default_hash_service,
                                         monkeypatch):
    monkeypatch.setattr(hash_request, '_source', None)
    assert default_hash_service.compute_hash(hash_request) == None

# def test_compute_hash_returns_ciphertext(hash_request, default_hash_service):
#    result = default_hash_service.compute_hash(hash_request)
#    assert type(result.get('ciphertext', None)) == bytearray

# def test_compute_hash_returns_hashconfig(hash_request, default_hash_service):
#    result = default_hash_service.compute_hash(hash_request)
#    assert type(result.get('config', None)) == dict

#    T:  call with a request object that does not contain iterations, asserting ciphertext value bytearray and config is returned in a result dict
#    T:  call with a request object that does not contain iterations nor a source attribute, asserting PepperPasswordException

