import pytest
from unittest import mock

from yosai import (
    CryptContextException,
    InvalidArgumentException,
    MissingDefaultHashAlgorithm,
    PepperPasswordException,
)

from yosai.authc import (
    DefaultHashService,
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
    # hash_request fixture has no iterations defined
    monkeypatch.setattr(hash_request, 'algorithm_name', 'sha256_crypt')
    assert patched_default_hash_service.get_iterations(hash_request) == 180000 
         
def test_get_iterations_wo_rounds_wo_algo(hash_request, monkeypatch,
                                          patched_default_hash_service):

    # hash_request fixture has no iterations defined
    monkeypatch.delitem(patched_default_hash_service.default_context,
                        'schemes', raising=True)
    assert patched_default_hash_service.get_iterations(hash_request) is None

def test_get_iterations_wo_any_rounds(hash_request, monkeypatch,
                                      patched_default_hash_service):

    # hash_request fixture has no iterations defined
    monkeypatch.delitem(patched_default_hash_service.default_context,
                        'sha256_crypt__default_rounds', raising=True)
    assert patched_default_hash_service.get_iterations(hash_request) is None

def test_generate_crypt_context(hash_request, patched_default_hash_service):
    
    pdhs = patched_default_hash_service
    cc = pdhs.generate_crypt_context(hash_request).to_dict()
    assert cc['schemes'] == ["bcrypt_sha256"]  # as per hash_request
 
def test_generate_crypt_context(hash_request, patched_default_hash_service,
                                monkeypatch):

    monkeypatch.setattr(hash_request, 'algorithm_name', 'blablabla')
    pdhs = patched_default_hash_service
    with pytest.raises(CryptContextException):
        pdhs.generate_crypt_context(hash_request)

def test_compute_hash_without_params(patched_default_hash_service):
    assert patched_default_hash_service.compute_hash(None) == None
    
def test_compute_hash_without_hashsource(hash_request, 
                                         patched_default_hash_service,
                                         monkeypatch):
    monkeypatch.setattr(hash_request, '_source', None)
    assert patched_default_hash_service.compute_hash(hash_request) == None

def test_compute_hash_returns_ciphertext(hash_request,
                                         patched_default_hash_service):
    result = patched_default_hash_service.compute_hash(hash_request)
    assert type(result.get('ciphertext', None)) == bytearray

def test_compute_hash_returns_hashconfig(hash_request,
                                         patched_default_hash_service):
    result = patched_default_hash_service.compute_hash(hash_request)
    assert type(result.get('config', None)) == dict

def test_compute_hash_raises_exception(hash_request,
                                       patched_default_hash_service,
                                       monkeypatch):
    pdhs = patched_default_hash_service
    monkeypatch.delattr(pdhs, '_private_salt', None)
    with pytest.raises(PepperPasswordException):
        pdhs.compute_hash(hash_request)

def test_generate_default_context_wo_algo(monkeypatch):
    authc_config = {'hash_algorithms': {}, 'private_salt': 'bla'}
    monkeypatch.setattr("yosai.authc.hash.AUTHC_CONFIG", authc_config)

    with pytest.raises(MissingDefaultHashAlgorithm):
        DefaultHashService()    

def test_hash_request_source_bytearray(monkeypatch, hash_request):
    hash_request.source = bytearray('blabla', 'utf-8')
    assert isinstance(hash_request.source, str)

def test_hash_request_source_exception(monkeypatch, hash_request):
    with pytest.raises(InvalidArgumentException):
        hash_request.source = None
