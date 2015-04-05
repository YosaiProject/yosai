import pytest
from unittest import mock

from yosai import (
    DefaultHashService,
    InvalidArgumentException,
    MissingPrivateSaltException,
    settings,
)


def test_init_private_salt_exception(authc_config):
    """ initialize without a private_salt defined in the authc_config """    
    authc_config.pop('private_salt')
    with mock.patch.object(settings, 'AUTHC_CONFIG', 
                           return_value=authc_config):
        with pytest.raises(MissingPrivateSaltException):
            DefaultHashService() 

@pytest.xfail
def test_private_salt_mutator_none_validation(default_hash_service):
    # private_salt cannot be None
    with pytest.raises(InvalidArgumentException):
        default_hash_service.private_salt = None


@pytest.xfail
def test_private_salt_mutator_nonstring_validation(default_hash_service):
    # private_salt cannot be None
    with pytest.raises(InvalidArgumentException):
        default_hash_service.private_salt = 12 

@pytest.xfail
def test_compute_hash_without_params(hash_request):
    pass

