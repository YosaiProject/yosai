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
