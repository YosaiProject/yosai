import pytest
from unittest import mock

from yosai import (
    MissingPrivateSaltException,
    PepperPasswordException,
)

from yosai.authc import (
    AuthenticationSettings,
    CryptContextFactory,
    DefaultAuthcService,
    DefaultHashService,
    DefaultPasswordService,
)

# DefaultAuthcService Tests
def test_pepper_password_fails(patched_default_authc_service):
    """
    A private salt must be concatenated with a cleartext password, else raising
    an exception if such concatenation fails
    """
    pdas = patched_default_authc_service
    with pytest.raises(PepperPasswordException):
        pdas.pepper_password(bytearray('testing', 'utf-8')) 

def test_pepper_password_succeeds(patched_default_authc_service):
    """
    A private salt must concatenate with a cleartext password
    """
    pdas = patched_default_authc_service
    assert pdas.pepper_password('testing')


# DefaultHashService Tests


# DefaultPasswordService Tests

