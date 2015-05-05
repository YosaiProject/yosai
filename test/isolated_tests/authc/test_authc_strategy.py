import pytest

from yosai import (
    InvalidAuthenticationTokenException,
)

from yosai.authc import (
    AllRealmsSuccessfulStrategy,
    AtLeastOneRealmSuccessfulStrategy,
    DefaultAuthenticationAttempt,
    FirstRealmSuccessfulStrategy,
)

# AllRealmsSuccessfulStrategy Tests

# AtLeastOneRealmSuccessfulStrategy Tests

# DefaultAuthenticationAttempt Tests
def test_invalid_authc_token(default_authc_attempt):
    invalid_token = {'username': 'dummy', 'password': 'blaurgh'}
    with pytest.raises(InvalidAuthenticationTokenException):
        default_authc_attempt.authentication_token = invalid_token


# FirstRealmSuccessfulStrategy Tests
