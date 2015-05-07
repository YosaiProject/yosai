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
def test_allrealmssuccessful_first_success(all_realms_successful_strategy,
                                           default_authc_attempt):


# def test_allrealmssuccessful_composite_success

# def test_allrealmssuccessful_fails_no_realm

# def test_allrealmssuccessful_fails_no_realm_supporting_token

# def test_allrealmssuccessful_fails_no_account_authenticates_from_realm


# AtLeastOneRealmSuccessfulStrategy Tests

# DefaultAuthenticationAttempt Tests
def test_invalid_authc_token(default_authc_attempt):
    invalid_token = {'username': 'dummy', 'password': 'blaurgh'}
    with pytest.raises(InvalidAuthenticationTokenException):
        default_authc_attempt.authentication_token = invalid_token


# FirstRealmSuccessfulStrategy Tests
