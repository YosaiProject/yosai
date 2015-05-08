import pytest

from yosai import (
    IAccount,
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
    """ The default_authc_attempt fixture contains a set with only one 
        AccountStoreRealm.  The attempt's authc_token is of type 
        UserPasswordToken, which is supported by AccountStoreRealm, and so it 
        will pass the supports test within the execute method.  Since there
        is only one realm,  a composite_account variable will not be created
        within execute, and consequently the first_account will return
    """
    result = all_realms_successful_strategy.execute(default_authc_attempt)
    assert (isinstance(result, IAccount) and (result.account_id == 12345))

def test_allrealmssuccessful_composite_success(all_realms_successful_strategy,
                                               multirealm_authc_attempt):
    """ The default_authc_attempt fixture contains a set with two 
        AccountStoreRealm instances.  The attempt's authc_token is of type 
        UserPasswordToken, which is supported by AccountStoreRealm, and so it 
        will pass the supports test within the execute method.  Since there
        are TWO realms,  a composite_account variable WILL be created
        within execute, and consequently be returned
    """

    results = all_realms_successful_strategy.execute(multirealm_authc_attempt)
    assert len(results.realm_names) == 2

# def test_allrealmssuccessful_fails_no_realm
    """
    An authentication_attempt without any realms will cause execute to 
    return None
    """

# def test_allrealmssuccessful_fails_no_realm_supporting_token
    """
    An authentication_token that contains an authc_token that is not of 
    type UserPasswordToken is not supported by the AccountStoreRealm 
    will result in execute returning None
    """

# def test_allrealmssuccessful_fails_no_account_authenticates_from_realm
    """
    An authc_token that fails to authenticate with any realm will result
    in execute returning None
    """

# AtLeastOneRealmSuccessfulStrategy Tests

# DefaultAuthenticationAttempt Tests
def test_invalid_authc_token(default_authc_attempt):
    invalid_token = {'username': 'dummy', 'password': 'blaurgh'}
    with pytest.raises(InvalidAuthenticationTokenException):
        default_authc_attempt.authentication_token = invalid_token


# FirstRealmSuccessfulStrategy Tests
