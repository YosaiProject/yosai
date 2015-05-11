import pytest

from yosai import (
    IAccount,
    IncorrectCredentialsException,
    InvalidAuthenticationTokenException,
    InvalidAuthcAttemptRealmsArgumentException,
    MultiRealmAuthenticationException,
)

from yosai.authc import (
    AllRealmsSuccessfulStrategy,
    AtLeastOneRealmSuccessfulStrategy,
    DefaultAuthenticationAttempt,
    FirstRealmSuccessfulStrategy,
)

# DefaultAuthenticationAttempt Tests
def test_authc_attempt_invalid_authc_token(default_authc_attempt):
    invalid_token = {'username': 'dummy', 'password': 'blaurgh'}
    with pytest.raises(InvalidAuthenticationTokenException):
        default_authc_attempt.authentication_token = invalid_token

def test_authc_attempt_invalid_realms(default_authc_attempt, monkeypatch):
    """
    realms must be a set
    """
    invalid_realm = {'dumbdict': 'dumb'}
    with pytest.raises(InvalidAuthcAttemptRealmsArgumentException):
        monkeypatch.setattr(default_authc_attempt, 'realms', invalid_realm) 


# FirstRealmSuccessfulStrategy Tests


# AtLeastOneRealmSuccessfulStrategy Tests
def test_alo_realmssuccessful_first_success(alo_realms_successful_strategy,
                                            default_authc_attempt):
    
    """ The default_authc_attempt fixture contains a set with only one 
        AccountStoreRealm.  The attempt's authc_token is of type 
        UserPasswordToken, which is supported by AccountStoreRealm, and so it 
        will pass the supports test within the execute method.  Since there
        is only one realm,  a composite_account variable will not be created
        within execute, and consequently the first_account will return
    """
    result = alo_realms_successful_strategy.execute(default_authc_attempt)
    assert (isinstance(result, IAccount) and (result.id == 12345))

def test_alo_realmssuccessful_composite_success(alo_realms_successful_strategy,
                                                multirealm_authc_attempt):
    """ The multirealm_authc_attempt fixture contains a set with two 
        AccountStoreRealm instances.  The attempt's authc_token is of type 
        UserPasswordToken, which is supported by AccountStoreRealm, and so it 
        will pass the supports test within the execute method.  Since there
        are TWO realms,  a composite_account variable WILL be created
        within execute, and consequently be returned
    """
    results = alo_realms_successful_strategy.execute(multirealm_authc_attempt)
    assert len(results.realm_names) == 2

def test_alorealmssuccessful_fails_no_realm(alo_realms_successful_strategy,
                                            realmless_authc_attempt): 
    """
    An authentication_attempt without any realms will cause execute to 
    return None
    """
    results = alo_realms_successful_strategy.execute(realmless_authc_attempt)
    assert results is None

def test_alorealmssuccessful_fails_bad_token(mock_token_attempt, 
                                             alo_realms_successful_strategy):
    """
    An authentication_token that is not of type UserPasswordToken is not 
    supported by the AccountStoreRealm, resulting in execute returning None
    """
    
    results = alo_realms_successful_strategy.execute(mock_token_attempt)
    assert results is None

def test_alorealmssuccessful_fails_authenticates_from_realm(
        alo_realms_successful_strategy, fail_authc_attempt): 
    """
    An authc_token that fails to authenticate with any realm will result
    in execute returning None
    """
    with pytest.raises(MultiRealmAuthenticationException):
        alo_realms_successful_strategy.execute(fail_authc_attempt)
    

# -----------------------------------------------------------------------

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
    assert (isinstance(result, IAccount) and (result.id == 12345))

def test_allrealmssuccessful_composite_success(all_realms_successful_strategy,
                                               multirealm_authc_attempt):
    """ The multirealm_authc_attempt fixture contains a set with two 
        AccountStoreRealm instances.  The attempt's authc_token is of type 
        UserPasswordToken, which is supported by AccountStoreRealm, and so it 
        will pass the supports test within the execute method.  Since there
        are TWO realms,  a composite_account variable WILL be created
        within execute, and consequently be returned
    """

    results = all_realms_successful_strategy.execute(multirealm_authc_attempt)
    assert len(results.realm_names) == 2


def test_allrealmssuccessful_fails_no_realm(all_realms_successful_strategy,
                                            realmless_authc_attempt): 
    """
    An authentication_attempt without any realms will cause execute to 
    return None
    """
    results = all_realms_successful_strategy.execute(realmless_authc_attempt)
    assert results is None


def test_allrealmssuccessful_fails_bad_token(mock_token_attempt, 
                                             all_realms_successful_strategy):
    """
    An authentication_token that is not of type UserPasswordToken is not 
    supported by the AccountStoreRealm, resulting in execute returning None
    """
    
    results = all_realms_successful_strategy.execute(mock_token_attempt)
    assert results is None

def test_allrealmssuccessful_fails_authenticates_from_realm(
        all_realms_successful_strategy, fail_authc_attempt): 
    """
    An authc_token that fails to authenticate with any realm will result
    in execute returning None
    """
    with pytest.raises(IncorrectCredentialsException):
        all_realms_successful_strategy.execute(fail_authc_attempt)
    
