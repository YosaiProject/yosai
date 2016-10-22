import pytest

from yosai.core import (
    all_realms_successful_strategy,
    at_least_one_realm_successful_strategy,
    first_realm_successful_strategy,
    IncorrectCredentialsException,
    MultiRealmAuthenticationException,
    account_abcs,
)

# -----------------------------------------------------------------------------
# FirstRealmSuccessfulStrategy Tests
# -----------------------------------------------------------------------------


def test_first_realmssuccessful_first_success(default_authc_attempt, sample_acct_info):
    result = first_realm_successful_strategy(default_authc_attempt)
    assert result['account_id'] == sample_acct_info['account_id']


def test_first_realmssuccessful_fails_no_realm(realmless_authc_attempt):
    """
    An authentication_attempt without any realms will cause execute to
    return None
    """
    results = first_realm_successful_strategy(realmless_authc_attempt)
    assert results is None


def test_first_realmssuccessful_fails_bad_token(mock_token_attempt):
    """
    An authentication_token that is not of type UserPasswordToken is not
    supported by the AccountStoreRealm, resulting in execute returning None
    """
    results = first_realm_successful_strategy(mock_token_attempt)
    assert results is None


def test_first_realmssuccessful_fails_authenticates_from_realm_single(
        fail_authc_attempt):
    """
    An authc_token that fails to authenticate with any realm will result
    in execute raising an exception
    """
    with pytest.raises(IncorrectCredentialsException):
        first_realm_successful_strategy(fail_authc_attempt)


def test_first_realmssuccessful_fails_authenticates_from_realm_multi(
        fail_multi_authc_attempt):
    """
    An authc_token that fails to authenticate with any realm will result
    in execute raising an exception
    """
    with pytest.raises(MultiRealmAuthenticationException):
        first_realm_successful_strategy(fail_multi_authc_attempt)


# -----------------------------------------------------------------------------
# AtLeastOneRealmSuccessfulStrategy Tests
# -----------------------------------------------------------------------------

def test_alo_realmssuccessful_first_success(default_authc_attempt, sample_acct_info):

    """ The default_authc_attempt fixture contains a set with only one
        AccountStoreRealm.  The attempt's authc_token is of type
        UserPasswordToken, which is supported by AccountStoreRealm, and so it
        will pass the supports test within the execute method.  Since there
        is only one realm,  a composite_account variable will not be created
        within execute, and consequently the first_account will return
    """
    result = at_least_one_realm_successful_strategy(default_authc_attempt)
    assert result['account_id'] == sample_acct_info['account_id']


def test_alo_realmssuccessful_fails_no_realm(realmless_authc_attempt):
    """
    An authentication_attempt without any realms will cause execute to
    return None
    """
    results = at_least_one_realm_successful_strategy(realmless_authc_attempt)
    assert results is None


def test_alo_realmssuccessful_fails_bad_token(mock_token_attempt):
    """
    An authentication_token that is not of type UserPasswordToken is not
    supported by the AccountStoreRealm, resulting in execute returning None
    """
    results = at_least_one_realm_successful_strategy(mock_token_attempt)
    assert results is None


def test_alo_realmssuccessful_fails_authenticates_from_realm(fail_authc_attempt):
    """
    An authc_token that fails to authenticate with any realm will result
    in execute raising an exception
    """
    with pytest.raises(MultiRealmAuthenticationException):
        at_least_one_realm_successful_strategy(fail_authc_attempt)


# -----------------------------------------------------------------------------
# AllRealmsSuccessfulStrategy Tests
# -----------------------------------------------------------------------------

def test_allrealmssuccessful_first_success(default_authc_attempt, sample_acct_info):
    """ The default_authc_attempt fixture contains a set with only one
        AccountStoreRealm.  The attempt's authc_token is of type
        UserPasswordToken, which is supported by AccountStoreRealm, and so it
        will pass the supports test within the execute method.  Since there
        is only one realm,  a composite_account variable will not be created
        within execute, and consequently the first_account will return
    """
    result = all_realms_successful_strategy(default_authc_attempt)
    assert result['account_id'] == sample_acct_info['account_id']


def test_allrealmssuccessful_fails_no_realm(realmless_authc_attempt):
    """
    An authentication_attempt without any realms will cause execute to
    return None
    """
    results = all_realms_successful_strategy(realmless_authc_attempt)
    assert results is None


def test_allrealmssuccessful_fails_bad_token(mock_token_attempt):
    """
    An authentication_token that is not of type UserPasswordToken is not
    supported by the AccountStoreRealm, resulting in execute returning None
    """

    results = all_realms_successful_strategy(mock_token_attempt)
    assert results is None


def test_allrealmssuccessful_fails_authenticates_from_realm(fail_authc_attempt):
    """
    An authc_token that fails to authenticate with any realm will result
    in execute raising an exception
    """
    with pytest.raises(IncorrectCredentialsException):
        all_realms_successful_strategy(fail_authc_attempt)
