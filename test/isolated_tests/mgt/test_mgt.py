import pytest
from unittest import mock

from yosai import (
    DefaultSecurityManager,
)


def test_dsm_setauthenticator_da(
        default_security_manager, default_authenticator, monkeypatch):
    """
    unit tested:  authenticator.setter

    test case:
    when authenticator=DefaultAuthenticator, then dsm.authenticator.realms is 
    set to self.realms
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'realms', 'verified') 
    da = default_authenticator

    with mock.patch.object(DefaultSecurityManager,
                           'apply_event_bus') as mock_aev:
        mock_aev.return_value = None

        with mock.patch.object(DefaultSecurityManager,
                               'apply_cache_manager') as mock_acm:
            mock_acm.return_value = None 
            dsm.authenticator = da

            mock_aev.assert_called_once_with(da)
            mock_acm.assert_called_once_with(da)
            
            assert dsm.authenticator.realms == 'verified' 

#def test_dsm_setauthenticator_raises
    """
    unit tested:

    test case:
    """
#def test_dsm_setauthorizer
    """
    unit tested:

    test case:
    """
#def test_dsm_setauthorizer_raises
    """
    unit tested:

    test case:
    """
#def test_dsm_set_cachemanager
    """
    unit tested:

    test case:
    """
#def test_dsm_set_cachemanager_raises
    """
    unit tested:

    test case:
    """
#def test_dsm_set_eventbus
    """
    unit tested:

    test case:
    """
#def test_dsm_set_eventbus_raises
    """
    unit tested:

    test case:
    """


#@pytest.mark.parametrize
#def test_set_realms
    """
    unit tested:

    test case:
    """

#def test_set_realms_raises
    """
    unit tested:

    test case:
    """

#@pytest.mark.parametrize
#def test_apply_cache_manager
    """
    unit tested:

    test case:
    """

#@pytest.mark.parametrize
#def test_apply_eventbus
    """
    unit tested:

    test case:
    """

#def test_dsm_get_dependencies_for_injection
    """
    unit tested:

    test case:
    """
#def test_dsm_get_dependencies_for_injection_raises
    """
    unit tested:

    test case:
    """
#def test_dsm_authenticate_account
    """
    unit tested:

    test case:
    """
#def test_dsm_is_permitted
    """
    unit tested:

    test case:
    """
#def test_dsm_is_permitted_all
    """
    unit tested:

    test case:
    """
#def test_dsm_check_permission
    """
    unit tested:

    test case:
    """
#def test_dsm_has_role
    """
    unit tested:

    test case:
    """
#def test_dsm_has_all_roles
    """
    unit tested:

    test case:
    """
#def test_dsm_check_role
    """
    unit tested:

    test case:
    """
#def test_dsm_start
    """
    unit tested:

    test case:
    """
#def test_dsm_get_session
    """
    unit tested:

    test case:
    """
#def test_dsm_create_subject_context
    """
    unit tested:

    test case:
    """
#def test_dsm_create_subject_wo_context
    """
    unit tested:

    test case:
    """
#def test_dsm_create_subject_w_context
    """
    unit tested:

    test case:
    """
#def test_dsm_rememberme_successful_login
    """
    unit tested:

    test case:
    """
#def test_dsm_rememberme_successful_login_warned(capsys, 
    """
    unit tested:

    test case:
    """
#def test_dsm_rememberme_failed_login
    """
    unit tested:

    test case:
    """
#def test_dsm_rememberme_failed_login_warned(capsys,
    """
    unit tested:

    test case:
    """
#def test_dsm_rememberme_logout
    """
    unit tested:

    test case:
    """
#def test_dsm_rememberme_logout_warned(capsys,
    """
    unit tested:

    test case:
    """



