import pytest
from unittest import mock
from cryptography.fernet import Fernet

from yosai import (
    AuthenticationException,
    SaveSubjectException,
    DefaultAuthenticator,
    DefaultSecurityManager,
    DefaultSessionKey,
    DefaultSubjectContext,
    DeleteSubjectException,
    IllegalArgumentException,
    ModularRealmAuthorizer,
    SerializationManager,
    UsernamePasswordToken,
    cache_abcs,
    authc_abcs,
    security_utils,
    mgt_settings,
)

from ..session.doubles import (
    MockDefaultSessionManager,
)

from .doubles import (
    MockRememberMeManager,
)

# ------------------------------------------------------------------------------
# DefaultSecurityManager
# ------------------------------------------------------------------------------

def test_dsm_setauthenticator_da(
        default_security_manager, default_authenticator, monkeypatch):
    """
    unit tested:  authenticator.setter

    test case:
    when authenticator=DefaultAuthenticator, then dsm.authenticator.realms is
    set to self.realms and then eventbus and cachemanager are set for it
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

def test_dsm_setauthenticator_raises(
        default_security_manager, default_authenticator, monkeypatch):
    """
    unit tested:  authenticator.setter

    test case:
    passing None as an argument value raises an exception
    """
    dsm = default_security_manager

    with pytest.raises(IllegalArgumentException):
        dsm.authenticator = None

def test_dsm_setauthorizer(default_security_manager):
    """
    unit tested:  authorizer.setter

    test case:  setting an authorizer attribute in turn applies an event_bus
                and cache_manager to it
    """
    dsm = default_security_manager

    with mock.patch.object(DefaultSecurityManager,
                           'apply_event_bus') as mock_aev:
        mock_aev.return_value = None

        with mock.patch.object(DefaultSecurityManager,
                               'apply_cache_manager') as mock_acm:
            mock_acm.return_value = None
            dsm.authorizer = 'authorizer'

            mock_aev.assert_called_once_with(dsm.authorizer)
            mock_acm.assert_called_once_with(dsm.authorizer)

            assert dsm.authorizer == 'authorizer'

def test_dsm_setauthorizer_raises(default_security_manager):
    """
    unit tested:  authorizer.setter

    test case:
    passing None as an argument value raises an exception
    """
    dsm = default_security_manager

    with pytest.raises(IllegalArgumentException):
        dsm.authorizer = None


def test_dsm_set_cachemanager(default_security_manager):
    """
    unit tested:  cache_manager.setter

    test case:
    sets cache_manager attribute and then applies the cachemanager to its
    related objects (those that implement the CacheManagerAware interface)
    """
    dsm = default_security_manager

    with mock.patch.object(DefaultSecurityManager,
                           'get_dependencies_for_injection') as dsm_gdfi:
        dsm_gdfi.return_value = {'val1', 'val2'}
        with mock.patch.object(DefaultSecurityManager,
                               'apply_cache_manager') as dsm_acm:
            dsm_acm.return_value = None

            dsm.cache_manager = 'cachemanager'

            dsm_gdfi.assert_called_once_with('cachemanager')
            assert dsm_acm.called and dsm.cache_manager == 'cachemanager'

def test_dsm_set_cachemanager_raises(default_security_manager):
    """
    unit tested:  cache_manager.setter

    test case:
    passing None as an argument value raises an exception
    """
    dsm = default_security_manager

    with pytest.raises(IllegalArgumentException):
        dsm.cache_manager = None

def test_dsm_set_eventbus(default_security_manager):
    """
    unit tested:  event_bus.setter

    test case:
    sets attribute and calls method
    """
    dsm = default_security_manager
    with mock.patch.object(DefaultSecurityManager,
                           'get_dependencies_for_injection') as dsm_gdfi:
        dsm_gdfi.return_value = {'val1', 'val2'}
        with mock.patch.object(DefaultSecurityManager,
                               'apply_event_bus') as dsm_aeb:
            dsm_aeb.return_value = None

            dsm.event_bus = 'eventbus'

            dsm_gdfi.assert_called_once_with('eventbus')
            assert dsm_aeb.called and dsm.event_bus == 'eventbus'


def test_dsm_set_eventbus_raises(default_security_manager):
    """
    unit tested:  event_bus.setter

    test case:
    passing None as an argument value raises an exception
    """
    dsm = default_security_manager

    with pytest.raises(IllegalArgumentException):
        dsm.event_bus = None


@pytest.mark.parametrize(
    'authenticator, expected_authc_realms, authorizer, expected_authz_realms',
    [(DefaultAuthenticator(event_bus='eventbus'), 'realms',
     ModularRealmAuthorizer(), 'realms'),
     (type('DumbAuthenticator', (object,), {'realms': None})(), None,
      type('DumbAuthorizer', (object,), {'realms': None})(), None)])
def test_set_realms(
        default_security_manager, authenticator, expected_authc_realms,
        authorizer, expected_authz_realms, monkeypatch):
    """
    unit tested:  set_realms

    test case:
    applies eventbus and cachemanager to eligible realms, then tries to assign
    realms to the authenticator and authorizer
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'authenticator', authenticator)
    monkeypatch.setattr(dsm, 'authorizer', authorizer)

    with mock.patch.object(DefaultSecurityManager,
                           'apply_event_bus') as dsm_aeb:
        dsm_aeb.return_value = None
        with mock.patch.object(DefaultSecurityManager,
                               'apply_cache_manager') as dsm_acm:
            dsm_acm.return_value = None

            dsm.set_realms('realms')

            dsm_aeb.assert_called_once_with('realms')
            dsm_acm.assert_called_once_with('realms')
            assert (dsm.authenticator.realms == expected_authc_realms and
                    dsm.authorizer.realms == expected_authz_realms)

def test_set_realms_raises(default_security_manager):
    """
    unit tested:  set_realms

    test case:
    passing None as an argument value raises an exception
    """
    dsm = default_security_manager

    with pytest.raises(IllegalArgumentException):
        dsm.set_realms(None)

def test_apply_targets_single(default_security_manager):
    """
    unit tested:  apply_targets

    test case:
    passing a single value results in using except block logic and a single call
    """
    dsm = default_security_manager
    va = mock.MagicMock()
    dc = type('DumbClass', (object,), {})()
    dsm.apply_target_s(va, dc)
    va.assert_called_once_with(dc)

def test_apply_targets_collection(default_security_manager):
    """
    unit tested:  apply_targets

    test case:
    passing a collection results in using try block logic and iterative calls
    """
    dsm = default_security_manager
    va = mock.MagicMock()
    dc = type('DumbClass', (object,), {})
    mylist = [dc(), dc(), dc()]

    dsm.apply_target_s(va, mylist)

    calls = [mock.call(mylist[0]), mock.call(mylist[1]), mock.call(mylist[2])]
    assert calls in va.call_args_list

def test_apply_cache_manager(default_security_manager):
    """
    unit tested:  apply_cache_manager

    test case:
    calls apply_target_s with inner function
    """
    dsm = default_security_manager

    with mock.patch.object(dsm, 'apply_target_s') as dsm_ats:
        dsm_ats.return_value = None

        dsm.apply_cache_manager('target1')

        assert 'target1' in dsm_ats.call_args[0]

def test_apply_eventbus(default_security_manager):
    """
    unit tested:  apply_event_bus

    test case:
    calls apply_target_s with inner function
    """
    dsm = default_security_manager

    with mock.patch.object(dsm, 'apply_target_s') as dsm_ats:
        dsm_ats.return_value = None

        dsm.apply_event_bus('target1')

        assert 'target1' in dsm_ats.call_args[0]

def test_dsm_get_dependencies_for_injection(default_security_manager):
    """
    unit tested:  get_dependencies_for_injection

    test case:
    ignores the argument passed, returns the rest of the dependents
    """
    dsm = default_security_manager
    result = dsm.get_dependencies_for_injection(dsm._event_bus)
    assert dsm._event_bus not in result

def test_dsm_get_dependencies_for_injection_raises(
        default_security_manager, dependencies_for_injection):
    """
    unit tested:  get_dependencies_for_injection

    test case:
    fails to find the argument passed, returns all of the dependents
    """
    dsm = default_security_manager
    dc = type('DumbClass', (object,), {})
    result = dsm.get_dependencies_for_injection(dc)
    assert result == dependencies_for_injection


def test_dsm_authenticate_account(
        default_security_manager, username_password_token):
    """
    unit tested:  authenticate_account

    test case:
    passes request on to authenticator
    """
    dsm = default_security_manager
    upt = username_password_token
    with mock.patch.object(DefaultAuthenticator,
                           'authenticate_account') as da_aa:
        dsm.authenticate_account(upt)
        da_aa.assert_called_once_with(upt)

def test_dsm_is_permitted(default_security_manager):
    """
    unit tested:  is_permitted

    test case:
    passes request on to authorizer
    """
    dsm = default_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'is_permitted') as mra_ip:
        dsm.is_permitted('identifiers', 'permission_s')
        mra_ip.assert_called_once_with('identifiers', 'permission_s')


def test_dsm_is_permitted_all(default_security_manager):
    """
    unit tested: is_permitted_all

    test case:
    passes request on to authorizer
    """
    dsm = default_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'is_permitted_all') as mra_ipa:
        dsm.is_permitted_all('identifiers', 'permission_s')
        mra_ipa.assert_called_once_with('identifiers', 'permission_s')


def test_dsm_check_permission(default_security_manager):
    """
    unit tested:  check_permission

    test case:
    passes request on to authorizer
    """
    dsm = default_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'check_permission') as mra_cp:
        dsm.check_permission('identifiers', 'permission_s')
        mra_cp.assert_called_once_with('identifiers', 'permission_s')


def test_dsm_has_role(default_security_manager):
    """
    unit tested:  has_role

    test case:
    passes request on to authorizer
    """
    dsm = default_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'has_role') as mra_hr:
        dsm.has_role('identifiers', 'permission_s')
        mra_hr.assert_called_once_with('identifiers', 'permission_s')


def test_dsm_has_all_roles(default_security_manager):
    """
    unit tested:  has_all_roles

    test case:
    passes request on to authorizer
    """
    dsm = default_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'has_all_roles') as mra_har:
        dsm.has_all_roles('identifiers', 'permission_s')
        mra_har.assert_called_once_with('identifiers', 'permission_s')


def test_dsm_check_role(default_security_manager):
    """
    unit tested:  check_role

    test case:
    passes request on to authorizer
    """
    dsm = default_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'check_role') as mra_cr:
        dsm.check_role('identifiers', 'permission_s')
        mra_cr.assert_called_once_with('identifiers', 'permission_s')

def test_dsm_start(
        default_security_manager, mock_default_session_manager, monkeypatch):
    """
    unit tested:  start

    test case:
    passes request on to session manager
    """
    dsm = default_security_manager
    mdsm = mock_default_session_manager
    monkeypatch.setattr(dsm, 'session_manager', mdsm)
    with mock.patch.object(MockDefaultSessionManager, 'start') as mdsm_start:
        mdsm_start.return_value = None
        dsm.start('session_context')
        mdsm_start.assert_called_once_with('session_context')

def test_dsm_get_session(
        default_security_manager, mock_default_session_manager, monkeypatch):
    """
    unit tested:  get_session

    test case:
    passes request on to session manager
    """
    dsm = default_security_manager
    mdsm = mock_default_session_manager
    monkeypatch.setattr(dsm, 'session_manager', mdsm)
    with mock.patch.object(MockDefaultSessionManager, 'get_session') as mdsm_gs:
        mdsm_gs.return_value = None
        dsm.get_session('sessionkey123')
        mdsm_gs.assert_called_once_with('sessionkey123')


def test_dsm_create_subject_context(
        default_security_manager, mock_default_session_manager, monkeypatch):
    """
    unit tested:  create_subject_context

    test case:
    returns a new DefaultSubjectContext instance
    """
    dsm = default_security_manager
    result = dsm.create_subject_context()
    assert isinstance(result, DefaultSubjectContext)

def test_dsm_create_subject_wo_context(default_security_manager):
    """
    unit tested:  create_subject

    test case:
    When no subject_context argument is given, a new subject_context is
    created.  The subject_context is used to create a new subject, which is
    saved and then returned.
    """
    dsm = default_security_manager

    testcontext = DefaultSubjectContext(security_utils)
    testcontext.authenticated = True
    testcontext.authentication_token = 'dumb_token'
    testcontext.account = 'dumb_account'
    testcontext.subject = 'existing_subject'

    with mock.patch.object(dsm, 'ensure_security_manager') as dsm_esm:
        dsm_esm.return_value = testcontext
        with mock.patch.object(dsm, 'resolve_session') as dsm_rs:
            dsm_rs.return_value = testcontext
            with mock.patch.object(dsm, 'resolve_identifiers') as dsm_rp:
                dsm_rp.return_value = testcontext
                with mock.patch.object(dsm, 'do_create_subject') as dsm_dcs:
                    dsm_dcs.return_value = 'subject'
                    with mock.patch.object(dsm, 'save') as dsm_save:
                        dsm_save.return_value = None

                        result = dsm.create_subject(authc_token='dumb_token',
                                                    account='dumb_account',
                                                    existing_subject='existing_subject')

                        dsm_esm.assert_called_once_with(testcontext)
                        dsm_rs.assert_called_once_with(testcontext)
                        dsm_rp.assert_called_once_with(testcontext)
                        dsm_dcs.assert_called_once_with(testcontext)
                        assert result == 'subject'

def test_dsm_create_subject_w_context(default_security_manager):
    """
    unit tested:  create_subject

    test case:
    context is passed as an argument, and so it is used
    """
    dsm = default_security_manager

    testcontext = DefaultSubjectContext(security_utils)
    testcontext.authenticated = True
    testcontext.authentication_token = 'dumb_token'
    testcontext.account = 'dumb_account'
    testcontext.subject = 'existing_subject'

    with mock.patch.object(dsm, 'ensure_security_manager') as dsm_esm:
        dsm_esm.return_value = testcontext
        with mock.patch.object(dsm, 'resolve_session') as dsm_rs:
            dsm_rs.return_value = testcontext
            with mock.patch.object(dsm, 'resolve_identifiers') as dsm_rp:
                dsm_rp.return_value = testcontext
                with mock.patch.object(dsm, 'do_create_subject') as dsm_dcs:
                    dsm_dcs.return_value = None
                    with mock.patch.object(dsm, 'save') as dsm_save:
                        dsm_save.return_value = None

                        dsm.create_subject(subject_context=testcontext)

                        dsm_esm.assert_called_once_with(testcontext)
                        dsm_rs.assert_called_once_with(testcontext)
                        dsm_rp.assert_called_once_with(testcontext)
                        dsm_dcs.assert_called_once_with(testcontext)


def test_dsm_rememberme_successful_login(
        default_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_me_successful_login

    test case:
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_successful_login') as mrmm_osl:
        mrmm_osl.return_value = None
        dsm.remember_me_successful_login('authc_token', 'account', 'subject')
        mrmm_osl.assert_called_once_with('subject', 'authc_token', 'account')

def test_dsm_rememberme_successful_login_rmm_set_but_raises(
        capsys, default_security_manager, mock_remember_me_manager,
        monkeypatch):
    """
    unit tested:  remember_me_successful_login

    test case:
    1) the remember_me_manager attribute is set
    2) the call for rmm.on_successful_login raises an exception
    3) a warning message is emitted
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_successful_login') as mrmm_osl:
        mrmm_osl.side_effect = Exception
        dsm.remember_me_successful_login('authc_token', 'account', 'subject')
        out, err = capsys.readouterr()
        assert 'threw an exception' in out


def test_dsm_rememberme_successful_login_rmm_notset(
        capsys, default_security_manager):
    """
    unit tested:  remember_me_successful_login

    test case:
    when the remember_me_manager attribute is not set, a warning message is
    emitted
    """
    dsm = default_security_manager
    dsm.remember_me_successful_login('authc_token', 'account', 'subject')
    out, err = capsys.readouterr()
    assert 'does not have' in out

def test_dsm_rememberme_failed_login(
        default_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_me_failed_login

    test case:
    when a remember_me_manager is set, it's on_failed_login is called
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_failed_login') as mrmm_ofl:
        mrmm_ofl.return_value = None
        dsm.remember_me_failed_login('authc_token', 'authc_exc', 'subject')
        mrmm_ofl.assert_called_once_with('subject', 'authc_token', 'authc_exc')


def test_dsm_rememberme_failed_login_warned(
        default_security_manager, mock_remember_me_manager, monkeypatch,
        capsys):
    """
    unit tested:  remember_me_failed_login

    test case:
    when the remember_me_manager attribute is not set, a warning message is
    emitted
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_failed_login') as mrmm_ofl:
        mrmm_ofl.side_effect = Exception
        dsm.remember_me_failed_login('authc_token', 'authc_exc', 'subject')
        out, err = capsys.readouterr()
        assert 'threw an exception' in out

def test_dsm_rememberme_logout(
        default_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_me_logout

    test case:
    when a remember_me_manager is set, it's on_logout is called
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_logout') as mrmm_ol:
        mrmm_ol.return_value = None
        dsm.remember_me_logout('subject')
        mrmm_ol.assert_called_once_with('subject')

def test_dsm_rememberme_logout_warned(
        default_security_manager, mock_remember_me_manager, monkeypatch,
        capsys):
    """
    unit tested:  remember_me_logout

    test case:
    prints a warning when remember_me_manager raises an exception
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'remember_me_manager', mock_remember_me_manager)

    class MockSubject:
        def __init__(self):
            self.identifiers = {'username': 'username'}

    with mock.patch.object(MockRememberMeManager,
                           'on_logout') as mrmm_ol:
        mrmm_ol.side_effect = Exception
        dsm.remember_me_logout(MockSubject())
        out, err = capsys.readouterr()
        assert 'threw an exception during on_logout' in out

def test_dsm_login_success(default_security_manager):
    """
    unit tested:  login

    test case:
        authenticate_account returns an account, create_subject is called,
        on_successful_login is called, and then logged_in is returned
    """
    dsm = default_security_manager
    with mock.patch.object(DefaultSecurityManager,
                           'authenticate_account') as dsm_ac:
        dsm_ac.return_value = 'account'

        with mock.patch.object(DefaultSecurityManager,
                               'create_subject') as dsm_cs:
            dsm_cs.return_value = 'logged_in'
            with mock.patch.object(DefaultSecurityManager,
                                   'on_successful_login') as dsm_osl:
                dsm_osl.return_value = None

                result = dsm.login('subject', 'authc_token')

                dsm_ac.assert_called_once_with('authc_token')
                dsm_cs.assert_called_once_with('authc_token','account','subject')
                dsm_osl.assert_called_once_with('authc_token','account','logged_in')

                assert result == 'logged_in'

def test_dsm_login_raises_then_succeeds(default_security_manager):
    """
    unit tested:  login

    test case:
    authenticate_account raises an AuthenticationException, on_failed_login
    succeeds, and an AuthenticationException is raised up the stack
    """
    dsm = default_security_manager

    with mock.patch.object(DefaultSecurityManager,
                           'authenticate_account') as dsm_ac:
        dsm_ac.side_effect = AuthenticationException

        with mock.patch.object(DefaultSecurityManager,
                               'on_failed_login') as dsm_ofl:
            dsm_ofl.return_value = None

            with pytest.raises(AuthenticationException):
                dsm.login('subject', 'authc_token')
                dsm_ac.assert_called_once_with('authc_token')
                dsm_ofl.assert_called_once_with(
                    'authc_token', AuthenticationException, 'subject')

def test_dsm_login_raises_then_raises(default_security_manager, capsys):
    """
    unit tested:  login

    test case:
    authenticate_account raises an AuthenticationException, on_failed_login
    raises, a warning is emitted, and an AuthenticationException is raised up
    the stack
    """
    dsm = default_security_manager

    with mock.patch.object(DefaultSecurityManager,
                           'authenticate_account') as dsm_ac:
        dsm_ac.side_effect = AuthenticationException

        with mock.patch.object(DefaultSecurityManager,
                               'on_failed_login') as dsm_ofl:
            dsm_ofl.side_effect = Exception

            with pytest.raises(AuthenticationException):
                dsm.login('subject', 'authc_token')
                dsm_ac.assert_called_once_with('authc_token')
                dsm_ofl.assert_called_once_with(
                    'authc_token', AuthenticationException, 'subject')

                out, err = capsys.readouterr()
                assert 'on_failed_login method raised' in out

def test_dsm_on_successful_login(default_security_manager):
    """
    unit tested:  on_successful_login

    test case:
    passes call on to remember_me_successful_login
    """
    dsm = default_security_manager

    with mock.patch.object(DefaultSecurityManager,
                           'remember_me_successful_login') as dsm_rmsl:
        dsm_rmsl.return_value = None

        dsm.on_successful_login('authc_token', 'account', 'subject')

        dsm_rmsl.assert_called_once_with('authc_token', 'account', 'subject')

def test_dsm_onfailed_login(default_security_manager):
    """
    unit tested:  on_failed_login

    test case:
    passes call on to remember_me_failed_login
    """
    dsm = default_security_manager
    with mock.patch.object(DefaultSecurityManager,
                           'remember_me_failed_login') as dsm_rmfl:
        dsm_rmfl.return_value = None
        dsm.on_failed_login('authc_token', 'authc_exc', 'subject')
        dsm_rmfl.assert_called_once_with('authc_token', 'authc_exc', 'subject')


def test_dsm_before_logout(default_security_manager):
    """
    unit tested:  before_logout

    test case:
    passes call on to remember_me_logout
    """
    dsm = default_security_manager
    with mock.patch.object(DefaultSecurityManager,
                           'remember_me_logout') as dsm_rml:
        dsm_rml.return_value = None

        dsm.before_logout('subject')

        dsm_rml.assert_called_once_with('subject')


def test_dsm_copy(default_security_manager):
    """
    unit tested:  copy

    test case:
    returns a new DefaultSubjectContext
    """
    dsm = default_security_manager

    result = dsm.copy(security_utils, {'subject_context': 'subject_context'})
    assert result == DefaultSubjectContext(security_utils,
                                           {'subject_context': 'subject_context'})

def test_dsm_do_create_subject(default_security_manager, monkeypatch):
    """
    unit tested:  do_create_subject

    test case:
    passes call onto subject_factory.create_subject
    """
    dsm = default_security_manager

    class DumbFactory:
        def create_subject(self, context):
            return 'verified'

    monkeypatch.setattr(dsm, 'subject_factory', DumbFactory())

    result = dsm.do_create_subject('anything')
    assert result == 'verified'


def test_dsm_save(default_security_manager, monkeypatch):
    """
    unit tested:  save

    test case:
    passes call onto subject_store.save
    """
    dsm = default_security_manager

    class DumbStore:
        def save(self, subject):
            return 'saved'

    monkeypatch.setattr(dsm, 'subject_store', DumbStore())
    with mock.patch.object(DumbStore, 'save') as ds_save:
        dsm.save('subject')
        ds_save.assert_called_once_with('subject')

def test_save_raises(default_security_manager):
    """
    unit tested:  save

    test case:
    passes call onto None, raising
    """
    dsm = default_security_manager
    with pytest.raises(SaveSubjectException):
        dsm.save('subject')


def test_delete_raises(default_security_manager):
    """
    unit tested:  delete

    test case:
    passes call onto None, raising
    """
    dsm = default_security_manager
    with pytest.raises(DeleteSubjectException):
        dsm.delete('subject')

def test_dsm_delete(default_security_manager, monkeypatch):
    """
    unit tested:  delete

    test case:
    passes call onto subject_store.delete
    """
    dsm = default_security_manager

    class DumbStore:
        def delete(self, subject):
            return None

    monkeypatch.setattr(dsm, 'subject_store', DumbStore())
    with mock.patch.object(DumbStore, 'delete') as ds_delete:
        dsm.delete('subject')
        ds_delete.assert_called_once_with('subject')


def test_dsm_ensure_security_manager_resolves(
        default_security_manager, mock_subject_context, monkeypatch):
    """
    unit tested:  ensure_security_manager

    test case:
    resolve_security_manager returns the subject_context
    """
    dsm = default_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'resolve_security_manager', lambda: True)

    result = dsm.ensure_security_manager(msc)

    assert result

def test_dsm_ensure_security_manager_doesntresolve(
        default_security_manager, mock_subject_context, monkeypatch):

    """
    unit tested:  ensure_security_manager

    test case:
    resolve_security_manager returns None, and then ensure_security_manager
    returns a subject_context whose security_manager is the dsm
    """
    dsm = default_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'resolve_security_manager', lambda: None)

    result = dsm.ensure_security_manager(msc)

    assert result.security_manager == dsm

def test_dsm_ensure_security_manager_doesntresolve_raises(
        default_security_manager, monkeypatch):
    """
    unit tested:  ensure_security_manager

    test case:
    resolve_security_manager returns None, and then ensure_security_manager
    returns a subject_context whose security_manager is the dsm
    """
    dsm = default_security_manager

    with pytest.raises(IllegalArgumentException):
        dsm.ensure_security_manager('subject_context')

def test_dsm_resolve_session_returns_none(
        default_security_manager, mock_subject_context, monkeypatch):
    """
    unit tested:  resolve_session

    test case:
    the subject_context.resolve_session returns None, implying that the
    context already contains a session, so returns it as is
    """
    dsm = default_security_manager
    msc = mock_subject_context

    monkeypatch.setattr(msc, 'resolve_session', lambda: 'session')

    result = dsm.resolve_session(msc)

    assert result == msc


def test_dsm_resolve_session_contextsessionisnone(
        default_security_manager, mock_subject_context, monkeypatch):
    """
    unit tested:  resolve_session

    test case:
    the subject_context returns and resolve_context_session returns None,
    subject_context.session doesn't get set

    """
    dsm = default_security_manager
    msc = mock_subject_context

    monkeypatch.setattr(msc, 'resolve_session', lambda: None)

    with mock.patch.object(DefaultSecurityManager,
                           'resolve_context_session') as dsm_rcs:
        dsm_rcs.return_value = None
        result = dsm.resolve_session(msc)
        assert not hasattr(result, 'session')

def test_dsm_resolve_context_session_nokey(
        default_security_manager, monkeypatch):
    """
    unit tested:  resolve_context_session

    test case:
    get_session_key returns none , returning None
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'get_session_key', lambda x: None)
    result = dsm.resolve_context_session('subject_context')
    assert result is None

def test_dsm_resolve_context_session(default_security_manager, monkeypatch):
    """
    unit tested:  resolve_context_session

    test case:
    get_session_key returns a key, so get_session called and returns
    """
    dsm = default_security_manager
    monkeypatch.setattr(dsm, 'get_session_key', lambda x: 'sessionkey123')
    monkeypatch.setattr(dsm, 'get_session', lambda x: 'session')

    result = dsm.resolve_context_session('subject_context')
    assert result == 'session'


def test_dsm_get_session_key_w_sessionid(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  get_session_key

    test case:

    """
    dsm = default_security_manager
    msc = mock_subject_context

    monkeypatch.setattr(msc, 'session_id', 'sessionid123', raising=False)

    result = dsm.get_session_key(msc)

    assert result == DefaultSessionKey('sessionid123')

def test_dsm_get_session_key_wo_sessionid(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  get_session_key

    test case:

    """
    dsm = default_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'session_id', None, raising=False)
    result = dsm.get_session_key(msc)
    assert result is None

def test_dsm_resolve_identifiers_incontext(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    subject_context contains identifiers, so returns it back immediately
    """
    dsm = default_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'resolve_identifiers', lambda: 'identifiers')
    result = dsm.resolve_identifiers(msc)

    assert result == msc


def test_dsm_resolve_identifiers_notincontext_remembered(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    - by default, the mock subject context's resolve_identifiers returns None
    - obtains identifiers from remembered identity
    """

    dsm = default_security_manager
    msc = mock_subject_context

    dsm.resolve_identifiers(msc)


def test_dsm_resolve_identifiers_notincontext_notremembered(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    - by default, the mock subject context's resolve_identifiers returns None
    - fails to obtain identifiers from remembered identity
    """

    dsm = default_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(dsm, 'get_remembered_identity', lambda x: None)
    result = dsm.resolve_identifiers(msc)
    assert not hasattr(result, 'identifiers')


def test_dsm_resolve_identifiers_notincontext_remembered(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    - by default, the mock subject context's resolve_identifiers returns None
    - fails to obtain identifiers from remembered identity
    """

    dsm = default_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(dsm, 'get_remembered_identity', lambda x: 'identifiers')
    result = dsm.resolve_identifiers(msc)
    assert hasattr(result, 'identifiers')


def test_dsm_create_session_context_empty(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  create_session_context

    test case:
    subject_context=empty,passes
    session_id=None, passes
    host=None, passes
    """
    dsm = default_security_manager
    msc = mock_subject_context

    monkeypatch.setattr(msc, 'context', {}, raising=False)
    monkeypatch.setattr(msc, 'session_id', None, raising=False)
    monkeypatch.setattr(msc, 'resolve_host', lambda: None, raising=False)

    result = dsm.create_session_context(msc)

    assert result.session_id is None and result.host is None

def test_dsm_create_session_context(
        default_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  create_session_context

    test case:
    subject_context has values
    session_id has values
    host has values
    """
    dsm = default_security_manager
    msc = mock_subject_context
    msc.put('attrY', 'attributeY')

    monkeypatch.setattr(msc, 'session_id', 'session_id', raising=False)
    monkeypatch.setattr(msc, 'resolve_host', lambda: 'host', raising=False)

    result = dsm.create_session_context(msc)

    assert (result.session_id == 'session_id' and
            result.host == 'host' and
            'attrY' in result)

def test_dsm_logout_raises(default_security_manager):
    """
    unit tested:  logout

    test case:
    a subject must be passed as an argument
    """
    dsm = default_security_manager
    with pytest.raises(IllegalArgumentException):
        dsm.logout(None)

def test_dsm_logout_succeeds(
        default_security_manager, mock_subject, monkeypatch):
    """
    unit tested:  logout

    test case:
    calls before_logout, obtains identifiers from subject, calls the
    authenticator's on_logout method, calls delete, calls stop_session
    """
    dsm = default_security_manager
    ms = mock_subject

    class MockAuthenticator(authc_abcs.LogoutAware):
        def on_logout(self, identifiers):
            pass

    monkeypatch.setattr(dsm, 'authenticator', MockAuthenticator())

    with mock.patch.object(dsm, 'before_logout') as dsm_bl:
        dsm_bl.return_value = None
        with mock.patch.object(MockAuthenticator, 'on_logout') as ma_ol:
            with mock.patch.object(dsm, 'delete') as dsm_delete:
                dsm_delete.return_value = None
                with mock.patch.object(dsm, 'stop_session') as dsm_ss:
                    dsm_ss.return_value = None

                    dsm.logout(ms)
                    dsm_bl.assert_called_once_with(ms)
                    ma_ol.assert_called_once_with(ms.identifiers)
                    dsm_delete.assert_called_once_with(ms)
                    dsm_ss.assert_called_once_with(ms)


def test_dsm_logout_succeeds_until_delete_raises(
        default_security_manager, mock_subject, monkeypatch, capsys):
    """
    unit tested:  logout

    test case:
    calls before_logout, obtains identifiers from subject, calls the
    authenticator's on_logout method, calls delete and raises
    """
    dsm = default_security_manager
    ms = mock_subject

    class MockAuthenticator(authc_abcs.LogoutAware):
        def on_logout(self, identifiers):
            pass

    monkeypatch.setattr(dsm, 'authenticator', MockAuthenticator())
    monkeypatch.setattr(ms, '_identifiers', None)

    with mock.patch.object(dsm, 'before_logout') as dsm_bl:
        dsm_bl.return_value = None
        with mock.patch.object(dsm, 'delete') as dsm_delete:
            dsm_delete.side_effect = Exception
            with mock.patch.object(dsm, 'stop_session') as dsm_ss:
                dsm_ss.side_effect = Exception

                dsm.logout(ms)
                dsm_bl.assert_called_once_with(ms)
                dsm_delete.assert_called_once_with(ms)
                dsm_ss.assert_called_once_with(ms)

                out, err = capsys.readouterr()
                assert ('Unable to cleanly unbind Subject' in out
                        and 'Unable to cleanly stop Session' in out)

def test_dsm_stop_session(default_security_manager, monkeypatch, mock_subject):
    """
    unit tested:  stop_session

    test case:
    gets a session and calls its stop method
    """
    dsm = default_security_manager
    ms = mock_subject

    class MockSession:
        def stop():
            pass

    monkeypatch.setattr(ms, 'get_session', lambda x: MockSession(), raising=False)

    with mock.patch.object(MockSession, 'stop') as ms_stop:
        dsm.stop_session(ms)
        ms_stop.assert_called_once_with()

def test_dsm_get_remembered_identity(
        default_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  get_remembered_identity

    test case:
    returns remembered identifiers from the rmm
    """
    dsm = default_security_manager
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(dsm, 'remember_me_manager', mrmm)
    monkeypatch.setattr(mrmm,
                        'get_remembered_identifiers',
                        lambda x: 'remembered_identifier')
    result = dsm.get_remembered_identity('subjectcontext')
    assert result == 'remembered_identifier'


def test_dsm_get_remembered_identity_not_remembered(default_security_manager):
    """
    unit tested:  get_remembered_identity

    test case:
    remember_me_manager by default isn't set, so None is returned
    """
    dsm = default_security_manager
    result = dsm.get_remembered_identity('subject_context')
    assert result is None


def test_dsm_get_remembered_identity_raises(
        default_security_manager, mock_remember_me_manager, monkeypatch,
        capsys):
    """
    unit tested:  get_remembered_identity

    test case:
    raises an exception while trying to get remembered identifiers from rmm
    """

    dsm = default_security_manager
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(dsm, 'remember_me_manager', mrmm)
    with mock.patch.object(MockRememberMeManager,
                           'get_remembered_identifiers') as mrmm_gri:
        mrmm_gri.side_effect = Exception

        result = dsm.get_remembered_identity('subjectcontext')
        out, err = capsys.readouterr()
        assert (result is None and 'raised an exception' in out)


# ------------------------------------------------------------------------------
# AbstractRememberMeManager
# ------------------------------------------------------------------------------

def test_armm_init():
    """
    unit tested:  __init__

    test case:
    confirm that init calls set_cipher_key using mgt_settings default_cipher_key
    """
    default_key = mgt_settings.default_cipher_key
    with mock.patch.object(MockRememberMeManager, 'set_cipher_key') as rmm_ssk:
        rmm_ssk.return_value = None
        mrmm = MockRememberMeManager()
        rmm_ssk.assert_called_once_with(encrypt_key=default_key,
                                        decrypt_key=default_key)


def test_armm_set_cipher_key(mock_remember_me_manager):
    """
    unit tested:  set_cipher_key

    test case:
    this method sets two key attributes used for encryption/decryption
    """
    mrmm = mock_remember_me_manager
    key = mgt_settings.default_cipher_key
    assert (mrmm.encryption_cipher_key == bytes(key, 'utf-8') and
            mrmm.decryption_cipher_key == bytes(key, 'utf-8'))


@pytest.mark.parametrize('authc_token, expected',
                         [(UsernamePasswordToken(username='userone',
                                                 password='useronepw',
                                                 remember_me=True), True),
                          (UsernamePasswordToken(username='usertwo',
                                                 password='usertwopw',
                                                 remember_me=False), False),
                          (type('DumbToken', (object,), {})(), False)])
def test_armm_is_remember_me(mock_remember_me_manager, authc_token, expected):
    """
    unit tested:  is_remember_me

    test case:
    confirms that an authentication token addresses the RememberMe criteria
    """
    mrmm = mock_remember_me_manager
    result = mrmm.is_remember_me(authc_token)
    assert result == expected


def test_armm_on_successful_login_isrememberme(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  on_successful_login

    test case:
    the subject identity is forgotten and then remembered
    """
    mrmm = mock_remember_me_manager
    monkeypatch.setattr(mrmm, 'is_remember_me', lambda x: True)

    with mock.patch.object(MockRememberMeManager, 'forget_identity') as mrmm_fi:
        mrmm_fi.return_value = None

        with mock.patch.object(MockRememberMeManager, 'remember_identity') as mrmm_ri:
            mrmm_ri.return_value = None
            mrmm.on_successful_login('subject', 'authc_token', 'account')
            mrmm_fi.assert_called_once_with('subject')
            mrmm_ri.assert_called_once_with('subject', 'authc_token', 'account')


def test_armm_on_successful_login_isnotrememberme(
        mock_remember_me_manager, monkeypatch, capsys):
    """
    unit tested:  on_successful_login

    test case:
    the subject identity is forgotten and then debug output is printed
    """
    mrmm = mock_remember_me_manager
    monkeypatch.setattr(mrmm, 'is_remember_me', lambda x: False)

    with mock.patch.object(MockRememberMeManager, 'forget_identity') as mrmm_fi:
        mrmm_fi.return_value = None

        mrmm.on_successful_login('subject', 'authc_token', 'account')
        out, err = capsys.readouterr()

        mrmm_fi.assert_called_once_with('subject')
        assert "AuthenticationToken did not indicate" in out


def test_armm_remember_identity_woidentitiers_raises(mock_remember_me_manager):
    """
    unit tested:  remember_identity

    test case:
    if identifiers cannot be obtained as an argument, and when calling
    get_identity_to_remember an exception is raised, an exception is raised
    """
    mrmm = mock_remember_me_manager
    with mock.patch.object(MockRememberMeManager, 'get_identity_to_remember') as gitr:
        gitr.side_effect = AttributeError
        pytest.raises(IllegalArgumentException,
                      "mrmm.remember_identity('subject', identifiers=None, account=None)")


def test_armm_remember_identity_wo_identitiersarg(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_identity

    test case:
    - identifiers obtained through get_identity_to_remember
    - calls remember_serialized_identity using serialized identifier collection
      and subject
    """
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(mrmm, 'get_identity_to_remember', lambda x,y: 'identifiers')

    with mock.patch.object(MockRememberMeManager, 'convert_identifiers_to_bytes') as citb:
        citb.return_value = 'serialized'

        with mock.patch.object(MockRememberMeManager, 'remember_serialized_identity') as rsi:
            rsi.return_value = None

            mrmm.remember_identity('subject', identifiers=None, account='account')

            citb.assert_called_once_with('identifiers')
            rsi.assert_called_once_with('subject', 'serialized')


def test_armm_remember_identity_w_identitiersarg(mock_remember_me_manager):
    """
    unit tested:  remember_identity

    test case:
    calls remember_serialized_identity using serialized identifier collection and
    subject
    """
    mrmm = mock_remember_me_manager

    with mock.patch.object(MockRememberMeManager,
                           'convert_identifiers_to_bytes') as citb:
        citb.return_value = 'serialized'

        with mock.patch.object(MockRememberMeManager,
                               'remember_serialized_identity') as rsi:
            rsi.return_value = None

            mrmm.remember_identity('subject',
                                   identifiers='identifiers',
                                   account='account')

            citb.assert_called_once_with('identifiers')
            rsi.assert_called_once_with('subject', 'serialized')

def test_armm_get_identity_to_remember(
        mock_remember_me_manager, full_mock_account):
    """
    unit tested:  get_identity_to_remember

    test case:
    returns account.identifiers
    """
    mrmm = mock_remember_me_manager
    result = mrmm.get_identity_to_remember('subject', full_mock_account)
    assert result == full_mock_account.identifiers


def test_armm_convert_identifiers_to_bytes(mock_remember_me_manager):
    """
    unit tested:  convert_identifiers_to_bytes

    test case:
    returns a byte string encoded serialized identifiers collection
    """
    mrmm = mock_remember_me_manager
    with mock.patch.object(SerializationManager, 'serialize') as sm_ser:
        sm_ser.return_value = 'serialized'
        result = mrmm.convert_identifiers_to_bytes('identifiers')
        sm_ser.assert_called_once_with('identifiers')


def test_armm_get_remembered_identifiers_raises(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  get_remembered_identifiers

    test case:
    - get_remembered_serialized_identity raises an exception
        - on_remembered_identifier_failure is called as a result
    - backup identifiers from o.r.i.f are returned
    """
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(mrmm, 'on_remembered_identifier_failure',
                        lambda x, y: 'identifiers')

    with mock.patch.object(MockRememberMeManager,
                           'get_remembered_serialized_identity') as grsi:
        grsi.side_effect = AttributeError
        result = mrmm.get_remembered_identifiers('subject_context')
        assert result == 'identifiers'


def test_armm_get_remembered_identifiers_serialized(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  get_remembered_identifiers

    test case:
    - obtains a remembered serialized identitifiers
    - returns deserialized identitifiers
    """
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(mrmm, 'convert_bytes_to_identifiers',
                        lambda x, y: 'identifiers')

    with mock.patch.object(MockRememberMeManager,
                           'get_remembered_serialized_identity') as grsi:
        grsi.return_value = 'serialized_identity'
        result = mrmm.get_remembered_identifiers('subject_context')
        assert result == 'identifiers'


def test_armm_convert_bytes_to_identifiers(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  convert_bytes_to_identifiers

    test case:
    first calls decrypt method and then returns deserialized object
    """
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(mrmm, 'decrypt', lambda x: 'decrypted')

    with mock.patch.object(SerializationManager, 'deserialize') as sm_deserialize:
        sm_deserialize.return_value = 'deserialized'
        result = mrmm.convert_bytes_to_identifiers('serialized', 'subject_context')
        sm_deserialize.assert_called_with('decrypted')
        assert result == 'deserialized'


def test_armm_on_remembered_identifier_failure(mock_remember_me_manager):
    """
    unit tested:  on_remembered_identifier_failure

    test case:
    logs, calls forget_identity, and then propagates the exception
    """
    mrmm = mock_remember_me_manager
    exc = AttributeError()
    with mock.patch.object(MockRememberMeManager, 'forget_identity') as fi:
        fi.return_value = None
        with pytest.raises(AttributeError):
            mrmm.on_remembered_identifier_failure(exc, 'subject_context')
            fi.assert_called_once_with('subject_context')


def test_armm_encrypt(mock_remember_me_manager, monkeypatch):
    """
    unit tested:  encrypt

    test case:
    passes call to fernet.encrypt
    """
    mrmm = mock_remember_me_manager
    key = Fernet.generate_key()
    monkeypatch.setattr(mrmm, 'encryption_cipher_key', key)
    with mock.patch.object(Fernet, 'encrypt') as fernet_encrypt:
        fernet_encrypt.return_value = 'encrypted'
        result = mrmm.encrypt('serialized')
        fernet_encrypt.assert_called_once_with('serialized')
        assert result == 'encrypted'


def test_armm_decrypt(mock_remember_me_manager, monkeypatch):
    """
    unit tested:  decrypt

    test case:
    passes call to fernet.decrypt
    """
    mrmm = mock_remember_me_manager
    key = Fernet.generate_key()
    monkeypatch.setattr(mrmm, 'decryption_cipher_key', key)
    with mock.patch.object(Fernet, 'decrypt') as fernet_decrypt:
        fernet_decrypt.return_value = 'decrypted'
        result = mrmm.decrypt('serialized')
        fernet_decrypt.assert_called_once_with('serialized')
        assert result == 'decrypted'


def test_armm_on_failed_login(mock_remember_me_manager):
    """
    unit tested:  on_failed_login

    test case:
    calls forget_identity
    """
    mrmm = mock_remember_me_manager
    with mock.patch.object(MockRememberMeManager, 'forget_identity') as fi:
        fi.return_value = None

        mrmm.on_failed_login('subject', 'token', 'exception')

        fi.assert_called_once_with('subject')


def test_armm_on_logout(mock_remember_me_manager):
    """
    unit tested:  on_logout

    test case:
    calls forget_identity
    """
    mrmm = mock_remember_me_manager
    with mock.patch.object(MockRememberMeManager, 'forget_identity') as fi:
        fi.return_value = None

        mrmm.on_logout('subject')

        fi.assert_called_once_with('subject')
