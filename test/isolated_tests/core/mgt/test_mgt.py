import pytest
from unittest import mock
from cryptography.fernet import Fernet

from yosai.core import (
    AdditionalAuthenticationRequired,
    AuthenticationException,
    DefaultAuthenticator,
    DelegatingSession,
    DelegatingSubject,
    NativeSecurityManager,
    SessionKey,
    SubjectContext,
    InvalidSessionException,
    ModularRealmAuthorizer,
    NativeSessionManager,
    SerializationManager,
    UsernamePasswordToken,
    authc_abcs,
)

from ..session.doubles import (
    MockNativeSessionManager,
)

from .doubles import (
    MockRememberMeManager,
)

# ------------------------------------------------------------------------------
# NativeSecurityManager
# ------------------------------------------------------------------------------


def test_nsm_apply_cachehandler(
        native_security_manager, monkeypatch, account_store_realm):
    """
    applies the cachehandler to its related objects (those that implement the
    CacheHandlerAware interface)
    """
    nsm = native_security_manager
    realms = (account_store_realm,)
    monkeypatch.setattr(nsm, 'realms', realms)
    nsm.apply_cache_handler('cache_handler')

    assert realms[0].cache_handler == 'cache_handler'
    assert nsm.session_manager.session_handler.session_store.cache_handler == 'cache_handler'


def test_nsm_apply_eventbus(native_security_manager, event_bus, monkeypatch):
    """
    test case:
    sets attribute and calls method
    """
    nsm = native_security_manager
    mock_sm = mock.create_autospec(NativeSessionManager)
    monkeypatch.setattr(nsm, 'session_manager', mock_sm)
    nsm.apply_event_bus('event_bus')
    mock_sm.apply_event_bus.assert_called_once_with('event_bus')
    assert nsm.authenticator.event_bus == 'event_bus'
    assert nsm.authorizer.event_bus == 'event_bus'


def test_apply_realms(native_security_manager, monkeypatch):
    nsm = native_security_manager
    mock_authc = mock.create_autospec(DefaultAuthenticator)
    mock_authz = mock.create_autospec(ModularRealmAuthorizer)
    monkeypatch.setattr(nsm, 'authenticator', mock_authc)
    monkeypatch.setattr(nsm, 'authorizer', mock_authz)
    monkeypatch.setattr(nsm, 'realms', 'realms')
    nsm.apply_realms()
    mock_authc.init_realms.assert_called_once_with('realms')
    mock_authz.init_realms.assert_called_once_with('realms')


def test_nsm_is_permitted(native_security_manager):
    """
    unit tested:  is_permitted

    test case:
    passes request on to authorizer
    """
    nsm = native_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'is_permitted') as mra_ip:
        nsm.is_permitted('identifiers', 'permission_s')
        mra_ip.assert_called_once_with('identifiers', 'permission_s')


def test_nsm_is_permitted_collective(native_security_manager):
    """
    unit tested: is_permitted_collective

    test case:
    passes request on to authorizer
    """
    nsm = native_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'is_permitted_collective') as mra_ipa:
        nsm.is_permitted_collective('identifiers', 'permission_s', all)
        mra_ipa.assert_called_once_with('identifiers', 'permission_s', all)


def test_nsm_check_permission(native_security_manager):
    """
    unit tested:  check_permission

    test case:
    passes request on to authorizer
    """
    nsm = native_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'check_permission') as mra_cp:
        nsm.check_permission('identifiers', 'permission_s', all)
        mra_cp.assert_called_once_with('identifiers', 'permission_s', all)


def test_nsm_has_role(native_security_manager):
    """
    unit tested:  has_role

    test case:
    passes request on to authorizer
    """
    nsm = native_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'has_role') as mra_hr:
        nsm.has_role('identifiers', 'permission_s')
        mra_hr.assert_called_once_with('identifiers', 'permission_s')


def test_nsm_has_role_collective(native_security_manager):
    """
    unit tested:  has_role_collective

    test case:
    passes request on to authorizer
    """
    nsm = native_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'has_role_collective') as mra_har:
        nsm.has_role_collective('identifiers', 'permission_s', all)
        mra_har.assert_called_once_with('identifiers', 'permission_s', all)


def test_nsm_check_role(native_security_manager):
    """
    unit tested:  check_role

    test case:
    passes request on to authorizer
    """
    nsm = native_security_manager
    with mock.patch.object(ModularRealmAuthorizer, 'check_role') as mra_cr:
        nsm.check_role('identifiers', 'permission_s', all)
        mra_cr.assert_called_once_with('identifiers', 'permission_s', all)

def test_nsm_start(
        native_security_manager, mock_default_session_manager, monkeypatch):
    """
    unit tested:  start

    test case:
    passes request on to session manager
    """
    nsm = native_security_manager
    mnsm = mock_default_session_manager
    monkeypatch.setattr(nsm, 'session_manager', mnsm)
    with mock.patch.object(MockNativeSessionManager, 'start') as mnsm_start:
        mnsm_start.return_value = None
        nsm.start('session_context')
        mnsm_start.assert_called_once_with('session_context')

def test_nsm_get_session(
        native_security_manager, mock_default_session_manager, monkeypatch):
    """
    unit tested:  get_session

    test case:
    passes request on to session manager
    """
    nsm = native_security_manager
    mnsm = mock_default_session_manager
    monkeypatch.setattr(nsm, 'session_manager', mnsm)
    with mock.patch.object(MockNativeSessionManager, 'get_session') as mnsm_gs:
        mnsm_gs.return_value = None
        nsm.get_session('sessionkey123')
        mnsm_gs.assert_called_once_with('sessionkey123')


def test_nsm_create_subject_context(
        native_security_manager, mock_default_session_manager, monkeypatch,
        mock_subject):
    """
    unit tested:  create_subject_context

    test case:
    returns a new SubjectContext instance
    """
    nsm = native_security_manager
    result = nsm.create_subject_context(mock_subject)
    assert isinstance(result, SubjectContext)


def test_nsm_create_subject_wo_context(
        native_security_manager, yosai):
    """
    unit tested:  create_subject

    test case:
    When no subject_context argument is given, a new subject_context is
    created.  The subject_context is used to create a new subject, which is
    saved and then returned.
    """
    nsm = native_security_manager

    testcontext = SubjectContext(yosai=yosai, security_manager=nsm)
    testcontext.authenticated = True
    testcontext.authentication_token = 'dumb_token'
    testcontext.account_id = 'dumb_account'
    testcontext.subject = 'existing_subject'

    with mock.patch.object(nsm, 'ensure_security_manager') as nsm_esm:
        nsm_esm.return_value = testcontext
        with mock.patch.object(nsm, 'resolve_session') as nsm_rs:
            nsm_rs.return_value = testcontext
            with mock.patch.object(nsm, 'resolve_identifiers') as nsm_rp:
                nsm_rp.return_value = testcontext
                with mock.patch.object(nsm, 'do_create_subject') as nsm_dcs:
                    nsm_dcs.return_value = 'subject'
                    with mock.patch.object(nsm, 'save') as nsm_save:
                        nsm_save.return_value = None

                        result = nsm.create_subject(authc_token='dumb_token',
                                                    account_id='dumb_account',
                                                    existing_subject='existing_subject')

                        nsm_esm.assert_called_once_with(testcontext)
                        nsm_rs.assert_called_once_with(testcontext)
                        nsm_rp.assert_called_once_with(testcontext)
                        nsm_dcs.assert_called_once_with(testcontext)
                        assert result == 'subject'

def test_nsm_create_subject_w_context(native_security_manager, yosai):
    """
    unit tested:  create_subject

    test case:
    context is passed as an argument, and so it is used
    """
    nsm = native_security_manager

    testcontext = SubjectContext(yosai=yosai, security_manager=nsm)
    testcontext.authenticated = True
    testcontext.authentication_token = 'dumb_token'
    testcontext.account_id = 'dumb_account'
    testcontext.subject = 'existing_subject'

    with mock.patch.object(nsm, 'ensure_security_manager') as nsm_esm:
        nsm_esm.return_value = testcontext
        with mock.patch.object(nsm, 'resolve_session') as nsm_rs:
            nsm_rs.return_value = testcontext
            with mock.patch.object(nsm, 'resolve_identifiers') as nsm_rp:
                nsm_rp.return_value = testcontext
                with mock.patch.object(nsm, 'do_create_subject') as nsm_dcs:
                    nsm_dcs.return_value = None
                    with mock.patch.object(nsm, 'save') as nsm_save:
                        nsm_save.return_value = None

                        nsm.create_subject(subject_context=testcontext)

                        nsm_esm.assert_called_once_with(testcontext)
                        nsm_rs.assert_called_once_with(testcontext)
                        nsm_rp.assert_called_once_with(testcontext)
                        nsm_dcs.assert_called_once_with(testcontext)


def test_nsm_rememberme_successful_login(
        native_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_me_successful_login

    test case:
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_successful_login') as mrmm_osl:
        mrmm_osl.return_value = None
        nsm.remember_me_successful_login('authc_token', 'account', 'subject')
        mrmm_osl.assert_called_once_with('subject', 'authc_token', 'account')


def test_nsm_rememberme_successful_login_rmm_set_but_raises(
        caplog, native_security_manager, mock_remember_me_manager,
        monkeypatch):
    """
    unit tested:  remember_me_successful_login

    test case:
    1) the remember_me_manager attribute is set
    2) the call for rmm.on_successful_login raises an exception
    3) a warning message is emitted
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_successful_login') as mrmm_osl:
        mrmm_osl.side_effect = Exception
        nsm.remember_me_successful_login('authc_token', 'account', 'subject')
        out = caplog.text
        assert 'threw an exception' in out


def test_nsm_rememberme_successful_login_rmm_notset(caplog, native_security_manager):
    """
    unit tested:  remember_me_successful_login

    test case:
    when the remember_me_manager attribute is not set, a warning message is
    emitted
    """
    nsm = native_security_manager
    nsm.remember_me_successful_login('authc_token', 'account_id', 'subject')
    out = caplog.text
    assert 'does not have' in out

def test_nsm_rememberme_failed_login(
        native_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_me_failed_login

    test case:
    when a remember_me_manager is set, it's on_failed_login is called
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_failed_login') as mrmm_ofl:
        mrmm_ofl.return_value = None
        nsm.remember_me_failed_login('authc_token', 'authc_exc', 'subject')
        mrmm_ofl.assert_called_once_with('subject', 'authc_token', 'authc_exc')


def test_nsm_rememberme_failed_login_warned(
        native_security_manager, mock_remember_me_manager, monkeypatch,
        caplog):
    """
    unit tested:  remember_me_failed_login

    test case:
    when the remember_me_manager attribute is not set, a warning message is
    emitted
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_failed_login') as mrmm_ofl:
        mrmm_ofl.side_effect = Exception
        nsm.remember_me_failed_login('authc_token', 'authc_exc', 'subject')
        out = caplog.text
        assert 'threw an exception' in out

def test_nsm_rememberme_logout(
        native_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_me_logout

    test case:
    when a remember_me_manager is set, it's on_logout is called
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'remember_me_manager', mock_remember_me_manager)

    with mock.patch.object(MockRememberMeManager,
                           'on_logout') as mrmm_ol:
        mrmm_ol.return_value = None
        nsm.remember_me_logout('subject')
        mrmm_ol.assert_called_once_with('subject')


def test_nsm_rememberme_logout_warned(
        native_security_manager, mock_remember_me_manager, monkeypatch,
        caplog):
    """
    unit tested:  remember_me_logout

    test case:
    prints a warning when remember_me_manager raises an exception
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'remember_me_manager', mock_remember_me_manager)

    class MockSubject:
        def __init__(self):
            self.identifiers = {'username': 'username'}

    with mock.patch.object(MockRememberMeManager,
                           'on_logout') as mrmm_ol:
        mrmm_ol.side_effect = Exception
        nsm.remember_me_logout(MockSubject())
        out = caplog.text
        assert 'threw an exception during on_logout' in out


def test_nsm_login_success(native_security_manager, monkeypatch, mock_subject):
    """
    unit tested:  login

    test case:
        authenticate_account returns an account, create_subject is called,
        on_successful_login is called, and then logged_in is returned
    """
    nsm = native_security_manager
    mock_subject.identifiers = 'identifiers'
    mock_authc = mock.create_autospec(DefaultAuthenticator)
    mock_authc.authenticate_account.return_value = 'accountid'
    monkeypatch.setattr(nsm, 'authenticator', mock_authc)

    with mock.patch.object(NativeSecurityManager,
                           'create_subject') as nsm_cs:
        nsm_cs.return_value = 'logged_in'
        with mock.patch.object(NativeSecurityManager,
                               'on_successful_login') as nsm_osl:
            nsm_osl.return_value = None

            result = nsm.login(mock_subject, 'authc_token')

            nsm_cs.assert_called_once_with(authc_token='authc_token',
                                           account_id='accountid',
                                           existing_subject=mock_subject)
            nsm_osl.assert_called_once_with('authc_token','accountid','logged_in')
            mock_authc.authenticate_account.assert_called_once_with('identifiers', 'authc_token')
            assert result == 'logged_in'


def test_nsm_login_raises_additional(native_security_manager, monkeypatch, mock_subject):
    nsm = native_security_manager
    mock_subject.identifiers = 'identifiers'
    mock_authc = mock.create_autospec(DefaultAuthenticator)
    mock_authc.authenticate_account.side_effect = AdditionalAuthenticationRequired
    monkeypatch.setattr(nsm, 'authenticator', mock_authc)
    mock_usi = mock.MagicMock()
    monkeypatch.setattr(nsm, 'update_subject_identity', mock_usi)

    with pytest.raises(AdditionalAuthenticationRequired):
        nsm.login(mock_subject, 'authc_token')

    assert mock_usi.called


def test_nsm_login_raises_then_succeeds(native_security_manager, monkeypatch, mock_subject):
    """
    unit tested:  login

    test case:
    authenticate_account raises an AuthenticationException, on_failed_login
    succeeds, and an AuthenticationException is raised up the stack
    """
    nsm = native_security_manager
    mock_authc = mock.create_autospec(DefaultAuthenticator)
    mock_authc.authenticate_account.side_effect = AuthenticationException
    monkeypatch.setattr(nsm, 'authenticator', mock_authc)
    mock_subject.identifiers = 'identifiers'

    with mock.patch.object(NativeSecurityManager, 'on_failed_login') as nsm_ofl:
        nsm_ofl.return_value = None

        with pytest.raises(AuthenticationException):
            nsm.login(mock_subject, 'authc_token')
            nsm_ofl.assert_called_once_with(
                'authc_token', AuthenticationException, 'subject')


def test_nsm_login_raises_then_raises(native_security_manager, caplog, monkeypatch, mock_subject):
    """
    unit tested:  login

    test case:
    authenticate_account raises an AuthenticationException, on_failed_login
    raises, a warning is emitted, and an AuthenticationException is raised up
    the stack
    """
    nsm = native_security_manager
    mock_authc = mock.create_autospec(DefaultAuthenticator)
    mock_authc.authenticate_account.side_effect = AuthenticationException
    monkeypatch.setattr(nsm, 'authenticator', mock_authc)
    mock_subject.identifiers = 'identifiers'

    with mock.patch.object(NativeSecurityManager,
                           'on_failed_login') as nsm_ofl:
        nsm_ofl.side_effect = Exception

        with pytest.raises(AuthenticationException):
            nsm.login(mock_subject, 'authc_token')

            nsm_ofl.assert_called_once_with(
                'authc_token', AuthenticationException, 'subject')

            out = caplog.text
            assert 'on_failed_login method raised' in out


def test_nsm_on_successful_login(native_security_manager):
    """
    unit tested:  on_successful_login

    test case:
    passes call on to remember_me_successful_login
    """
    nsm = native_security_manager

    with mock.patch.object(NativeSecurityManager,
                           'remember_me_successful_login') as nsm_rmsl:
        nsm_rmsl.return_value = None

        nsm.on_successful_login('authc_token', 'account', 'subject')

        nsm_rmsl.assert_called_once_with('authc_token', 'account', 'subject')


def test_nsm_onfailed_login(native_security_manager):
    """
    unit tested:  on_failed_login

    test case:
    passes call on to remember_me_failed_login
    """
    nsm = native_security_manager
    with mock.patch.object(NativeSecurityManager,
                           'remember_me_failed_login') as nsm_rmfl:
        nsm_rmfl.return_value = None
        nsm.on_failed_login('authc_token', 'authc_exc', 'subject')
        nsm_rmfl.assert_called_once_with('authc_token', 'authc_exc', 'subject')


def test_nsm_before_logout(native_security_manager):
    """
    unit tested:  before_logout

    test case:
    passes call on to remember_me_logout
    """
    nsm = native_security_manager
    with mock.patch.object(NativeSecurityManager,
                           'remember_me_logout') as nsm_rml:
        nsm_rml.return_value = None

        nsm.before_logout('subject')

        nsm_rml.assert_called_once_with('subject')


@mock.patch.object(DelegatingSubject, '__init__', return_value=None)
def test_nsm_do_create_subject(mock_ds, native_security_manager, monkeypatch):
    """
    unit tested:  do_create_subject

    """
    nsm = native_security_manager
    mock_sc = mock.create_autospec(SubjectContext)
    mock_sc.resolve_security_manager.return_value = 'security_manager'
    mock_sc.resolve_session.return_value = 'session'
    mock_sc.session_creation_enabled = 'session_creation_enabled'
    mock_sc.resolve_identifiers.return_value = 'identifiers'
    mock_sc.remembered = True
    mock_sc.resolve_authenticated.return_value = True
    mock_sc.resolve_host.return_value = 'host'

    nsm.do_create_subject(mock_sc)
    mock_ds.assert_called_once_with(identifiers='identifiers',
                                    remembered=True,
                                    authenticated=True,
                                    host='host',
                                    session='session',
                                    session_creation_enabled='session_creation_enabled',
                                    security_manager='security_manager')


def test_nsm_save(native_security_manager, monkeypatch):
    """
    unit tested:  save

    test case:
    passes call onto subject_store.save
    """
    nsm = native_security_manager

    class DumbStore:
        def save(self, subject):
            return 'saved'

    monkeypatch.setattr(nsm, 'subject_store', DumbStore())
    with mock.patch.object(DumbStore, 'save') as ds_save:
        nsm.save('subject')
        ds_save.assert_called_once_with('subject')


def test_nsm_delete(native_security_manager, monkeypatch):
    """
    unit tested:  delete

    test case:
    passes call onto subject_store.delete
    """
    nsm = native_security_manager

    class DumbStore:
        def delete(self, subject):
            return None

    monkeypatch.setattr(nsm, 'subject_store', DumbStore())
    with mock.patch.object(DumbStore, 'delete') as ds_delete:
        nsm.delete('subject')
        ds_delete.assert_called_once_with('subject')


def test_nsm_ensure_security_manager_resolves(
        native_security_manager, mock_subject_context, monkeypatch):
    """
    unit tested:  ensure_security_manager

    test case:
    resolve_security_manager returns the subject_context
    """
    nsm = native_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'resolve_security_manager', lambda: True)

    result = nsm.ensure_security_manager(msc)

    assert result


def test_nsm_ensure_security_manager_doesntresolve(
        native_security_manager, mock_subject_context, monkeypatch):

    """
    unit tested:  ensure_security_manager

    test case:
    resolve_security_manager returns None, and then ensure_security_manager
    returns a subject_context whose security_manager is the nsm
    """
    nsm = native_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'resolve_security_manager', lambda: None)

    result = nsm.ensure_security_manager(msc)

    assert result.security_manager == nsm


def test_nsm_resolve_session_returns_none(
        native_security_manager, mock_subject_context, monkeypatch):
    """
    unit tested:  resolve_session

    test case:
    the subject_context.resolve_session returns None, implying that the
    context already contains a session, so returns it as is
    """
    nsm = native_security_manager
    msc = mock_subject_context

    monkeypatch.setattr(msc, 'resolve_session', lambda: 'session')

    result = nsm.resolve_session(msc)

    assert result == msc


def test_nsm_resolve_session_contextsessionisnone(
        native_security_manager, mock_subject_context, monkeypatch):
    """
    unit tested:  resolve_session

    test case:
     - the subject_context doesnt resolve a session
     - resolve_context_session returns None,
     - subject_context.session doesn't get set

    """
    nsm = native_security_manager
    msc = mock_subject_context
    msc.resolve_session.return_value = None

    with mock.patch.object(NativeSecurityManager,
                           'resolve_context_session') as nsm_rcs:
        nsm_rcs.side_effect = InvalidSessionException
        result = nsm.resolve_session(msc)
        assert not hasattr(result, 'session')


def test_nsm_resolve_context_session_nokey(
        native_security_manager, monkeypatch):
    """
    unit tested:  resolve_context_session

    test case:
    get_session_key returns none , returning None
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'get_session_key', lambda x: None)
    result = nsm.resolve_context_session('subject_context')
    assert result is None

def test_nsm_resolve_context_session(native_security_manager, monkeypatch):
    """
    unit tested:  resolve_context_session

    test case:
    get_session_key returns a key, so get_session called and returns
    """
    nsm = native_security_manager
    monkeypatch.setattr(nsm, 'get_session_key', lambda x: 'sessionkey123')
    monkeypatch.setattr(nsm, 'get_session', lambda x: 'session')

    result = nsm.resolve_context_session('subject_context')
    assert result == 'session'


def test_nsm_get_session_key_w_sessionid(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  get_session_key

    test case:

    """
    nsm = native_security_manager
    msc = mock_subject_context

    monkeypatch.setattr(msc, 'session_id', 'sessionid123', raising=False)

    result = nsm.get_session_key(msc)

    assert result == SessionKey('sessionid123')

def test_nsm_get_session_key_wo_sessionid(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  get_session_key

    test case:

    """
    nsm = native_security_manager
    msc = mock_subject_context
    monkeypatch.setattr(msc, 'session_id', None, raising=False)
    result = nsm.get_session_key(msc)
    assert result is None


def test_nsm_resolve_identifiers_incontext(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    subject_context contains identifiers, so returns it back immediately
    """
    nsm = native_security_manager
    msc = mock_subject_context
    msc.session = None
    msc.resolve_identifiers.return_value = 'identifiers'
    result = nsm.resolve_identifiers(msc)

    assert result == msc


def test_nsm_resolve_identifiers_notincontext_notremembered(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    - by default, the mock subject context's resolve_identifiers returns None
    - fails to obtain identifiers from remembered identity
    """

    nsm = native_security_manager
    msc = mock_subject_context

    msc.session = None
    msc.resolve_identifiers.return_value = None

    result = nsm.resolve_identifiers(msc)
    assert not hasattr(result, 'identifiers')


def test_nsm_resolve_identifiers_notincontext_remembered(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    - by default, the mock subject context's resolve_identifiers returns None
    - fails to obtain identifiers from remembered identity
    """
    nsm = native_security_manager
    msc = mock_subject_context
    msc.session = None
    msc.resolve_identifiers.return_value = None

    monkeypatch.setattr(nsm, 'get_remembered_identity', lambda x: 'identifiers')
    result = nsm.resolve_identifiers(msc)
    assert hasattr(result, 'identifiers')


def test_nsm_create_session_context_empty(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  create_session_context

    test case:
    subject_context=empty,passes
    session_id=None, passes
    host=None, passes
    """
    nsm = native_security_manager
    msc = mock_subject_context
    msc.is_empty = True
    msc.session_id = None
    msc.resolve_host.return_value = None
    result = nsm.create_session_context(msc)

    assert 'session_id' not in result
    assert 'host' not in result


def test_nsm_create_session_context(
        native_security_manager, monkeypatch, mock_subject_context):
    """
    unit tested:  create_session_context

    test case:
    subject_context has values
    session_id has values
    host has values
    """
    nsm = native_security_manager
    msc = mock_subject_context

    msc.is_empty = False
    msc.session_id = 'session_id'
    msc.resolve_host.return_value = 'host'

    result = nsm.create_session_context(msc)

    assert (result['session_id'] == 'session_id' and
            result['host'] == 'host')


def test_nsm_logout_raises(native_security_manager):
    """
    unit tested:  logout

    test case:
    a subject must be passed as an argument
    """
    nsm = native_security_manager
    with pytest.raises(ValueError):
        nsm.logout(None)


def test_nsm_logout_succeeds(native_security_manager, monkeypatch, mock_subject):
    """
    unit tested:  logout

    test case:
    calls before_logout, obtains identifiers from subject, calls the
    authenticator's on_logout method, calls delete, calls stop_session
    """
    nsm = native_security_manager

    mock_subject.identifiers.primary_identifier = 'identifiers'

    with mock.patch.object(nsm, 'before_logout') as nsm_bl:
        nsm_bl.return_value = None
        with mock.patch.object(nsm, 'delete') as nsm_delete:
            nsm_delete.return_value = None
            with mock.patch.object(nsm, 'stop_session') as nsm_ss:
                nsm_ss.return_value = None

                nsm.logout(mock_subject)

                nsm_bl.assert_called_once_with(mock_subject)
                nsm_delete.assert_called_once_with(mock_subject)
                nsm_ss.assert_called_once_with(mock_subject)


def test_nsm_logout_succeeds_until_delete_raises(
        native_security_manager, monkeypatch, caplog, mock_subject):
    """
    unit tested:  logout

    test case:
    calls before_logout, obtains identifiers from subject, calls the
    authenticator's on_logout method, calls delete and raises
    """
    nsm = native_security_manager
    mock_subject.identifiers.primary_identifier = 'identifiers'

    with mock.patch.object(nsm, 'before_logout') as nsm_bl:
        nsm_bl.return_value = None
        with mock.patch.object(nsm, 'delete') as nsm_delete:
            nsm_delete.side_effect = Exception
            with mock.patch.object(nsm, 'stop_session') as nsm_ss:
                nsm_ss.side_effect = Exception

                nsm.logout(mock_subject)
                nsm_bl.assert_called_once_with(mock_subject)
                nsm_delete.assert_called_once_with(mock_subject)
                nsm_ss.assert_called_once_with(mock_subject)

                out = caplog.text
                assert ('Unable to cleanly unbind Subject' in out and
                        'Unable to cleanly stop Session' in out)


def test_nsm_stop_session(native_security_manager, monkeypatch, mock_subject):
    """
    unit tested:  stop_session

    test case:
    gets a session and calls its stop method
    """
    nsm = native_security_manager
    mock_subject.identifiers.primary_identifier = 'identifiers'
    mock_ds = mock.create_autospec(DelegatingSession)
    mock_subject.get_session.return_value = mock_ds

    nsm.stop_session(mock_subject)
    mock_ds.stop.assert_called_once_with(mock_subject.identifiers)


def test_nsm_get_remembered_identity(
        native_security_manager, mock_remember_me_manager, monkeypatch):
    """
    unit tested:  get_remembered_identity

    test case:
    returns remembered identifiers from the rmm
    """
    nsm = native_security_manager
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(nsm, 'remember_me_manager', mrmm)
    monkeypatch.setattr(mrmm,
                        'get_remembered_identifiers',
                        lambda x: 'remembered_identifiers')
    result = nsm.get_remembered_identity('subjectcontext')
    assert result == 'remembered_identifiers'


def test_nsm_get_remembered_identity_not_remembered(native_security_manager):
    """
    unit tested:  get_remembered_identity

    test case:
    remember_me_manager by default isn't set, so None is returned
    """
    nsm = native_security_manager
    result = nsm.get_remembered_identity('subject_context')
    assert result is None


def test_nsm_get_remembered_identity_raises(
        native_security_manager, mock_remember_me_manager, monkeypatch,
        caplog):
    """
    unit tested:  get_remembered_identity

    test case:
    raises an exception while trying to get remembered identifiers from rmm
    """

    nsm = native_security_manager
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(nsm, 'remember_me_manager', mrmm)
    with mock.patch.object(MockRememberMeManager,
                           'get_remembered_identifiers') as mrmm_gri:
        mrmm_gri.side_effect = Exception

        result = nsm.get_remembered_identity('subjectcontext')
        out = caplog.text
        assert (result is None and 'raised an exception' in out)


# ------------------------------------------------------------------------------
# AbstractRememberMeManager
# ------------------------------------------------------------------------------

def test_armm_init(remember_me_settings, core_settings, session_attributes):
    """
    unit tested:  __init__

    test case:
    confirm that init calls set_cipher_key using remember_me_settings.default_cipher_key
    """
    default_key = remember_me_settings.default_cipher_key
    mrmm = MockRememberMeManager(core_settings, session_attributes)
    assert (mrmm.encryption_cipher_key == mrmm.decryption_cipher_key and
            mrmm.encryption_cipher_key == default_key)


def test_armm_on_successful_login_isrememberme(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  on_successful_login

    test case:
    the subject identity is forgotten and then remembered
    """
    mrmm = mock_remember_me_manager
    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.is_remember_me = True

    with mock.patch.object(MockRememberMeManager, 'forget_identity') as mrmm_fi:
        mrmm_fi.return_value = None

        with mock.patch.object(MockRememberMeManager, 'remember_identity') as mrmm_ri:
            mrmm_ri.return_value = None
            mrmm.on_successful_login('subject', mock_token, 'accountid')
            mrmm_fi.assert_called_once_with('subject')
            mrmm_ri.assert_called_once_with('subject', mock_token, 'accountid')


def test_armm_on_successful_login_isnotrememberme(
        mock_remember_me_manager, monkeypatch, caplog):
    """
    unit tested:  on_successful_login

    test case:
    the subject identity is forgotten and then debug output is printed
    """
    mrmm = mock_remember_me_manager

    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.is_remember_me = False

    with mock.patch.object(MockRememberMeManager, 'forget_identity') as mrmm_fi:
        mrmm_fi.return_value = None

        mrmm.on_successful_login('subject', mock_token, 'accountid')
        out = caplog.text

        mrmm_fi.assert_called_once_with('subject')
        assert "AuthenticationToken did not indicate" in out


def test_armm_remember_identity_woidentitiers_raises(mock_remember_me_manager):
    """
    unit tested:  remember_identity

    test case:
        - get_identity_to_remember raises an AttributeError
        - InvalidArgumentException is raised
    """
    mrmm = mock_remember_me_manager
    with mock.patch.object(MockRememberMeManager, 'get_identity_to_remember') as gitr:
        gitr.side_effect = AttributeError
        with pytest.raises(AttributeError):
            mrmm.remember_identity('subject', 'authc_token', 'account')


def test_armm_remember_identity(mock_remember_me_manager, monkeypatch):
    """
    unit tested:  remember_identity

    test case:
    - identifiers obtained through get_identity_to_remember
    - calls remember_encrypted_identity using serialized identifiers collection
      and subject
    """
    mrmm = mock_remember_me_manager
    monkeypatch.setattr(mrmm, 'get_identity_to_remember', lambda x,y: 'identifiers')

    with mock.patch.object(mrmm, 'convert_identifiers_to_bytes') as mock_citb:
        mock_citb.return_value = 'serialized'
        with mock.patch.object(MockRememberMeManager, 'remember_encrypted_identity') as rsi:
            mrmm.remember_identity('subject', 'authc_token', 'account')

            rsi.assert_called_once_with('subject', 'serialized')


def test_armm_get_identity_to_remember(mock_remember_me_manager):
    """
    unit tested:  get_identity_to_remember

    test case:
    returns account.identifiers
    """
    mrmm = mock_remember_me_manager
    result = mrmm.get_identity_to_remember('subject', 'account_id')
    assert result == 'account_id'


def test_armm_convert_identifiers_to_bytes(mock_remember_me_manager, monkeypatch):
    """
    unit tested:  convert_identifiers_to_bytes

    test case:
    returns a byte string encoded serialized identifiers collection
    """
    mrmm = mock_remember_me_manager
    with mock.patch.object(mrmm.serialization_manager, 'serialize') as mock_sms:
        mock_sms.return_value = 'serialized'
        with mock.patch.object(mrmm, 'encrypt') as mock_rmm_enc:
            mrmm.convert_identifiers_to_bytes('identifiers')
            mock_rmm_enc.assert_called_once_with('serialized')


def test_armm_get_remembered_identifiers_raises(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  get_remembered_identifiers

    test case:
    - get_remembered_encrypted_identity raises an exception
        - on_remembered_identifiers_failure is called as a result
    - backup identifiers from o.r.i.f are returned
    """
    mrmm = mock_remember_me_manager

    monkeypatch.setattr(mrmm, 'on_remembered_identifiers_failure',
                        lambda x, y: 'identifiers')

    with mock.patch.object(MockRememberMeManager,
                           'get_remembered_encrypted_identity') as grsi:
        grsi.side_effect = AttributeError
        result = mrmm.get_remembered_identifiers('subject_context')
        assert result == 'identifiers'


def test_armm_get_remembered_identifiers_serialized(
        mock_remember_me_manager, monkeypatch):
    """
    unit tested:  get_remembered_identifiers

    test case:
    - obtains a remembered encrypted identitifiers
    - returns deserialized identitifiers
    """
    mrmm = mock_remember_me_manager
    monkeypatch.setattr(mrmm, 'convert_bytes_to_identifiers', lambda x, y: 'identifiers')
    with mock.patch.object(MockRememberMeManager,
                           'get_remembered_encrypted_identity') as grsi:
        grsi.return_value = 'encrypted'
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


def test_armm_on_remembered_identifiers_failure(mock_remember_me_manager):
    """
    unit tested:  on_remembered_identifiers_failure

    test case:
    logs, calls forget_identity, and then propagates the exception
    """
    mrmm = mock_remember_me_manager
    exc = AttributeError()
    with mock.patch.object(MockRememberMeManager, 'forget_identity') as fi:
        fi.return_value = None
        with pytest.raises(AttributeError):
            mrmm.on_remembered_identifiers_failure(exc, 'subject_context')
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
