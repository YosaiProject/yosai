import pytest
import collections
from unittest import mock

from yosai.core import (
    AuthenticationException,
    DefaultSessionContext,
    DefaultSessionStorageEvaluator,
    DefaultSubjectContext,
    DefaultSubjectStore,
    DelegatingSubject,
    DisabledSessionException,
    IdentifiersNotSetException,
    InvalidArgumentException,
    IllegalStateException,
    SimpleIdentifierCollection,
    SessionException,
    SubjectBuilder,
    SecurityUtils,
    thread_local,
    UnauthenticatedException,
    UnavailableSecurityManagerException,
)

from ..doubles import (
    MockSecurityManager,
    MockSession,
    MockSubjectBuilder,
)

# ------------------------------------------------------------------------------
# DefaultSubjectContext
# ------------------------------------------------------------------------------


def test_dsc_init(subject_context, default_subject_context):
    """
    unit tested:  __init__

    test case:
    Verify that the two subject contexts used for testing are initialized as
    expected
    """
    dsc = DefaultSubjectContext()
    assert (not dsc.attributes and
            'DefaultSubjectContext.AUTHENTICATION_TOKEN' in
            default_subject_context.attribute_keys)


@pytest.mark.parametrize(
    'attr', ['security_manager', 'session_id', 'subject', 'identifiers',
             'session', 'session_creation_enabled', 'authentication_token',
             'host'])
def test_dsc_property_accessors(
        attr, default_subject_context, subject_context):
    """
    unit tested:  every property accessor method, except authenticated

    test case:
    each property references an underlying context map for its corresponding
    value
    """
    dsc = default_subject_context
    result = getattr(dsc, attr)
    assert result == 'value_' + subject_context.get(attr.upper())


@pytest.mark.parametrize(
    'attr', ['security_manager', 'session_id', 'subject', 'identifiers',
             'session', 'session_creation_enabled', 'account',
             'authentication_token', 'host'])
def test_dsc_property_mutator(attr, default_subject_context):
    """
    unit tested:  every property mutator method, except authenticated

    test case:
    confirm the property setters work as expected
    """
    dsc = default_subject_context
    setattr(dsc, attr, attr)
    assert dsc.context[dsc.get_key(attr.upper())] == attr


def test_dsc_resolve_security_manager_exists(default_subject_context):
    """
    unit tested:  resolve_security_manager

    test case:
    resolves first to a security manager that already exists
    """
    dsc = default_subject_context
    result = dsc.resolve_security_manager()
    assert result == dsc.security_manager and bool(result)


def test_dsc_resolve_security_manager_none(
        default_subject_context, monkeypatch, capsys):
    """
    unit tested:  resolve_security_manager

    test case:
    when no security manager attribute exists, next tries to obtain one from
    SecurityUtils
    """
    dsc = default_subject_context
    monkeypatch.setitem(dsc.context, dsc.get_key('SECURITY_MANAGER'), None)
    monkeypatch.setattr(thread_local, 'security_manager', 'mysecuritymanager', raising=False)
    result = dsc.resolve_security_manager()
    out, err = capsys.readouterr()
    assert ("No SecurityManager available" in out and
            result == 'mysecuritymanager')

def test_dsc_resolve_security_manager_none_raises(
        default_subject_context, monkeypatch, capsys):
    """
    unit tested:  resolve_security_manager

    test case:
    no security manager attribute exists, DSC raises an exception
    """

    dsc = default_subject_context
    monkeypatch.setitem(dsc.context, dsc.get_key('SECURITY_MANAGER'), None)
    monkeypatch.setattr(thread_local, 'security_manager', None, raising=False)
    result = dsc.resolve_security_manager()
    out, err = capsys.readouterr()
    assert ("No SecurityManager available in subject context" in out and
            result is None)

def test_dsc_resolve_identifiers_exists(default_subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    resolves to the dsc's identifiers attribute when it is set
    """
    dsc = default_subject_context
    result = dsc.resolve_identifiers()
    assert result == dsc.identifiers and bool(result)

def test_dsc_resolve_identifiers_none_accountreturns(
        default_subject_context, monkeypatch, subject_context):
    """
    unit tested:  resolve_identifiers

    test case:
    when the dsc doesn't have an identifiers attribute set, but the subject attr
    does, the subject's identifiers is returned
    """
    dsc = default_subject_context

    class DumbSubject:
        def __init__(self):
            self.identifiers = 'subjectidentifiers'

    monkeypatch.setitem(dsc.context, subject_context['IDENTIFIERS'], None)
    monkeypatch.setitem(dsc.context, subject_context['ACCOUNT'], None)
    monkeypatch.setitem(dsc.context, subject_context['SUBJECT'], DumbSubject())

    result = dsc.resolve_identifiers()
    assert result == 'subjectidentifiers'


def test_dsc_resolve_identifiers_none_sessionreturns(
        default_subject_context, monkeypatch, mock_session):
    """
    unit tested:  resolve_identifiers

    test case:
    when the dsc doesn't have an identifiers attribute set, and neither account
    nor subject has identifiers, resolve_session is called to obtain a session,
    and then the session's identifiers is obtained
    """
    dsc = default_subject_context
    monkeypatch.setattr(dsc, 'get', lambda x: None)
    monkeypatch.setattr(mock_session, 'get_internal_attribute',
                        lambda x: 'identifiers')
    monkeypatch.setattr(dsc, 'resolve_session', lambda: mock_session)
    result = dsc.resolve_identifiers()
    assert result == 'identifiers'


def test_dsc_resolve_session_exists(default_subject_context):
    """
    unit tested:  resolve_session

    test case:
    when a session attribute is set in the dsc, it is returned
    """
    dsc = default_subject_context
    result = dsc.resolve_session()
    assert result == dsc.session


def test_dsc_resolve_session_notexists(
        default_subject_context, monkeypatch, subject_context):
    """
    unit tested:  resolve_session

    test case:
    when a session attribute is NOT set in the dsc, resolve_session tries to
    obtain the session from the subject attribute
    """
    dsc = default_subject_context

    class DumbSubject:
        def get_session(self, mybool):
            return 'subjectsession'

    monkeypatch.setitem(dsc.context, subject_context['SESSION'], None)
    monkeypatch.setitem(dsc.context, subject_context['SUBJECT'], DumbSubject())

    result = dsc.resolve_session()
    assert result is None


def test_dsc_resolve_authenticated(default_subject_context, monkeypatch):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is set, it is returned
    """
    dsc = default_subject_context
    monkeypatch.setitem(dsc.context, 'AUTHENTICATED', False)
    result = dsc.resolve_authenticated()
    assert bool(result) == bool(dsc.authenticated)


def test_dsc_resolve_authenticated_usingaccount(
        default_subject_context, monkeypatch, subject_context):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is NOT set, but an Account attribute
    exists, authentication is True
    """
    dsc = default_subject_context

    monkeypatch.setitem(dsc.context, subject_context['AUTHENTICATED'], None)
    assert dsc.account
    result = dsc.resolve_authenticated()
    assert result is True


def test_dsc_resolve_authenticated_usingsession(
        default_subject_context, monkeypatch, subject_context, mock_session):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is NOT set, no Account attribute
    exists, but a session exists and has proof of authentication, returns True
    """
    dsc = default_subject_context

    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: True)
    monkeypatch.setattr(dsc, 'resolve_session', lambda: mock_session)
    monkeypatch.setitem(dsc.context, "DefaultSubjectContext.ACCOUNT", None)
    monkeypatch.setitem(dsc.context, "DefaultSubjectContext.AUTHENTICATED", None)

    result = dsc.resolve_authenticated()
    assert result is True


def test_dsc_resolve_host_exists(default_subject_context):
    """
    unit tested:   resolve_host

    test case:
    when a host attribute exists, it is returned
    """
    dsc = default_subject_context
    result = dsc.resolve_host()
    assert result == dsc.host


def test_dsc_resolve_host_notexists_token(
        default_subject_context, monkeypatch, subject_context):
    """
    unit tested:   resolve_host

    test case:
    no host attribute exists, so token's host is returned
    """
    dsc = default_subject_context

    class DumbToken:
        def __init__(self):
            self.host = 'tokenhost'

    monkeypatch.setitem(dsc.context, subject_context['HOST'], None)
    monkeypatch.setattr(dsc, 'resolve_session', lambda: DumbToken())
    result = dsc.resolve_host()
    assert result == 'tokenhost'


def test_dsc_resolve_host_notexists_session(
        default_subject_context, monkeypatch, subject_context):
    """
    unit tested:   resolve_host

    test case:
    no host attribute exists, no token host, session's host is returned
    """
    dsc = default_subject_context
    class DumbSession:
        def __init__(self):
            self.host = 'sessionhost'

    monkeypatch.setitem(dsc.context, subject_context['HOST'], None)
    monkeypatch.setitem(dsc.context, subject_context['AUTHENTICATION_TOKEN'], None)
    monkeypatch.setattr(dsc, 'resolve_session', lambda: DumbSession())

    result = dsc.resolve_host()
    assert result == 'sessionhost'

# ------------------------------------------------------------------------------
# DelegatingSubject
# ------------------------------------------------------------------------------


def test_ds_init(delegating_subject):
    """
    unit tested:  __init__

    test case:
    a session passed as an argument into init should be wrapped by a SAPS
    - also exercises the decorate method code path
    """
    ds = delegating_subject
    assert isinstance(ds.session, DelegatingSubject.StoppingAwareProxiedSession)


def test_ds_decorate_type_check(delegating_subject):
    """
    unit tested: decorate

    test case:
    only objects implementing the Session interface may be wrapped by the SAPS
    """
    ds = delegating_subject
    with pytest.raises(InvalidArgumentException):
        ds.decorate('bla')


def test_ds_identifiers_fromstack(delegating_subject, monkeypatch):
    """
    unit tested:  identifiers

    test case:
    first tries to obtain identifiers from get_run_as_identifiers_stack
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: ['identifiers1'] )
    result = ds.identifiers
    assert result == 'identifiers1'


def test_ds_identifiers_fromidentifiers(
        delegating_subject, monkeypatch, simple_identifiers_collection):
    """
    unit tested:  identifiers

    test case:
    first tries to obtain identifiers from get_run_as_identifiers_stack, fails,
    and reverts to _identifiers attribute
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    result = ds.identifiers
    assert result == simple_identifiers_collection


def test_ds_is_permitted_withidentifiers(delegating_subject, monkeypatch):
    """
    unit test:  is_permitted

    test case:
    the identifiers attribute is set for the fixture and is passed on as an
    argument to the security manager
    """

    ds = delegating_subject
    monkeypatch.setattr(ds.security_manager, 'is_permitted', lambda x,y: 'sm_permitted')
    result = ds.is_permitted('permission')
    assert result == 'sm_permitted'


def test_ds_is_permitted_withoutidentifiers(delegating_subject, monkeypatch):
    """
    unit test:  is_permitted

    test case:
    when no identifiers attribute is set, no permission can be determined and
    so an exception raises
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IdentifiersNotSetException, "ds.is_permitted('anything')")

def test_ds_is_permitted_collective(delegating_subject):
    """
    unit tested:  is_permitted_collective

    test case:
        given a DS with identifiers attribute:
            calls security_manager's method, which is a verified double whose
            return value is hard coded True

        otherwise, raises
    """
    ds = delegating_subject
    result = ds.is_permitted_collective('permission_s', all)
    assert result is True


def test_ds_is_permitted_collective_raises(delegating_subject, monkeypatch):
    """
    unit tested:  is_permitted_collective

    test case:
        given a DS with identifiers attribute:
            calls security_manager's method, which is a verified double whose
            return value is hard coded True

        otherwise, raises
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IdentifiersNotSetException,
                  "ds.is_permitted_collective('permission_s', all)")


def test_ds_assert_authz_check_possible(delegating_subject, monkeypatch):
    """
    unit tested:  assert_authz_check_possible

    test case:
    raises an exception when identifiers attribute isn't set
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(UnauthenticatedException, "ds.assert_authz_check_possible()")


def test_ds_check_permission(delegating_subject, monkeypatch):
    """
    unit tested:  check_permission

    test case:
    delegates call to security_manager
    """
    ds = delegating_subject
    monkeypatch.setattr(ds,'assert_authz_check_possible', lambda: None)
    with mock.patch.object(MockSecurityManager, 'check_permission') as mock_cp:
        mock_cp.return_value = None
        ds.check_permission('arbitrary', all)
        assert mock_cp.called


def test_ds_check_permission_raises(delegating_subject, monkeypatch):
    """
    unit tested:  check_permission

    test case:
    requires the identifiers attribute, raising if it doesn't exist
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'assert_authz_check_possible', lambda: None)
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IdentifiersNotSetException, "ds.check_permission('anything', all)")


def test_ds_has_role(delegating_subject, monkeypatch):
    """
    unit tested:  has_role

    test case:
    delegates call to security_manager
    """
    ds = delegating_subject
    monkeypatch.setattr(ds.security_manager, 'has_role', lambda x,y: 'yup')
    result = ds.has_role('roleid123')
    assert result == 'yup'


def test_ds_has_role_raises(delegating_subject, monkeypatch):
    """
    unit tested:  has_role

    test case:
    when the identifiers attribute isn't set, an exception is raised
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IdentifiersNotSetException, "ds.has_role('role123')")


def test_has_role_collective(delegating_subject, monkeypatch):
    """
    unit tested:  has_role_collective

    test case:
    has identifiers and so delegates to security_master
    """
    ds = delegating_subject
    monkeypatch.setattr(ds.security_manager, 'has_role_collective', lambda x,y,z: 'yup')
    result = ds.has_role_collective('roleid123', any)
    assert result == 'yup'



def test_ds_has_role_collective_raises(delegating_subject, monkeypatch):
    """
    unit tested:  has_role_collective

    test case:
    when the identifiers attribute isn't set, an exception is raised
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IdentifiersNotSetException, "ds.has_role_collective('role123', any)")


def test_check_role(delegating_subject):
    """
    unit tested:  check_role

    test case:
    when identifiers attribute exists, delegates request to
    security_manager.check_role
    """
    ds = delegating_subject
    with mock.patch.object(MockSecurityManager, 'check_role') as mock_cr:
        ds.check_role('roleid123', any)
        assert mock_cr.called


def test_check_role_raises(delegating_subject, monkeypatch):
    """
    unit tested:  check_role

    test case:
    when the identifiers attribute isn't set, an exception is raised
    """

    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IdentifiersNotSetException, "ds.check_role('role123', any)")


def test_ds_login_succeeds(
        delegating_subject, monkeypatch, mock_subject,
        simple_identifiers_collection, mock_session):
    """
    unit tested:  login

    test case:
    Login Succeeds.
    - uses a MockSecurityManager, which is patched to return a MockSubject when
      login is called
    - obtains a mocksubject from security_manager.login, which includes
      identifiers and host attributes (patched in), both of which are assigned
      to the DS
    - patch the subject's get_session to return a "session", and assigns that
      to the DS's session attributee
    """
    ds = delegating_subject
    sic = simple_identifiers_collection
    monkeypatch.setattr(mock_subject, '_identifiers', sic)
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda:  None)
    monkeypatch.setattr(mock_subject, 'get_session', lambda x: mock_session)

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            with mock.patch.object(DelegatingSubject, 'decorate') as mock_dec:
                mock_dec.return_value = mock_session

                ds.login('dumb_authc_token')

                mock_smlogin.assert_called_once_with(subject=ds, authc_token='dumb_authc_token')
                mock_dec.assert_called_once_with(mock_session)

                assert (ds.session == mock_session and
                        ds.host == mock_subject.host and
                        ds._identifiers == simple_identifiers_collection)

def test_ds_login_raises(delegating_subject, monkeypatch):
    """
    unit tested:  login

    test case:
    login fails, raising an Authentication exception up the stack
    """
    ds = delegating_subject

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.side_effect = AuthenticationException

            pytest.raises(AuthenticationException, "ds.login('dumb_authc_token')")


def test_ds_login_noidentifiers_raises(
        delegating_subject, monkeypatch, mock_subject):
    """
    unit tested:  login

    test case:
    Login Succeeds but no Identifiers returned = Exception
    - uses a MockSecurityManager, which is patched to return a MockSubject when
      login is called
    - obtains a mocksubject from security_manager.login, which DOES NOT include
      an identifiers attribute
    - an identitifers attribute is required, so an exception is raised
    """
    ds = delegating_subject
    monkeypatch.setattr(mock_subject, '_identifiers', None)

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            pytest.raises(IllegalStateException, "ds.login('dumb_authc_token')")


def test_ds_login_nohost(
        delegating_subject, monkeypatch, mock_subject,
        simple_identifiers_collection, mock_session, username_password_token):
    """
    unit tested:  login

    test case:
    Login Succeeds.
    - uses a MockSecurityManager, which is patched to return a MockSubject when
      login is called
    - obtains a mocksubject from security_manager.login, which includes
      identifiers but NO host attribute
    - since no host attribute is available from the subject, login obtains
      a host from the authc_token
    - patch the subject's get_session to return a "session", and assigns that
      to the DS's session attributee
    """
    ds = delegating_subject
    sic = simple_identifiers_collection
    monkeypatch.setattr(mock_subject, '_identifiers', sic)
    monkeypatch.setattr(mock_subject, 'host', None)
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda:  None)
    monkeypatch.setattr(mock_subject, 'get_session', lambda x: mock_session)

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            with mock.patch.object(DelegatingSubject, 'decorate') as mock_dec:
                mock_dec.return_value = mock_session

                ds.login(username_password_token)

                mock_smlogin.assert_called_once_with(subject=ds,
                                                     authc_token=username_password_token)
                mock_dec.assert_called_once_with(mock_session)

                assert (ds.session == mock_session and
                        ds.host == username_password_token.host and
                        ds._identifiers == simple_identifiers_collection)


def test_ds_login_nosession(delegating_subject, monkeypatch, mock_subject,
                            simple_identifiers_collection):
    """
    unit tested:  login

    test case:
    login succeeds but no session is available from the subject, therefore
    session is None
    """

    ds = delegating_subject
    sic = simple_identifiers_collection
    monkeypatch.setattr(mock_subject, '_identifiers', sic)
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda:  None)
    monkeypatch.setattr(mock_subject, 'get_session', lambda x: None)

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            ds.login('dumb_authc_token')

            mock_smlogin.assert_called_once_with(subject=ds, authc_token='dumb_authc_token')

            assert (ds.session is None and
                    ds.host == mock_subject.host and
                    ds._identifiers == simple_identifiers_collection)


@pytest.mark.parametrize('attr',
                         ['security_manager', 'identifiers', 'session',
                          'authenticated'])
def test_ds_attribute_type_raises(delegating_subject, attr, monkeypatch):
    """
    unit tested:  every property mutator that validates

    test case:
    any unacceptable type raises an exception
    """
    ds = delegating_subject
    with pytest.raises(InvalidArgumentException):
        setattr(ds, attr, 'wrongvalue')


def test_get_session_withsessionattribute_succeeds(
        delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  get_session

    test case:
    the DS includes a MockSession attributes and so it is returned
    """
    ds = delegating_subject
    result = ds.get_session()

    expected = DelegatingSubject.StoppingAwareProxiedSession(mock_session, ds)
    assert result == expected


def test_get_session_withoutsessionattribute_createfalse(
        delegating_subject, monkeypatch):
    """
    unit tested:  get_session

    test case:
    when no session attribute is set and create=False returns None
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'session', None)
    result = ds.get_session(False)
    assert result is None


def test_get_session_withoutsessionattribute_raises(
        delegating_subject, monkeypatch):
    """
    unit tested:  get_session

    test case:
    if no session attribute exists and  session_creation_enabled is False, an
    exception raises
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'session', None)
    monkeypatch.setattr(ds, 'session_creation_enabled', False)
    pytest.raises(DisabledSessionException, "ds.get_session()")


def test_get_session_withoutsessionattribute_createsnew(
        delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  get_session

    test case:
    no session attribute, creation enabled, results in creation of a new session
    attribute
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'session', None)
    monkeypatch.setattr(ds, 'create_session_context', lambda: 'sessioncontext')
    with mock.patch.object(MockSecurityManager, 'start') as mock_start:
        mock_start.return_value = 'startedsession'
        with mock.patch.object(DelegatingSubject, 'decorate') as mock_decorate:
            mock_decorate.return_value = mock_session

            result = ds.get_session()

            mock_start.assert_called_once_with('sessioncontext')
            mock_decorate.assert_called_once_with('startedsession')
            assert result == mock_session


def test_create_session_context_without_host(delegating_subject, monkeypatch):
    """
    unit tested:  create_session_context

    test case:
    creates a new session context and does not set host
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'host', None)
    result = ds.create_session_context()
    assert isinstance(result, DefaultSessionContext) and result.host is None


def test_create_session_context_with_host(delegating_subject, monkeypatch):
    """
    unit tested:  create_session_context

    test case:
    creates a new session context and sets host
    """
    ds = delegating_subject
    result = ds.create_session_context()
    assert (isinstance(result, DefaultSessionContext) and
            result.host == ds.host)


def test_clear_run_as_identities_internal_with_warning(
        delegating_subject, capsys):
    """
    unit tested:  clear_run_as_identities_internal

    test case:
    calls clear_run_as_identities, raising an exception-warning
    """
    ds = delegating_subject
    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities') as mock_cri:
        mock_cri.side_effect = SessionException
        ds.clear_run_as_identities_internal()
        out, err = capsys.readouterr()
        assert 'Encountered session exception' in out


def test_logout(delegating_subject):
    """
    unit tested:  logout

    test case:

    """
    ds = delegating_subject
    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_clear:
        mock_clear.return_value = None

        with mock.patch.object(MockSecurityManager, 'logout') as mocksm_logout:
            mocksm_logout.return_value = None

            ds.logout()

            mock_clear.assert_called_once_with()
            mocksm_logout.assert_called_once_with(ds)
            assert (ds._session is None and ds._identifiers is None and
                    ds._authenticated == False)


def test_ds_run_as(delegating_subject):
    """
    unit tested:  run_as

    test case:
    pushes the current delegating subject's identifiers onto the run_as stack
    """
    ds = delegating_subject
    with mock.patch.object(DelegatingSubject, 'push_identity') as mock_pi:
        mock_pi.return_value = None
        ds.run_as('myidentifiers')
        mock_pi.assert_called_once_with('myidentifiers')


def test_ds_run_as_raises(delegating_subject, monkeypatch):
    """
    unit tested:  run_as

    test case:
    without the identifiers attribute, an exception is raised
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, '_identifiers', None)
    pytest.raises(IllegalStateException, "ds.run_as('dumb_identifiers')")


@pytest.mark.parametrize('stack, expected',
                         [(collections.deque(['identifiers']), True),
                          (collections.deque(), False)])
def test_ds_is_run_as_accessor(delegating_subject, stack, expected, monkeypatch):
    """
    unit tested:  is_run_as property

    test case:
    bools an empty deque or deque with identifiers
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: stack)
    ds.is_run_as == expected

def test_ds_get_previous_identifiers_wo_stack(delegating_subject, monkeypatch):
    """
    unit tested:  get_previous_identifiers

    test case:
    when no stack exists, None is returned
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    result = ds.get_previous_identifiers()
    assert result is None


def test_ds_get_previous_identifiers_w_singlestack(delegating_subject, monkeypatch):
    """
    unit tested:  get_previous_identifiers

    test case:
    when a single-element stack is obtained, previous_identifiers == self.identifiers
    """
    ds = delegating_subject
    stack = collections.deque(['one'])
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: stack)
    result = ds.get_previous_identifiers()
    assert result == ds.identifiers


def test_ds_get_previous_identifiers_w_multistack(delegating_subject, monkeypatch):
    """
    unit tested:  get_previous_identifiers

    test case:
    when a multi-element stack is obtained, returns the second element from the
    top of the stack
    """
    ds = delegating_subject
    stack = collections.deque(['two', 'one'])
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: stack)
    result = ds.get_previous_identifiers()
    assert result == 'one'


def test_ds_release_run_as(delegating_subject, monkeypatch):
    """
    unit test:  release_run_as

    test case:
    calls pop_identity
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'pop_identity', lambda: 'popped')
    result = ds.release_run_as()
    assert result == 'popped'


@pytest.mark.parametrize('key, expected',
                         [('key', collections.deque(['key'])),
                          (None, collections.deque([]))])
def test_ds_get_run_as_identifiers_stack(
        delegating_subject, key, expected, monkeypatch, mock_session):
    """
    unit tested:  get_run_as_identifiers_stack

    test case:
    returns a either a deque containing the key or as empty
    """
    ds = delegating_subject
    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: expected)
    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)
    result = ds.get_run_as_identifiers_stack()
    assert result == expected


def test_ds_clear_run_as_identities(
        delegating_subject, mock_session, monkeypatch):
    """
    unit tested:  clear_run_as_identities

    test case:
    when a session attribute exists, the key attribute is removed from it
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)
    with mock.patch.object(mock_session, 'remove_internal_attribute') as mock_ra:
        mock_ra.return_value = None
        ds.clear_run_as_identities()
        mock_ra.assert_called_once_with(ds.run_as_identifiers_session_key)


def test_ds_push_identity_raises(delegating_subject, monkeypatch):
    """
    unit tested:  push_identity

    test case:
    when no identifiers argument is passed, an exception is raised
    """
    ds = delegating_subject
    pytest.raises(InvalidArgumentException,
                  "ds.push_identity(None)")


def test_ds_push_identity_withstack(
        delegating_subject, monkeypatch, simple_identifiers_collection,
        mock_session):
    """
    unit tested:  push_identity

    test case:
    adds the identifiers argument to the existing stack
    """
    ds = delegating_subject
    sic = simple_identifiers_collection
    newstack = collections.deque(['collection1'])
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: newstack)
    monkeypatch.setattr(ds, 'get_session', lambda: mock_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as sia:
        sia.return_value = None

        ds.push_identity(sic)

        sia.assert_called_once_with('run_as_identifiers_session_key', newstack)


def test_ds_push_identity_withoutstack(
        delegating_subject, monkeypatch, simple_identifiers_collection,
        mock_session):
    """
    unit tested:  push_identity

    test case:
    creates a new stack and adds the identifiers argument to it
    """
    ds = delegating_subject
    sic = simple_identifiers_collection
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    monkeypatch.setattr(ds, 'get_session', lambda: mock_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as sia:
        sia.return_value = None

        ds.push_identity(sic)

        sia.assert_called_once_with('run_as_identifiers_session_key',
                                    collections.deque([sic]))


def test_ds_pop_identity_withoutstack(delegating_subject, monkeypatch):
    """
    unit tested:  pop_identity

    test case:
    if there is an empty run-as stack, this method returns None
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    result = ds.pop_identity()
    assert result is None


def test_ds_pop_identity_withsinglestack(delegating_subject, monkeypatch):
    """
    unit tested:  pop_identity

    test case:
    a run-as stack containing only one element is cleared
    """
    ds = delegating_subject
    newstack = collections.deque(['collection1'])
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: newstack)
    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities') as mock_crai:
        mock_crai.return_value

        result = ds.pop_identity()

        mock_crai.assert_called_once_with()
        assert result == 'collection1'


def test_ds_pop_identity_withmultistack(
        delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  pop_identity

    test case:
    a run-as stack containing two elements pops/returns the top element and sets
    the run-as session key to the next element in the stack
    """
    ds = delegating_subject
    newstack = collections.deque(['collection2', 'collection1'])
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: newstack)
    monkeypatch.setattr(ds, 'get_session', lambda: mock_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as sia:
        sia.return_value = None

        result = ds.pop_identity()

        sia.assert_called_once_with('run_as_identifiers_session_key',
                                    collections.deque(['collection1']))
    assert result == 'collection2'


def test_ds_stoppingawareproxiedsession_stop(delegating_subject, mock_session):
    """
    unit tested:  StoppingAwareProxiedSession.stop

    test case:
    stops a session and notifies the owning subject
    """

    ds = delegating_subject
    saps = ds.StoppingAwareProxiedSession(mock_session, ds)

    with mock.patch.object(MockSession, 'stop') as mock_stop:
        saps.stop('identifiers')
        mock_stop.assert_called_once_with('identifiers')
        assert ds.session is None


# ------------------------------------------------------------------------------
# DefaultSubjectStore
# ------------------------------------------------------------------------------

def test_dss_is_sse(default_subject_store, monkeypatch):
    """
    unit tested:  is_session_storage_enabled

    test case:
    delegates call to the sse's method
    """
    dss = default_subject_store
    with mock.patch.object(DefaultSessionStorageEvaluator,
                           'is_session_storage_enabled') as dsse_isse:
        dsse_isse.return_value = 'yup'
        result = dss.is_session_storage_enabled('subject')
        assert result == 'yup'


def test_dss_save_with_sse(default_subject_store, monkeypatch):
    """
    unit tested:  save

    test case:

    """
    dss = default_subject_store
    monkeypatch.setattr(dss, 'is_session_storage_enabled', lambda x: True)
    with mock.patch.object(DefaultSubjectStore, 'save_to_session') as dss_sts:
        dss_sts.return_value = None
        dss.save('dummysubject')
        dss_sts.assert_called_once_with('dummysubject')


def test_dss_save_without_sse(default_subject_store, monkeypatch, capsys):
    """
    unit tested:  save

    test case:

    """
    dss = default_subject_store
    monkeypatch.setattr(dss, 'is_session_storage_enabled', lambda x: False)
    with mock.patch.object(DefaultSubjectStore, 'save_to_session') as dss_sts:
        dss_sts.return_value = None
        dss.save('dummysubject')

        out, err = capsys.readouterr()
        assert (not dss_sts.called and
                'has been disabled' in out)


def test_dss_save_to_session(default_subject_store):
    """
    unit tested:  save_to_session

    test case:
    merges identifiers and authentication state
    """
    dss = default_subject_store
    with mock.patch.object(DefaultSubjectStore, 'merge_identifiers') as dss_mi:
        dss_mi.return_value = None
        with mock.patch.object(DefaultSubjectStore, 'merge_authentication_state') as dss_mas:
            dss_mas.return_value = None
            dss.save_to_session('subject')
            dss_mi.assert_called_once_with('subject')
            dss_mas.assert_called_once_with('subject')


def test_dss_merge_identifiers_runas_withsession(
        default_subject_store, delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  merge_identifiers

    test case:
    - run_as set for the DS
    - current_identifiers gets assigned to subject._identifiers attribute
        (bypassing the property logic),
    - current_identifiers is saved to the session
    """
    dss = default_subject_store
    ds = delegating_subject

    sic1 = SimpleIdentifierCollection(source_name='Current', identifier='Current')
    cids = collections.deque([sic1])
    monkeypatch.setattr(ds, '_identifiers', cids)

    sic2 = SimpleIdentifierCollection(source_name='Existing', identifier='Existing')
    eids = collections.deque([sic2])
    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: eids)

    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: True)
    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as mock_sa:
        mock_sa.return_value = None

        dss.merge_identifiers(ds)

        mock_sa.assert_called_once_with(dss.dsc_isk, cids)


def test_dss_merge_identifiers_notrunas_withsession(
        default_subject_store, delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  merge_identifiers

    test case:
    with run_as NOT set for the DS, current_identifiers is obtained from
    the identifiers property, and then the current_identifiers are saved to the
    session
    """
    dss = default_subject_store
    ds = delegating_subject

    sic1 = SimpleIdentifierCollection(source_name='Current', identifier='Current')
    cids = collections.deque([sic1])
    monkeypatch.setattr(ds, '_identifiers', cids)

    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: None)

    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: False)
    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as mock_sa:
        mock_sa.return_value = None

        dss.merge_identifiers(ds)

        mock_sa.assert_called_once_with(dss.dsc_isk, cids)


def test_dss_merge_identifiers_notrunas_withoutsession(
        default_subject_store, delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  merge_identifiers

    test case:
    get_session returns None
    """
    dss = default_subject_store
    ds = delegating_subject

    def get_session(create):
        if create == 'False':
            return None
        return mock_session

    sic1 = SimpleIdentifierCollection(source_name='Current', identifier='Current')
    cids = collections.deque([sic1])
    monkeypatch.setattr(ds, '_identifiers', cids)

    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: False)
    monkeypatch.setattr(ds, 'get_session', get_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as mock_sa:
        mock_sa.return_value = None

        dss.merge_identifiers(ds)

        mock_sa.assert_called_once_with(dss.dsc_isk, cids)


def test_dss_merge_authentication_state_case1(
        default_subject_store, monkeypatch, delegating_subject, mock_session):
    """
    unit tested:  merge_authentication_state

    test case:
    - subject has a session
    - subject not authenticated
    - existing_authc is None
    """
    dss = default_subject_store
    ds = delegating_subject

    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)
    monkeypatch.setattr(ds, '_authenticated', False)

    with mock.patch.object(mock_session, 'remove_internal_attribute') as ms_remove:
        ms_remove.return_value = None

        with mock.patch.object(mock_session, 'get_internal_attribute') as mock_ga:
            mock_ga.return_value = None

            dss.merge_authentication_state(ds)

            mock_ga.assert_called_once_with(dss.dsc_ask)
            assert not ms_remove.called


def test_dss_merge_authentication_state_case2(
        default_subject_store, monkeypatch, delegating_subject, mock_session):
    """
    unit tested:  merge_authentication_state

    test case:
    - subject has a session
    - subject not authenticated
    - existing_authc is True
    """
    dss = default_subject_store
    ds = delegating_subject

    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)
    monkeypatch.setattr(ds, '_authenticated', False)

    with mock.patch.object(MockSession, 'remove_internal_attribute') as ms_remove:
        ms_remove.return_value = None

        with mock.patch.object(MockSession, 'get_internal_attribute') as mock_ga:
            mock_ga.return_value = True

            dss.merge_authentication_state(ds)

            mock_ga.assert_called_once_with(dss.dsc_ask)
            ms_remove.assert_called_once_with(dss.dsc_ask)


def test_dss_merge_authentication_state_case3(
        default_subject_store, monkeypatch, delegating_subject, mock_session):
    """
    unit tested:  merge_authentication_state

    test case:
    - subject has a session
    - subject is authenticated
    - existing_authc is None

    """
    dss = default_subject_store
    ds = delegating_subject

    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)
    monkeypatch.setattr(ds, '_authenticated', True)

    with mock.patch.object(MockSession, 'set_internal_attribute') as mock_sa:
        mock_sa.return_value = None

        with mock.patch.object(MockSession, 'get_internal_attribute') as mock_ga:
            mock_ga.return_value = None

            dss.merge_authentication_state(ds)

            mock_ga.assert_called_once_with(dss.dsc_ask)
            mock_sa.assert_called_once_with(dss.dsc_ask, True)


def test_dss_merge_authentication_state_case4(
        delegating_subject, default_subject_store, mock_session, monkeypatch):
    """
    unit tested:  merge_authentication_state

    test case:
    subject has no session
    subject is authenticated
    """

    dss = default_subject_store
    ds = delegating_subject

    monkeypatch.setattr(ds, '_authenticated', True)

    with mock.patch.object(DelegatingSubject, 'get_session') as ds_gs:
        ds_gs.return_value = mock_session

        with mock.patch.object(MockSession, 'set_internal_attribute') as ms_sa:
            ms_sa.return_value = None

            dss.merge_authentication_state(ds)

            ms_sa.assert_called_once_with(dss.dsc_ask, True)
            ds_gs.assert_called_once_with(False)


def test_dss_remove_from_session(
        default_subject_store, delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  remove_from session

    test case:
        removes both key attributes from the session
    """
    dss = default_subject_store
    ds = delegating_subject

    monkeypatch.setattr(ds, 'get_session', lambda x: mock_session)
    with mock.patch.object(MockSession, 'remove_internal_attribute') as ms_ra:
        dss.remove_from_session(ds)
        calls = [mock.call(dss.dsc_ask), mock.call(dss.dsc_isk)]
        ms_ra.assert_has_calls(calls, any_order=True)


def test_dss_delete(default_subject_store):
    """
    unit tested:  delete

    test case:
    calls remove_from_session
    """
    dss = default_subject_store
    with mock.patch.object(DefaultSubjectStore, 'remove_from_session') as dss_rfs:
        dss_rfs.return_value = None
        dss.delete('subject')
        dss_rfs.assert_called_once_with('subject')


# ------------------------------------------------------------------------------
# SubjectBuilder
# ------------------------------------------------------------------------------

def test_sb_init_verify_argument_context(subject_builder_context):
    """
    unit tested:  __init__ and context_attribute

    test case:
    when a subject_context argument is passed into init, any context attribute
    arguments aren't used by init
    """
    sbc = subject_builder_context
    mycontext = DefaultSubjectContext(sbc)
    sb = SubjectBuilder(subject_context=mycontext, **sbc)
    assert (sb.subject_context == mycontext)


def test_sb_init_verify_generated_context(subject_builder_context):
    """
    unit tested:  __init__

    test case:
    confirm that the subject context created by init reflects the arguments
    passed to the builder
    """
    sbc = subject_builder_context
    sb = SubjectBuilder(**sbc)
    mycontext = DefaultSubjectContext(sbc)
    assert (sb.subject_context == mycontext)


def test_sb_build_subject(subject_builder, monkeypatch, mock_security_manager):
    """
    unit tested:  build_subject

    test case:
    build_subject defers to the security_manager's create_subject
    """
    sb = subject_builder

    monkeypatch.setattr(sb, 'security_manager', mock_security_manager)
    monkeypatch.setattr(sb.security_manager, 'create_subject',
                        lambda subject_context: 'subject')
    result = sb.build_subject()
    assert result == 'subject'


def test_sb_context_attribute_raises(subject_builder, monkeypatch):
    """
    unit tested: context_attribute

    test case:
    key cannot be None
    """
    sb = subject_builder
    pytest.raises(InvalidArgumentException, "sb.context_attribute(None)")


def test_sb_context_attribute_removes(subject_builder):
    """
    unit tested: context_attribute

    test case:
    passing a key but no value will remove the key from the context
    """
    sb = subject_builder
    assert sb.subject_context.get('attribute1')
    sb.context_attribute('attribute1')
    assert sb.subject_context.get('attribute1') is None

# ------------------------------------------------------------------------------
# DefaultSubjectFactory
# ------------------------------------------------------------------------------

def test_dsf_create_subject(
        default_subject_factory, default_subject_context, mock_security_manager,
        simple_identifiers_collection, monkeypatch, mock_session):
    """
    unit tested:  create_subject

    test case:
    returns a new DelegatingSubject instance based on the subject_context arg
    """
    monkeypatch.setattr(default_subject_context, 'resolve_session',
                        lambda: mock_session)
    default_subject_context.security_manager = mock_security_manager
    default_subject_context.identifiers = simple_identifiers_collection
    dsf = default_subject_factory
    result = dsf.create_subject(default_subject_context)
    assert isinstance(result, DelegatingSubject)


# ------------------------------------------------------------------------------
# SecurityUtils
# ------------------------------------------------------------------------------

@pytest.mark.xfail
def test_su_get_subject_notinthreadlocal(
        mock_subject_builder, monkeypatch, mock_security_manager):
    """
    unit tested:  get_subject

    test case:
    - when a subject attribute isn't available from the thread_local,
      subject_builder creates one
        - the newly created subject is bound to the thread managed by the
          thread_local
    - the subject is returned
    """

    monkeypatch.setattr(SecurityUtils, 'security_manager',
                        mock_security_manager)

    monkeypatch.setattr(SubjectBuilder, 'build_subject', lambda x: 'sbs')
    result = SecurityUtils.get_subject()

    assert (result == 'sbs' and thread_local.subject == result)


def test_su_get_subject_inthreadlocal(monkeypatch, mock_subject_builder):
    """
    unit tested:  get_subject

    test case:
    when a subject is bound to a threadlocal, it is returned
    """
    monkeypatch.setattr(thread_local, 'subject', 'threadlocalsubject',
                        raising=False)
    result = SecurityUtils.get_subject()
    assert result == 'threadlocalsubject'


def test_su_getsecuritymanager_in_threadlocal(monkeypatch):
    """
    unit tested:  security_manager.getter

    test case:
    obtains a security_manager from the thread_local
    """
    monkeypatch.setattr(thread_local, 'security_manager',
                        'threadlocalsecuritymanager', raising=False)
    result = SecurityUtils.get_security_manager()
    assert result == 'threadlocalsecuritymanager'


def test_su_getsecuritymanager_notin_threadlocal_from_securityutils(
        monkeypatch):
    """
    unit tested:  security_manager.getter

    test case:
    - security_manager not available from the thread_local
    - SecurityUtils.security_manager returned
    """
    monkeypatch.setattr(SecurityUtils, 'security_manager', 'local_security_manager')
    result = SecurityUtils.get_security_manager()
    assert result == SecurityUtils.security_manager
