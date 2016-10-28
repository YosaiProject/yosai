import pytest
import collections
from unittest import mock

from yosai.core import (
    AuthenticationException,
    SessionStorageEvaluator,
    SubjectStore,
    DelegatingSession,
    DelegatingSubject,
    NativeSecurityManager,
    SessionException,
    UsernamePasswordToken,
    Yosai,
    UnauthenticatedException,
)

from ..doubles import (
    MockSecurityManager,
)

# ------------------------------------------------------------------------------
# SubjectContext
# ------------------------------------------------------------------------------


def test_dsc_resolve_security_manager_exists(subject_context, monkeypatch):
    """
    unit tested:  resolve_security_manager

    test case:
    resolves first to a security manager that already exists
    """
    dsc = subject_context
    monkeypatch.setattr(dsc, 'security_manager', 'sm', raising=False)
    result = dsc.resolve_security_manager()
    assert result == 'sm'


def test_dsc_resolve_security_manager_none(
        subject_context, monkeypatch, caplog, yosai):
    """
    unit tested:  resolve_security_manager

    test case:
    when no security manager attribute exists, next tries to obtain one from
    Yosai
    """
    dsc = subject_context
    monkeypatch.setattr(dsc, 'security_manager', None, raising=False)
    monkeypatch.setattr(yosai, 'security_manager', 'mysecuritymanager', raising=False)

    result = dsc.resolve_security_manager()
    out = caplog.text
    assert ("No SecurityManager available" in out and result == 'mysecuritymanager')


def test_dsc_resolve_security_manager_none_raises(
        subject_context, monkeypatch, caplog, yosai):
    """
    unit tested:  resolve_security_manager

    test case:
    no security manager attribute exists, DSC raises an exception
    """

    dsc = subject_context
    monkeypatch.setattr(dsc, 'security_manager', None)
    monkeypatch.delattr(yosai, 'security_manager', raising=False)

    result = dsc.resolve_security_manager()
    out = caplog.text
    assert ("No SecurityManager available in subject context" in out and
            result is None)


def test_dsc_resolve_identifiers_exists(subject_context, monkeypatch):
    """
    unit tested:  resolve_identifiers

    test case:
    resolves to the dsc's identifiers attribute when it is set
    """
    dsc = subject_context
    monkeypatch.setattr(dsc, 'identifiers', 'identifiers')
    result = dsc.resolve_identifiers('session')
    assert result == 'identifiers'


def test_dsc_resolve_identifiers_none_sessionreturns(
        subject_context, monkeypatch, mock_session):
    """
    unit tested:  resolve_identifiers

    test case:
    - the dsc doesn't have an identifiers attribute set
    - neither account nor subject has identifiers
    - resolve_session is called to obtain a session and the session's
      identifiers obtained
    """
    dsc = subject_context
    mock_subject = mock.create_autospec(DelegatingSubject)
    mock_subject.identifiers = None
    monkeypatch.setattr(dsc, 'identifiers', None)
    monkeypatch.setattr(dsc, 'subject', mock_subject)
    monkeypatch.setattr(mock_session, 'get_internal_attribute',
                        lambda x: 'identifiers')
    result = dsc.resolve_identifiers(mock_session)
    assert result == 'identifiers'


def test_dsc_resolve_session_exists(subject_context):
    """
    unit tested:  resolve_session

    test case:
    when a session attribute is set in the dsc, it is returned
    """
    dsc = subject_context
    result = dsc.resolve_session()
    assert result == dsc.session


def test_dsc_resolve_session_notexists(subject_context, monkeypatch):
    """
    unit tested:  resolve_session

    test case:
    - resolve_session fails to obtains the session from anywhere
    """
    dsc = subject_context

    monkeypatch.setattr(dsc, 'session', None)
    monkeypatch.setattr(dsc, 'subject', None)

    result = dsc.resolve_session()
    assert result is None


def test_dsc_resolve_authenticated(subject_context, monkeypatch):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is set, it is returned
    """
    dsc = subject_context
    monkeypatch.setattr(dsc, 'authenticated', False)
    result = dsc.resolve_authenticated('session')
    assert bool(result) == bool(dsc.authenticated)


def test_dsc_resolve_authenticated_usingaccount(subject_context, monkeypatch):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is NOT set, but an Account attribute
    exists, authentication is True
    """
    dsc = subject_context

    monkeypatch.setattr(dsc, 'authenticated', None)
    monkeypatch.setattr(dsc, 'account_id', mock.MagicMock(account_id='id123'))
    result = dsc.resolve_authenticated('session')
    assert result is True


def test_dsc_resolve_authenticated_usingsession(
        subject_context, monkeypatch, mock_session):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is NOT set, no Account attribute
    exists, but a session exists and has proof of authentication, returns True
    """
    dsc = subject_context

    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: True)
    monkeypatch.setattr(dsc, 'resolve_session', lambda: mock_session)
    monkeypatch.setattr(dsc, 'account_id', None)
    monkeypatch.setattr(dsc, 'authenticated', None)

    result = dsc.resolve_authenticated(mock_session)
    assert result is True


def test_dsc_resolve_host_exists(subject_context, monkeypatch):
    """
    unit tested:   resolve_host

    test case:
    when a host attribute exists, it is returned
    """
    dsc = subject_context
    monkeypatch.setattr(dsc, 'host', '12356')
    result = dsc.resolve_host('session')
    assert result == '12356'


def test_dsc_resolve_host_notexists_token(subject_context, monkeypatch):
    """
    unit tested:   resolve_host

    test case:
    no host attribute exists, so token's host is returned
    """
    dsc = subject_context

    mock_token = mock.create_autospec(UsernamePasswordToken)
    mock_token.host = 'token_host'

    monkeypatch.setattr(dsc, 'host', None)
    monkeypatch.setattr(dsc, 'authentication_token', mock_token)

    result = dsc.resolve_host('session')
    assert result == 'token_host'


def test_dsc_resolve_host_notexists_session(subject_context, monkeypatch):
    """
    unit tested:   resolve_host

    test case:
    no host attribute exists, no token host, session's host is returned
    """
    dsc = subject_context
    monkeypatch.setattr(dsc, 'host', None)
    monkeypatch.setattr(dsc, 'authentication_token', None)

    result = dsc.resolve_host(mock.MagicMock(host='sessionhost'))
    assert result == 'sessionhost'

# ------------------------------------------------------------------------------
# DelegatingSubject
# ------------------------------------------------------------------------------


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


def test_ds_is_permitted_authorized(delegating_subject, monkeypatch):
    """
    unit test:  is_permitted

    test case:
    the identifiers attribute is set for the fixture and is passed on as an
    argument to the security manager
    """

    ds = delegating_subject
    monkeypatch.setattr(ds, 'authenticated', True)
    monkeypatch.setattr(ds.security_manager, 'is_permitted', lambda x,y: 'sm_permitted')
    result = ds.is_permitted('permission')
    assert result == 'sm_permitted'


def test_ds_is_permitted_notauthorized(delegating_subject, monkeypatch):
    """
    unit test:  is_permitted

    test case:
    when no identifiers attribute is set, no permission can be determined and
    so an exception raises
    """
    ds = delegating_subject
    pytest.raises(ValueError, "ds.is_permitted('anything')")


def test_ds_is_permitted_collective(delegating_subject, monkeypatch):
    """
    unit tested:  is_permitted_collective
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'authenticated', True)
    monkeypatch.setattr(ds.security_manager, 'is_permitted_collective', lambda x,y,z: True)
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
    pytest.raises(ValueError, "ds.is_permitted_collective('permission_s', all)")


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


@mock.patch.object(DelegatingSubject, 'assert_authz_check_possible')
def test_ds_check_permission(mock_aacp, delegating_subject, monkeypatch):
    """
    unit tested:  check_permission

    test case:
    delegates call to security_manager
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'authenticated', True)
    mock_cp = mock.create_autospec(NativeSecurityManager)
    monkeypatch.setattr(ds.security_manager, 'check_permission', mock_cp)
    ds.check_permission(['arbitrary'], all)
    mock_aacp.assert_called_once_with()
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
    pytest.raises(ValueError, "ds.check_permission('anything', all)")


def test_ds_has_role(delegating_subject, monkeypatch):
    """
    unit tested:  has_role

    test case:
    delegates call to security_manager
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'authenticated', True)
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
    pytest.raises(ValueError, "ds.has_role('role123')")


def test_has_role_collective(delegating_subject, monkeypatch):
    """
    unit tested:  has_role_collective

    test case:
    has identifiers and so delegates to security_master
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'authenticated', True)
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
    pytest.raises(ValueError, "ds.has_role_collective('role123', any)")


def test_check_role(delegating_subject, monkeypatch):
    """
    unit tested:  check_role

    test case:
    when identifiers attribute exists, delegates request to
    security_manager.check_role
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'authenticated', True)
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
    pytest.raises(ValueError, "ds.check_role('role123', any)")


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
    mock_subject._identifiers = sic
    mock_subject.host = 'host'
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda:  None)
    mock_subject.get_session.return_value = mock_session

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            ds.login('dumb_authc_token')

            mock_smlogin.assert_called_once_with(subject=ds, authc_token='dumb_authc_token')

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
    mock_subject._identifiers = None
    mock_subject.host = 'host'

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            pytest.raises(ValueError, "ds.login('dumb_authc_token')")


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
    mock_subject._identifiers = sic
    mock_subject.host = None
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda:  None)
    monkeypatch.setattr(mock_subject, 'get_session', lambda x: mock_session)

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            ds.login(username_password_token)

            mock_smlogin.assert_called_once_with(subject=ds,
                                                 authc_token=username_password_token)

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
    mock_subject._identifiers = sic
    mock_subject.host = 'host'
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    mock_subject.get_session.return_value = None

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_crii:
        mock_crii.return_value = None

        with mock.patch.object(MockSecurityManager, 'login') as mock_smlogin:
            mock_smlogin.return_value = mock_subject

            ds.login('dumb_authc_token')

            mock_smlogin.assert_called_once_with(subject=ds, authc_token='dumb_authc_token')

            assert (ds.session is None and
                    ds.host == mock_subject.host and
                    ds._identifiers == simple_identifiers_collection)


def test_get_session_withsessionattribute_succeeds(
        delegating_subject, monkeypatch, mock_session):
    """
    unit tested:  get_session

    test case:
    the DS includes a MockSession attributes and so it is returned
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'session', mock_session)

    result = ds.get_session()

    assert not mock_session.touch.called
    assert result == mock_session


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
    with pytest.raises(ValueError):
        ds.get_session()


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
    mock_sm = mock.create_autospec(NativeSecurityManager)
    mock_sm.start.return_value = mock_session
    monkeypatch.setattr(ds, 'security_manager', mock_sm)

    result = ds.get_session()

    mock_sm.start.assert_called_once_with('sessioncontext')
    assert result == mock_session
    assert mock_session.stop_session_callback == ds.session_stopped


def test_create_session_context_without_host(delegating_subject, monkeypatch):
    """
    unit tested:  create_session_context

    test case:
    creates a new session context and does not set host
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'host', None)
    result = ds.create_session_context()
    assert result['host'] is None


def test_create_session_context_with_host(delegating_subject, monkeypatch):
    """
    unit tested:  create_session_context

    test case:
    creates a new session context and sets host
    """
    ds = delegating_subject
    result = ds.create_session_context()
    assert (result['host'] == ds.host)


def test_clear_run_as_identities_internal_with_warning(
        delegating_subject, caplog):
    """
    unit tested:  clear_run_as_identities_internal

    test case:
    calls clear_run_as_identities, raising an exception-warning
    """
    ds = delegating_subject
    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities') as mock_cri:
        mock_cri.side_effect = SessionException
        ds.clear_run_as_identities_internal()
        out = caplog.text
        assert 'Encountered session exception' in out


def test_logout(delegating_subject, monkeypatch):
    """
    unit tested:  logout

    test case:

    """
    ds = delegating_subject
    mock_sm = mock.create_autospec(NativeSecurityManager)
    monkeypatch.setattr(ds, 'security_manager', mock_sm)

    with mock.patch.object(DelegatingSubject, 'clear_run_as_identities_internal') as mock_clear:
        mock_clear.return_value = None

        ds.logout()

        mock_clear.assert_called_once_with()
        mock_sm.logout.assert_called_once_with(ds)

        assert (ds.session is None and ds._identifiers is None and
                ds.authenticated == False)


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
    pytest.raises(ValueError, "ds.run_as('dumb_identifiers')")


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
    pytest.raises(ValueError, "ds.push_identity(None)")


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

        sia.assert_called_once_with('run_as_identifiers_session_key', [sic])


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
    newstack = ['collection2', 'collection1']
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: newstack)
    monkeypatch.setattr(ds, 'get_session', lambda: mock_session)

    with mock.patch.object(mock_session, 'set_internal_attribute') as sia:
        sia.return_value = None

        result = ds.pop_identity()

        sia.assert_called_once_with('run_as_identifiers_session_key',
                                    ['collection2'])
    assert result == 'collection1'


# ------------------------------------------------------------------------------
# SubjectStore
# ------------------------------------------------------------------------------

def test_dss_is_sse(default_subject_store, monkeypatch):
    """
    unit tested:  is_session_storage_enabled

    test case:
    delegates call to the sse's method
    """
    dss = default_subject_store
    with mock.patch.object(SessionStorageEvaluator,
                           'is_session_storage_enabled') as dsse_isse:
        dsse_isse.return_value = 'yup'
        result = dss.is_session_storage_enabled('subject')
        assert result == 'yup'


@mock.patch.object(SubjectStore, 'merge_identity')
def test_dss_save_with_sse(mock_mi, default_subject_store, monkeypatch):
    dss = default_subject_store
    monkeypatch.setattr(dss, 'is_session_storage_enabled', lambda x: True)

    monkeypatch.setattr(dss, 'merge_identity', mock_mi)
    dss.save('dummysubject')
    mock_mi.assert_called_once_with('dummysubject')


def test_dss_save_without_sse(default_subject_store, monkeypatch, caplog):
    """
    unit tested:  save

    test case:

    """
    dss = default_subject_store
    monkeypatch.setattr(dss, 'is_session_storage_enabled', lambda x: False)
    dss.save('dummysubject')

    out = caplog.text
    assert 'has been disabled' in out


@mock.patch.object(SubjectStore, 'merge_identity_with_session')
def test_dss_merge_identity_runas_withsession(
        mock_dss_miws, default_subject_store, monkeypatch):
    """
    unit tested:  merge_identity

    test case:
    - subject.is_run_as is set, current_identifiers assigned
    - subject.get_session(False) returns a session
    - merge_identity_with_session is called with x, y, z
    """
    dss = default_subject_store
    ds = mock.MagicMock(is_run_as=True, _identifiers='run_as_identifiers')
    ds.get_session.return_value = 'session'
    dss.merge_identity(ds)
    mock_dss_miws.assert_called_once_with('run_as_identifiers', ds, 'session')


@mock.patch.object(SubjectStore, 'merge_identity_with_session')
def test_dss_merge_identifiers_notrunas_withsession(
        mock_dss_miws, default_subject_store, monkeypatch):
    """
    unit tested:  merge_identifiers

    test case:
    - run_as NOT set for the subject
    - current_identifiers is obtained from the identifiers property and saved
      to the session
    - subject.get_session(False) returns a session
    - merge_identity_with_session is called with x, y, z
    """
    dss = default_subject_store
    ds = mock.MagicMock(is_run_as=False, identifiers='subject_identifiers')
    ds.get_session.return_value = 'session'
    dss.merge_identity(ds)
    mock_dss_miws.assert_called_once_with('subject_identifiers', ds, 'session')


@mock.patch.object(SubjectStore, 'merge_identity_with_session')
def test_dss_merge_identity_notrunas_withoutsession(
        mock_dss_miws, default_subject_store, delegating_subject,
        monkeypatch, mock_session):
    """
    unit tested:  merge_identity

    test case:
    - current_identifiers obtained from subject.identifiers
    - get_session returns None
    """
    dss = default_subject_store
    mock_session = mock.create_autospec(DelegatingSession)

    def get_session(create=True):
        if create:
            return mock_session
        return None

    mock_subject = mock.MagicMock(is_run_as=False,
                                  identifiers='subject_identifiers',
                                  get_session=get_session)

    dss.merge_identity(mock_subject)

    to_set = [['identifiers_session_key', 'subject_identifiers'],
              ['authenticated_session_key', True]]

    mock_session.set_internal_attributes.assert_called_once_with(to_set)
    assert not mock_dss_miws.called


def test_dss_merge_identity_with_session_case1(
        default_subject_store, monkeypatch, delegating_subject):
    """
    unit tested:  merge_authentication_state

    test case:
        - current_identifiers != existing_identifiers
        - subject authenticated
        - existing_authc is None
    """
    dss = default_subject_store
    ds = delegating_subject
    attrs = {'identifiers_session_key' : 'isk',
             'authenticated_session_key': None}
    mock_session = mock.create_autospec(DelegatingSession)
    mock_session.get_internal_attributes.return_value = attrs
    monkeypatch.setattr(ds, 'authenticated', True)
    dss.merge_identity_with_session('current_identifiers', ds, mock_session)

    to_set = [['identifiers_session_key', 'current_identifiers'],
              ['authenticated_session_key', True]]
    mock_session.set_internal_attributes.assert_called_once_with(to_set)
    assert not mock_session.remove_internal_attributes.called


def test_dss_merge_identity_with_session_case2(
        default_subject_store, monkeypatch, delegating_subject, mock_session):
    """
    unit tested:  merge_authentication_state

    test case:
        - current_identifiers == existing_identifiers
        - subject authenticated
        - existing_authc is None
    """
    dss = default_subject_store
    ds = delegating_subject
    attrs = {'identifiers_session_key' : 'current_identifiers',
             'authenticated_session_key': None}
    mock_session = mock.create_autospec(DelegatingSession)
    mock_session.get_internal_attributes.return_value = attrs
    monkeypatch.setattr(ds, 'authenticated', True)
    dss.merge_identity_with_session('current_identifiers', ds, mock_session)

    to_set = [['authenticated_session_key', True]]
    mock_session.set_internal_attributes.assert_called_once_with(to_set)
    assert not mock_session.remove_internal_attributes.called


def test_dss_merge_identity_with_session_case3(
        default_subject_store, monkeypatch, delegating_subject, mock_session):
    """
    unit tested:  merge_authentication_state

    test case:
        - no current_identifiers, existing_identifiers added to to_remove
        - subject not authenticated
        - existing_authc is None
    """
    dss = default_subject_store
    ds = delegating_subject
    attrs = {'identifiers_session_key' : 'identifiers',
             'authenticated_session_key': True}
    mock_session = mock.create_autospec(DelegatingSession)
    mock_session.get_internal_attributes.return_value = attrs
    monkeypatch.setattr(ds, 'authenticated', False)
    dss.merge_identity_with_session(None, ds, mock_session)

    to_remove = ['identifiers_session_key', 'authenticated_session_key']

    mock_session.remove_internal_attributes.assert_called_once_with(to_remove)
    assert not mock_session.set_internal_attributes.called


def test_dss_delete(default_subject_store, mock_session, mock_subject, monkeypatch):
    """
    unit tested:  delete

    test case:
    calls remove_from_session
    """
    dss = default_subject_store
    mock_subject.get_session.return_value = mock_session
    dss.delete(mock_subject)
    calls = [mock.call(dss.dsc_ask), mock.call(dss.dsc_isk)]
    mock_session.remove_internal_attribute.assert_has_calls(calls)


def test_security_manager_creator_init_realms_succeeds(
        security_manager_creator, settings):
    """
    successfully creates a tuple of initialized realm instances
    """
    smb = security_manager_creator

    class MockRealm:
        def __init__(self, account_store,
                     authc_verifiers=None, permission_verifier=None, role_verifier=None):
            self.settings = settings
            self.account_store = account_store

    class MockAccountStore:
        def __init__(self, settings):
            self.settings = settings

    verifiers = {'authc_verifiers': [],
                 'permission_verifier': None,
                 'role_verifier': None}

    realms = [[MockRealm, MockAccountStore, verifiers]]
    results = smb._init_realms('settings', realms)
    realm = results[0]
    assert isinstance(realm, MockRealm)
    assert isinstance(realm.account_store, MockAccountStore)


def test_security_manager_creator_init_realms_raises(
        security_manager_creator):

    smb = security_manager_creator
    realms = [(None, 'MockAccountStore')]

    with pytest.raises(ValueError):
        smb._init_realms('settings', realms)

def test_security_manager_creator_init_cache_handler_succeeds(
        security_manager_creator):
    smb = security_manager_creator
    mock_ch = mock.MagicMock()
    smb._init_cache_handler('settings', mock_ch, 'sm')
    mock_ch.assert_called_once_with(settings='settings',
                                    serialization_manager='sm')

def test_security_manager_creator_init_cache_handler_fails(
        security_manager_creator):
    smb = security_manager_creator
    result = smb._init_cache_handler('settings', None, 'sm')
    assert result is None


def test_security_manager_creator_init_sac_schema(
        security_manager_creator):
    smb = security_manager_creator
    result = smb._init_session_attributes('schema', None)
    assert result == 'schema'


def test_security_manager_creator_init_sac_attributes(
        security_manager_creator):
    smb = security_manager_creator
    attributes = {'session_attributes': 'sas'}
    result = smb._init_session_attributes(None, attributes)
    assert result == 'sas'


def test_security_manager_creator_init_sac_default(
        security_manager_creator):
    smb = security_manager_creator
    result = smb._init_session_attributes(None, None)
    assert result is None


@mock.patch.object(NativeSecurityManager, '__init__', return_value=None)
def test_security_manager_creator_create_manager(
        mock_nsm, security_manager_creator, monkeypatch, core_settings,
        session_attributes):

    smb = security_manager_creator

    monkeypatch.setattr(smb, '_init_realms', lambda x, y: 'realms')
    monkeypatch.setattr(smb, '_init_session_attributes', lambda x, y: session_attributes)
    monkeypatch.setattr(smb, '_init_cache_handler', lambda x, y, z: 'cache_handler')

    result = smb.create_manager('yosai', core_settings, 'session_attributes')

    assert isinstance(result, NativeSecurityManager)
