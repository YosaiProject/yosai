import pytest
from unittest import mock

from yosai import (
    DefaultSubjectContext,
    DelegatingSubject,
    MapContext,
    SecurityUtils,
    security_utils,
    ThreadContext,
    UnavailableSecurityManagerException,
)

# ------------------------------------------------------------------------------
# DefaultSubjectSettings
# ------------------------------------------------------------------------------


def test_default_subject_settings(default_subject_settings):
    """
    unit tested:  default context names

    test case:
    when subject settings are properly configured, a dict of context keys will
    be available through the context attribute
    """
    dss = default_subject_settings
    context = dss.context
    assert context.get('AUTHENTICATION_TOKEN') ==\
        "DefaultSubjectContext.AUTHENTICATION_TOKEN"

# ------------------------------------------------------------------------------
# DefaultSubjectContext
# ------------------------------------------------------------------------------


def test_dsc_init(subject_context, default_subject_context):
    """
    unit tested:  __init__

    test case:
    When initialized, context attribute names are obtained from yosai settings.
    Verify that the two subject contexts used for testing are initialized as
    expected
    """
    dsc = DefaultSubjectContext(security_utils)
    assert (not dsc.attributes and
            'DefaultSubjectContext.AUTHENTICATION_TOKEN' in
            default_subject_context.attribute_keys)


@pytest.mark.parametrize(
    'attr', ['security_manager', 'session_id', 'subject', 'identifiers',
             'session', 'session_creation_enabled', 'account',
             'authentication_token', 'host'])
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
    monkeypatch.setattr(ThreadContext, 'security_manager', 'mysecuritymanager', raising=False)
    result = dsc.resolve_security_manager()
    out, err = capsys.readouterr()
    assert ("No SecurityManager available" in out and
            result == 'mysecuritymanager')

def test_dsc_resolve_security_manager_none_raises(
        default_subject_context, monkeypatch, capsys):
    """
    unit tested:  resolve_security_manager

    test case:
    no security manager attribute exists, SecurityUtils raises an exception
    because it doesn't have a security manager either
    """

    dsc = default_subject_context
    monkeypatch.setitem(dsc.context, dsc.get_key('SECURITY_MANAGER'), None)
    monkeypatch.setattr(ThreadContext, 'security_manager', None, raising=False)
    result = dsc.resolve_security_manager()
    out, err = capsys.readouterr()
    assert ("No SecurityManager available via SecurityUtils" in out and
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
            self.identifiers = 'subjectidentifier'

    monkeypatch.setitem(dsc.context, subject_context['IDENTIFIERS'], None)
    monkeypatch.setitem(dsc.context, subject_context['ACCOUNT'], None)
    monkeypatch.setitem(dsc.context, subject_context['SUBJECT'], DumbSubject())

    result = dsc.resolve_identifiers()
    assert result == 'subjectidentifier'


def test_dsc_resolve_identifiers_none_sessionreturns(
        default_subject_context, monkeypatch):
    """
    unit tested:  resolve_identifiers

    test case:
    when the dsc doesn't have an identifiers attribute set, and neither account
    nor subject has identifiers, resolve_session is called to obtain a session,
    and then the session's identifiers is obtained
    """
    dsc = default_subject_context
    class DumbSession:
        def get_attribute(self, key):
            return 'identifier'

    monkeypatch.setattr(dsc, 'get', lambda x: None)
    monkeypatch.setattr(dsc, 'resolve_session', lambda: DumbSession())
    result = dsc.resolve_identifiers()
    assert result == 'identifier'


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


def test_dsc_resolve_authenticated(default_subject_context):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is set, it is returned
    """
    dsc = default_subject_context
    result = dsc.resolve_authenticated()
    assert result == bool(dsc.authenticated)


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
        default_subject_context, monkeypatch, subject_context):
    """
    unit tested:  resolve_authenticated

    test case:
    when the dsc's authenticated attribute is NOT set, no Account attribute
    exists, but a session exists and has proof of authentication, returns True
    """
    dsc = default_subject_context

    class DumbSession:
        def get_attribute(self, key):
            return 'AUTHC'

    monkeypatch.setitem(dsc.context, subject_context['AUTHENTICATED'], None)
    monkeypatch.setitem(dsc.context, subject_context['ACCOUNT'], None)
    monkeypatch.setattr(dsc, 'resolve_session', lambda: DumbSession())

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
    result = ds.decorate('session')
    assert result is None


def test_security_manager_typecheck(delegating_subject, mock_security_manager):
    """
    unit tested security_manager.setter

    test case:
    only objects implementing the SecurityManager interface may be assigned
    """
    ds = delegating_subject

    DumbSecurityManager = type("DumbSecurityManager", (), {})
    ds.security_manager = DumbSecurityManager()  # shouldn't set
    assert ds.security_manager == mock_security_manager


def test_ds_identifiers_fromstack(delegating_subject, monkeypatch):
    """
    unit tested:  identifiers

    test case:
    first tries to obtain identifiers from get_run_as_identifiers_stack
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: ['identifier1'] )
    result = ds.identifiers
    assert result == 'identifier1'


def test_ds_identifiers_fromidentifiers(
        delegating_subject, monkeypatch, simple_identifier_collection):
    """
    unit tested:  identifiers

    test case:
    first tries to obtain identifiers from get_run_as_identifiers_stack, fails,
    and reverts to _identifiers attribute
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, 'get_run_as_identifiers_stack', lambda: None)
    result = ds.identifiers
    assert result == simple_identifier_collection


def test_ds_identifiers_type(delegating_subject, monkeypatch):
    """
    unit tested:  identifiers.setter

    test case:
    only object of type IdentifierCollection may be set to the identifiers attribute
    """
    ds = delegating_subject
    monkeypatch.setattr(ds, '_identifiers', None)
    ds.identifiers = 'identifiers'
    assert ds._identifiers is None


def test_ds_is_permitted_withidentifiers(delegating_subject, monkeypatch):
    """
    unit test:  is_permitted

    test case:
    the identifiers attribute is set for the fixture and is passed on as an
    argument to the security manager
    """

    ds = delegating_subject
    print('security_manager: ', ds.security_manager)
    monkeypatch.setattr(ds.security_manager, 'is_permitted', lambda x,y: 'sm_permitted')
    result = ds.is_permitted('permission')
    assert result == 'sm_permitted'

# ------------------------------------------------------------------------------
# DefaultSubjectStore
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# SubjectBuilder
# ------------------------------------------------------------------------------



# ------------------------------------------------------------------------------
# DefaultSubjectFactory
# ------------------------------------------------------------------------------
