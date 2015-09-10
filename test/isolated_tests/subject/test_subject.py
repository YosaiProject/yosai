import pytest
from unittest import mock

from yosai import (
    DefaultSubjectContext,
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

# def test_dsc_resolve_authenticated
# def test_dsc_resolve_host

# ------------------------------------------------------------------------------
# DefaultSubjectStore
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# DelegatingSubject
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
# SubjectBuilder
# ------------------------------------------------------------------------------



# ------------------------------------------------------------------------------
# DefaultSubjectFactory
# ------------------------------------------------------------------------------
