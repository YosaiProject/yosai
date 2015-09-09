import pytest
from unittest import mock

from yosai import (
    DefaultSubjectContext,
    MapContext,
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
    dsc = DefaultSubjectContext()
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

def test_dsc_resolve_security_manager_none(default_subject_context):
    """
    unit tested:  resolve_security_manager

    test case:
    when no security manager attribute exists, next tries to obtain one from
    SecurityUtils
    """
    dsc = default_subject_context


def test_dsc_resolve_security_manager_none_raises(default_subject_context):
    """
    unit tested:  resolve_security_manager

    test case:
    no security manager attribute exists, SecurityUtils raises an exception
    because it doesn't have a security manager either
    """
    dsc = default_subject_context

# def test_dsc_resolve_identifiers
# def test_dsc_resolve_session
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
