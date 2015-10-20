import pytest
from yosai import (
    SecurityUtils,
    security_utils,
    ThreadContext,
    thread_context,
    UnavailableSecurityManagerException,
)
from .doubles import (
    MockThreadContext,
)
from unittest import mock

# ------------------------------------------------------------------------------
# SecurityUtils
# ------------------------------------------------------------------------------


def test_su_get_subject_notinthreadcontext(monkeypatch, mock_subject_builder):
    """
    unit tested:  get_subject

    test case:
    - when a subject attribute isn't available from the ThreadContext, the
      subject_builder creates one
        - the newly created subject is bound to the thread managed by the
          ThreadContext
    - the subject is returned
    """
    su = security_utils
    msb = mock_subject_builder

    monkeypatch.setattr(su, 'subject_builder', msb)

    with mock.patch.object(ThreadContext, 'bind', create=True) as tc_bind:
        tc_bind.return_value = None

        result = security_utils.get_subject()
        tc_bind.assert_called_once_with('subjectbuildersubject')
        assert result == 'subjectbuildersubject'


def test_su_get_subject_inthreadcontext(monkeypatch, mock_subject_builder):
    """
    unit tested:  get_subject

    test case:
    when a subject is bound to a threadcontext, it is returned
    """
    monkeypatch.setattr(thread_context, 'subject', 'threadcontextsubject',
                        raising=False)
    result = security_utils.get_subject()
    assert result == 'threadcontextsubject'


def test_su_getsecuritymanager_in_threadcontext(monkeypatch):
    """
    unit tested:  security_manager.getter

    test case:
    obtains a security_manager from the thread_context
    """
    monkeypatch.setattr(thread_context, 'security_manager',
                        'threadcontextsecuritymanager', raising=False)
    result = security_utils.security_manager
    assert result == 'threadcontextsecuritymanager'


def test_su_getsecuritymanager_notin_threadcontext_from_securityutils():
    """
    unit tested:  security_manager.getter

    test case:
    - security_manager not available from the thread_context
    - security_utils._security_manager returned
    """
    result = security_utils.security_manager
    assert result == security_utils._security_manager


def test_su_getsecuritymanager_notin_threadcontext_nor_securityutils_raises(
        monkeypatch):
    """
    unit tested:  security_manager.getter

    test case:

    """
    monkeypatch.delattr(security_utils, '_security_manager')

    with pytest.raises(UnavailableSecurityManagerException):
        security_utils.security_manager
