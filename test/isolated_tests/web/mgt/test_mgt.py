from unittest import mock
import pytest

from yosai.core import (
    DefaultSubjectFactory,
    MisconfiguredException,
    NativeSecurityManager,
)

from yosai.web import (
    DefaultWebSubjectContext,
    WebDelegatingSubject,
)


@mock.patch.object(DefaultSubjectFactory, 'create_subject', return_value='subject')
def test_web_subject_factory_create_subject_not_websubjectcontext(
        mock_sf_cs, web_subject_factory, web_subject_context):
    """
    when the subject_context argument is a DefaultSubjectcontext, super's
    create_subject method is called and its value returned
    """
    wsf = web_subject_factory
    wsf.create_subject('subject_context')
    mock_sf_cs.assert_called_once_with(subject_context='subject_context')


@mock.patch.object(WebDelegatingSubject, '__init__', return_value=None)
def test_web_subject_factory_create_subject(
        mock_wds, web_subject_context, monkeypatch, web_subject_factory):
    """
    A WebDelegatingSubject is created and returned when a fully formed web subject
    context is passed to create_subject
    """
    wsf = web_subject_factory
    wsc = web_subject_context
    monkeypatch.setattr(wsc, 'resolve_security_manager', lambda: 'security_manager')
    monkeypatch.setattr(wsc, 'resolve_session', lambda: 'session')
    monkeypatch.setattr(wsc, 'session_creation_enabled', 'session_creation_enabled')
    monkeypatch.setattr(wsc, 'resolve_identifiers', lambda x: 'identifiers')
    monkeypatch.setattr(wsc, 'resolve_authenticated', lambda x: 'authenticated')
    monkeypatch.setattr(wsc, 'resolve_host', lambda x: 'host')
    monkeypatch.setattr(wsc, 'web_registry', 'web_registry')

    wsf.create_subject(web_subject_context)

    mock_wds.assert_called_once_with(identifiers='identifiers',
                                     authenticated='authenticated',
                                     host='host',
                                     session='session',
                                     session_creation_enabled='session_creation_enabled',
                                     security_manager='security_manager',
                                     web_registry='web_registry')


def test_web_security_manager_create_subject_context_raises(
        web_security_manager, monkeypatch):
    """
    without a yosai attribute, an exception is raised
    """
    wsm = web_security_manager
    monkeypatch.delattr(wsm, 'yosai')
    with pytest.raises(MisconfiguredException):
        wsm.create_subject_context('subject')


@mock.patch.object(DefaultWebSubjectContext, '__init__', return_value=None)
def test_web_security_manager_create_subject_context(
        mock_dwsc_init, web_security_manager, mock_web_registry, web_yosai):
    """
    returns a new DefaultWebSubjectContext containing yosai, self,
    and web_registry
    """
    wsm = web_security_manager
    mock_subject = mock.create_autospec(WebDelegatingSubject)
    mock_subject.web_registry = mock_web_registry

    wsm.create_subject_context(mock_subject)
    mock_dwsc_init.assert_called_once_with(web_yosai, wsm, mock_web_registry)


@mock.patch.object(NativeSecurityManager, 'session_manager', new_callable=mock.PropertyMock)
def test_web_security_manager_session_manager_setter(
        mock_nsm_sm, web_security_manager, monkeypatch):
    """
    calls super's session_manager setter and then sets the session_storage_evaluator's
    session_manager
    """
    mock_nsm_sm.return_value.__set__ = mock.MagicMock()
    wsm = web_security_manager
    mock_eval = mock.MagicMock()
    monkeypatch.setattr(wsm.subject_store, 'session_storage_evaluator', mock_eval)

    wsm.session_manager = 'sessionmanager'
    mock_nsm_sm.return_value.__set__.assert_called_once_with(wsm, 'sessionmanager')
    assert mock_eval.session_manager == 'sessionmanager'

#def test_web_security_manager_create_session_context
"""
creates and returns a DefaultWebSessionContext
"""

#def test_web_security_manager_get_session_key_raise_revert
"""
if resolve_web_registry raises an AttributeError, it means a WebSubjectContext
wasn't passed, and consequently super's get_session_key is called with
the subject_context
"""

#def test_web_security_manager_get_session_key
"""
creates and returns a WebSessionKey
"""

#def test_web_security_manager_before_logout
"""
super's before_logout is called and then remove_identity
"""

#def test_web_security_manager_remove_identity_raise_passes
"""
an AttributeError indicates that a WebSubject wasn't passed, and so nothing
happens
"""

#def test_web_security_manager_remove_identity
"""
the subject's web_registry.remember_me cookie deleter is called
"""

#def test_web_security_manager_on_successful_login
"""
a new csrf token gets generated and then super's remember_me_successful_login
is called
"""

#def test_cookie_rmm_remember_init
"""
calls super init
"""

#def test_cookie_rmm_remember_encrypted_identity
"""
subject's web_registry remember_me cookie is set to the encoded value
"""

#def test_cookie_rmm_remember_encrypted_identity_raises
"""
an AttributeError results simply in debug logging
"""

#def test_cookie_rmm_is_identityremoved_raises_returns_false
"""
An AttributeError results in returning False
"""

# def test_cookie_rmm_is_identityremoved
"""
The webregistry's remember_me cookie is resolved and returns a check whether
remember_me is set
"""

# def test_get_remembered_encrypted_identity_removed_instance
"""
scenario:
    - the subject_context already had its remember_me identity removed
    - the subject_context isnt a WebSubjectContext

None returned
"""

# def test_get_remembered_encrypted_identity_removed_not_instance
"""
scenario:
    - the subject_context already had its remember_me identity removed
    - the subject_context isnt a WebSubjectContext

logger debug followed by None returned
"""

# def test_get_remembered_encrypted_identity_remember_me
"""
remember_me cookie exists, so it is b64 decoded and the encrypted val returned
"""

# def test_get_remembered_encrypted_identity_no_remember_me
"""
no remember_me cookie will return None
"""

#def test_forget_identity
"""
the subject's webregistry remember_me cookie deleter is called
"""
