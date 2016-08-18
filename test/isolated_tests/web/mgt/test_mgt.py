import base64
from unittest import mock
import pytest

from yosai.core import (
    DefaultSubjectFactory,
    MisconfiguredException,
    NativeSecurityManager,
)

from yosai.web import (
    DefaultWebSessionContext,
    DefaultWebSubjectContext,
    WebDelegatingSubject,
    WebSecurityManager,
    WebSessionKey,
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


@mock.patch.object(DefaultWebSessionContext, '__init__', return_value=None)
def test_web_security_manager_create_session_context(
        mock_dwsc_init, web_security_manager, web_subject_context, monkeypatch,
        mock_web_registry):
    """
    creates and returns a DefaultWebSessionContext
    """
    wsm = web_security_manager
    monkeypatch.setattr(web_subject_context,
                        'resolve_web_registry',
                        lambda: mock_web_registry)
    result = wsm.create_session_context(web_subject_context)
    mock_dwsc_init.assert_called_once_with(mock_web_registry)
    assert result.host == getattr(wsm, 'host', None)


@mock.patch.object(NativeSecurityManager, 'get_session_key',
                   return_value='native_session_key')
def test_web_security_manager_get_session_key_raise_revert(
        mock_nsm_gsk, web_security_manager):
    """
    if resolve_web_registry raises an AttributeError, it means a WebSubjectContext
    wasn't passed, and consequently super's get_session_key is called with
    the subject_context
    """
    wsm = web_security_manager
    wsm.get_session_key('subjectcontext')
    mock_nsm_gsk.assert_called_once_with('subjectcontext')


@mock.patch.object(WebSessionKey, '__init__', return_value=None)
def test_web_security_manager_get_session_key(
        mock_wsk_init, web_security_manager, web_subject_context,
        monkeypatch, mock_web_registry):
    """
    creates and returns a WebSessionKey
    """
    wsm = web_security_manager
    monkeypatch.setattr(web_subject_context, 'resolve_web_registry', lambda: mock_web_registry)
    monkeypatch.setattr(web_subject_context, 'session_id', 'sessionid1234')
    result = wsm.get_session_key(web_subject_context)
    mock_wsk_init.assert_called_once_with(session_id='sessionid1234',
                                          web_registry=mock_web_registry)
    assert isinstance(result, WebSessionKey)


@mock.patch.object(NativeSecurityManager, 'before_logout')
@mock.patch.object(WebSecurityManager, 'remove_identity')
def test_web_security_manager_before_logout(
        mock_wsm_ri, mock_nsm_bl, web_security_manager):
    """
    super's before_logout is called and then remove_identity
    """
    web_security_manager.before_logout('subject')

    mock_wsm_ri.assert_called_once_with('subject')
    mock_nsm_bl.assert_called_once_with('subject')


def test_web_security_manager_remove_identity_raise_passes(
        web_security_manager):
    """
    an AttributeError indicates that a WebSubject wasn't passed, and so nothing
    happens
    """
    assert web_security_manager.remove_identity('subject') is None


def test_web_security_manager_remove_identity(
        web_security_manager, mock_web_registry, monkeypatch):
    """
    the subject's web_registry.remember_me cookie deleter is called
    """
    wsm = web_security_manager
    mock_subject = mock.MagicMock()
    mock_subject.web_registry = mock_web_registry
    wsm.remove_identity(mock_subject)
    assert mock_web_registry.remember_me_history == [('DELETE', None)]


@mock.patch.object(NativeSecurityManager, 'remember_me_successful_login')
def test_web_security_manager_on_successful_login(
        mock_nsm_rmsl, web_security_manager):
    """
    a new csrf token gets generated and then super's remember_me_successful_login
    is called
    """
    wsm = web_security_manager
    mock_subject = mock.MagicMock()
    mock_subject.session.recreate_session.return_value = 'recreated'
    wsm.on_successful_login('authc_token', 'account', mock_subject)

    mock_nsm_rmsl.assert_called_once_with('authc_token', 'account', mock_subject)
    assert mock_subject.session == 'recreated'


def test_cookie_rmm_remember_encrypted_identity(
        cookie_rmm, mock_web_delegating_subject):
    """
    subject's web_registry remember_me cookie is set to the encoded value
    """
    mwds = mock_web_delegating_subject

    assert mwds.web_registry.current_remember_me is None

    cookie_rmm.remember_encrypted_identity(mwds, b'encrypted')

    assert mwds.web_registry.current_remember_me is not None


def test_cookie_rmm_remember_encrypted_identity_raises(
        cookie_rmm, caplog):
    """
    an AttributeError results simply in debug logging
    """
    cookie_rmm.remember_encrypted_identity('subject', b'encrypted')
    assert 'not an HTTP-aware' in caplog.text


def test_cookie_rmm_is_identityremoved_raises_returns_false(
        cookie_rmm):
    """
    An AttributeError results in returning False
    """
    assert cookie_rmm.is_identity_removed('subject_context') is False


def test_cookie_rmm_is_identityremoved(
        cookie_rmm, monkeypatch, mock_web_registry, web_subject_context):
    """
    The webregistry's remember_me cookie is resolved and returns a check whether
    remember_me is set
    """
    monkeypatch.setattr(mock_web_registry, 'current_remember_me', 'remembered')
    monkeypatch.setattr(web_subject_context, 'resolve_web_registry', lambda: mock_web_registry)
    cookie_rmm.is_identity_removed(web_subject_context) is True


def test_cookie_rmm_get_remembered_encrypted_identity_removed_instance(
        cookie_rmm, caplog, monkeypatch, web_subject_context):
    """
    scenario:
        - the subject_context already had its remember_me identity removed
        - the subject_context isnt a WebSubjectContext

    None returned
    """
    monkeypatch.setattr(cookie_rmm, 'is_identity_removed', lambda x: True)
    result = cookie_rmm.get_remembered_encrypted_identity(web_subject_context)
    assert 'not an HTTP' not in caplog.text and result is None


def test_cookie_rmm_get_remembered_encrypted_identity_removed_not_instance(
        cookie_rmm, caplog, monkeypatch):
    """
    scenario:
        - the subject_context already had its remember_me identity removed
        - the subject_context isnt a WebSubjectContext

    logger debug followed by None returned
    """
    monkeypatch.setattr(cookie_rmm, 'is_identity_removed', lambda x: True)
    result = cookie_rmm.get_remembered_encrypted_identity('subject_context')
    assert 'not an HTTP' in caplog.text and result is None


def test_cookie_rmm_get_remembered_encrypted_identity_remember_me(
        cookie_rmm, monkeypatch, mock_web_registry, web_subject_context):
    """
    remember_me cookie exists, so it is b64 decoded and the encrypted val returned
    """
    encoded = base64.b64encode(b'remembered')

    monkeypatch.setattr(mock_web_registry, 'current_remember_me', encoded)
    monkeypatch.setattr(cookie_rmm, 'is_identity_removed', lambda x: False)
    monkeypatch.setattr(web_subject_context, 'web_registry', mock_web_registry)

    result = cookie_rmm.get_remembered_encrypted_identity(web_subject_context)

    assert result == base64.b64decode(encoded)


def test_cookie_rmm_get_remembered_encrypted_identity_no_remember_me(
        cookie_rmm, monkeypatch, mock_web_registry, web_subject_context):
    """
    no remember_me cookie will return None
    """

    monkeypatch.setattr(mock_web_registry, 'current_remember_me', None)
    monkeypatch.setattr(cookie_rmm, 'is_identity_removed', lambda x: False)
    monkeypatch.setattr(web_subject_context, 'web_registry', mock_web_registry)

    result = cookie_rmm.get_remembered_encrypted_identity(web_subject_context)

    assert result is None


def test_cookie_rmm_forget_identity(
        cookie_rmm, mock_web_delegating_subject):
    """
    the subject's webregistry remember_me cookie deleter is called
    """
    cookie_rmm.forget_identity(mock_web_delegating_subject, 'sc')

    assert (mock_web_delegating_subject.web_registry.remember_me_history ==
            [('DELETE', None)])
