import base64
from unittest import mock

from yosai.core import (
    NativeSecurityManager,
)

from yosai.web import (
    WebSubjectContext,
    WebDelegatingSubject,
    WebSecurityManager,
    WebSessionKey,
)

# ------------------------------------------------------------------------
#  WebSecurityManager Tests
# ------------------------------------------------------------------------

@mock.patch.object(WebSubjectContext, '__init__', return_value=None)
def test_web_security_manager_create_subject_context(
        mock_dwsc_init, web_security_manager, mock_web_registry, web_yosai):
    """
    returns a new WebSubjectContext containing yosai, self,
    and web_registry
    """
    wsm = web_security_manager
    mock_subject = mock.create_autospec(WebDelegatingSubject)
    mock_subject.web_registry = mock_web_registry

    wsm.create_subject_context(mock_subject)
    mock_dwsc_init.assert_called_once_with(web_yosai, wsm, mock_web_registry)


def test_wsm_create_session_context(web_security_manager):
    wsm = web_security_manager
    subject_context = mock.create_autospec(WebSubjectContext)
    subject_context.resolve_web_registry.return_value = 'web_registry'
    result = wsm.create_session_context(subject_context)
    assert result == {'web_registry': 'web_registry', 'host': None}


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


def test_web_security_manager_get_session_key(
        web_security_manager, web_subject_context, monkeypatch, mock_web_registry):
    """
    creates and returns a WebSessionKey
    """
    wsm = web_security_manager
    monkeypatch.setattr(web_subject_context, 'resolve_web_registry', lambda: mock_web_registry)
    monkeypatch.setattr(web_subject_context, 'session_id', 'sessionid1234')
    result = wsm.get_session_key(web_subject_context)
    assert result == WebSessionKey(session_id='sessionid1234', web_registry=mock_web_registry)


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


@mock.patch.object(WebDelegatingSubject, '__init__', return_value=None)
def test_wsm_do_create_subject(mock_ds, web_security_manager, monkeypatch):
    wsm = web_security_manager
    mock_sc = mock.create_autospec(WebSubjectContext)
    mock_sc.resolve_security_manager.return_value = 'security_manager'
    mock_sc.resolve_session.return_value = 'session'
    mock_sc.session_creation_enabled = 'session_creation_enabled'
    mock_sc.resolve_identifiers.return_value = 'identifiers'
    mock_sc.remembered = True
    mock_sc.resolve_authenticated.return_value = True
    mock_sc.resolve_host.return_value = 'host'
    mock_sc.web_registry = 'web_registry'

    wsm.do_create_subject(mock_sc)
    mock_ds.assert_called_once_with(identifiers='identifiers',
                                    remembered=True,
                                    authenticated=True,
                                    host='host',
                                    session='session',
                                    session_creation_enabled='session_creation_enabled',
                                    security_manager='security_manager',
                                    web_registry=mock_sc.web_registry)


# ------------------------------------------------------------------------
#  CookieRememberMeManager Tests
# ------------------------------------------------------------------------


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
