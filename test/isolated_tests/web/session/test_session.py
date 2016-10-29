from unittest import mock
import pytest

from yosai.core import (
    NativeSessionHandler,
)

from yosai.web import (
    CSRFTokenException,
    WebSessionManager,
    WebDelegatingSession,
    WebSessionHandler,
    WebSessionKey,
    WebSimpleSession,
)


def test_web_simple_session_getstate(
        web_simple_session, web_simple_session_state):
    """
    Confirm that all expected session attributes are accounted for in __getstate__
    """
    wss = web_simple_session
    wss_state = web_simple_session_state

    gs = wss.__getstate__()

    for key in wss_state.keys():
        assert wss_state[key] == gs[key]


def test_web_simple_session_setstate(
        web_simple_session, web_simple_session_state, monkeypatch):
    """
    Confirm that all expected session attributes are set from __setstate__
    """

    wss = web_simple_session
    wss_state = web_simple_session_state
    monkeypatch.setitem(wss_state, 'attributes', {'one': 1, 'two': 2})
    wss.__setstate__(wss_state)

    for key in wss_state.keys():
        assert wss_state[key] == getattr(wss, key)


def test_web_session_handler_on_start_sice_true(
        web_session_handler, mock_web_simple_session, mock_session_context):

    wsh = web_session_handler
    wsh.on_start(mock_web_simple_session, mock_session_context)
    assert mock_session_context['web_registry'].session_id == 'simplesessionid123'


def test_web_session_handler_on_start_sice_false(
        web_session_handler, mock_web_simple_session, mock_session_context,
        monkeypatch, caplog):

    wsh = web_session_handler
    monkeypatch.setattr(wsh, 'is_session_id_cookie_enabled', False)
    wsh.on_start(mock_web_simple_session, mock_session_context)
    assert (mock_session_context['web_registry'].session_id is None and
            'cookie is disabled' in caplog.text)


def test_web_session_handler_on_recreate_session(
        web_session_handler, web_session_key):
    web_session_handler.on_recreate_session('newsessionid345', web_session_key)
    assert web_session_key.web_registry.current_session_id == 'newsessionid345'


@mock.patch.object(NativeSessionHandler, 'on_stop')
def test_web_session_handler_on_stop(
        mock_nsh_os, mock_web_simple_session, web_session_key, web_session_handler):
    web_session_handler.on_stop(mock_web_simple_session, web_session_key)

    assert (web_session_key.web_registry.session_id is None and
            web_session_key.web_registry.session_id_history == [('DELETE', None)])


@mock.patch.object(NativeSessionHandler, 'on_expiration')
@mock.patch.object(WebSessionHandler, 'on_invalidation')
def test_web_session_handler_on_expiration(wsh_oi, dsh_oe, web_session_handler):
    web_session_handler.on_expiration('session', 'ese', 'web_session_key')
    dsh_oe.assert_called_once_with('session', 'ese', 'web_session_key')
    wsh_oi.assert_called_once_with('web_session_key')


@mock.patch.object(NativeSessionHandler, 'on_invalidation')
def test_web_session_handler_on_invalidation(
        mock_nsh_oi, web_session_key, web_session_handler):
    web_session_handler.on_invalidation(web_session_key, 'session', 'ise')

    mock_nsh_oi.assert_called_once_with('session', 'ise', web_session_key)

    assert (web_session_key.web_registry.session_id is None and
            web_session_key.web_registry.session_id_history == [('DELETE', None)])


@mock.patch.object(NativeSessionHandler, 'on_invalidation')
def test_web_session_handler_on_invalidation_wo_session(
        mock_nsh_oi, web_session_key, web_session_handler):
    web_session_handler.on_invalidation(web_session_key, None, 'ise')

    assert mock_nsh_oi.called is False

    assert (web_session_key.web_registry.session_id is None and
            web_session_key.web_registry.session_id_history == [('DELETE', None)])

# ------------------------------------------------------------------------------
# WebSessionManager
# ------------------------------------------------------------------------------


@mock.patch.object(WebSessionManager, 'create_exposed_session')
@mock.patch.object(WebSessionHandler, 'do_get_session', return_value='oldsession')
@mock.patch.object(WebSessionHandler, 'create_session', return_value='newsessionid')
@mock.patch.object(WebSessionHandler, 'delete')
@mock.patch.object(WebSessionHandler, 'on_recreate_session')
def test_web_session_mgr_recreate_session(
        mock_sh_ors, mock_sh_delete, mock_sh_cs, mock_sh_dgs, mock_sm_ces,
        web_session_manager, web_session_key):
    wsm = web_session_manager

    wsm.recreate_session(web_session_key)

    mock_sh_delete.assert_called_once_with('oldsession')
    mock_sh_dgs.assert_called_once_with(web_session_key)
    mock_sh_cs.assert_called_once_with('oldsession')
    mock_sh_ors.assert_called_once_with('newsessionid', web_session_key)
    assert mock_sm_ces.called


@mock.patch.object(WebSessionHandler, 'do_get_session', return_value='oldsession')
@mock.patch.object(WebSessionHandler, 'create_session', return_value=None)
@mock.patch.object(WebSessionHandler, 'delete')
def test_web_session_mgr_recreate_session_raises(
        mock_sh_delete, mock_sh_cs, mock_sh_dgs, web_session_manager, web_session_key):
    wsm = web_session_manager

    with pytest.raises(ValueError):
        wsm.recreate_session(web_session_key)

        mock_sh_delete.assert_called_once_with('oldsession')
        mock_sh_dgs.assert_called_once_with(web_session_key)
        mock_sh_cs.assert_called_once_with('oldsession')


def test_web_session_mgr_create_exposed_session_without_key(
        mock_web_delegating_session, web_session_manager, mock_session_context):

    wsm = web_session_manager
    result = wsm.create_exposed_session(mock_web_delegating_session,
                                        context=mock_session_context)

    assert (isinstance(result, WebDelegatingSession) and
            result.session_key.web_registry == mock_session_context['web_registry'])


def test_web_session_mgr_create_exposed_session_w_key(
        mock_web_delegating_session, web_session_manager, web_session_key):

    wsm = web_session_manager
    result = wsm.create_exposed_session(mock_web_delegating_session,
                                        key=web_session_key)

    assert (isinstance(result, WebDelegatingSession) and
            result.session_key.web_registry == web_session_key.web_registry)


@mock.patch.object(WebSessionHandler, 'on_change')
def test_web_session_mgr_new_csrf_token(
        mock_sh_oc, web_session_manager, monkeypatch, mock_web_delegating_session):
    wsm = web_session_manager
    mwds = mock_web_delegating_session
    monkeypatch.setattr(wsm, '_generate_csrf_token', lambda: 'csrftoken')
    monkeypatch.setattr(wsm, '_lookup_required_session', lambda x: mwds)
    result = wsm.new_csrf_token('sessionkey123')
    mwds.set_internal_attribute.assert_called_once_with('csrf_token', 'csrftoken')
    mock_sh_oc.assert_called_once_with(mwds)

    assert result == 'csrftoken'


def test_web_session_mgr_new_csrf_token_raises(
        web_session_manager, monkeypatch, mock_web_delegating_session):
    wsm = web_session_manager
    monkeypatch.setattr(wsm, '_generate_csrf_token', lambda: 'csrftoken')
    monkeypatch.setattr(wsm, '_lookup_required_session', lambda x: 'failed')

    with pytest.raises(CSRFTokenException):
        wsm.new_csrf_token('sessionkey123')


def test_web_session_mgr_generate_csrf_token(web_session_manager):
    result = web_session_manager._generate_csrf_token()
    assert len(result) == 40  # it's always 40


@mock.patch('yosai.web.session.session.WebSimpleSession')
def test_web_session_mgr_create_session(mock_wss, web_session_manager, monkeypatch):
    mock_wss.return_value = 'session'
    wsm = web_session_manager
    monkeypatch.setattr(wsm, '_generate_csrf_token', lambda: 'csrftoken')

    mock_sh = mock.create_autospec(WebSessionHandler)
    mock_sh.create_session.return_value = 'sessionid'
    monkeypatch.setattr(wsm, 'session_handler', mock_sh)

    wsm._create_session({'host': 'host'})
    mock_sh.create_session.assert_called_once_with('session')


@mock.patch.object(NativeSessionHandler, 'create_session', return_value=None)
def test_web_session_mgr_create_session_raises(
        mock_sh_cs, web_session_manager, monkeypatch):
    wsm = web_session_manager
    monkeypatch.setattr(wsm, '_generate_csrf_token', lambda: 'csrftoken')

    with pytest.raises(ValueError):
        wsm._create_session({'host': 'host'})
        mock_sh_cs.assert_called_once_with('session')


def test_web_delegating_session_new_csrf_token(
        web_delegating_session, monkeypatch, web_session_key):
    wds = web_delegating_session
    monkeypatch.setattr(wds, 'session_key', 'testing')
    monkeypatch.setattr(wds.session_manager, 'new_csrf_token', lambda x: x)

    assert wds.new_csrf_token() == 'testing'


def test_web_delegating_session_get_csrf_token_no_token(
        web_delegating_session, monkeypatch):
    wds = web_delegating_session
    monkeypatch.setattr(wds, 'get_internal_attribute', lambda x: None)
    monkeypatch.setattr(wds, 'new_csrf_token', lambda: 'newtoken')
    assert wds.get_csrf_token() == 'newtoken'


def test_web_delegating_session_get_csrf_token_with_token(
        web_delegating_session, monkeypatch):
    wds = web_delegating_session
    monkeypatch.setattr(wds, 'get_internal_attribute', lambda x: 'token')
    monkeypatch.setattr(wds, 'new_csrf_token', lambda: 'newtoken')
    assert wds.get_csrf_token() == 'token'


@mock.patch.object(WebDelegatingSession, 'set_internal_attribute')
def test_web_delegating_session_flash_allow_duplicate(
        mock_wds_sia, web_delegating_session, monkeypatch):
    wds = web_delegating_session

    flashmessages = {'default': ['testing123']}
    monkeypatch.setattr(wds, 'get_internal_attribute', lambda x: flashmessages)

    wds.flash('testing123', allow_duplicate=True)

    flashmessages = {'default': ['testing123', 'testing123']}
    mock_wds_sia.assert_called_once_with('flash_messages', flashmessages)


@mock.patch.object(WebDelegatingSession, 'set_internal_attribute')
def test_web_delegating_session_flash_notallow_msg_in_flash_messages(
        mock_wds_sia, web_delegating_session, monkeypatch):
    wds = web_delegating_session

    flashmessages = {'default': ['testing123']}
    monkeypatch.setattr(wds, 'get_internal_attribute', lambda x: flashmessages)

    wds.flash('testing123')

    assert not mock_wds_sia.called


@mock.patch.object(WebDelegatingSession, 'set_internal_attribute')
def test_web_delegating_session_flash_notallow_msg_notin_flash_messages(
        mock_wds_sia, web_delegating_session, monkeypatch):
    wds = web_delegating_session

    flashmessages = {'default': ['testing123']}
    monkeypatch.setattr(wds, 'get_internal_attribute', lambda x: flashmessages)

    wds.flash('testing456')

    flashmessages = {'default': ['testing123', 'testing456']}
    mock_wds_sia.assert_called_once_with('flash_messages', flashmessages)


@mock.patch.object(WebDelegatingSession,
                   'get_internal_attribute',
                   return_value={'default': ['testing123']})
def test_web_delegating_session_peek_flash(mock_ds_gia, web_delegating_session):
    assert web_delegating_session.peek_flash() == ['testing123']
    mock_ds_gia.assert_called_once_with('flash_messages')


@mock.patch.object(WebDelegatingSession, 'set_internal_attribute')
def test_web_delegating_session_pop_flash(
        mock_wds_sia, web_delegating_session, monkeypatch):
    wds = web_delegating_session
    flashmessages = {'default': ['testing123', 'testing456'],
                     'custom_queue': ['custom123']}
    monkeypatch.setattr(wds, 'get_internal_attribute', lambda x: flashmessages)
    result = wds.pop_flash()

    flashmessages = {'custom_queue': ['custom123']}

    mock_wds_sia.assert_called_once_with('flash_messages', flashmessages)
    assert result == ['testing123', 'testing456']


def test_web_delegating_session_recreate_session(
        web_delegating_session, monkeypatch):
    wds = web_delegating_session
    monkeypatch.setattr(wds.session_manager, 'recreate_session', lambda x: x)
    assert wds.recreate_session() == wds.session_key


def test_web_sse_is_session_storage_enabled_true(
        web_session_storage_evaluator, mock_web_delegating_subject, monkeypatch):
    wsse = web_session_storage_evaluator
    monkeypatch.setattr(mock_web_delegating_subject, 'get_session', lambda x: True)
    assert wsse.is_session_storage_enabled(mock_web_delegating_subject) is True


def test_web_sse_is_session_storage_enabled_state_false(
        web_session_storage_evaluator, mock_web_delegating_subject, monkeypatch):

    wsse = web_session_storage_evaluator
    monkeypatch.setattr(mock_web_delegating_subject, 'get_session', lambda x: False)
    monkeypatch.setattr(wsse, 'session_storage_enabled', lambda: False)
    assert wsse.is_session_storage_enabled(mock_web_delegating_subject) is True


def test_web_sse_is_session_storage_enabled_not_websubject_false(
        web_session_storage_evaluator, monkeypatch):
    wsse = web_session_storage_evaluator

    mock_subject = mock.MagicMock()
    mock_subject.get_session.return_value = False
    mock_subject.web_registry.session_creation_enabled = False

    monkeypatch.setattr(wsse, 'session_manager', 'sessman')
    monkeypatch.setattr(wsse, 'session_storage_enabled', lambda: True)
    assert wsse.is_session_storage_enabled(mock_subject) is False


def test_web_sse_is_session_storage_enabled_nostate_webregistry_true(
        web_session_storage_evaluator, monkeypatch, web_delegating_subject):
    wsse = web_session_storage_evaluator

    mock_subject = mock.MagicMock()
    mock_subject.get_session.return_value = False

    monkeypatch.setattr(wsse, 'session_storage_enabled', lambda: True)
    monkeypatch.setattr(web_delegating_subject.web_registry, 'session_creation_enabled', False)

    assert wsse.is_session_storage_enabled(web_delegating_subject)
