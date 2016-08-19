from unittest import mock
import pytest

from yosai.core import (
    DefaultNativeSessionHandler,
    SessionCreationException,
)

from yosai.web import (
    DefaultWebSessionManager,
    WebSessionHandler,
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
        web_simple_session, web_simple_session_state, attributes_schema,
        monkeypatch):
    """
    Confirm that all expected session attributes are set from __setstate__
    """

    wss = web_simple_session
    wss_state = web_simple_session_state
    monkeypatch.setitem(wss_state, '_attributes', attributes_schema())
    wss.__setstate__(wss_state)

    for key in wss_state.keys():
        assert wss_state[key] == getattr(wss, key)


@mock.patch.object(WebSimpleSession, '__init__', return_value=None)
def test_web_session_factory_create_session(
        mock_wss_init, web_session_factory, attributes_schema,
        mock_session_context):

    web_session_factory.create_session('csrf_token', mock_session_context)

    mock_wss_init.assert_called_once_with('csrf_token',
                                          1800000,
                                          300000,
                                          attributes_schema,
                                          host='123.45.6789')


def test_web_session_handler_on_start_sice_true(
        web_session_handler, mock_web_simple_session, mock_session_context):

    wsh = web_session_handler
    wsh.on_start(mock_web_simple_session, mock_session_context)
    assert mock_session_context.web_registry.session_id == 'simplesessionid123'


def test_web_session_handler_on_start_sice_false(
        web_session_handler, mock_web_simple_session, mock_session_context,
        monkeypatch, caplog):

    wsh = web_session_handler
    monkeypatch.setattr(wsh, 'is_session_id_cookie_enabled', False)
    wsh.on_start(mock_web_simple_session, mock_session_context)
    assert (mock_session_context.web_registry.session_id is None and
            'cookie is disabled' in caplog.text)


def test_web_session_handler_on_recreate_session(
        web_session_handler, web_session_key):
    web_session_handler.on_recreate_session('newsessionid345', web_session_key)
    assert web_session_key.web_registry.current_session_id == 'newsessionid345'


@mock.patch.object(DefaultNativeSessionHandler, 'on_stop')
def test_web_session_handler_on_stop(
        mock_nsh_os, mock_web_simple_session, web_session_key, web_session_handler):
    web_session_handler.on_stop(mock_web_simple_session, web_session_key)

    assert (web_session_key.web_registry.session_id is None and
            web_session_key.web_registry.session_id_history == [('DELETE', None)])


@mock.patch.object(DefaultNativeSessionHandler, 'on_expiration')
@mock.patch.object(WebSessionHandler, 'on_invalidation')
def test_web_session_handler_on_expiration(wsh_oi, dsh_oe, web_session_handler):
    web_session_handler.on_expiration('session', 'ese', 'web_session_key')
    dsh_oe.assert_called_once_with('session', 'ese', 'web_session_key')
    wsh_oi.assert_called_once_with('web_session_key')


@mock.patch.object(DefaultNativeSessionHandler, 'on_invalidation')
def test_web_session_handler_on_invalidation(
        mock_nsh_oi, web_session_key, web_session_handler):
    web_session_handler.on_invalidation(web_session_key, 'session', 'ise')

    mock_nsh_oi.assert_called_once_with('session', 'ise', web_session_key)

    assert (web_session_key.web_registry.session_id is None and
            web_session_key.web_registry.session_id_history == [('DELETE', None)])


@mock.patch.object(DefaultNativeSessionHandler, 'on_invalidation')
def test_web_session_handler_on_invalidation_wo_session(
        mock_nsh_oi, web_session_key, web_session_handler):
    web_session_handler.on_invalidation(web_session_key, None, 'ise')

    assert mock_nsh_oi.called is False

    assert (web_session_key.web_registry.session_id is None and
            web_session_key.web_registry.session_id_history == [('DELETE', None)])


@mock.patch.object(DefaultWebSessionManager, 'create_exposed_session')
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

    with pytest.raises(SessionCreationException):
        wsm.recreate_session(web_session_key)

        mock_sh_delete.assert_called_once_with('oldsession')
        mock_sh_dgs.assert_called_once_with(web_session_key)
        mock_sh_cs.assert_called_once_with('oldsession')


# def test_web_session_mgr_recreate_session_no_newsessionid
# def test_web_session_mgr_create_exposed_session_with_key
# def test_web_session_mgr_create_exposed_session_wo_key
# def test_web_session_mgr_new_csrf_token
# def test_web_session_mgr_new_csrf_token_raises
# def test_web_session_mgr_generate_csrf_token
# def test_web_session_mgr_create_session
# def test_web_session_mgr_create_session_raises


# def test_web_delegating_session_new_csrf_token(web_delegating_session):
# def test_web_delegating_session_get_csrf_token_no_token
# def test_web_delegating_session_get_csrf_token_with_token
# def test_web_delegating_session_flash_allow_duplicate
# def test_web_delegating_session_flash_notallow_msg_in_flash_messages
# def test_web_delegating_session_flash_notallow_msg_notin_flash_messages
# def test_web_delegating_session_peek_flash
# def test_web_delegating_session_pop_flash

# def test_web_proxied_session_new_csrf_token
# def test_web_proxied_session_get_csrf_token
# def test_web_proxied_session_flash
# def test_web_proxied_session_peek_flash
# def test_web_proxied_session_pop_flash

# def test_web_caching_session_store_cache_identifiers_to_key_map
# def test_web_caching_session_store_cache_identifiers_to_key_map_raises

# def test_web_sse_is_session_storage_enabled_true
# def test_web_sse_is_session_storage_enabled_state_false
# def test_web_sse_is_session_storage_enabled_not_websubject_false
# def test_web_sse_is_session_storage_enabled_nostate_webregistry_false


# def test_web_session_key_session_id
# def test_web_session_key_session_id_using_webregistry
# def test_web_session_key_resolve_session_id
# def test_web_session_key_resolve_session_id_using_webregistry
# def test_web_session_key_getstate
# def test_web_session_key_setstate
