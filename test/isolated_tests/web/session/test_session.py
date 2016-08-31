from unittest import mock
import pytest

from yosai.core import (
    DefaultNativeSessionHandler,
    SessionCreationException,
)

from yosai.web import (
    CSRFTokenException,
    DefaultWebSessionManager,
    WebDelegatingSession,
    WebSessionFactory,
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
        web_simple_session, web_simple_session_state, mock_serializable,
        monkeypatch):
    """
    Confirm that all expected session attributes are set from __setstate__
    """

    wss = web_simple_session
    wss_state = web_simple_session_state
    monkeypatch.setitem(wss_state, '_attributes', mock_serializable('one','two','three'))
    wss.__setstate__(wss_state)

    for key in wss_state.keys():
        assert wss_state[key] == getattr(wss, key)


@mock.patch.object(WebSimpleSession, '__init__', return_value=None)
def test_web_session_factory_create_session(
        mock_wss_init, web_session_factory, mock_session_context):

    web_session_factory.create_session('csrf_token', mock_session_context)

    mock_wss_init.assert_called_once_with('csrf_token',
                                          1800000,
                                          300000,
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


def test_web_session_mgr_create_exposed_session_without_key(
        mock_web_delegating_session, web_session_manager, mock_session_context):

    wsm = web_session_manager
    result = wsm.create_exposed_session(mock_web_delegating_session,
                                        context=mock_session_context)

    assert (isinstance(result, WebDelegatingSession) and
            result.session_key.web_registry == mock_session_context.web_registry)


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


@mock.patch.object(WebSessionFactory, 'create_session', return_value='session')
def test_web_session_mgr_create_session(
        mock_wsf_cs, web_session_manager, monkeypatch):

    wsm = web_session_manager
    monkeypatch.setattr(wsm, '_generate_csrf_token', lambda: 'csrftoken')
    monkeypatch.setattr(wsm.session_handler, 'create_session', lambda x: 'sessionid')

    wsm._create_session('session_context')
    mock_wsf_cs.assert_called_once_with('csrftoken', 'session_context')


@mock.patch.object(DefaultNativeSessionHandler, 'create_session', return_value=None)
@mock.patch.object(WebSessionFactory, 'create_session', return_value='session')
def test_web_session_mgr_create_session_raises(
        mock_wsf_cs, mock_sh_cs, web_session_manager, monkeypatch):
    wsm = web_session_manager
    monkeypatch.setattr(wsm, '_generate_csrf_token', lambda: 'csrftoken')

    with pytest.raises(SessionCreationException):
        wsm._create_session('session_context')
        mock_wsf_cs.assert_called_once_with('csrftoken', 'session_context')
        mock_sh_cs.assert_called_once_with('session')


@mock.patch.object(WebSessionKey, 'resolve_session_id')
def test_web_session_key_session_id(mock_wsk_rsi, web_session_key, monkeypatch):
    wsk = web_session_key
    monkeypatch.setattr(wsk, '_session_id', None)

    wsk.session_id
    mock_wsk_rsi.assert_called_once_with()


def test_web_session_key_resolve_session_id(web_session_key, monkeypatch):
    wsk = web_session_key
    monkeypatch.setattr(wsk, '_session_id', 'sessionid')
    monkeypatch.setattr(wsk.web_registry, 'current_session_id', 'currentsessionid')
    wsk.resolve_session_id()
    assert wsk._session_id == 'sessionid'


def test_web_session_key_resolve_session_id_using_webregistry(
        web_session_key, monkeypatch):

    wsk = web_session_key
    monkeypatch.setattr(wsk, '_session_id', None)
    monkeypatch.setattr(wsk.web_registry, 'current_session_id', 'currentsessionid')
    wsk.resolve_session_id()
    assert wsk._session_id == 'currentsessionid'


def test_web_session_key_serialization(web_session_key, monkeypatch):
    wsk = web_session_key
    monkeypatch.setattr(wsk, '_session_id', 'sessionid123456')
    wsk.__setstate__(wsk.__getstate__())
    assert wsk._session_id == 'sessionid123456'


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


def test_web_proxied_session_new_csrf_token(web_proxied_session, monkeypatch):
    monkeypatch.setattr(web_proxied_session._delegate,
                        'new_csrf_token',
                        lambda: 'delegated_token')
    assert web_proxied_session.new_csrf_token() == 'delegated_token'


def test_web_proxied_session_get_csrf_token(web_proxied_session, monkeypatch):
    monkeypatch.setattr(web_proxied_session._delegate,
                        'get_csrf_token',
                        lambda: 'delegated_token')
    assert web_proxied_session.get_csrf_token() == 'delegated_token'


def test_web_proxied_session_flash(web_proxied_session, monkeypatch):
    monkeypatch.setattr(web_proxied_session._delegate,
                        'flash',
                        lambda x, y, z: [x, y, z])
    result = web_proxied_session.flash('message', 'other_q', False)
    assert result == ['message', 'other_q', False]


def test_web_proxied_session_peek_flash(web_proxied_session, monkeypatch):
    monkeypatch.setattr(web_proxied_session._delegate, 'peek_flash', lambda x: x)
    result = web_proxied_session.peek_flash('other_q')
    assert result == 'other_q'


def test_web_proxied_session_pop_flash(web_proxied_session, monkeypatch):
    monkeypatch.setattr(web_proxied_session._delegate, 'pop_flash', lambda x: x)
    result = web_proxied_session.pop_flash('other_q')
    assert result == 'other_q'


def test_web_proxied_recreate_session(web_proxied_session, monkeypatch):
    monkeypatch.setattr(web_proxied_session._delegate, 'recreate_session', lambda: 'recreated')
    result = web_proxied_session.recreate_session()
    assert result == 'recreated'


def test_web_caching_session_store_cache_identifiers_to_key_map(
        web_caching_session_store, mock_web_simple_session, monkeypatch):
    wcss = web_caching_session_store
    mock_cache_handler = mock.MagicMock()
    mock_identifiers = mock.MagicMock(primary_identifier='primary')

    monkeypatch.setattr(wcss, 'cache_handler', mock_cache_handler)
    monkeypatch.setattr(mock_web_simple_session,
                        'get_internal_attribute',
                        lambda x: mock_identifiers)

    wcss._cache_identifiers_to_key_map(mock_web_simple_session, 'simplesessionid123')

    wcss.cache_handler.set.assert_called_once_with(
        domain='session',
        identifier=mock_identifiers.primary_identifier,
        value=WebSessionKey(session_id='simplesessionid123'))


def test_web_caching_session_store_cache_identifiers_to_key_map_raises(
        web_caching_session_store, mock_web_simple_session, monkeypatch, caplog):
    wcss = web_caching_session_store
    mock_cache_handler = mock.MagicMock()

    monkeypatch.setattr(wcss, 'cache_handler', mock_cache_handler)
    monkeypatch.setattr(mock_web_simple_session,
                        'get_internal_attribute',
                        lambda x: 'mock_identifiers')

    wcss._cache_identifiers_to_key_map(mock_web_simple_session, 'simplesessionid123')

    assert 'Could not cache' in caplog.text


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
