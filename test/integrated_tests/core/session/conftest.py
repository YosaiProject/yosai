import pytest

from yosai.core import (
    DefaultSessionKey,
    NativeSessionManager,
    NativeSessionHandler,
    CachingSessionStore,
)


@pytest.fixture(scope='function')
def session_store(cache_handler):
    css = CachingSessionStore()
    css.cache_handler = cache_handler
    return css



@pytest.fixture(scope='function')
def session_key(session):
    return DefaultSessionKey(session.session_id)


@pytest.fixture(scope='function')
def session_handler(session_store, event_bus):
    handler = NativeSessionHandler()
    handler.session_store = session_store
    handler.event_bus = event_bus
    return handler


@pytest.fixture(scope='function')
def session_manager(core_settings, cache_handler, event_bus):
    nsm = NativeSessionManager(core_settings)
    nsm.apply_cache_handler(cache_handler)
    nsm.apply_event_bus(event_bus)
    return nsm


@pytest.fixture(scope='function')
def session_context():
    return {'host': '127.0.0.1'}


@pytest.fixture(scope='function')
def session(session_manager, session_handler):
    return session_manager._create_session({})
