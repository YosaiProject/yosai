import pytest

from yosai.core import (
    DefaultSessionKey,
    DefaultNativeSessionManager,
    SessionEventHandler,
    DefaultNativeSessionHandler,
    SimpleSessionFactory,
    CachingSessionStore,
)


@pytest.fixture(scope='function')
def session_store(cache_handler):
    css = CachingSessionStore()
    css.cache_handler = cache_handler
    return css


@pytest.fixture(scope='function')
def session_factory(core_settings):
    return SimpleSessionFactory(core_settings)


@pytest.fixture(scope='function')
def session_key(session):
    return DefaultSessionKey(session.session_id)


@pytest.fixture(scope='function')
def session_event_handler(event_bus):
    eh = SessionEventHandler()
    eh.event_bus = event_bus
    return eh


@pytest.fixture(scope='function')
def session_handler(session_event_handler, session_store):
    handler = DefaultNativeSessionHandler()
    handler.session_event_handler = session_event_handler
    handler.session_store = session_store
    return handler


@pytest.fixture(scope='function')
def session_manager(core_settings, cache_handler, event_bus):
    nsm = DefaultNativeSessionManager(core_settings)
    nsm.apply_cache_handler(cache_handler)
    nsm.apply_event_bus(event_bus)
    return nsm


@pytest.fixture(scope='function')
def session_context():
    return {'host': '127.0.0.1'}


@pytest.fixture(scope='function')
def session(session_factory, session_handler):
    session = session_factory.create_session()
    session_handler.create_session(session)  # obtains a session_id
    return session
