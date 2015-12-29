import pytest

from yosai.core import (
    DefaultSessionKey,
    DefaultSessionContext,
    DefaultNativeSessionManager,
    SessionEventHandler,
    DefaultNativeSessionHandler,
    SimpleSessionFactory,
    CachingSessionStore,
    event_bus,
)


@pytest.fixture(scope='function')
def session_store(cache_handler):
    css = CachingSessionStore()
    css.cache_handler = cache_handler
    return css


@pytest.fixture(scope='function')
def session_factory():
    return SimpleSessionFactory()


@pytest.fixture(scope='function')
def session_key(session):
    return DefaultSessionKey(session.session_id)


@pytest.fixture(scope='function')
def session_event_handler():
    eh = SessionEventHandler()
    eh.event_bus = event_bus
    return eh


@pytest.fixture(scope='function')
def session_handler(session_event_handler, session_store):
    handler = DefaultNativeSessionHandler(session_event_handler=session_event_handler,
                                          auto_touch=True)
    handler.session_store = session_store
    return handler

@pytest.fixture(scope='function')
def session_manager():
    return DefaultNativeSessionManager()


@pytest.fixture(scope='function')
def session_context():
    sc = DefaultSessionContext()
    sc.host = '127.0.0.1'
    return sc


@pytest.fixture(scope='function')
def session(session_factory, session_handler):
    session = session_factory.create_session()
    session_handler.create_session(session)  # obtains a session_id
    return session

