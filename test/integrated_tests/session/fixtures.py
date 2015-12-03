import pytest

from yosai_dpcache.cache import DPCacheHandler
from yosai import (
    DefaultSessionKey,
    SessionEventHandler,
    SessionHandler,
    SimpleSessionFactory,
    CachingSessionStore,
    event_bus,
)


@pytest.fixture(scope='function')
def cache_handler():
    return DPCacheHandler()


@pytest.fixture(scope='function')
def session_store(cache_handler):
    css = CachingSessionStore()
    css.cache_handler = cache_handler
    return css


@pytest.fixture(scope='function')
def session():
    ssf = SimpleSessionFactory()
    return ssf.create_session()


@pytest.fixture(scope='function')
def session_key(session):
    return DefaultSessionKey(session.session_id)


@pytest.fixture(scope='function')
def session_event_handler():
    eh = SessionEventHandler()
    eh.event_bus = event_bus
    return eh


@pytest.fixture(scope='function')
def session_handler(session_event_handler):
    return SessionHandler(session_event_handler=session_event_handler,
                          auto_touch=True)
