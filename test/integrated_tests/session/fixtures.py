import pytest

from yosai_dpcache.cache import DPCacheHandler
from yosai import (
    SessionEventHandler,
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
def session_event_handler():
    eh = SessionEventHandler()
    eh.event_bus = event_bus
    return eh
