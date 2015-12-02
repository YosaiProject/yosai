import pytest

from yosai_dpcache.cache import DPCacheHandler
from yosai import (
    SimpleSessionFactory,
    CachingSessionStore,
)


@pytest.fixture(scope='function')
def cache_handler():
    return DPCacheHandler()


@pytest.fixture(scope='function')
def session_store(cache_handler):
    css = CachingSessionStore()
    css.cache_handler = cache_handler


@pytest.fixture(scope='function')
def session():
    ssf = SimpleSessionFactory()
    return ssf.create_session()
