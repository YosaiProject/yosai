import pytest

from yosai.core import (
    CachingSessionStore,
    DefaultNativeSessionManager,
    DefaultSessionKey,
    DefaultSessionSettings,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    ExecutorServiceSessionValidationScheduler,
    MemorySessionStore,
    ProxiedSession,
    SessionEventHandler,
    DefaultNativeSessionHandler,
    SimpleSession,
    event_bus,
)

from .doubles import (
    MockDefaultNativeSessionManager,
    MockAbstractSessionStore,
    MockSessionManager,
)

from ..doubles import (
    MockCacheHandler,
)


@pytest.fixture(scope='function')
def mock_cache_handler():
    return MockCacheHandler()


@pytest.fixture(scope='function')
def default_proxied_session(mock_session):
    return ProxiedSession(mock_session)


@pytest.fixture(scope='function')
def simple_session():
    return SimpleSession(DefaultSessionSettings())


@pytest.fixture(scope='function')
def patched_delegating_session():
    return DelegatingSession(MockSessionManager(), 'dumbkey')


@pytest.fixture(scope='function')
def default_native_session_manager():
    nsm = DefaultNativeSessionManager()
    nsm.event_bus = event_bus
    return nsm


@pytest.fixture(scope='function')
def executor_session_validation_scheduler(patched_abstract_native_session_manager):
    pansm = patched_abstract_native_session_manager
    interval = 360
    return ExecutorServiceSessionValidationScheduler(session_manager=pansm,
                                                     interval=interval)


@pytest.fixture(scope='function')
def mock_abstract_session_store():
    return MockAbstractSessionStore()


@pytest.fixture(scope='function')
def memory_session_store():
    return MemorySessionStore()


@pytest.fixture(scope='function')
def default_session_storage_evaluator():
    return DefaultSessionStorageEvaluator()


@pytest.fixture(scope='function')
def caching_session_store():
    return CachingSessionStore()


@pytest.fixture(scope='function')
def session_event_handler():
    seh = SessionEventHandler()
    seh.event_bus = event_bus
    return seh


@pytest.fixture(scope='function')
def session_handler(session_event_handler):
    return DefaultNativeSessionHandler(session_event_handler=session_event_handler)


@pytest.fixture(scope='function')
def session_key():
    return DefaultSessionKey('sessionid123')
