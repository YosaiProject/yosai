import pytest

from yosai.core import (
    NativeSessionManager,
    SessionKey,
    SessionStorageEvaluator,
    DelegatingSession,
    # ExecutorServiceSessionValidationScheduler,
    MemorySessionStore,
    SimpleSession,
)

from .doubles import (
    MockAbstractSessionStore,
)

from ..doubles import (
    MockCacheHandler,
)


@pytest.fixture(scope='function')
def mock_cache_handler():
    return MockCacheHandler()


@pytest.fixture(scope='function')
def simple_session(mock_serializable):
    ss = SimpleSession(1800000, 600000)
    serializable = mock_serializable('attribute1', 'attribute2', 'attribute3')
    ss.set_attribute('serializable', serializable)
    return ss


@pytest.fixture(scope='function')
def default_native_session_manager(core_settings, event_bus):
    nsm = NativeSessionManager(core_settings)
    nsm.event_bus = event_bus
    return nsm


@pytest.fixture(scope='function')
def mock_abstract_session_store():
    return MockAbstractSessionStore()


@pytest.fixture(scope='function')
def memory_session_store():
    return MemorySessionStore()


@pytest.fixture(scope='function')
def default_session_storage_evaluator():
    return SessionStorageEvaluator()


@pytest.fixture(scope='function')
def session_key():
    return SessionKey('sessionid123')


@pytest.fixture(scope='function')
def patched_delegating_session(session_key, default_native_session_manager):
    return DelegatingSession(default_native_session_manager, session_key)
