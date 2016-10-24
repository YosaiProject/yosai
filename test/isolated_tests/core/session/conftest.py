import pytest

from yosai.core import (
    CachingSessionStore,
    NativeSessionHandler,
    NativeSessionManager,
    DefaultSessionKey,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    # ExecutorServiceSessionValidationScheduler,
    MemorySessionStore,
    SimpleSession,
)

from .doubles import (
    MockNativeSessionManager,
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
def simple_session(mock_serializable):
    ss = SimpleSession(1800000, 600000)
    serializable = mock_serializable('attribute1', 'attribute2', 'attribute3')
    ss.set_attribute('serializable', serializable)
    return ss

@pytest.fixture(scope='function')
def patched_delegating_session():
    return DelegatingSession(MockSessionManager(), 'dumbkey')


@pytest.fixture(scope='function')
def default_native_session_manager(core_settings, event_bus):
    nsm = NativeSessionManager(core_settings)
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
def session_key():
    return DefaultSessionKey('sessionid123')
