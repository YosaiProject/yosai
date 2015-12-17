import pytest

from yosai.core import (
    DefaultNativeSessionManager,
    CachingSessionStore,
    DefaultSessionContext,
    DefaultSessionSettings,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    ExecutorServiceSessionValidationScheduler,
    MemorySessionStore,
    ProxiedSession,
    SimpleSession,
)

from .doubles import (
    MockDefaultNativeSessionManager,
    MockAbstractSessionStore,
    MockCachingSessionStore,
    MockSessionManager,
)

from ..doubles import (
    MockSession,
)

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
def abstract_native_session_manager():
    return MockDefaultNativeSessionManager()


@pytest.fixture(scope='function')
def patched_abstract_native_session_manager(monkeypatch, mock_session):
    ansm = MockDefaultNativeSessionManager()
    monkeypatch.setattr(ansm, 'lookup_required_session', lambda x: mock_session) 
    return ansm


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
def mock_caching_session_store():
    return MockCachingSessionStore()

@pytest.fixture(scope='function')
def default_session_storage_evaluator():
    return DefaultSessionStorageEvaluator()
