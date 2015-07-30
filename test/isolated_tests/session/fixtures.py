import pytest

from yosai import (
    AbstractNativeSessionManager,
    AbstractValidatingSessionManager,
    CachingSessionDAO,
    DefaultSessionContext,
    DefaultSessionSettings,
    DelegatingSession,
    ExecutorServiceSessionValidationScheduler,
    ImmutableProxiedSession,
    MemorySessionDAO,
    ProxiedSession,
    SimpleSession,
)

from .doubles import (
    MockAbstractNativeSessionManager,
    MockAbstractSessionDAO,
    MockAbstractValidatingSessionManager,
    MockCachingSessionDAO,
    MockSession,
    MockSessionManager,
)


@pytest.fixture(scope='function')
def mock_session():
    return MockSession()


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
def immutable_proxied_session():
    return ImmutableProxiedSession(MockSession())


# uses patched_event_bus from upper branch
@pytest.fixture(scope='function')
def abstract_native_session_manager(patched_event_bus):
    return MockAbstractNativeSessionManager(event_bus=patched_event_bus)


@pytest.fixture(scope='function')
def patched_abstract_native_session_manager(patched_event_bus, monkeypatch, mock_session):
    ansm = MockAbstractNativeSessionManager(event_bus=patched_event_bus)
    monkeypatch.setattr(ansm, 'lookup_required_session', lambda x: mock_session) 
    return ansm


@pytest.fixture(scope='function')
def executor_session_validation_scheduler(patched_abstract_native_session_manager):
    pansm = patched_abstract_native_session_manager
    interval = 360
    return ExecutorServiceSessionValidationScheduler(session_manager=pansm, 
                                                     interval=interval) 

@pytest.fixture(scope='function')
def abstract_validating_session_manager(patched_event_bus):
    return MockAbstractValidatingSessionManager(patched_event_bus)


@pytest.fixture(scope='function')
def default_session_context():
    return DefaultSessionContext(context_map={'attr1': 'attributeOne',
                                              'attr2': 'attributeTwo',
                                              'attr3': 'attributeThree'})

@pytest.fixture(scope='function')
def mock_abstract_session_dao():
    return MockAbstractSessionDAO()

@pytest.fixture(scope='function')
def memory_session_dao():
    return MemorySessionDAO()

@pytest.fixture(scope='function')
def mock_caching_session_dao():
    return MockCachingSessionDAO()
