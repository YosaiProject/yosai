import pytest

from yosai import (
    AbstractNativeSessionManager,
    DefaultSessionSettings,
    DelegatingSession,
    ImmutableProxiedSession,
    ProxiedSession,
    SimpleSession,
)

from .doubles import (
    MockAbstractNativeSessionManager,
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
