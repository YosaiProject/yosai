import pytest

from yosai import (
    DefaultSessionSettings,
    DelegatingSession,
    ImmutableProxiedSession,
    ProxiedSession,
    SimpleSession,
)

from .doubles import (
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

@pytest.fixture(scope='module')
def immutable_proxied_session():
    return ImmutableProxiedSession(MockSession())
