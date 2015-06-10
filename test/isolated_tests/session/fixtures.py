import pytest

from yosai import (
    ProxiedSession,
)

from .doubles import (
    MockSession,
)

@pytest.fixture(scope='function')
def mock_session():
    return MockSession()


@pytest.fixture(scope='function')
def default_proxied_session():
    return ProxiedSession(mock_session)
