from yosai.core import (
    NativeSecurityManager,
)

import pytest

from .doubles import (
    MockRememberMeManager,
)


@pytest.fixture(scope='session')
def mock_remember_me_manager():
    return MockRememberMeManager()
