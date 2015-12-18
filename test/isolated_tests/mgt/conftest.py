from yosai.core import (
    NativeSecurityManager,
)

import pytest

from .doubles import (
    MockRememberMeManager,
)


@pytest.fixture(scope='function')
def native_security_manager(default_accountstorerealm):
    return NativeSecurityManager(realms=(default_accountstorerealm,))


@pytest.fixture(scope='function')
def mock_remember_me_manager():
    return MockRememberMeManager()
