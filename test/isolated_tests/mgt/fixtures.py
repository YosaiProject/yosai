from yosai import (
    DefaultSecurityManager,
)

import pytest


@pytest.fixture(scope='function')
def default_security_manager():
    return DefaultSecurityManager()

