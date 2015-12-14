import pytest

from yosai.core import (
    NativeSecurityManager,
)


@pytest.fixture(scope='module')
def native_security_manager():
    return NativeSecurityManager()

