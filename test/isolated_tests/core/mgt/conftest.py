from yosai.core import (
    NativeSecurityManager,
    RememberMeSettings,
)

import pytest

from .doubles import (
    MockRememberMeManager,
)


@pytest.fixture(scope='function')
def remember_me_settings(settings):
    return RememberMeSettings(settings)


@pytest.fixture(scope='function')
def mock_remember_me_manager(settings, attributes_schema):
    return MockRememberMeManager(settings, attributes_schema)
