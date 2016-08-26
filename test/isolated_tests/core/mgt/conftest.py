from yosai.core import (
    NativeSecurityManager,
    RememberMeSettings,
)

import pytest

from .doubles import (
    MockRememberMeManager,
)


@pytest.fixture(scope='function')
def remember_me_settings(core_settings):
    return RememberMeSettings(core_settings)


@pytest.fixture(scope='function')
def mock_remember_me_manager(core_settings, attributes_schema):
    return MockRememberMeManager(core_settings, attributes_schema)
