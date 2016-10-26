from yosai.core import (
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
def mock_remember_me_manager(core_settings, session_attributes):
    return MockRememberMeManager(core_settings, session_attributes)
