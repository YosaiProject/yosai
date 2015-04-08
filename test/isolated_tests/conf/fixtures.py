import pytest
from unittest import mock

from yosai import (
    LazySettings,
    Settings,
)

@pytest.fixture(scope='function')
def env_var():
    return 'YOSAI_SETTINGS_MODULE'

@pytest.fixture(scope='function')
def empty():
    return object()

@pytest.fixture(scope='function')
def lazy_settings():
    return LazySettings()

@pytest.fixture(scope='function')
def config():
    return {'ONE': {'one': 1}, 'TWO': {'two': 2}}

@pytest.fixture(scope='function')
def filepath():
    return "../../../yosai/conf/yosai_settings.json"

@pytest.fixture(scope='function')
def settings_fixture(filepath):
    return Settings(filepath)

@pytest.fixture(scope='function')
def empty_settings():
    with mock.patch.object(Settings, 'load_config', return_value=None): 
        return Settings()
