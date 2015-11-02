import pytest
from unittest import mock
import imp 
import os
import sys

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
    path = os.path.dirname(sys.modules[LazySettings.__module__].__file__)
    return path + "/yosai_settings.yaml"  # within same directory

@pytest.fixture(scope='function')
def settings_fixture(filepath):
    return Settings(filepath)  # COULD mock this instead..

@pytest.fixture(scope='function')
def empty_settings():
    with mock.patch.object(Settings, 'load_config', return_value=None): 
        return Settings()
