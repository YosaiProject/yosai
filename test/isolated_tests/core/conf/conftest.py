import pytest
from unittest import mock
import imp
import os
import sys

from yosai.core import (
    LazySettings,
    Settings,
)


@pytest.fixture(scope='function')
def empty():
    return object()


@pytest.fixture(scope='function')
def config():
    return {'ONE': {'one': 1}, 'TWO': {'two': 2}}


@pytest.fixture(scope='function')
def settings_file():
    return os.environ.get('YOSAI_SETTINGS')


@pytest.fixture(scope='function')
def settings_fixture(settings_file):
    return Settings(settings_file)  # COULD mock this instead..


@pytest.fixture(scope='function')
def empty_settings():
    with mock.patch.object(Settings, 'load_config', return_value=None):
        return Settings('')

@pytest.fixture(scope='function')
def lazy_settings():
    return LazySettings('YOSAI_SETTINGS')
