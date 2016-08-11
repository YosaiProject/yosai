import pytest
import os
from unittest import mock
from pyramid.request import Request
from pyramid_yosai import PyramidWebRegistry
from yosai.web import (
    WebYosai,
)


@pytest.fixture(scope='function')
def web_yosai():
    current_filepath = os.path.dirname(__file__)
    settings_file = current_filepath + '/yosai_api/yosai_settings.yaml'
    return WebYosai(file_path=settings_file)


@pytest.fixture(scope='function')
def mock_request():
    return mock.create_autospec(Request)


@pytest.fixture(scope='function')
def mock_web_registry():
    return mock.create_autospec(PyramidWebRegistry)


@pytest.fixture(scope='function')
def web_registry(mock_request):
    return PyramidWebRegistry(mock_request)
