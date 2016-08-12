import pytest
from unittest import mock
from pyramid.request import Request
from pyramid_yosai import PyramidWebRegistry

from yosai.web import (
    WebYosai,
)


@pytest.fixture(scope='function')
def pyramid_request():
    return Request()


@pytest.fixture(scope='function')
def mock_request():
    return mock.create_autospec(Request)


@pytest.fixture(scope='function')
def pyramid_web_registry(pyramid_request):
    return PyramidWebRegistry(pyramid_request)


@pytest.fixture(scope='function')
def new_web_subject(web_yosai, web_registry):
    with WebYosai.context(web_yosai, web_registry):
        return WebYosai.get_current_subject()
