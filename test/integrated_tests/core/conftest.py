import pytest
from yosai.core import Yosai


@pytest.fixture(scope='session')
def new_subject():
    return Yosai.get_current_subject()
