from yosai.core import RememberMeSettings
import pytest


@pytest.fixture(scope='function')
def remember_me_settings(settings):
    return RememberMeSettings(settings)
