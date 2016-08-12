from yosai.web import (
    WebYosai,
)
from yosai_alchemystore import AlchemyAccountStore
from yosai_dpcache.cache import DPCacheHandler

import os


def test_create_yosai_instance(monkeypatch, web_yosai):
    """
    Create a new WebYosai instance from env_var settings and from file_path
    settings.  This subsequently creates a configured WebSecurityManager.
    web_yosai is configured using the file_path approach
    """
    current_filepath = os.path.dirname(__file__)
    settings_file = current_filepath + '/../../../yosai_settings.yaml'
    monkeypatch.setenv('TEST_ENV_VAR', settings_file)
    first_yosai = WebYosai(env_var='TEST_ENV_VAR')

    assert first_yosai._security_manager and web_yosai._security_manager


def test_webyosai_security_manager_configuration(web_yosai):
    """
    Assert that upon creation of a new WebYosai instance that the managers
    automatically generated using yaml settings are as expected.
    """

    # using a random sample:
    assert isinstance(web_yosai.security_manager.authorizer.realms[0].account_store,
                      AlchemyAccountStore)
    assert isinstance(web_yosai.security_manager.session_manager.session_handler.cache_handler,
                      DPCacheHandler)
    assert web_yosai.signed_cookie_secret == 'changeme'
