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


def test_webyosai_requires_authentication(
        web_yosai, mock_web_registry, monkeypatch, valid_username_password_token):

    # yeah, its a dumb example but I chose the big lebowski cuz I love the movie
    @WebYosai.requires_authentication
    def transport_ransom(the_ringer, destination):
        return 'transported'

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        subject.login(valid_username_password_token)
        result = transport_ransom('the_ringer', 'the_nihilists')
        assert result == 'transported'

        subject.logout()

        with pytest.raises(???):
            transport_ransom('the_ringer', 'the_nihilists')


    """
    A session that absolute timeouts will raise an exception at validation and
    the sessionmanager deletes the expired session from cache.
    """


# def test_webyosai_requires_user

# def test_webyosai_requires_guest

# def test_webyosai_requires_permission
    # perm3 = permission_resolver('leatherduffelbag:transport:theringer')
    # perm4 = permission_resolver('leatherduffelbag:access:theringer')


# def test_webyosai_requires_dynamic_permission

# def tests_webyosai_requires_role
