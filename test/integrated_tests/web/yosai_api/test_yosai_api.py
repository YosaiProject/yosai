import pdb

from yosai.core.subject.subject import global_subject_context, global_yosai_context
from yosai.web.subject.subject import global_webregistry_context

from yosai.web import (
    WebYosai,
)
from yosai_alchemystore import AlchemyAccountStore
from yosai_dpcache.cache import DPCacheHandler

import os
import pytest
from unittest import mock


def test_create_yosai_instance(monkeypatch, web_yosai):
    """
    Create a new WebYosai instance from env_var settings and from file_path
    settings.  This subsequently creates a configured WebSecurityManager.
    web_yosai is configured using the file_path approach
    """
    current_filepath = os.path.dirname(__file__)
    settings_file = current_filepath + '/yosai_settings.yaml'
    monkeypatch.setenv('TEST_ENV_VAR', settings_file)
    first_yosai = WebYosai(env_var='TEST_ENV_VAR')

    assert first_yosai._security_manager and web_yosai._security_manager


def test_security_manager_configuration(web_yosai):
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


def test_web_context(web_yosai, web_registry):
    """
    When entering a new WebYosai context, a yosai instance is pushed onto a yosai_context
    stack and a web_registry is pushed onto a yosai_webregistry_context stack.
    When closing the context: the pushed yosai instance is popped from the
    yosai_context stack, the pushed web_registry is popped from the
    yosai_webregistry_context, and the current executing subject is popped
    from the global_subject_context stack.

    elements tested include:
        get_current_yosai
        get_current_webregistry
        get_current_subject
    """
    # first ensure that the threadlocal is empty
    assert (global_subject_context.stack == [] and
            global_yosai_context.stack == [] and
            global_webregistry_context.stack == [])

    with WebYosai.context(web_yosai, web_registry):
        assert (global_subject_context.stack == [] and
                global_yosai_context.stack == [web_yosai] and
                global_webregistry_context.stack == [web_registry])

    # this tests context exit
    assert (global_subject_context.stack == [] and
            global_yosai_context.stack == [] and
            global_webregistry_context.stack == [])


def test_requires_authentication_succeeds(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(authenticated=True)

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_authentication
    def do_this():
        return 'dothis'

    result = do_this()

    assert result == 'dothis'


def test_requires_authentication_raises(monkeypatch):
    """
    This test verifies that the decorator works as expected.
    """
    @staticmethod
    def mock_gcs():
        return mock.MagicMock(authenticated=False)

    @staticmethod
    def mock_cwr():
        m = mock.MagicMock()
        m.raise_unauthorized.return_value = Exception
        return m

    monkeypatch.setattr(WebYosai, 'get_current_subject', mock_gcs)
    monkeypatch.setattr(WebYosai, 'get_current_webregistry', mock_cwr)

    @WebYosai.requires_authentication
    def do_this():
        return 'dothis'

    with pytest.raises(Exception):
        do_this()


#def test_requires_user
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_guest
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_permission
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_dynamic_permission
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """

#def test_requires_role
    """
    This test verifies that the decorator works as expected.
    Two parametrized tests:  one that succeeds and another that fails
    """
