import pytest
from unittest import mock
from yosai import (
    LazySettings,
    FileNotFoundException,
    MisconfiguredException,
    Settings,
)

# LazySettings Tests
def test_get_attr_from_empty_wrapped(lazy_settings):
    # This test confirms that _setup is called during getattr.
    # Initially, wrapped is empty until setup is called.
    getattr(lazy_settings, 'blabla', None)
    assert isinstance(lazy_settings._wrapped, Settings)

def test_set_attr_wrapped(lazy_settings, config):
    lazy_settings._wrapped = config 
    assert lazy_settings._wrapped == config

def test_set_attr_in_existing_wrapped(lazy_settings):
    lazy_settings.something = 'something'
    assert lazy_settings._wrapped.something == 'something'

def test_del_attr_named_wrapped_exception(lazy_settings):
    with pytest.raises(TypeError):
        del lazy_settings._wrapped

def test_del_attr_from_empty_wrapped():
    """
    test case:
    self._wrapped is empty, so trying to delete from it will invoke _setup()

    delete an attribute that doesnt exist, ignoring the exception, and confirm
    that _setup() was called
    """
    lazy_settings = LazySettings()
    with mock.patch.object(LazySettings, '_setup', return_value=None) as setup:
        try:
            del lazy_settings.blabla
        except AttributeError:
            setup.assert_called_once_with()
        
def test_del_attr_from_existing_wrapped(lazy_settings):
    lazy_settings.anything = 'anything'
    del lazy_settings.anything
    assert lazy_settings.anything is None

def test_setup_envvar_exception(monkeypatch, lazy_settings):
    monkeypatch.setattr('yosai.conf.yosaisettings.ENV_VAR', 'blablabla') 
    with pytest.raises(MisconfiguredException):
        lazy_settings._setup()

# Settings Tests
def test_get_config_file_not_exists_exception(empty_settings):
    with pytest.raises(FileNotFoundException):
        empty_settings.get_config('nowhere')

def test_get_config_file_exists(filepath, empty_settings):
    assert empty_settings.get_config(filepath)  # only needs to be True

def test_load_config_with_none_config():
    with mock.patch.object(Settings, 'get_config', return_value=3):
        with pytest.raises(MisconfiguredException):
            assert Settings() 

def test_load_config_with_config(settings_fixture):
    assert settings_fixture
    

