import pytest

def test_getattr_with_authc(monkeypatch, authc_settings):
    mock_authc = {'test': 1}
    monkeypatch.setattr(authc_settings, 'default_config', mock_authc)
    assert authc_settings.test == 1 
    
def test_getattr_without_authc_with_default(monkeypatch, authc_settings):
    monkeypatch.setitem(authc_settings.default_config, 'test', 1)
    assert authc_settings.test == 1

def test_getattr_without_authc_without_default(monkeypatch, authc_settings):
    assert authc_settings.test is None 
