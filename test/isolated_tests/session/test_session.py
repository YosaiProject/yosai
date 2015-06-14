import pytest
from unittest import mock

from .doubles import MockSession

from yosai import (
    DefaultSessionSettings,
    ProxiedSession,
)

@pytest.mark.parametrize(
    'field', ['session_id', 'start_timestamp', 'last_access_time', 'timeout', 
              'host', 'attribute_keys'])
def test_ps_getter_confirm(mock_session, default_proxied_session, field):
    """
    unit tested:  ProxiedSession:  every accessor (property) 

    test case:
    confirm that the proxying to delegate is working for every attribute
    """
    ms = mock_session 
    dps = default_proxied_session 
    assert getattr(dps, field) == getattr(ms, field) 

def test_ps_get_attribute(default_proxied_session):
    """
    unit tested:  ProxiedSession.get_attribute

    test case:
    confirm that the proxying to delegate is working for get_attribute 
    """
    dps = default_proxied_session 
    with mock.patch.object(MockSession, 'get_attribute') as ms_ga:
        ms_ga.return_value = None
        dps.get_attribute('attr1')
        assert ms_ga.assert_called_once_with('attr1') is None

def test_ps_set_attribute(default_proxied_session):
    """
    unit tested:  ProxiedSession.set_attribute

    test case:
    confirm that the proxying to delegate is working for set_attribute 
    """
    dps = default_proxied_session 
    with mock.patch.object(MockSession, 'set_attribute') as ms_sa:
        ms_sa.return_value = None
        dps.set_attribute('attrX', 'X')
        assert ms_sa.assert_called_once_with('attrX', 'X') is None

def test_ps_remove_attribute(default_proxied_session):
    """
    unit tested:  ProxiedSession.remove_attribute

    test case:
    confirm that the proxying to delegate is working for remove_attribute 
    """
    dps = default_proxied_session 
    with mock.patch.object(MockSession, 'remove_attribute') as ms_ra:
        ms_ra.return_value = None
        dps.remove_attribute('attr1')
        assert ms_ra.assert_called_once_with('attr1') is None

@pytest.mark.parametrize(
    'attr', ['absolute_timeout', 'idle_timeout', 'validation_scheduler_enable',
             'validation_time_interval'])
def test_default_session_settings(attr):
    dss = DefaultSessionSettings()
    assert getattr(dss, attr) is not None

