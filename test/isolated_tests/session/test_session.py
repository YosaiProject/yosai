import pytest
from unittest import mock
import datetime

from .doubles import MockSession

from yosai import (
    DefaultSessionSettings,
    ExpiredSessionException,
    IllegalStateException,
    ProxiedSession,
    SimpleSession,
    StoppedSessionException,
)

# ----------------------------------------------------------------------------
# SessionSettings
# ----------------------------------------------------------------------------

def test_create_session_settings():
    """
    unit tested:  __init__

    test case:
    basic code path exercise, ensuring object instantiation
    """
    dss = DefaultSessionSettings()
    assert hasattr(dss, 'absolute_timeout') and hasattr(dss, 'idle_timeout')

# ----------------------------------------------------------------------------
# ProxiedSession
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    'field', ['session_id', 'start_timestamp', 'last_access_time', 
              'idle_timeout', 'absolute_timeout', 'host', 'attribute_keys'])
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
        ms_ga.assert_called_once_with('attr1')

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
        ms_sa.assert_called_once_with('attrX', 'X')

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
        ms_ra.assert_called_once_with('attr1')

@pytest.mark.parametrize(
    'attr', ['absolute_timeout', 'idle_timeout', 'validation_scheduler_enable',
             'validation_time_interval'])
def test_default_session_settings(attr):
    dss = DefaultSessionSettings()
    assert getattr(dss, attr) is not None

# ----------------------------------------------------------------------------
# SimpleSession
# ----------------------------------------------------------------------------

def test_ss_stop_updates_timestamp(simple_session):
    """
    unit tested:  stop
    
    test case:
    stop updates the stop_timestamp when a session has not yet stopped
    """
    ss = simple_session
    ss.stop()
    assert ss.stop_timestamp
    
def test_ss_stop_doesnt_update_timestamp(simple_session):
    """
    unit tested:  stop
    
    test case:
    stop does not update the stop_timestamp after a session has already stopped
    """
    ss = simple_session
    ss.stop()
    st = ss.stop_timestamp
    ss.stop()
    assert ss.stop_timestamp == st

def test_ss_expire(simple_session):
    """
    unit test:  expire

    test case:
    expire() invokes stop and sets the expired attribute to True
    """
    ss = simple_session
    ss.expire()
    assert ss.stop_timestamp and ss.is_expired


@pytest.mark.parametrize(
    'is_stopped,is_expired,check', 
    [(True, True, False), (True, None, False), (False, True, False), 
     (None, None, True)])
def test_ss_is_valid(
        simple_session, is_stopped, is_expired, check, monkeypatch): 
    """
    unit tested:  is_valid

    test case:
    to be valid, neither is_stopped nor is_expired are true

    I arbitrarily assign a bool to the stop_timestamp since it suffices
    """
    ss = simple_session
    monkeypatch.setattr(ss, '_stop_timestamp', is_stopped)
    monkeypatch.setattr(ss, '_is_expired', is_expired)
    assert ss.is_valid() == check 


# see docstring below for more information about these parameters:
@pytest.mark.parametrize(
    ('is_expired,absolute_timeout,idle_timeout,last_access_time,start_timestamp,timedout'),
    [(True, None, None, None, None, True),
     (False, datetime.timedelta(minutes=60), None, 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=3), 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=120), True),
     (False, None, datetime.timedelta(minutes=15), 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=20), 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=30), True),
     (False, datetime.timedelta(minutes=60), datetime.timedelta(minutes=15), 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=1), 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=5),
      False),
     (False, None, None, 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=1), 
      datetime.datetime.utcnow() - datetime.timedelta(minutes=5), False)])
def test_ss_is_timed_out(
        simple_session, is_expired, absolute_timeout, 
        idle_timeout, last_access_time, start_timestamp, timedout,
        monkeypatch):
    """
    unit tested:  is_timed_out

    test case:
            is_timed_out()=True:
            ----------------------
            expired:
         I) expired = True, rest is None 

            absolute timeout:
        II) expired = False, absolute_timeout = 1hour, idle_timeout=None
            start_timestamp = currenttime-2hours, rest is arbitrary

            inactive timeout:
       III) expired = False, absolute_timeout = None, idle_timeout = 15min, 
            start_timestamp = currenttime, last_access_time=current-30minutes
     

            is_timed_out()=False:
            ----------------------
            not idle nor beyond absolute:
        IV) expired = False, absolute_timeout = 1hr, idle_timeout = 15min, 
            start_timestamp = currenttime-5, last_access_time=current-1minutes

            not expired, neither timeout set: 
        V)  expired = False, absolute_timeout = None, idle_timeout = None, 
            rest is None
    """
    ss = simple_session

    monkeypatch.setattr(ss, '_is_expired', is_expired)
    monkeypatch.setattr(ss, '_absolute_timeout', absolute_timeout) 
    monkeypatch.setattr(ss, '_idle_timeout', idle_timeout) 
    monkeypatch.setattr(ss, '_last_access_time', last_access_time) 
    monkeypatch.setattr(ss, '_start_timestamp', start_timestamp)
   
    assert ss.is_timed_out() == timedout


@pytest.mark.parametrize(
    ('is_expired,absolute_timeout,idle_timeout,last_access_time,start_timestamp,timedout'),
    [(False, datetime.timedelta(minutes=60), datetime.timedelta(minutes=15),
      None, None, False)])
def test_ss_is_timed_out_raises(
        simple_session, is_expired, absolute_timeout, 
        idle_timeout, last_access_time, start_timestamp, timedout,
        monkeypatch):

    ss = simple_session
    monkeypatch.setattr(ss, '_is_expired', is_expired)
    monkeypatch.setattr(ss, '_absolute_timeout', absolute_timeout) 
    monkeypatch.setattr(ss, '_idle_timeout', idle_timeout) 
    monkeypatch.setattr(ss, '_last_access_time', last_access_time) 
    monkeypatch.setattr(ss, '_start_timestamp', start_timestamp)
   
    with pytest.raises(IllegalStateException):
        ss.is_timed_out()


def test_ss_validate_stopped(simple_session, monkeypatch):
    """
    unit tested:  validate

    test case:
    a stopped session raises an exception in validate
    """
    ss = simple_session
    monkeypatch.setattr(ss, '_stop_timestamp', datetime.datetime.utcnow())

    with pytest.raises(StoppedSessionException):
        ss.validate()


def test_ss_validate_not_timedout(simple_session, monkeypatch):
    """
    unit test:  validate

    test case:
    if not yet timed out, validate returns None      
    """
    ss = simple_session
    monkeypatch.setattr(ss, 'is_timed_out', lambda: False)
    assert ss.validate() is None


def test_ss_validate_is_timedout(simple_session, monkeypatch):
    """
    unit tested:  validate

    test case:
    if not yet stopped but timed out, expired is called and exception is raised
    """
    ss = simple_session
    monkeypatch.setattr(ss, 'is_timed_out', lambda: True) 
    
    with pytest.raises(ExpiredSessionException) as exc_info:
        ss.validate()

    assert 'set to' in str(exc_info.value) 


@pytest.mark.parametrize('attributes,expected', 
                         [(None, {}), ({'attr1': 1}, {'attr1': 1})])
def test_get_attributes_lazy(simple_session, attributes, expected, monkeypatch):
    """
    unit tested:  get_attributes_lazy

    test case:
    assigns and returns an empty dict, else the existing dict
    """
    ss = simple_session
    monkeypatch.setattr(ss, '_attributes', attributes)
    assert ss.get_attributes_lazy() == expected

    
@pytest.mark.parametrize('attributes,key,expected', 
                         [(None, 'attr1', None), 
                          ({'attr1': 'number1'}, 'attr1', 'number1')])
def test_get_attribute(simple_session, attributes, key, expected, monkeypatch):
    """
    unit tested:  get_attribute

    test case:
    returns None either when no attributes or when key doesn't exist
    """
    ss = simple_session
    monkeypatch.setattr(ss, '_attributes', attributes)
    assert ss.get_attribute(key) == expected

def test_set_attribute_removes(simple_session, monkeypatch):
    """
    unit tested:  set_attribute

    test case:
    setting an attribute without a value will remove the attribute
    """
    ss = simple_session
    attributes = {'attr1': 'attr1', 'attr2': 'attr2'}
    monkeypatch.setattr(ss, '_attributes', attributes)
    ss.set_attribute('attr1')
    assert ss.attributes.get('attr1', 'nope') == 'nope' 

def test_set_attribute_adds(simple_session, monkeypatch):
    """
    unit tested:  set_attribute

    test case:
    setting an attribute adds or overrides existing attribute 
    """
    ss = simple_session
    attributes = {'attr1': 'attr1', 'attr2': 'attr2'}
    monkeypatch.setattr(ss, '_attributes', attributes)
    ss.set_attribute('attr1')
    assert ss.attributes.get('attr1', 'nope') == 'nope' 
