import pytest
from unittest import mock
import datetime

from .doubles import (
    MockAbstractNativeSessionManager,
    MockSession,
    MockSessionManager,
)

from yosai import (
    DefaultSessionSettings,
    DefaultSessionKey,
    DelegatingSession,
    EventBus,
    ExpiredSessionException,
    SessionEventException,
    StoppedSessionException,
    IllegalStateException,
    ImmutableProxiedSession,
    InvalidSessionException,
    ProxiedSession,
    SimpleSession,
    RandomSessionIDGenerator,
    UUIDSessionIDGenerator,
    UnknownSessionException,
    SimpleSessionFactory,
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
def test_ss_get_attributes_lazy(simple_session, attributes, expected, monkeypatch):
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
def test_ss_get_attribute(simple_session, attributes, key, expected, monkeypatch):
    """
    unit tested:  get_attribute

    test case:
    returns None either when no attributes or when key doesn't exist
    """
    ss = simple_session
    monkeypatch.setattr(ss, '_attributes', attributes)
    assert ss.get_attribute(key) == expected

def test_ss_set_attribute_removes(simple_session, monkeypatch):
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

def test_ss_set_attribute_adds(simple_session, monkeypatch):
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


@pytest.mark.parametrize('attributes,key,expected', 
                         [(None, 'attr2', None),
                          ({'attr1': 100, 'attr2': 200}, 'attr2', 200)])
def test_ss_remove_attribute(simple_session, monkeypatch, attributes, 
                             key, expected): 
    """
    unit tested: remove_attribute
    
    test case:
    remove an attribute, if attributes exists, else None
    """
    ss = simple_session
    monkeypatch.setattr(ss, '_attributes', attributes)
    assert ss.remove_attribute(key) == expected 


def test_ss_eq_clone():
    """
    unit tested: 
    
    test case:
      other is a clone of self
   """
    s1 = SimpleSession()
    s1._is_expired = False
    s1.session_id = 'sessionid123'
    s1._absolute_timeout = datetime.timedelta(minutes=60)
    s1._idle_timeout = datetime.timedelta(minutes=15)
    s1._last_access_time = datetime.datetime(2011, 1, 1, 11, 17, 10, 101011) 
    s1._start_timestamp = datetime.datetime(2011, 1, 1, 11, 11, 11, 101011) 
    s1._host = '127.0.0.1'
    s1._attributes = {'attr1': 100, 'attr2': 200}
   
    s2 = SimpleSession()
    s2.session_id = 'sessionid123'
    s2._is_expired = False
    s2._absolute_timeout = datetime.timedelta(minutes=60)
    s2._idle_timeout = datetime.timedelta(minutes=15)
    s2._last_access_time = datetime.datetime(2011, 1, 1, 11, 17, 10, 101011) 
    s2._start_timestamp = datetime.datetime(2011, 1, 1, 11, 11, 11, 101011) 
    s2._host = '127.0.0.1'
    s2._attributes = {'attr1': 100, 'attr2': 200}
  
    assert s1 == s2


def test_ss_eq_different_values():
    """
    unit tested: 
    
    test case:
    other has different attribute values than self
   """
    s1 = SimpleSession()
    s1.session_id = 'sessionid123'
    s1._is_expired = False
    s1._absolute_timeout = datetime.timedelta(minutes=60)
    s1._idle_timeout = datetime.timedelta(minutes=25)
    s1._last_access_time = datetime.datetime(2014, 4, 1, 11, 17, 10, 101011) 
    s1._start_timestamp = datetime.datetime(2014, 4, 1, 11, 11, 11, 101011) 
    s1._host = '192.168.1.1'
    s1._attributes = {'attr3': 100, 'attr4': 200}
   
    s2 = SimpleSession()
    s2.session_id = 'sessionid345'
    s2._is_expired = False
    s2._absolute_timeout = datetime.timedelta(minutes=60)
    s2._idle_timeout = datetime.timedelta(minutes=15)
    s2._last_access_time = datetime.datetime(2011, 1, 1, 11, 17, 10, 101011) 
    s2._start_timestamp = datetime.datetime(2011, 1, 1, 11, 11, 11, 101011) 
    s2._host = '127.0.0.1'
    s2._attributes = {'attr1': 100, 'attr2': 200}
  
    assert not s1 == s2

def test_ss_eq_different_attributes():
    """
    unit tested: 
    
    test case:
    other does not have same attributes as self
   """
    s1 = SimpleSession()
    s1.session_id = 'session242'
    s1._is_expired = False
    s1._absolute_timeout = datetime.timedelta(minutes=60)
    s1._idle_timeout = datetime.timedelta(minutes=15)
    s1._last_access_time = datetime.datetime(2011, 1, 1, 11, 17, 10, 101011) 
    s1._start_timestamp = datetime.datetime(2011, 1, 1, 11, 11, 11, 101011) 
    s1._host = '127.0.0.1'
    s1._attributes = {'attr1': 100, 'attr2': 200}
   
    s2 = SimpleSession()
    s2._is_expired = False
    s2._absolute_timeout = datetime.timedelta(minutes=60)
    s2._idle_timeout = datetime.timedelta(minutes=15)
    s2._attributes = {'attr1': 100, 'attr2': 200}
  
    assert not s1 == s2

# ----------------------------------------------------------------------------
# SimpleSessionFactory 
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    'context,expected',
    [(type('SessionContext', (object,), {'host': '123.456.789.10'})(),
      '123.456.789.10'),
     (type('SessionContext', (object,), {})(), None), (None, None)])
def test_ssf_create_session(context, expected):
    """
    unit tested:  create_session

    test case:
      I) a context with a host 
     II) a context without a host
    III) no context
    """
    session = SimpleSessionFactory.create_session(session_context=context)
    assert session.host == expected 

# ----------------------------------------------------------------------------
# UUIDSessionIdGenerator 
# ----------------------------------------------------------------------------

def test_uuid_sig_generates():
    """
    unit tested: generate_id

    test case:
    calling generate_id returns a string
    """
    sid_gen = UUIDSessionIDGenerator
    result = sid_gen.generate_id('arbitraryvalue')
    assert isinstance(result, str)

# ----------------------------------------------------------------------------
# RandomSessionIdGenerator 
# ----------------------------------------------------------------------------

def test_random_sig_generates():
    """
    unit tested: generate_id

    test case:
    calling generate_id returns a string
    """
    sid_gen = RandomSessionIDGenerator
    result = sid_gen.generate_id('arbitraryvalue')
    assert isinstance(result, str)


# ----------------------------------------------------------------------------
# DelegatingSession 
# ----------------------------------------------------------------------------

def test_ds_start_timestamp_not_exists(patched_delegating_session):
    """
    unit tested:  start_timestamp

    test case:  since there is no start_timestamp set, it delegates to the sm
    """
    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'get_start_timestamp') as msm:
        msm.return_value = None
        pds.start_timestamp 
        msm.assert_called_once_with(pds.key)

def test_ds_start_timestamp_exists(
        patched_delegating_session, monkeypatch):
    """
    unit tested:  start_timestamp

    test case:
    since the start_timestamp is set for the pds, it is used
    """
    pds = patched_delegating_session

    dumbdate = datetime.datetime(2013, 3, 3, 3, 33, 33, 333333)
    monkeypatch.setattr(pds, '_start_timestamp', dumbdate)
    assert pds.start_timestamp == dumbdate 

def test_ds_last_access_time(patched_delegating_session):
    """
    unit tested:  last_access_time

    test case:  delegates the request to the MockSessionManager 
    """
    pds = patched_delegating_session
    result = pds.last_access_time

    # verifeis a pre-defined result from the mock
    assert result == datetime.datetime(2015, 1, 2, 12, 34, 59, 111111) 


def test_ds_get_idle_timeout(patched_delegating_session):
    """
    unit tested: idle_timeout

    test case: delegates the request to the MockSessionManager 
    """
    pds = patched_delegating_session
    result = pds.idle_timeout
    assert result == datetime.timedelta(minutes=15)

def test_ds_set_idle_timeout(patched_delegating_session):
    """
    unit tested: idle_timeout

    test case: delegates the request to the MockSessionManager 
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'set_idle_timeout') as msm_sit:
        msm_sit.return_value = None
        now = datetime.datetime.utcnow()
        pds.idle_timeout = now 
        msm_sit.assert_called_once_with(pds.key, now)

def test_ds_get_absolute_timeout(patched_delegating_session):
    """
    unit tested: absolute_timeout

    test case: delegates the request to the MockSessionManager 
    """
    pds = patched_delegating_session
    result = pds.absolute_timeout
    assert result == datetime.timedelta(minutes=60)

def test_ds_set_absolute_timeout(patched_delegating_session):
    """
    unit tested: absolute_timeout

    test case: delegates the request to the MockSessionManager 
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'set_absolute_timeout') as msm_sit:
        msm_sit.return_value = None
        now = datetime.datetime.utcnow()
        pds.absolute_timeout = now 
        msm_sit.assert_called_once_with(pds.key, now)

def test_ds_host_not_exists(patched_delegating_session):
    """
    unit tested:  host 

    test case:  there is no host set, so delegates to the sm
    """
    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'get_host') as msm_gh:
        msm_gh.return_value = None
        pds.host
        msm_gh.assert_called_once_with(pds.key)

def test_ds_host_exists(
        patched_delegating_session, monkeypatch):
    """
    unit tested:  host 

    test case:
    host is monkeypatch-set for the pds, and so it gets used
    """
    pds = patched_delegating_session

    dumbhost = '127.0.0.1'
    monkeypatch.setattr(pds, '_host', dumbhost)
    assert pds.host == dumbhost 

def test_ds_touch(patched_delegating_session):
    """
    unit tested: touch 

    test case: delegates the request to the MockSessionManager 
    """
    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'touch') as msm_touch:
        msm_touch.return_value = None
        pds.touch()
        msm_touch.assert_called_once_with(pds.key)

def test_ds_stop(patched_delegating_session):
    """
    unit tested:  stop 

    test case: 
    delegates the request to the MockSessionManager 
    """
    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'stop') as msm_stop:
        msm_stop.return_value = None
        pds.stop()
        msm_stop.assert_called_once_with(pds.key)

def test_ds_attribute_keys(patched_delegating_session):
    """
    unit tested:  attribute_keys

    test case:
    delegates the request to the MockSessionManager 
    """

    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'get_attribute_keys') as gak: 
        gak.return_value = None
        pds.attribute_keys
        gak.assert_called_once_with(pds.key)

def test_ds_get_attribute(patched_delegating_session):
    """
    unit tested:  get_attribute 

    test case:
    delegates the request to the MockSessionManager 
    """

    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'get_attribute') as ga:
        ga.return_value = None
        pds.get_attribute('attributekey')
        ga.assert_called_once_with(pds.key, 'attributekey')

def test_ds_set_attribute_removes(patched_delegating_session):
    """
    unit tested:  set_attribute 

    test case:
    value is None, and so remove_attribute is called 
    """
    pds = patched_delegating_session

    with mock.patch.object(DelegatingSession, 'remove_attribute') as ds_ra:
        ds_ra.return_value = None
        pds.set_attribute('attributekey')
        ds_ra.assert_called_once_with('attributekey')

def test_ds_set_attribute_delegates(patched_delegating_session):
    """
    unit tested:  set_attribute 

    test case:
    delegates to the MockSessionManager 
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'set_attribute') as msm_sa: 
        msm_sa.return_value = None
        pds.set_attribute('attributekey', 'value')
        msm_sa.assert_called_once_with(pds.key, 'attributekey', 'value')

def test_ds_remove_attribute_delegates(patched_delegating_session):
    """
    unit tested:  remove_attribute 

    test case:
    delegates to the MockSessionManager 
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'remove_attribute') as msm_ra: 
        msm_ra.return_value = None
        pds.remove_attribute('attributekey')
        msm_ra.assert_called_once_with(pds.key, 'attributekey')


# ----------------------------------------------------------------------------
# ImmutableProxiedSession 
# ----------------------------------------------------------------------------

def test_ips_set_idle_timeout(immutable_proxied_session):
    """
    unit tested:  set_idle_timeout 

    test case:
    method call raises exception
    """
    ips = immutable_proxied_session 
    with pytest.raises(InvalidSessionException):
        ips.set_idle_timeout('anything')

def test_ips_set_absolute_timeout(immutable_proxied_session):
    """
    unit tested:  set_absolute_timeout 

    test case:
    method call raises exception
    """
    ips = immutable_proxied_session 
    with pytest.raises(InvalidSessionException):
        ips.set_absolute_timeout('anything')

def test_ips_touch(immutable_proxied_session):
    """
    unit tested:  touch 

    test case:
    method call raises exception
    """
    ips = immutable_proxied_session 
    with pytest.raises(InvalidSessionException):
        ips.touch()

def test_ips_stop(immutable_proxied_session):
    """
    unit tested:  stop 

    test case:
    method call raises exception
    """
    ips = immutable_proxied_session 
    with pytest.raises(InvalidSessionException):
        ips.stop()

def test_ips_set_attribute(immutable_proxied_session):
    """
    unit tested:  set_attribute 

    test case:
    method call raises exception
    """
    ips = immutable_proxied_session 
    with pytest.raises(InvalidSessionException):
        ips.set_attribute('key', 'value')

def test_ips_remove_attribute(immutable_proxied_session):
    """
    unit tested:  remove_attribute 

    test case:
    method call raises exception
    """
    ips = immutable_proxied_session 
    with pytest.raises(InvalidSessionException):
        ips.remove_attribute('key')


# ----------------------------------------------------------------------------
# DefaultSessionKey 
# ----------------------------------------------------------------------------
@pytest.mark.parametrize('first,second,boolcheck',
                         [('sessionid123', 'sessionid123', True),
                          ('sessionid123', 'sessionid345', False),
                          ('sessionid123', None, False),
                          (None, 'sessionid123', False)])
def test_dsk_eq(first, second, boolcheck):
    """
    unit tested:  __eq__

    test case:
    equality based on session_id
    """
    dsk1 = DefaultSessionKey(session_id=first)
    dsk2 = DefaultSessionKey(session_id=second)
    assert (dsk1 == dsk2) == boolcheck


# ----------------------------------------------------------------------------
# AbstractNativeSessionManager 
# ----------------------------------------------------------------------------

def test_ansm_publish_event_succeeds(abstract_native_session_manager):
    """
    unit tested:  publish_event

    test case:  successful publish of event to event bus
    """
    ansm = abstract_native_session_manager
    with mock.patch.object(EventBus, 'publish') as meb_pub:
        meb_pub.return_value = None
        ansm.publish_event('dumbevent')
        meb_pub.assert_called_once_with('dumbevent')

def test_ansm_publish_event_fails(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  publish_event

    test case: 
    when no event_bus is set, raises an exception 
    """
    ansm = abstract_native_session_manager
    monkeypatch.delattr(ansm, '_event_bus')
    with pytest.raises(SessionEventException):
        ansm.publish_event('dumbevent')

def test_ansm_start(abstract_native_session_manager, monkeypatch):
    """
    unit tested:  start 

    test case:
    start calls other methods and doesn't compute anything on its own so 
    not much to test here other than to exercise the code path
    """
    ansm = abstract_native_session_manager
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    monkeypatch.setattr(ansm, 'create_session', lambda x: dumbsession) 
    monkeypatch.setattr(ansm, 'apply_session_timeouts', lambda x: None)
    monkeypatch.setattr(ansm, 'on_start', lambda x, y: None)
    monkeypatch.setattr(ansm, 'notify_start', lambda x: None)
    monkeypatch.setattr(ansm, 'create_exposed_session', lambda x, y: dumbsession)

    result = ansm.start('session_context')
    assert result == dumbsession 

def test_ansm_apply_session_timeouts(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  apply_session_timeouts 

    test case:
    confirms that the timeout attributes are set in the session object and 
    that on_change is called
    """
    ansm = abstract_native_session_manager
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        ansm.apply_session_timeouts(dumbsession)
        assert (mocky.called and 
                dumbsession.absolute_timeout and 
                dumbsession.idle_timeout)

def test_ansm_get_session_locates(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested: get_session 

    test case:
    lookup_session returns a session, and so create_exposed_session is called
    with it
    """
    ansm = abstract_native_session_manager
    monkeypatch.setattr(ansm, 'lookup_session', lambda x: 'session')
    monkeypatch.setattr(ansm, 'create_exposed_session', lambda x, y: 'ces')
    
    results = ansm.get_session('key')

    assert results == 'ces'  # asserts that it was called
    
def test_ansm_get_session_doesnt_locate(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  get_session

    test case:
    lookup session fails to locate a session and so None is returned
    """
    ansm = abstract_native_session_manager

    monkeypatch.setattr(ansm, 'lookup_session', lambda x: None) 
    results = ansm.get_session('key')

    assert results is None
    
def test_ansm_lookup_session(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  lookup_session

    test case:
    a basic code path exercise confirming that do_get_session is called 
    """
    ansm = abstract_native_session_manager

    monkeypatch.setattr(ansm, 'do_get_session', lambda x: 'dgs_called') 
    results = ansm.lookup_session('key')

    assert results == 'dgs_called'

def test_ansm_lookup_required_session_locates(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  lookup_required_session

    test case:
    lookup_session finds and returns a session
    """
    ansm = abstract_native_session_manager

    monkeypatch.setattr(ansm, 'lookup_session', lambda x: 'session')
    results = ansm.lookup_required_session('key')
    assert results == 'session'  # asserts that it was called
  
def test_ansm_lookup_required_session_failstolocate(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  lookup_required_session

    test case:
    lookup_session fails to locate a session, raising an exception instead 
    """
    ansm = abstract_native_session_manager

    monkeypatch.setattr(ansm, 'lookup_session', lambda x: None) 
    with pytest.raises(UnknownSessionException):
        ansm.lookup_required_session('key')

def test_ansm_create_exposed_session(abstract_native_session_manager):
    """
    unit tested:  create_exposed_session 

    test case:
    basic codepath exercise
    """
    ansm = abstract_native_session_manager
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    result = ansm.create_exposed_session(dumbsession)
    assert isinstance(result, DelegatingSession)

def test_ansm_before_invalid_notification(abstract_native_session_manager):
    """
    unit tested:  before_invalid_notification 

    test case:
    basic codepath exercise
    """
    ansm = abstract_native_session_manager
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    result = ansm.before_invalid_notification(dumbsession)
    assert isinstance(result, ImmutableProxiedSession)

def test_ansm_notify_start(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  notify_start 

    test case:
    iterates through the list of listeners, calling each's on_start
    """
    ansm = abstract_native_session_manager
    mocklist = [mock.MagicMock(), mock.MagicMock()]
    monkeypatch.setattr(ansm, 'listeners', mocklist)
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    ansm.notify_start(dumbsession)
    results = (mocklist[0].on_start.called and mocklist[1].on_start.called)
    assert results

def test_ansm_notify_stop(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  notify_stop

    test case:
    iterates through the list of listeners, calling each's on_stop
    """
    ansm = abstract_native_session_manager
    mocklist = [mock.MagicMock(), mock.MagicMock()]
    monkeypatch.setattr(ansm, 'listeners', mocklist)
    monkeypatch.setattr(ansm, 'before_invalid_notification', lambda x: 'bla')
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    ansm.notify_stop(dumbsession)
    results = (mocklist[0].on_stop.called and mocklist[1].on_stop.called)
    assert results

def test_ansm_notify_expiration(
        abstract_native_session_manager, monkeypatch):
    """
    unit tested:  notify_expiration

    test case:
    iterates through the list of listeners, calling each's on_expiration
    """
    ansm = abstract_native_session_manager
    mocklist = [mock.MagicMock(), mock.MagicMock()]
    monkeypatch.setattr(ansm, 'listeners', mocklist)
    monkeypatch.setattr(ansm, 'before_invalid_notification', lambda x: 'bla')
    dumbsession = type('DumbSession', (object,), {'session_id': '1234'})()
    ansm.notify_expiration(dumbsession)
    results = (mocklist[0].on_expiration.called and 
               mocklist[1].on_expiration.called)
    assert results

def test_ansm_get_start_timestamp(
        patched_abstract_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_start_timestamp

    test case:
    basic code exercise, passes through and returns
    """
    ansm = patched_abstract_native_session_manager
    results = ansm.get_start_timestamp('sessionkey')
    expected = datetime.datetime(2015, 6, 17, 19, 43, 51, 818810) 
    assert results == expected

def test_ansm_get_last_access_time(
        patched_abstract_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_last_access_time

    test case:
    basic code exercise, passes through and returns
    """
    ansm = patched_abstract_native_session_manager
    results = ansm.get_last_access_time('sessionkey')
    expected = datetime.datetime(2015, 6, 17, 19, 45, 51, 818810) 
    assert results == expected

def test_ansm_get_absolute_timeout(
        patched_abstract_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_absolute_timeout

    test case:
    basic code exercise, passes through and returns
    """
    ansm = patched_abstract_native_session_manager
    results = ansm.get_absolute_timeout('sessionkey')
    expected = datetime.timedelta(minutes=60)
    assert results == expected

def test_ansm_get_idle_timeout(
        patched_abstract_native_session_manager, monkeypatch, mock_session):
    """
    unit tested: get_idle_timeout 

    test case:
    basic code exercise, passes through and returns
    """
    ansm = patched_abstract_native_session_manager
    results = ansm.get_idle_timeout('sessionkey')
    expected = datetime.timedelta(minutes=15)
    assert results == expected

def test_ansm_set_idle_timeout(
        patched_abstract_native_session_manager, monkeypatch, mock_session):
    """
    unit tested: set_idle_timeout 

    test case:
    basic code exercise, passes through and returns
    """
    ansm = patched_abstract_native_session_manager
    timeout = datetime.timedelta(minutes=30)
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        ansm.set_idle_timeout('sessionkey123', timeout)
        assert (mocky.called and mock_session.idle_timeout == timeout)

def test_ansm_set_absolute_timeout(
        patched_abstract_native_session_manager, monkeypatch, mock_session):
    """
    unit tested: set_absolute_timeout 

    test case:
    basic code exercise, passes through and returns
    """
    ansm = patched_abstract_native_session_manager
    timeout = datetime.timedelta(minutes=30)

    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        ansm.set_absolute_timeout('sessionkey123', timeout)
        assert (mocky.called and mock_session.absolute_timeout == timeout)

def test_ansm_touch(patched_abstract_native_session_manager, mock_session):
    """
    unit tested:  touch

    test case:
    basic code exercise, passes through
    """
    ansm = patched_abstract_native_session_manager
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        with mock.patch.object(MockSession, 'touch') as touchy:
            ansm.touch('sessionkey123')
            assert (mocky.called and touchy.called)

def test_ansm_get_host(patched_abstract_native_session_manager):
    """
    unit tested:  get_host

    test case:
    basic code exercise, passes through and returns host
    """
    ansm = patched_abstract_native_session_manager
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        result = ansm.get_host('sessionkey123')
        assert result == '127.0.0.1'

def test_ansm_get_attribute_keys_results(
        patched_abstract_native_session_manager):
    """
    unit tested:  get_attribute_keys

    test case:
    basic code exercise, passes through and returns a tuple contains 3 mock items
    """
    ansm = patched_abstract_native_session_manager
    result = ansm.get_attribute_keys('sessionkey123')
    assert 'attr2' in result  # arbitrary check

def test_ansm_get_attribute_keys_empty(
        patched_abstract_native_session_manager, monkeypatch):
    """
    unit tested:  get_attribute_keys

    test case:
    basic code exercise, passes through and returns an empty tuple
    """
    ansm = patched_abstract_native_session_manager
    dumbsession = type('DumbSession', (object,), {'session_id': '1234',
                                                  'attribute_keys': None})()
    monkeypatch.setattr(ansm, 'lookup_required_session', lambda x: dumbsession) 
    result = ansm.get_attribute_keys('sessionkey123')
    assert result == tuple()

def test_ansm_get_attribute(patched_abstract_native_session_manager):
    """
    unit tested:  get_attribute

    test case:
    basic code exercise, passes through and returns an attribute 
    """
    ansm = patched_abstract_native_session_manager
    result = ansm.get_attribute('sessionkey123', 'attr2')
    assert result == 'attrX'

def test_ansm_set_attribute(patched_abstract_native_session_manager):
    """
    unit tested:  set_attribute

    test case:
    sets an attribute 
    """
    ansm = patched_abstract_native_session_manager
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        ansm.set_attribute('sessionkey123', attribute_key='attr321', value=321)
        mocksession = ansm.lookup_required_session('bla')
        assert (mocky.called and 
                'attr321' in mocksession.session)

def test_ansm_set_attribute_removes(
        patched_abstract_native_session_manager):
    """
    unit tested:  set_attribute

    test case:
    calling set_attribute without a value results in the removal of an attribute 
    """
    ansm = patched_abstract_native_session_manager

    with mock.patch.object(ansm, 'remove_attribute') as mock_ra:
        ansm.set_attribute('sessionkey123', attribute_key='attr1')
        assert mock_ra.called

def test_ansm_remove_attribute(patched_abstract_native_session_manager):
    """
    unit tested:  remove_attribute

    test case:  
    successfully removes an attribute
    """
    ansm = patched_abstract_native_session_manager
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        result = ansm.remove_attribute('sessionkey123', 'attr3')
        assert result == 3 and mocky.called

def test_ansm_remove_attribute_nothing(patched_abstract_native_session_manager):
    """
    unit tested:  remove_attribute

    test case:  
    removing an attribute that doesn't exist returns None
    """
    ansm = patched_abstract_native_session_manager
    with mock.patch.object(MockAbstractNativeSessionManager, 'on_change') as mocky: 
        result = ansm.remove_attribute('sessionkey123', 'attr5')
        assert result is None and not mocky.called

def test_ansm_is_valid(patched_abstract_native_session_manager):
    """
    unit tested:  is_valid

    test case:
    a valid sesion returns True
    """
    ansm = patched_abstract_native_session_manager

    with mock.patch.object(MockAbstractNativeSessionManager, 'check_valid') as mocky: 
        mocky.return_value = True
        result = ansm.is_valid('sessionkey123')
        assert result

def test_ansm_is_valid_raisefalse(patched_abstract_native_session_manager):
    """
    unit tested:  is_valid

    test case:
    an invalid sesion returns False 
    """
    ansm = patched_abstract_native_session_manager

    with mock.patch.object(MockAbstractNativeSessionManager, 'check_valid') as mocky: 
        mocky.side_effect = InvalidSessionException
        result = ansm.is_valid('sessionkey123')
        assert result is False

def test_ansm_stop(patched_abstract_native_session_manager):
    """
    unit tested:  stop

    test case:
    basic method exercise, calling methods and completing
    """
    ansm = patched_abstract_native_session_manager
    mocksession = ansm.lookup_required_session('bla')
    with mock.patch.object(MockSession, 'stop') as stop:
        with mock.patch.object(ansm, 'on_stop') as on_stop:
            with mock.patch.object(ansm, 'notify_stop') as notify_stop:
                with mock.patch.object(ansm, 'after_stopped') as after_stopped:
                    ansm.stop('sessionkey123')
                    stop.assert_called_with()
                    on_stop.assert_called_with(mocksession, 'sessionkey123')
                    notify_stop.assert_called_with(mocksession)
                    after_stopped.assert_called_with(mocksession)
    
def test_ansm_stop_raises(patched_abstract_native_session_manager):
    """
    unit tested:  stop

    test case:
    exception is raised and finally section is executed
    """
    ansm = patched_abstract_native_session_manager
    mocksession = ansm.lookup_required_session('bla')
    with mock.patch.object(MockSession, 'stop') as stop:
        stop.side_effect = InvalidSessionException
        with mock.patch.object(ansm, 'after_stopped') as after_stopped:
            with pytest.raises(InvalidSessionException) as exc:
                ansm.stop('sessionkey123')
            after_stopped.assert_called_with(mocksession)
            assert exc

def test_ansm_on_stop(patched_abstract_native_session_manager):
    """
    unit tested:  on_stop

    test case:
    calls on_change
    """
    ansm = patched_abstract_native_session_manager
    mocksession = ansm.lookup_required_session('bla')
    with mock.patch.object(ansm, 'on_change') as mock_onchange:
        ansm.on_stop(mocksession)
        mock_onchange.assert_called_with(mocksession)

def test_ansm_check_valid_raises(patched_abstract_native_session_manager):
    """
    unit tested:  check_valid

    test case:
    calls lookup_required_session
    """
    ansm = patched_abstract_native_session_manager
    with mock.patch.object(ansm, 'lookup_required_session') as mocky:
        ansm.check_valid('sessionkey123')
        mocky.assert_called_with('sessionkey123')


# ----------------------------------------------------------------------------
# ExecutorServiceSessionValidationScheduler 
# ----------------------------------------------------------------------------

def test_svs_
svs = session_validation_scheduler



# ----------------------------------------------------------------------------
# AbstractValidatingSessionManager 
# ----------------------------------------------------------------------------
