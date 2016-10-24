import pytest
import time
from unittest import mock
import datetime

from .doubles import (
    MockSessionManager,
)

from yosai.core import (
    DefaultSessionSettings,
    DefaultSessionKey,
    ExpiredSessionException,
    StoppedSessionException,
    SimpleSession,
)

# ----------------------------------------------------------------------------
# SessionSettings
# ----------------------------------------------------------------------------


def test_create_session_settings(core_settings):
    """
    unit tested:  __init__

    test case:
    basic code path exercise, ensuring object instantiation
    """
    dss = DefaultSessionSettings(core_settings)
    assert hasattr(dss, 'absolute_timeout') and hasattr(dss, 'idle_timeout')


@pytest.mark.parametrize(
    'attr', ['absolute_timeout', 'idle_timeout', 'validation_scheduler_enable',
             'validation_time_interval'])
def test_default_session_settings(attr, core_settings):
    dss = DefaultSessionSettings(core_settings)
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
    monkeypatch.setattr(ss, 'stop_timestamp', is_stopped)
    monkeypatch.setattr(ss, 'is_expired', is_expired)
    assert ss.is_valid == check


# see docstring below for more information about these parameters:
@pytest.mark.parametrize(
    ('is_expired,absolute_timeout,idle_timeout,last_access_time,start_timestamp,timedout'),
    [(False, (60 * 60 * 1000), (10 * 60 * 1000),
      round(time.time() * 1000) - (3 * 60 * 1000),
      round(time.time() * 1000) - (120 * 60 * 1000), True),
     (False, (60 * 60 * 1000), (15 * 60 * 1000),
      round(time.time() * 1000) - (20 * 60 * 1000),
      round(time.time() * 1000) - (30 * 60 * 1000), True),
     (False, (60 * 60 * 1000), (15 * 60 * 1000),
      round(time.time() * 1000) - (1 * 60 * 1000),
      round(time.time() * 1000) - (5 * 60 * 1000),
      False)])
def test_ss_is_timed_out(
        simple_session, is_expired, absolute_timeout,
        idle_timeout, last_access_time, start_timestamp, timedout,
        monkeypatch):
    """
    unit tested:  is_timed_out

    test case:
            is_timed_out()=True:
            ----------------------

            absolute timeout:
        I) expired = False, absolute_timeout = 1hour, idle_timeout=None
            start_timestamp = currenttime-2hours, rest is arbitrary

            inactive timeout:
       II) expired = False, absolute_timeout = None, idle_timeout = 15min,
            start_timestamp = currenttime, last_access_time=current-30minutes


            is_timed_out()=False:
            ----------------------
            not idle nor beyond absolute:
        III) expired = False, absolute_timeout = 1hr, idle_timeout = 15min,
            start_timestamp = currenttime-5, last_access_time=current-1minutes

    """
    ss = simple_session

    monkeypatch.setattr(ss, 'is_expired', is_expired)
    monkeypatch.setattr(ss, 'absolute_timeout', absolute_timeout)
    monkeypatch.setattr(ss, 'idle_timeout', idle_timeout)
    monkeypatch.setattr(ss, 'last_access_time', last_access_time)
    monkeypatch.setattr(ss, 'start_timestamp', start_timestamp)

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
    monkeypatch.setattr(ss, 'is_expired', is_expired)
    monkeypatch.setattr(ss, 'absolute_timeout', absolute_timeout)
    monkeypatch.setattr(ss, 'idle_timeout', idle_timeout)
    monkeypatch.setattr(ss, 'last_access_time', last_access_time)
    monkeypatch.setattr(ss, 'start_timestamp', start_timestamp)

    with pytest.raises(ValueError):
        ss.is_timed_out()


def test_ss_validate_stopped(simple_session, monkeypatch):
    """
    unit tested:  validate

    test case:
    a stopped session raises an exception in validate
    """
    ss = simple_session
    monkeypatch.setattr(ss, 'stop_timestamp', datetime.datetime.utcnow())

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


def test_ss_get_attribute(simple_session, mock_serializable):
    """
    unit tested:  get_attribute

    test case:
    returns None either when no attributes or when key doesn't exist
    """
    ss = simple_session
    result = ss.get_attribute('serializable')
    assert isinstance(result, mock_serializable)


def test_ss_set_attribute(simple_session, monkeypatch):
    """
    unit tested:  set_attribute

    test case:
    setting an attribute adds or overrides existing attribute
    """
    ss = simple_session
    ss.set_attribute('attribute1', 'testing')
    assert ss.attributes['attribute1'] == 'testing'


def test_ss_set_attributes(simple_session, monkeypatch):
    """
    unit tested:  set_attributes
    """
    ss = simple_session
    attributes = {'attribute1': 'test1', 'attribute2': 'test2'}

    ss.set_attributes(attributes)

    assert (ss.attributes['attribute1'] == 'test1' and
            ss.attributes['attribute2'] == 'test2')


def test_ss_remove_attribute(simple_session, monkeypatch):
    """
    unit tested: remove_attribute

    test case:
    remove an attribute, if attributes exists, else None
    """
    ss = simple_session
    monkeypatch.setitem(ss.attributes, 'attribute1', 'attribute1')
    assert (ss.remove_attribute('attribute1') == 'attribute1'
            and not hasattr(ss.attributes, 'attribute1'))


def test_ss_get_internal_attribute(simple_session):
    """
    unit tested:  get_internal_attribute

    test case:
    returns None either when no internal_attributes or when key doesn't exist
    """
    ss = simple_session
    result = ss.get_internal_attribute('identifiers_session_key')
    assert result is None


def test_ss_set_internal_attribute(simple_session):
    """
    unit tested:  set_internal_attribute

    test case:
    setting an internal_attribute adds or overrides existing internal_attribute
    """
    ss = simple_session
    ss.set_internal_attribute('identifiers_session_key', 'testing')
    assert ss.internal_attributes.get('identifiers_session_key') == 'testing'


def test_ss_remove_internal_attribute(simple_session):
    """
    unit tested: remove_internal_attribute

    test case:
    remove an internal_attribute, if internal_attributes exists, else None
    """
    ss = simple_session
    result = ss.remove_internal_attribute('identifiers_session_key')
    assert ss.internal_attributes.get('identifiers_session_key') is None


def test_ss_eq_clone():
    """
    unit tested:

    test case:
      other is a clone of self
   """
    idle_timeout = (10 * 60 * 1000)
    absolute_timeout = (60 * 60 * 1000)
    last_access_time = round(time.time() * 1000) - (5 * 60 * 1000)
    start_timestamp = round(time.time() * 1000) - (8 * 60 * 1000)

    s1 = SimpleSession(absolute_timeout, idle_timeout)
    s1.is_expired = False
    s1.session_id = 'sessionid123'
    s1.last_access_time = last_access_time
    s1.start_timestamp = start_timestamp
    s1._host = '127.0.0.1'

    s2 = SimpleSession(absolute_timeout, idle_timeout)
    s2.session_id = 'sessionid123'
    s2.is_expired = False
    s2.last_access_time = last_access_time
    s2.start_timestamp = start_timestamp
    s2._host = '127.0.0.1'

    assert s1 == s2


def test_ss_eq_different_values():
    """
    unit tested:

    test case:
    other has different attribute values than self
    """
    idle_timeout = (10 * 60 * 1000)
    absolute_timeout = (60 * 60 * 1000)
    last_access_time = round(time.time() * 1000) - (5 * 60 * 1000)
    start_timestamp = round(time.time() * 1000) - (8 * 60 * 1000)

    s1 = SimpleSession(absolute_timeout, idle_timeout)
    s1.is_expired = False
    s1.session_id = 'sessionid1234567'
    s1.last_access_time = last_access_time
    s1.start_timestamp = start_timestamp
    s1._host = '127.0.0.1'

    s2 = SimpleSession(absolute_timeout, idle_timeout)
    s2.session_id = 'sessionid123'
    s2.is_expired = False
    s2.last_access_time = last_access_time
    s2.start_timestamp = start_timestamp
    s2._host = '127.0.0.1'

    assert not s1 == s2


def test_ss_eq_different_attributes():
    """
    unit tested:

    test case:
    other does not have same attributes as self
   """
    idle_timeout = (10 * 60 * 1000)
    absolute_timeout = (60 * 60 * 1000)
    last_access_time = round(time.time() * 1000) - (5 * 60 * 1000)
    start_timestamp = round(time.time() * 1000) - (8 * 60 * 1000)

    s1 = SimpleSession(absolute_timeout, idle_timeout)
    s2 = SimpleSession(absolute_timeout, idle_timeout)

    assert s1 == s2

    s1.set_attribute('attribute1', 'test')
    s2.set_attribute('attribute1', 'testing')

    assert not s1 == s2

# ----------------------------------------------------------------------------
# DelegatingSession
# ----------------------------------------------------------------------------

def test_dsstart_timestamp_not_exists(patched_delegating_session):
    """
    unit tested:  start_timestamp

    test case:  since there is no start_timestamp set, it delegates to the sm
    """
    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'getstart_timestamp') as msm:
        msm.return_value = None
        pds.start_timestamp
        msm.assert_called_once_with(pds.session_key)

def test_dsstart_timestamp_exists(
        patched_delegating_session, monkeypatch):
    """
    unit tested:  start_timestamp

    test case:
    since the start_timestamp is set for the pds, it is used
    """
    pds = patched_delegating_session

    now = round(time.time() * 1000)
    monkeypatch.setattr(pds, 'start_timestamp', now)
    assert pds.start_timestamp == now

def test_dslast_access_time(patched_delegating_session):
    """
    unit tested:  last_access_time

    test case:  delegates the request to the MockSessionManager
    """
    pds = patched_delegating_session
    result = pds.last_access_time

    # verifeis a pre-defined result from the mock
    assert result == 1472291665100


def test_ds_getidle_timeout(patched_delegating_session):
    """
    unit tested: idle_timeout

    test case: delegates the request to the MockSessionManager
    """
    pds = patched_delegating_session
    result = pds.idle_timeout
    assert result == (10 * 60 * 1000)

def test_ds_setidle_timeout(patched_delegating_session):
    """
    unit tested: idle_timeout

    test case: delegates the request to the MockSessionManager
    """
    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'setidle_timeout') as msm_sit:
        msm_sit.return_value = None
        now = (5 * 60 * 1000)
        pds.idle_timeout = now
        msm_sit.assert_called_once_with(pds.session_key, now)

def test_ds_getabsolute_timeout(patched_delegating_session):
    """
    unit tested: absolute_timeout

    test case: delegates the request to the MockSessionManager
    """
    pds = patched_delegating_session
    result = pds.absolute_timeout
    assert result == (60 * 60 * 1000)

def test_ds_setabsolute_timeout(patched_delegating_session):
    """
    unit tested: absolute_timeout

    test case: delegates the request to the MockSessionManager
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'setabsolute_timeout') as msm_sit:
        msm_sit.return_value = None
        now = round(time.time() * 1000)
        pds.absolute_timeout = now
        msm_sit.assert_called_once_with(pds.session_key, now)

def test_ds_host_not_exists(patched_delegating_session):
    """
    unit tested:  host

    test case:  there is no host set, so delegates to the sm
    """
    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'get_host') as msm_gh:
        msm_gh.return_value = None
        pds.host
        msm_gh.assert_called_once_with(pds.session_key)

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
        msm_touch.assert_called_once_with(pds.session_key)


def test_ds_stop(patched_delegating_session):
    """
    unit tested:  stop

    test case:
    delegates the request to the MockSessionManager
    """
    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'stop') as msm_stop:
        msm_stop.return_value = None
        pds.stop('identifiers')
        msm_stop.assert_called_once_with(pds.session_key, 'identifiers')


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
        gak.assert_called_once_with(pds.session_key)


def test_ds_get_attribute(patched_delegating_session):
    """
    unit tested:  get_attribute

    test case:
    delegates the request to the MockSessionManager
    """

    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'get_attribute') as ga:
        ga.return_value = None
        result = pds.get_attribute('serializable')
        ga.assert_called_once_with(pds.session_key, 'serializable')


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
        msm_sa.assert_called_once_with(pds.session_key, 'attributekey', 'value')


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
        msm_ra.assert_called_once_with(pds.session_key, 'attributekey')


def test_ds_internal_attribute_keys(patched_delegating_session):
    """
    unit tested:  internal_attribute_keys

    test case:
    delegates the request to the MockSessionManager
    """

    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'get_internal_attribute_keys') as gak:
        gak.return_value = None
        pds.internal_attribute_keys
        gak.assert_called_once_with(pds.session_key)


def test_ds_get_internal_attribute(patched_delegating_session):
    """
    unit tested:  get_internal_attribute

    test case:
    delegates the request to the MockSessionManager
    """

    pds = patched_delegating_session

    with mock.patch.object(MockSessionManager, 'get_internal_attribute') as ga:
        ga.return_value = None
        pds.get_internal_attribute('internal_attribute_key')
        ga.assert_called_once_with(pds.session_key, 'internal_attribute_key')


def test_ds_set_internal_attribute_delegates(patched_delegating_session):
    """
    unit tested:  set_internal_attribute

    test case:
    delegates to the MockSessionManager
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'set_internal_attribute') as msm_sa:
        msm_sa.return_value = None
        pds.set_internal_attribute('internal_attribute_key', 'value')
        msm_sa.assert_called_once_with(pds.session_key, 'internal_attribute_key', 'value')


def test_ds_remove_internal_attribute_delegates(patched_delegating_session):
    """
    unit tested:  remove_internal_attribute

    test case:
    delegates to the MockSessionManager
    """

    pds = patched_delegating_session
    with mock.patch.object(MockSessionManager, 'remove_internal_attribute') as msm_ra:
        msm_ra.return_value = None
        pds.remove_internal_attribute('internal_attribute_key')
        msm_ra.assert_called_once_with(pds.session_key, 'internal_attribute_key')


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
# DefaultSessionStorageEvaluator
# ----------------------------------------------------------------------------

def test_dsse_isse_wo_subject(default_session_storage_evaluator):
    """
    unit tested:  is_session_storage_enabled

    test case:
    basic code path exercise where no param is passed to the method and so
    method defaults
    """
    dsse = default_session_storage_evaluator
    result = dsse.is_session_storage_enabled()
    assert result is True

def test_dsse_isse_w_subject(default_session_storage_evaluator, monkeypatch):
    """
    unit tested:  is_session_storage_enabled

    test case:
    basic code path exercise where subject param is passed to the method and
    so boolean logic is applied
    """
    class MockSubject:
        def get_session(self, booly):
            return None

    dsse = default_session_storage_evaluator
    monkeypatch.setattr(dsse, '_session_storage_enabled', False)
    result = dsse.is_session_storage_enabled(subject=MockSubject())
    assert result is False
