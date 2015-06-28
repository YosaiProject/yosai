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
    DelegatingSession,
    EventBus,
    ExpiredSessionException,
    SessionEventException,
    StoppableScheduledExecutor,
    StoppedSessionException,
    IllegalStateException,
    ImmutableProxiedSession,
    InvalidSessionException,
    UnknownSessionException,
)


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

def test_esvs_enable_session_validation(executor_session_validation_scheduler):
    esvs = executor_session_validation_scheduler
    sse = StoppableScheduledExecutor  # from yosai.concurrency
    with mock.patch.object(sse, 'start') as sse_start:
        esvs.enable_session_validation()
        sse_start.assert_called_with() and esvs.is_enabled


def test_esvs_run(executor_session_validation_scheduler):
    esvs = executor_session_validation_scheduler

    with mock.patch.object(MockAbstractNativeSessionManager, 
                           'validate_sessions') as sm_vs:
        sm_vs.return_value = None
        esvs.run()
        sm_vs.assert_called_with()

# ----------------------------------------------------------------------------
# AbstractValidatingSessionManager 
# ----------------------------------------------------------------------------
