import pytest
from unittest import mock
import collections

from yosai.core import (
    CachingSessionStore,
    SessionKey,
    DelegatingSession,
    ExpiredSessionException,
    NativeSessionHandler,
    SimpleSession,
    StoppedSessionException,
    InvalidSessionException,
)


# ----------------------------------------------------------------------------
# NativeSessionHandler
# ----------------------------------------------------------------------------


def test_sh_create_session(session_handler, monkeypatch):
    sh = session_handler
    session_store = mock.create_autospec(CachingSessionStore)
    monkeypatch.setattr(sh, 'session_store', session_store)
    sh.create_session('session')
    session_store.create.assert_called_once_with('session')


def test_sh_delete(
        session_handler, monkeypatch, session_store):
    sh = session_handler
    monkeypatch.setattr(sh, 'session_store', session_store)
    with mock.patch.object(CachingSessionStore, 'delete') as css_del:
        css_del.return_value = None
        sh.delete('session')
        css_del.assert_called_once_with('session')


def test_sh_retrieve_session_w_sessionid_raising(
        session_handler, monkeypatch, session_store, session_key):
    """
    unit tested:  retrieve_session

    test case:
    when no session can be retrieved from a data source when using a sessionid,
    an exception is raised
    """
    sh = session_handler
    css = session_store

    monkeypatch.setattr(css, 'read', lambda x: None)
    monkeypatch.setattr(sh, 'session_store', css)

    with pytest.raises(ValueError):
        sh._retrieve_session(session_key)


def test_sh_retrieve_session_withsessionid_returning(
        session_handler, monkeypatch, session_store, session_key):
    """
    unit tested:  retrieve_session

    test case:
    retrieves session from a data source, using a sessionid as parameter,
    and returns it
    """
    sh = session_handler
    css = session_store

    monkeypatch.setattr(css, 'read', lambda x: x)
    monkeypatch.setattr(sh, 'session_store', css)

    result = sh._retrieve_session(session_key)
    assert result == 'sessionid123'


def test_sh_retrieve_session_withoutsessionid(
        session_handler, monkeypatch, session_store):
    """
    unit tested:  retrieve_session

    test case:
    fails to obtain a session_id value from the sessionkey, returning None
    """
    sh = session_handler
    session_key = SessionKey(None)

    result = sh._retrieve_session(session_key)
    assert result is None


def test_sh_dogetsession_none(session_handler, monkeypatch, session_key):
    """
    unit tested: do_get_session

    test case:
    - retrieve_session fails to returns a session, returning None
    """
    sh = session_handler

    monkeypatch.setattr(sh, '_retrieve_session', lambda x: None)

    result = sh.do_get_session(session_key)
    assert result is None


def test_sh_dogetsession_notouch(session_handler, monkeypatch, session_key):
    """
    unit tested: do_get_session

    test case:
    - retrieve_session returns a session
    - validate will be called
    - auto_touch is False by default, so skipping its clode block
    - session is returned
    """
    sh = session_handler

    monkeypatch.setattr(sh, '_retrieve_session', lambda x: 'session')

    with mock.patch.object(NativeSessionHandler, 'validate') as sh_validate:
        sh_validate.return_value = None

        result = sh.do_get_session(session_key)
        sh_validate.assert_called_once_with('session', session_key)
        assert result == 'session'


def test_sh_validate_succeeds(session_handler, monkeypatch, mock_session, session_key):
    """
    unit test:  validate

    test case:
    basic code path exercise
    """
    sh = session_handler

    with mock.patch.object(mock_session, 'validate') as sessval:
        sessval.return_value = None
        sh.validate(mock_session, 'sessionkey123')


def test_sh_validate_expired(session_handler, mock_session, monkeypatch,
                             session_key):
    """
    unit test:  validate

    test case:
    do_validate raises expired session exception, calling on_expiration and
    raising
    """
    sh = session_handler

    with mock.patch.object(mock_session, 'validate') as ms_dv:
        ms_dv.side_effect = ExpiredSessionException
        with mock.patch.object(NativeSessionHandler, 'on_expiration') as sh_oe:
            sh_oe.return_value = None
            with pytest.raises(ExpiredSessionException):

                sh.validate(mock_session, 'sessionkey123')

                sh_oe.assert_called_once_with(mock_session,
                                              ExpiredSessionException,
                                              'sessionkey123')

def test_sh_validate_invalid(session_handler, mock_session, monkeypatch,
                             session_key):
    """
    unit test:  validate

    test case:
    do_validate raises expired session exception, calling on_expiration and
    raising
    """
    sh = session_handler

    with mock.patch.object(mock_session, 'validate') as ms_dv:
        ms_dv.side_effect = StoppedSessionException
        with mock.patch.object(NativeSessionHandler, 'on_invalidation') as sh_oe:
            sh_oe.return_value = None
            with pytest.raises(InvalidSessionException):

                sh.validate(mock_session, 'sessionkey123')

                sh_oe.assert_called_once_with(mock_session,
                                              ExpiredSessionException,
                                              'sessionkey123')


def test_sh_on_stop(session_handler, mock_session, monkeypatch):
    """
    unit tested:  on_stop

    test case:
    updated last_access_time and calls on_change
    """
    sh = session_handler

    mock_session = mock.create_autospec(SimpleSession)
    mock_session.stop_timestamp = 1234567

    with mock.patch.object(sh, 'on_change') as mock_onchange:
        sh.on_stop(mock_session, 'session_key')
        mock_onchange.assert_called_with(mock_session)
        assert mock_session.last_access_time == mock_session.stop_timestamp


def test_sh_after_stopped(session_handler, monkeypatch):
    """
    unit tested:  after_stopped

    test case:
    if delete_invalid_sessions is True, call delete method
    """
    sh = session_handler
    monkeypatch.setattr(sh, 'delete_invalid_sessions', True)
    with mock.patch.object(sh, 'delete') as sh_delete:
        sh_delete.return_value = None
        sh.after_stopped('session')
        sh_delete.assert_called_once_with('session')


def test_sh_on_expiration(session_handler, monkeypatch, mock_session):
    """
    unit tested:  on_expiration

    test case:
    set's a session to expired and then calls on_change
    """
    sh = session_handler
    with mock.patch.object(sh, 'on_change') as sh_oc:
        sh_oc.return_value = None
        sh.on_expiration(mock_session)
        sh_oc.assert_called_once_with(mock_session)


@pytest.mark.parametrize('ese,session_key',
                         [('ExpiredSessionException', None),
                          (None, 'sessionkey123')])
def test_sh_on_expiration_onenotset(session_handler, ese, session_key):
    """
    unit tested:  on_expiration

    test case:
        expired_session_exception or session_key are set, but not both
    """
    sh = session_handler

    with pytest.raises(ValueError):
        sh.on_expiration(session='testsession',
                         expired_session_exception=ese,
                         session_key=session_key)


def test_sh_on_expiration_allset(session_handler, monkeypatch, mock_session):
    """
    unit tested:  on_expiration

    test case:
        all parameters are passed, calling on_change, notify_expiration, and
        after_expired
    """
    sh = session_handler

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_id'])
    mysession = session_tuple('identifiers', 'sessionkey123')
    mock_session.get_internal_attribute.return_value = 'identifiers'
    mock_session.session_id = 'session123'

    with mock.patch.object(sh, 'notify_event') as sh_ne:
        sh_ne.return_value = None
        with mock.patch.object(sh, 'after_expired') as sh_ae:
            sh_ae.return_value = None
            with mock.patch.object(sh, 'on_change') as sh_oc:
                sh_oc.return_value = None

                sh.on_expiration(session=mock_session,
                                 expired_session_exception='ExpiredSessionException',
                                 session_key=SessionKey('sessionkey123'))

                sh_ne.assert_called_once_with(mysession, 'SESSION.EXPIRE')
                sh_ae.assert_called_once_with(mock_session)
                sh_oc.assert_called_once_with(mock_session)


def test_sh_after_expired(session_handler, monkeypatch):
    """
    unit tested:  after_expired

    test case:
    when delete_invalid_sessions is True, invoke delete method
    """
    sh = session_handler
    monkeypatch.setattr(sh, 'delete_invalid_sessions', True)
    with mock.patch.object(sh, 'delete') as sh_del:
        sh_del.return_value = None

        sh.after_expired('session')

        sh_del.assert_called_once_with('session')


def test_sh_on_invalidation_esetype(session_handler, mock_session):
    """
    unit tested:  on_invalidation

    test case:
        when an exception of type ExpiredSessionException is passed,
        on_expiration is called and then method returns
    """
    sh = session_handler
    ise = ExpiredSessionException('testing')
    session_key = 'sessionkey123'
    with mock.patch.object(sh, 'on_expiration') as mock_oe:
        sh.on_invalidation(session=mock_session, ise=ise, session_key=session_key)
        mock_oe.assert_called_with


def test_sh_on_invalidation_isetype(session_handler, mock_session, monkeypatch):
    """
    unit tested:  on_invalidation

    test case:
        when an exception NOT of type ExpiredSessionException is passed,
        an InvalidSessionException higher up the hierarchy is assumed
        and on_stop, notify_stop, and after_stopped are called
    """
    sh = session_handler
    ise = StoppedSessionException('testing')
    session_key = SessionKey('sessionkey123')

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_key'])
    mysession = session_tuple('identifiers', 'sessionkey123')

    monkeypatch.setattr(mock_session, 'get_internal_attribute',
                        lambda x: 'identifiers')

    with mock.patch.object(sh, 'on_stop') as mock_onstop:
        mock_onstop.return_value = None

        with mock.patch.object(sh, 'notify_event') as mock_ns:
            mock_ns.return_value = None

            with mock.patch.object(sh, 'after_stopped') as mock_as:
                mock_as.return_value = None

                sh.on_invalidation(session=mock_session,
                                   ise=ise,
                                   session_key=session_key)

                mock_onstop.assert_called_once_with(mock_session, SessionKey('sessionkey123'))
                mock_ns.assert_called_once_with(mysession, 'SESSION.STOP')
                mock_as.assert_called_once_with(mock_session)


def test_sh_on_change(session_handler, monkeypatch, session_store):
    """
    unit tested:  on_change

    test case:
    passthrough call to session_store.update
    """
    sh = session_handler
    monkeypatch.setattr(sh, 'session_store', session_store)
    with mock.patch.object(sh.session_store, 'update') as ss_up:
        ss_up.return_value = None

        sh.on_change('session')

        ss_up.assert_called_once_with('session')


# ------------------------------------------------------------------------------
# NativeSessionManager
# ------------------------------------------------------------------------------


def test_nsm_apply_ch(default_native_session_manager):
    nsm = default_native_session_manager
    nsm.apply_cache_handler('cachehandler')
    assert nsm.session_handler.session_store.cache_handler == 'cachehandler'


def test_nsm_apply_eventbus(default_native_session_manager):
    nsm = default_native_session_manager
    nsm.apply_event_bus('eventbus')
    assert nsm.event_bus == 'eventbus'
    assert nsm.session_handler.event_bus == 'eventbus'


def test_nsm_start(default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  start

    test case:
    verify that start calls other methods
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm, '_create_session', lambda x: mock_session)
    monkeypatch.setattr(nsm, 'create_exposed_session',
                        lambda session=None, context=None: (session, context))

    with mock.patch.object(nsm.session_handler, 'on_start') as mock_os:
        mock_os.return_value = None
        with mock.patch.object(nsm, 'notify_event') as ns:
            ns.return_value = None
            result = nsm.start('session_context')

            session_tuple = collections.namedtuple('session_tuple',
                                                   ['identifiers', 'session_id'])

            mock_os.assert_called_once_with(mock_session, 'session_context')
            ns.assert_called_once_with(session_tuple(None, 'sessionid123'), 'SESSION.START')
            assert result == (mock_session, 'session_context')


def test_nsm_stop(
        default_native_session_manager, monkeypatch, mock_session, session_key):
    """
    unit tested:  stop

    test case:
    basic method exercise, calling methods and completing
    """
    nsm = default_native_session_manager

    session_tuple = collections.namedtuple(
        'session_tuple', ['identifiers', 'session_id'])
    mysession = session_tuple('identifiers', 'sessionkey123')
    monkeypatch.setattr(mock_session, 'get_internal_attribute',
                        lambda x: 'identifiers')

    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)

    with mock.patch.object(nsm.session_handler, 'on_stop') as on_stop:
        on_stop.return_value = None
        with mock.patch.object(nsm, 'notify_event') as notify_stop:
            notify_stop.return_value = None
            with mock.patch.object(nsm.session_handler, 'after_stopped') as after_stopped:
                after_stopped.return_value = None

                nsm.stop(SessionKey('sessionkey123'), 'identifiers')

                mock_session.stop.assert_called_with()
                on_stop.assert_called_with(mock_session, SessionKey('sessionkey123'))
                notify_stop.assert_called_with(mysession, 'SESSION.STOP')
                after_stopped.assert_called_with(mock_session)


def test_nsm_stop_raises(
        default_native_session_manager, mock_session, monkeypatch):
    """
    unit tested:  stop

    test case:
    exception is raised and finally section is executed
    """
    nsm = default_native_session_manager

    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    mock_session.stop.side_effect = InvalidSessionException
    with mock.patch.object(nsm.session_handler, 'after_stopped') as after_stopped:
        with pytest.raises(InvalidSessionException):
            nsm.stop('sessionkey123', 'identifiers')
            after_stopped.assert_called_with(mock_session)


@mock.patch('yosai.core.session.session.SimpleSession')
def test_nsm_create_session(
        mock_ss, default_native_session_manager, monkeypatch, mock_session):
    mock_ss.return_value = mock_session
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm.session_handler, 'create_session', lambda x: 'sessionid123')

    result = nsm._create_session({'bla': 'bla'})
    assert result == mock_session


@mock.patch('yosai.core.session.session.SimpleSession')
def test_nsm_create_session_raises(
        mock_ss, default_native_session_manager, monkeypatch, mock_session):

    mock_ss.return_value = mock_session
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm.session_handler, 'create_session', lambda x: None)

    with pytest.raises(ValueError):
        nsm._create_session({'bla': 'bla'})


def test_nsm_create_exposed_session(default_native_session_manager, mock_session):
    """
    unit tested:  create_exposed_session

    test case:
    basic codepath exercise
    """
    nsm = default_native_session_manager
    result = nsm.create_exposed_session(mock_session)
    assert isinstance(result, DelegatingSession)


def test_nsm_get_session_locates(default_native_session_manager, monkeypatch):
    """
    unit tested: get_session

    test case:
    lookup_session returns a session, and so create_exposed_session is called
    with it
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm.session_handler,
                        'do_get_session', lambda x: x)
    monkeypatch.setattr(nsm, 'create_exposed_session', lambda x, y: x)

    results = nsm.get_session('key')

    assert results == 'key'  # asserts that it was called


def test_nsm_get_session_doesnt_locate(
        default_native_session_manager, monkeypatch):
    """
    unit tested:  get_session

    test case:
    lookup session fails to locate a session and so None is returned
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm.session_handler, 'do_get_session', lambda x: None)
    results = nsm.get_session('key')

    assert results is None


def test_nsm_lookup_required_session_locates(
        default_native_session_manager, monkeypatch):
    """
    unit tested:  lookup_required_session

    test case:
    lookup_session finds and returns a session
    """
    nsm = default_native_session_manager

    monkeypatch.setattr(nsm.session_handler, 'do_get_session', lambda x: 'session')
    results = nsm._lookup_required_session('key')
    assert results == 'session'


def test_nsm_lookup_required_session_failstolocate(
        default_native_session_manager, monkeypatch):
    """
    unit tested:  lookup_required_session

    test case:
    lookup_session fails to locate a session, raising an exception instead
    """
    nsm = default_native_session_manager

    monkeypatch.setattr(nsm.session_handler, 'do_get_session', lambda x: None)
    with pytest.raises(ValueError):
        nsm._lookup_required_session('key')


def test_nsm_is_valid(default_native_session_manager):
    """
    unit tested:  is_valid

    test case:
    a valid sesion returns True
    """
    nsm = default_native_session_manager

    with mock.patch.object(nsm, 'check_valid') as mocky:
        mocky.return_value = True
        result = nsm.is_valid('sessionkey123')
        assert result


def test_nsm_is_valid_raisefalse(default_native_session_manager):
    """
    unit tested:  is_valid

    test case:
    an invalid sesion returns False
    """
    nsm = default_native_session_manager

    with mock.patch.object(nsm, 'check_valid') as mocky:
        mocky.side_effect = InvalidSessionException
        result = nsm.is_valid('sessionkey123')
        assert result is False


def test_nsm_check_valid_raises(default_native_session_manager):
    """
    unit tested:  check_valid

    test case:
    calls lookup_required_session
    """
    nsm = default_native_session_manager
    with mock.patch.object(nsm, '_lookup_required_session') as mocky:
        mock.return_value = None
        nsm.check_valid('sessionkey123')
        mocky.assert_called_with('sessionkey123')


def test_nsm_get_start_timestamp(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_start_timestamp

    test case:
    basic code exercise, passes through and returns
    """
    nsm = default_native_session_manager
    mock_session.start_timestamp = 'starttime'
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    results = nsm.get_start_timestamp('sessionkey')
    assert results == mock_session.start_timestamp


def test_nsm_getlast_access_time(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  getlast_access_time

    test case:
    basic code exercise, passes through and returns
    """
    nsm = default_native_session_manager
    mock_session.last_access_time = 'lasttime'
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    results = nsm.get_last_access_time('sessionkey')
    assert results == mock_session.last_access_time


def test_nsm_get_absolute_timeout(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_absolute_timeout

    test case:
    basic code exercise, passes through and returns
    """
    nsm = default_native_session_manager
    mock_session.absolute_timeout = 'abstimeout'
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    results = nsm.get_absolute_timeout(mock_session)
    assert results == 'abstimeout'


def test_nsm_get_idle_timeout(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested: get_idle_timeout

    test case:
    basic code exercise, passes through and returns
    """
    nsm = default_native_session_manager
    mock_session.idle_timeout = 'idletimeout'
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    results = nsm.get_idle_timeout(mock_session)
    assert results == 'idletimeout'


def test_nsm_set_idle_timeout(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested: set_idle_timeout

    test case:
    basic code exercise, passes through and returns
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)

    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None
        nsm.set_idle_timeout('sessionkey123', 'timeout')
        mocky.assert_called_once_with(mock_session)
        assert mock_session.idle_timeout == 'timeout'


def test_nsm_set_absolute_timeout(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested: set_absolute_timeout

    test case:
    basic code exercise, passes through and returns
    """
    nsm = default_native_session_manager

    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)

    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None
        nsm.set_absolute_timeout('sessionkey123', 'timeout')
        mocky.assert_called_once_with(mock_session)
        assert mock_session.absolute_timeout == 'timeout'


def test_nsm_touch(default_native_session_manager, mock_session, monkeypatch):
    """
    unit tested:  touch

    test case:
    basic code exercise, passes through
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None
        nsm.touch('sessionkey123')
        mock_session.touch.assert_called_once_with()
        mocky.assert_called_once_with(mock_session)


def test_nsm_get_host(default_native_session_manager, mock_session, monkeypatch):
    """
    unit tested:  get_host

    test case:
    basic code exercise, passes through and returns host
    """
    nsm = default_native_session_manager
    mock_session.host = '127.0.0.1'
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None
        result = nsm.get_host('sessionkey123')
        assert result == '127.0.0.1'


def test_nsm_get_internal_attribute_keys_results(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_internal_attribute_keys

    test case:
    basic code exercise, passes through and returns a tuple contains 3 mock items
    """
    nsm = default_native_session_manager
    mock_session.internal_attribute_keys = ['one', 'two']
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    result = nsm.get_internal_attribute_keys('sessionkey123')
    assert result == tuple(['one', 'two'])


def test_nsm_get_internal_attribute_keys_empty(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_internal_attribute_keys

    test case:
    basic code exercise, passes through and returns an empty tuple
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(mock_session, '_internal_attribute_keys', [], raising=False)
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    result = nsm.get_internal_attribute_keys('sessionkey123')
    assert result == tuple()


def test_nsm_get_internal_attribute(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_internal_attribute

    test case:
    basic code exercise, passes through and returns an internal_attribute
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: 'attr')
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    result = nsm.get_internal_attribute('sessionkey123','anything')
    assert result == 'attr'


def test_nsm_set_internal_attribute(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  set_internal_attribute

    test case:
    sets an internal_attribute
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None
        with mock.patch.object(mock_session, 'set_internal_attribute') as sia:
            sia.return_value = None

            nsm.set_internal_attribute('sessionkey123',
                                       attribute_key='attr321', value=321)

            sia.assert_called_once_with('attr321', 321)
            mocky.assert_called_once_with(mock_session)


def test_nsm_remove_internal_attribute(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  remove_internal_attribute

    test case:
    successfully removes an internal_attribute
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(mock_session, 'remove_internal_attribute', lambda x: 'attr1')
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None

        result = nsm.remove_internal_attribute('sessionkey123',
                                               attribute_key='attr321')

        mocky.assert_called_once_with(mock_session)
        assert result == 'attr1'


def test_nsm_remove_internal_attribute_nothing(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  remove_internal_attribute

    test case:
    removing an internal_attribute that doesn't exist returns None
    """
    nsm = default_native_session_manager
    mock_session.remove_internal_attribute.return_value = None
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None

        result = nsm.remove_internal_attribute('sessionkey123',
                                               attribute_key='attr321')

        assert result is None


def test_nsm_get_attribute_keys_results(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_attribute_keys

    test case:
    basic code exercise, passes through and returns a tuple contains 3 mock items
    """
    nsm = default_native_session_manager
    mock_session.attribute_keys = ['one', 'two']
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    result = nsm.get_attribute_keys('sessionkey123')
    assert result == tuple(['one', 'two'])


def test_nsm_get_attribute_keys_empty(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_attribute_keys

    test case:
    basic code exercise, passes through and returns an empty tuple
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(mock_session, '_attribute_keys', [], raising=False)
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    result = nsm.get_attribute_keys('sessionkey123')
    assert result == tuple()


def test_nsm_get_attribute(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  get_attribute

    test case:
    basic code exercise, passes through and returns an attribute
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(mock_session, 'get_attribute', lambda x: 'attr')
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    result = nsm.get_attribute('sessionkey123','anything')
    assert result == 'attr'


def test_nsm_set_attribute(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  set_attribute

    test case:
    sets an attribute
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None
        with mock.patch.object(mock_session, 'set_attribute') as sia:
            sia.return_value = None

            nsm.set_attribute('sessionkey123',
                              attribute_key='attr321', value=321)

            sia.assert_called_once_with('attr321', 321)
            mocky.assert_called_once_with(mock_session)


def test_nsm_set_attribute_removes(
        default_native_session_manager):
    """
    unit tested:  set_attribute

    test case:
    calling set_attribute without a value results in the removal of an attribute
    """
    nsm = default_native_session_manager

    with mock.patch.object(nsm, 'remove_attribute') as mock_ra:
        nsm.set_attribute('sessionkey123', attribute_key='attr1')
        mock_ra.assert_called_once_with('sessionkey123', 'attr1')


def test_nsm_remove_attribute(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  remove_attribute

    test case:
    successfully removes an attribute
    """
    nsm = default_native_session_manager
    monkeypatch.setattr(mock_session, 'remove_attribute', lambda x: 'attr1')
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None

        result = nsm.remove_attribute('sessionkey123',
                                      attribute_key='attr321')

        mocky.assert_called_once_with(mock_session)
        assert result == 'attr1'


def test_nsm_remove_attribute_nothing(
        default_native_session_manager, monkeypatch, mock_session):
    """
    unit tested:  remove_attribute

    test case:
    removing an attribute that doesn't exist returns None
    """
    nsm = default_native_session_manager
    mock_session.remove_attribute.return_value = None
    monkeypatch.setattr(nsm, '_lookup_required_session', lambda x: mock_session)
    with mock.patch.object(nsm.session_handler, 'on_change') as mocky:
        mocky.return_value = None

        result = nsm.remove_attribute('sessionkey123',
                                      attribute_key='attr321')

        assert result is None
