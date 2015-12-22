import pytest
import datetime
import pytz
from collections import namedtuple

from yosai.core import (
    DefaultSessionKey,
    DelegatingSession,
    ExpiredSessionException,
    InvalidSessionException,
    SimpleIdentifierCollection,
    UnknownSessionException,
    event_bus,
)


def test_create_cache_session(session_store, session, cache_handler):
    """
    test objective:  cache new session entry and read session from cache

    aspects tested:
        - session.set_internal_attribute
        - session_store.create
        - session_store.read
        - session_store.delete
        - cache_handler.get
        - session.__eq__
    """
    css = session_store
    sic = SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                     identifier='user12345678')
    session.set_internal_attribute('identifiers_session_key', sic)
    sessionid = css.create(session)

    cached_session = css.read(sessionid)
    cached_session_token = css.cache_handler.get('session', 'user12345678')
    assert (cached_session == session and
            cached_session_token == DefaultSessionKey(sessionid))

@pytest.mark.xfail
def test_update_cached_session(session_store, session):
    """
    this test will pass if test_create_cache_session runs first
    """

    css = session_store
    session.set_internal_attribute('testing', 'testing123')
    css.update(session)
    cached_session = css.read(session.session_id)
    assert cached_session == session


def test_delete_cached_session(session_store, session, cache_handler):
    """
    this test will pass if test_create_cache_session runs first
    """

    css = session_store

    sic = SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                     identifier='user12345678')
    session.set_internal_attribute('identifiers_session_key', sic)
    sessionid = css.create(session)

    css.delete(session)

    cached_session = css.read(sessionid)
    cached_session_token = cache_handler.get('session', 'user12345678')
    assert cached_session is None
    assert cached_session_token is None

# can't test notify_start without conflicting with other listeners

def test_seh_notify_stop(session_event_handler, session):
    session_tuple = namedtuple(
                    'session_tuple', ['identifiers', 'session_key'])

    seh = session_event_handler
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'SESSION.STOP')

    mysession = session_tuple(None, session.session_id)

    seh.notify_stop(mysession)
    assert event_detected.results == mysession


def test_seh_notify_expiration(session_event_handler, session):

    seh = session_event_handler
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'SESSION.EXPIRE')

    seh.notify_expiration(session)
    assert event_detected.results == session


def test_session_handler_create_dgs(session_handler, cache_handler, session):
    """
    test objective:  create a new session and read it from the cachestore

    session_handler aspects tested:
        - apply_cache_handler_to_session_store
        - create_session
        - do_get_session
        - _retrieve_session
        - validate
        - on_change
    """
    sh = session_handler
    sh.cache_handler = cache_handler

    session.set_internal_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')
    sessionid = sh.create_session(session)
    cachedsession = sh.do_get_session(DefaultSessionKey(sessionid))

    assert cachedsession == session


def test_session_handler_delete(session_handler, cache_handler, session, capsys):
    """
    test objective:  delete a session from cache storage
    """
    sh = session_handler
    sh.cache_handler = cache_handler

    session.set_internal_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')

    sessionid = sh.create_session(session)
    sh.delete(session)

    with pytest.raises(UnknownSessionException):
        sh.do_get_session(DefaultSessionKey(sessionid))

        out, err = capsys.readouterr()
        assert 'Coult not find session' in out


@pytest.mark.parametrize('myminutes', [10, 50])
def test_sh_expired_session(
        session_handler, cache_handler, session, myminutes):
    """
    test objective:  validate idle and absolute timeout expiration handling

    session_handler aspects tested:
        - create_session
        - do_get_session
        - on_change
        - validate
        - on_expiration
        - before_invalid_notification
    """
    sh = session_handler
    sh.auto_touch = False
    sh.cache_handler = cache_handler

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event

    event_bus.register(event_listener, 'SESSION.EXPIRE')

    session.set_internal_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')
    sessionid = sh.create_session(session)
    cachedsession = sh.do_get_session(DefaultSessionKey(sessionid))

    now = datetime.datetime.now(pytz.utc)
    minutes_ago = datetime.timedelta(minutes=myminutes)
    cachedsession.last_access_time = now - minutes_ago

    sh.on_change(cachedsession)

    with pytest.raises(ExpiredSessionException):
        sh.do_get_session(DefaultSessionKey(sessionid))

        assert event_detected.results.identifiers


def test_sh_stopped_session(
        session_handler, cache_handler, session, monkeypatch):
    """
    test objective:  validate stopped session handling

    session_handler aspects tested:
        - create_session
        - do_get_session
        - on_change
        - validate
        - on_invalidation
        - before_invalid_notification
        - after_stopped
    """
    ch = cache_handler
    sh = session_handler
    monkeypatch.setattr(sh, 'auto_touch', False)
    sh.cache_handler = cache_handler

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event

    event_bus.register(event_listener, 'SESSION.STOP')

    session.set_internal_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')

    sessionid = sh.create_session(session)
    cachedsession = ch.get(domain='session', identifier=sessionid)

    now = datetime.datetime.now(pytz.utc)
    cachedsession.stop_timestamp = now
    ch.set(domain='session', identifier=sessionid, value=cachedsession)

    with pytest.raises(InvalidSessionException):
        sh.do_get_session(DefaultSessionKey(sessionid))

        assert event_detected.results.identifiers


def test_session_manager_start(session_manager, cache_handler, session_context):
    """
    test objective:

    aspects tested:
        - _create_session
        - create_exposed_session
    """
    sm = session_manager
    sm.cache_handler = cache_handler
    sm.event_bus = event_bus

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event

    event_bus.register(event_listener, 'SESSION.START')

    session = sm.start(session_context)

    assert (isinstance(session, DelegatingSession) and event_detected)


def test_session_manager_stop(
        session_manager, cache_handler, session_context, session_handler,
        capsys):
    """
    test objective:

    aspects tested:
        - stop
        - _lookup_required_session
    """
    sh = session_handler
    sm = session_manager
    sm.cache_handler = cache_handler
    sm.event_bus = event_bus

    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event

    event_bus.register(event_listener, 'SESSION.STOP')

    session = sm.start(session_context)  # a DelegatingSession
    sessionid = session.session_id

    sm.stop(session.session_key, 'random')

    with pytest.raises(UnknownSessionException):
        sh.do_get_session(DefaultSessionKey(sessionid))

        out, err = capsys.readouterr()
        assert ('Coult not find session' in out and
                isinstance(event_detected.results, namedtuple))


def test_delegatingsession_getters(
        session_manager, cache_handler, session_context):
    """
    test objective:  verify the pass-through getter methods

    session manager aspects tested:
        - get_X internal_attribute methods
    """
    sm = session_manager
    sm.cache_handler = cache_handler
    sm.event_bus = event_bus

    session = sm.start(session_context)  # returns a DelegatingSession

    assert (session.session_id is not None and
            session.start_timestamp is not None and
            session.last_access_time is not None and
            session.idle_timeout is not None and
            session.absolute_timeout is not None and
            session.host is not None)


def test_delegatingsession_setters(
        session_manager, cache_handler, session_context):
    sm = session_manager
    sm.cache_handler = cache_handler
    sm.event_bus = event_bus

    session = sm.start(session_context)  # returns a DelegatingSession
    session.idle_timeout = datetime.timedelta(minutes=90)
    assert session.idle_timeout == datetime.timedelta(minutes=90)

    session.absolute_timeout = datetime.timedelta(minutes=120)
    assert session.absolute_timeout == datetime.timedelta(minutes=120)

    old_last_access = session.last_access_time
    session.touch()
    assert session.last_access_time > old_last_access

    is_valid = sm.is_valid(session.session_key)
    assert is_valid
    session.stop(session.session_key)
    is_valid = sm.is_valid(session.session_key)
    assert not is_valid


def test_delegatingsession_internal_attributes(
        session_manager, cache_handler, session_context):
    """
    test objective:  verify the pass-through internal_attribute methods

    """
    sm = session_manager
    sm.cache_handler = cache_handler
    sm.event_bus = event_bus

    session = sm.start(session_context)  # returns a DelegatingSession

    session.set_internal_attribute('authenticated_session_key', True)
    result = session.get_internal_attribute('authenticated_session_key')

    assert result is True

    session.remove_internal_attribute('authenticated_session_key')

    result = session.get_internal_attribute('authenticated_session_key')

    assert result is None
