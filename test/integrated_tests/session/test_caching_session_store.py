import pytest
import threading
import datetime
import pytz

from yosai import (
    DefaultSessionKey,
    ExpiredSessionException,
    ImmutableProxiedSession,
    InvalidSessionException,
    event_bus,
    UnknownSessionException,
)


def test_create_cache_session(session_store, session, cache_handler):
    """
    test objective:  cache new session entry and read session from cache

    aspects tested:
        - session.set_attribute
        - session_store.create
        - session_store.read
        - session_store.delete
        - cache_handler.get
        - session.__eq__
    """
    css = session_store

    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')
    sessionid = css.create(session)

    cached_session = css.read(sessionid)
    cached_session_token = css.cache_handler.get('session', 'user12345678')
    assert (cached_session == session and
            cached_session_token == DefaultSessionKey(sessionid))


def test_update_cached_session(session_store, session):
    """
    this test will pass if test_create_cache_session runs first
    """

    css = session_store
    session.set_attribute('testing', 'testing123')
    css.update(session)
    cached_session = css.read(session.session_id)
    assert cached_session == session


def test_delete_cached_session(session_store, session, cache_handler):
    """
    this test will pass if test_create_cache_session runs first
    """

    css = session_store
    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')
    sessionid = session.session_id
    css.delete(session)

    cached_session = css.read(sessionid)
    cached_session_token = cache_handler.get('session', 'user12345678')
    assert cached_session is None
    assert cached_session_token is None


def test_seh_notify_start(session_event_handler, session):

    seh = session_event_handler
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'SESSION.START')

    seh.notify_start(session)
    assert event_detected.results == session


def test_seh_notify_stop(session_event_handler, session):

    seh = session_event_handler
    event_detected = None

    def event_listener(event):
        nonlocal event_detected
        event_detected = event
    event_bus.register(event_listener, 'SESSION.STOP')

    seh.notify_stop(session)
    assert event_detected.results == session


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

    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
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

    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
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

    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')
    sessionid = sh.create_session(session)
    cachedsession = sh.do_get_session(DefaultSessionKey(sessionid))

    now = datetime.datetime.now(pytz.utc)
    minutes_ago = datetime.timedelta(minutes=myminutes)
    cachedsession.last_access_time = now - minutes_ago

    sh.on_change(cachedsession)

    with pytest.raises(ExpiredSessionException):
        sh.do_get_session(DefaultSessionKey(sessionid))

        assert event_detected.results == ImmutableProxiedSession(session)


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

    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY',
                          'user12345678')

    sessionid = sh.create_session(session)
    cachedsession = ch.get(domain='session', identifier=sessionid)

    now = datetime.datetime.now(pytz.utc)
    cachedsession.stop_timestamp = now
    ch.set(domain='session', identifier=sessionid, value=cachedsession)

    with pytest.raises(InvalidSessionException):
        sh.do_get_session(DefaultSessionKey(sessionid))

        assert event_detected.results == ImmutableProxiedSession(session)
