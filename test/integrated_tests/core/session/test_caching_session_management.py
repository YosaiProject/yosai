import pytest
import time
from collections import namedtuple

from yosai.core import (
    SessionKey,
    DelegatingSession,
    ExpiredSessionException,
    InvalidSessionException,
    SimpleIdentifierCollection,
    SimpleSession,
)


session_tuple = namedtuple('session_tuple', ['identifiers', 'session_key'])


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
    assert isinstance(cached_session, SimpleSession)


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

    session.set_internal_attribute('SubjectContext.IDENTIFIERS_SESSION_KEY',
                                   'user12345678')
    sessionid = sh.create_session(session)
    cachedsession = sh.do_get_session(SessionKey(sessionid))

    assert cachedsession == session


def test_session_handler_delete(session_handler, cache_handler, session, capsys):
    """
    test objective:  delete a session from cache storage
    """
    sh = session_handler
    sh.cache_handler = cache_handler

    session.set_internal_attribute('SubjectContext.IDENTIFIERS_SESSION_KEY',
                                   'user12345678')

    sessionid = sh.create_session(session)
    sh.delete(session)

    with pytest.raises(ValueError):
        sh.do_get_session(SessionKey(sessionid))

        out, err = capsys.readouterr()
        assert 'Coult not find session' in out


def test_sh_idle_expired_session(
        session_handler, cache_handler, session, event_bus, monkeypatch):
    """
    test objective:  validate idle timeout expiration handling / communication

    idle test:  idle set to 5 minutes, last accessed set to 6 minutes ago
    """
    sh = session_handler
    sh.auto_touch = False
    sh.cache_handler = cache_handler

    event_detected = None

    def event_listener(items=None):
        nonlocal event_detected
        event_detected = items

    event_bus.subscribe(event_listener, 'SESSION.EXPIRE')

    session.set_internal_attribute('SubjectContext.IDENTIFIERS_SESSION_KEY',
                                   'user12345678')
    sessionid = sh.create_session(session)
    cachedsession = sh.do_get_session(SessionKey(sessionid))

    idle_timeout = (5 * 60 * 1000)
    absolute_timeout = (30 * 60 * 1000)
    start_timestamp = round(time.time() * 1000) - (10 * 60 * 1000)
    last_access_time = round(time.time() * 1000) - (6 * 60 * 1000)

    monkeypatch.setattr(cachedsession, 'last_access_time', last_access_time)
    monkeypatch.setattr(cachedsession, 'start_timestamp', start_timestamp)
    monkeypatch.setattr(cachedsession, 'idle_timeout', idle_timeout)
    monkeypatch.setattr(cachedsession, 'absolute_timeout', absolute_timeout)

    sh.on_change(cachedsession)

    with pytest.raises(ExpiredSessionException):
        sh.do_get_session(SessionKey(sessionid))

        assert event_detected.items.identifiers


def test_sh_stopped_session(
        session_handler, cache_handler, session, monkeypatch, event_bus):
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
    sh.cache_handler = cache_handler

    event_detected = None

    def event_listener(items=None):
        nonlocal event_detected
        event_detected = items

    event_bus.subscribe(event_listener, 'SESSION.STOP')

    session.set_internal_attribute('SubjectContext.IDENTIFIERS_SESSION_KEY',
                                   'user12345678')

    sessionid = sh.create_session(session)
    cachedsession = ch.get(domain='session', identifier=sessionid)

    now = round(time.time() * 1000)
    cachedsession.stop_timestamp = now
    ch.set(domain='session', identifier=sessionid, value=cachedsession)

    with pytest.raises(InvalidSessionException):
        sh.do_get_session(SessionKey(sessionid))

        assert event_detected.identifiers


def test_session_manager_start(
        session_manager, cache_handler, session_context, event_bus, monkeypatch):
    """
    test objective:

    aspects tested:
        - _create_session
        - create_exposed_session
    """
    sm = session_manager
    sm.apply_cache_handler(cache_handler)
    sm.apply_event_bus(event_bus)

    event_detected = None

    def event_listener(items=None):
        nonlocal event_detected
        event_detected = items

    event_bus.subscribe(event_listener, 'SESSION.START')

    session = sm.start(session_context)

    assert (isinstance(session, DelegatingSession) and event_detected)


def test_session_manager_stop(
        session_manager, cache_handler, session_context, session_handler,
        capsys, event_bus):
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

    def event_listener(items=None):
        nonlocal event_detected
        event_detected = items

    event_bus.subscribe(event_listener, 'SESSION.STOP')

    session = sm.start(session_context)  # a DelegatingSession
    sessionid = session.session_id

    sm.stop(session.session_key, 'random')

    with pytest.raises(ValueError):
        sh.do_get_session(SessionKey(sessionid))

        out, err = capsys.readouterr()
        assert ('Coult not find session' in out and
                isinstance(event_detected.results, namedtuple))


def test_delegatingsession_internal_attributes(
        session_manager, cache_handler, session_context, event_bus):
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
