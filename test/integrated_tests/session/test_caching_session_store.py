import pytest
import threading

from yosai import (
    DefaultSessionKey,
    event_bus,
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
    print('\n\ncached_session.start_timestamp: ', cached_session.start_timestamp)
    print('\n\n-------session.start_timestamp: ', session.start_timestamp)
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
    event_notified = False

    def event_listener(event=session):
        nonlocal event_notified
        event_notified = True
        session.set_attribute('notify_start', True)
    event_bus.register(event_listener, 'SESSION.START')

    seh.notify_start(session)
    print('event_notified is: ', event_notified)
    assert session.get_attribute('notify_start') is True
