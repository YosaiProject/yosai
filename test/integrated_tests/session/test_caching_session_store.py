import pytest

def test_create_session(session_store, session, cache_handler):
    """
    test objective:  cache a session through a session store

    aspects tested:
        - session.set_attribute
        - session_store.create
        - cache_handler.get
        - session.__eq__
    """
    css = session_store

    session.set_attribute('DefaultSubjectContext.IDENTIFIERS_SESSION_KEY', 'dkc123')
    css.create(session)

    cached_session = cache_handler.get('session', ... )

    assert cached_session == session
