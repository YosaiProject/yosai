import pdb
from time import sleep

from yosai.web import (
    WebYosai
)


def test_idle_timeout(web_yosai, mock_web_registry, monkeypatch,
                      valid_username_password_token):
    """
    A session that idle timeouts will raise an exception at validation and the
    sessionmanager deletes the expired session from cache.
    """
    pdb.set_trace()
    monkeypatch.setattr(web_yosai.security_manager.session_manager.session_factory,
                        'idle_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        subject.login(valid_username_password_token)
        sleep(2)
        subject = WebYosai.get_current_subject()
        print(mock_web_registry)


#def test_absolute_timeout
    """
    A session that absolute timeouts will raise an exception at validation and
    the sessionmanager deletes the expired session from cache.
    """

#def test_stopped_session
    """
    When a user logs out, the user's session is stopped.
    """

#def test_websimplesession_serialization
    """
    Verify that a WebSimpleSession serializes correctly, across all supported
    Serialiers
    """

#def test_session_attributes(web_yosai)
    """
    Developer-defined session attribute schema is to serialize correctly
    """

#def csrf_token_management
    """
    CSRF Token generation and retrieval from session state
    """

#def flash_messages_management
    """
    flash messages saving and retrieval from session state
    """

#def test_anonymous_session_generation
    """
    Every web request should be associated with a session.  Consequently, an
    anonymous web request gets a new session associated with it.
    """

#def test_new_session_at_login
    """
    At login, an anonymous session is deleted from cache and a new session is created.
    """
