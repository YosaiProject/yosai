
#def test_idle_timeout
    """
    A session that idle timeouts will raise an exception at validation and the
    sessionmanager deletes the expired session from cache.
    """


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

#def test_session_attribute_state
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
