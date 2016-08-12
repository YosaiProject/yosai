
#def test_remember_me_at_login
    """
    Remember a user at login.  The remember_me cookie is to be set at login
    when remember_me setting is True in UsernamePasswordToken.  Confirm
    user identity.
    """

#def test_remember_me_with_expired_session
    """
    Send a request that contains an idle expired session_id and remember_me cookie.
    A new session is created and the user remembered.  Confirm user identity.
    """


#def test_forget_remembered_identity
    """
    Logout and ensure that the identity is forgotten through removal of the
    remember_me cookie.
    """
