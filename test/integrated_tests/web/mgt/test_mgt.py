import time

from yosai.web import (
    WebYosai,
)


def test_remember_me_at_login(
        web_yosai, mock_web_registry, remembered_valid_username_password_token):
    """
    Remember a user at login.  The remember_me cookie is to be set at login
    when remember_me setting is True in UsernamePasswordToken.  Confirm
    user identity.
    """

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        assert mock_web_registry.current_remember_me is None
        subject.login(remembered_valid_username_password_token)
        assert mock_web_registry.current_remember_me is not None


def test_remember_me_with_expired_session(
        web_yosai, mock_web_registry, remembered_valid_username_password_token,
        monkeypatch):
    """
    Send a request that contains an idle expired session_id and remember_me cookie.
    A new session is created and the user remembered.  Confirm user identity.
    """
    monkeypatch.setattr(web_yosai.security_manager.session_manager.session_factory,
                        'idle_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        subject.login(remembered_valid_username_password_token)

        old_session_id = subject.get_session().session_id
        time.sleep(2)
        subject = WebYosai.get_current_subject()
        new_session_id = subject.get_session().session_id

        assert old_session_id != new_session_id


#def test_forget_remembered_identity
    """
    Logout and ensure that the identity is forgotten through removal of the
    remember_me cookie.
    """
