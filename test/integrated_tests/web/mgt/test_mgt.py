import time
from yosai.core import (
    AdditionalAuthenticationRequired,
)
from yosai.web import (
    WebYosai,
)


def test_remember_me_at_login(
        web_yosai, mock_web_registry, remembered_valid_thedude_username_password_token,
        remembered_valid_thedude_totp_token):
    """
    Remember a user at login.  The remember_me cookie is to be set at login
    when remember_me setting is True in UsernamePasswordToken.  Confirm
    user identity.
    """

    with WebYosai.context(web_yosai, mock_web_registry):
        new_subject = WebYosai.get_current_subject()
        assert mock_web_registry.current_remember_me is None

        try:
            new_subject.login(remembered_valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            new_subject.login(remembered_valid_thedude_totp_token)

        assert mock_web_registry.current_remember_me is not None


def test_remember_me_with_expired_session(
        web_yosai, mock_web_registry, monkeypatch,
        remembered_valid_thedude_username_password_token, remembered_valid_thedude_totp_token
        ):
    """
    Send a request that contains an idle expired session_id and remember_me cookie.
    A new session is created and the user remembered.  Confirm user identity.
    """
    monkeypatch.setattr(web_yosai.security_manager.session_manager, 'idle_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        try:
            subject.login(remembered_valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(remembered_valid_thedude_totp_token)

        old_session_id = subject.get_session().session_id
        time.sleep(2)
        subject = WebYosai.get_current_subject()
        new_session_id = subject.get_session().session_id

        assert old_session_id != new_session_id


def test_forget_remembered_identity(
        web_yosai, mock_web_registry, monkeypatch,
        remembered_valid_thedude_username_password_token, remembered_valid_thedude_totp_token):
    """
    Logout and ensure that the identity is forgotten through removal of the
    remember_me cookie.
    """
    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        try:
            subject.login(remembered_valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(remembered_valid_thedude_totp_token)

        assert mock_web_registry.current_remember_me is not None
        subject.logout()
        assert mock_web_registry.current_remember_me is None
