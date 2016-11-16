from time import sleep
import pytest

from yosai.core import (
    AdditionalAuthenticationRequired,
)

from yosai.web import (
    WebYosai
)

from cbor2.encoder import CBOREncodeError

def test_idle_timeout(web_yosai, mock_web_registry, monkeypatch,
                      valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    A session that idle timeouts will raise an exception at validation and the
    sessionmanager deletes the expired session from cache.
    """
    monkeypatch.setattr(web_yosai.security_manager.session_manager, 'idle_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)

        sleep(2)
        try:
            subject = WebYosai.get_current_subject()
        except mock_web_registry.mock_exception:
            assert (mock_web_registry.current_session_id is None and
                    mock_web_registry.session_id_history[0][0] == 'SET')


def test_absolute_timeout(web_yosai, mock_web_registry, monkeypatch,
        valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    A session that absolute timeouts will raise an exception at validation and
    the sessionmanager deletes the expired session from cache.
    """
    monkeypatch.setattr(web_yosai.security_manager.session_manager, 'absolute_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)
        sleep(2)
        try:
            subject = WebYosai.get_current_subject()
        except mock_web_registry.mock_exception:
            assert (mock_web_registry.current_session_id is None and
                    mock_web_registry.session_id_history[0][0] == 'SET')


def test_stopped_session(web_yosai, mock_web_registry,
        valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    When a user logs out, the user's session is stopped.
    """
    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)
        subject.logout()
        assert (mock_web_registry.current_session_id is None and
                mock_web_registry.session_id_history[0][0] == 'SET' and
                mock_web_registry.session_id_history[1][0] == 'SET' and
                mock_web_registry.session_id_history[2][0] == 'DELETE')


def test_new_session_at_login(web_yosai, mock_web_registry,
        valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    At login, an anonymous session is deleted from cache and a new session is created.
    """
    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        old_session_id = subject.get_session().session_id
        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)
        new_session_id = subject.get_session().session_id
        assert old_session_id != new_session_id


def test_session_attributes(web_yosai, mock_web_registry, monkeypatch,
        valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    Developer-defined session attribute schema is to serialize correctly
    """

    value1 = {'attribute1': 'value1'}
    values = {'attribute2': 'value2', 'attribute3': 'value3'}

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        old_session = subject.get_session()

        old_session.set_attribute('attribute1', 'value1')
        old_session.set_attributes(values)

        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)

        new_session = subject.get_session()
        values.update(value1)
        assert (new_session.get_attributes(values.keys()) == values.keys())

    class Value4:
        pass

    with pytest.raises(CBOREncodeError):
        new_session.set_attribute('attribute4', Value4())  # not serializable

def test_csrf_token_management(web_yosai, mock_web_registry, monkeypatch,
        valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    CSRF Token generation and retrieval from session state
    """

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        old_session = subject.get_session()
        old_token = old_session.get_csrf_token()

        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)

        new_session = subject.get_session()
        new_token = new_session.new_csrf_token()

        assert new_token != old_token


def test_flash_messages_management(web_yosai, mock_web_registry, monkeypatch,
        valid_thedude_username_password_token, valid_thedude_totp_token):
    """
    flash messages saving and retrieval from session state
    """

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        old_session = subject.get_session()

        msg = 'Flash Message One, Default Queue'
        msg2 = 'Flash Message Two, Default Queue'
        old_session.flash(msg)
        old_session.flash(msg2)

        msg3 = 'Flash Message Two'
        old_session.flash(msg3, queue='queue2')

        default_queue_flash_peek = old_session.peek_flash()
        default_queue_flash_pop = old_session.pop_flash()
        try:
            subject.login(valid_thedude_username_password_token)
        except AdditionalAuthenticationRequired:
            subject.login(valid_thedude_totp_token)

        new_session = subject.get_session()
        default_queue_flash_peek_new = new_session.peek_flash()
        default_queue_flash_pop_new = new_session.pop_flash()
        queue2_flash_peek_new = new_session.peek_flash('queue2')
        queue2_flash_pop_new = new_session.pop_flash('queue2')

    assert (default_queue_flash_peek == [msg, msg2]
            and default_queue_flash_pop == [msg, msg2]
            and default_queue_flash_peek_new == []
            and default_queue_flash_pop_new is None
            and queue2_flash_peek_new == [msg3]
            and queue2_flash_pop_new == [msg3])
