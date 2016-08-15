from time import sleep
from yosai.core import (
    ExpiredSessionException
)
from yosai.web import (
    WebYosai
)


def test_idle_timeout(web_yosai, mock_web_registry, monkeypatch,
                      valid_username_password_token):
    """
    A session that idle timeouts will raise an exception at validation and the
    sessionmanager deletes the expired session from cache.
    """
    monkeypatch.setattr(web_yosai.security_manager.session_manager.session_factory,
                        'idle_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        subject.login(valid_username_password_token)
        sleep(2)
        try:
            subject = WebYosai.get_current_subject()
        except ExpiredSessionException:
            assert (mock_web_registry.current_session_id is None and
                    mock_web_registry.session_id_history[0][0] == 'SET')


def test_absolute_timeout(web_yosai, mock_web_registry, monkeypatch,
                          valid_username_password_token):
    """
    A session that absolute timeouts will raise an exception at validation and
    the sessionmanager deletes the expired session from cache.
    """
    monkeypatch.setattr(web_yosai.security_manager.session_manager.session_factory,
                        'absolute_timeout', 1000)  # milliseconds

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        subject.login(valid_username_password_token)
        sleep(2)
        try:
            subject = WebYosai.get_current_subject()
        except ExpiredSessionException:
            assert (mock_web_registry.current_session_id is None and
                    mock_web_registry.session_id_history[0][0] == 'SET')


def test_stopped_session(web_yosai, mock_web_registry, valid_username_password_token):
    """
    When a user logs out, the user's session is stopped.
    """
    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        subject.login(valid_username_password_token)
        subject.logout()
        assert (mock_web_registry.current_session_id is None and
                mock_web_registry.session_id_history[0][0] == 'SET' and
                mock_web_registry.session_id_history[1][0] == 'SET' and
                mock_web_registry.session_id_history[2][0] == 'DELETE')


def test_new_session_at_login(web_yosai, mock_web_registry, valid_username_password_token):
    """
    At login, an anonymous session is deleted from cache and a new session is created.
    """
    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()
        old_session_id = subject.get_session().session_id

        subject.login(valid_username_password_token)
        new_session_id = subject.get_session().session_id
        assert old_session_id != new_session_id


def test_session_attributes(web_yosai, mock_web_registry, monkeypatch,
                            valid_username_password_token):
    """
    Developer-defined session attribute schema is to serialize correctly
    """

    value1 = {'attribute1': 'value1'}
    values = {'attribute2': 'value2', 'attribute3': 'value3'}

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        old_session = subject.get_session()
        old_session.set_attribute('attribute1', value1['attribute1'])
        old_session.set_attributes(values)

        subject.login(valid_username_password_token)

        new_session = subject.get_session()
        new_session.set_attribute('attribute4', 'value4')

        assert (new_session.get_attribute('attribute1') == value1['attribute1'] and
                new_session.get_attributes(values.keys()) == values and
                new_session.get_attribute('attribute4') == 'value4')


def test_csrf_token_management(web_yosai, mock_web_registry, monkeypatch,
                               valid_username_password_token):
    """
    CSRF Token generation and retrieval from session state
    """

    with WebYosai.context(web_yosai, mock_web_registry):
        subject = WebYosai.get_current_subject()

        old_session = subject.get_session()
        old_token = old_session.get_csrf_token()

        subject.login(valid_username_password_token)

        new_session = subject.get_session()
        new_token = new_session.new_csrf_token()

        assert new_token != old_token


def test_flash_messages_management(web_yosai, mock_web_registry, monkeypatch,
                                   valid_username_password_token):
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
        subject.login(valid_username_password_token)

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
