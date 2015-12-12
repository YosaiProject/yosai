import pytest
from yosai.core import (
    AuthenticationException,
)


def test_subject_invalid_login(new_subject, invalid_username_password_token, 
                               thedude, thedude_credentials):
    with pytest.raises(AuthenticationException):
        new_subject.login(invalid_username_password_token)


def test_authenticated_subject_session_attribute(
        new_subject, valid_username_password_token, thedude, thedude_credentials):
    new_subject.login(valid_username_password_token)

    session = new_subject.get_session()
    print('\n\n', session)
    session.set_attribute('name', 'nametest')
    session.set_attribute('unknown', 'unknown')
    assert (session.get_attribute('name') == 'nametest' and
            session.get_attribute('unknown') is None) 
