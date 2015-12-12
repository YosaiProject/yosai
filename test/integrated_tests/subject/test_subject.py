import pytest
from yosai.core import (
    AuthenticationException,
)


def test_subject_valid_login(new_subject, valid_username_password_token, 
                             thedude, thedude_credentials):
    new_subject.login(valid_username_password_token)


def test_subject_invalid_login(new_subject, invalid_username_password_token, 
                               thedude, thedude_credentials):
    with pytest.raises(AuthenticationException):
        new_subject.login(invalid_username_password_token)

