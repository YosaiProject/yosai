import pytest
from unittest import mock

from yosai.authc import (
    UsernamePasswordToken,
    DefaultAuthenticator,
    FailedAuthenticationEvent,
    SuccessfulAuthenticationEvent,
)

# UsernamePasswordToken Tests
def test_upt_clear_existing_password(username_password_token):
    """ clear a password equal to 'secret' """
    upt = username_password_token
    upt.clear() 
    assert upt.password == bytearray(b'\x00\x00\x00\x00\x00\x00')  


# -----------------------------------------------------------------------------
# DefaultAuthenticator Tests
# -----------------------------------------------------------------------------

