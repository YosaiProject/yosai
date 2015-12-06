import pytest

from yosai.core import (
    DefaultAuthenticator,
    UsernamePasswordToken,
    event_bus,
)

@pytest.fixture(scope='function')
def default_authenticator(account_store_realm):
    da = DefaultAuthenticator()
    da.realms = (account_store_realm,)
    da.event_bus = event_bus
    return da


@pytest.fixture(scope='function')
def valid_authc_token(authc_token)
