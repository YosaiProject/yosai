import pytest

from yosai.core import (
    DefaultAuthenticator,
    event_bus,
)

@pytest.fixture(scope='module')
def default_authenticator(account_store_realm):
    da = DefaultAuthenticator()
    da.realms = (account_store_realm,)
    da.event_bus = event_bus
    return da
