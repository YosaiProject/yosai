import pytest

from yosai.core import (
    DefaultAuthenticator,
    event_bus,
)

import datetime


@pytest.fixture(scope='module')
def default_authenticator(account_store_realm, credential_resolver):
    da = DefaultAuthenticator()
    da.realms = (account_store_realm,)
    da.event_bus = event_bus
    da.credential_resolver = credential_resolver
    return da
