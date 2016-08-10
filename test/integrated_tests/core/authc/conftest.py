import pytest

from yosai.core import (
    DefaultAuthenticator,
    event_bus,
)

import datetime


@pytest.fixture(scope='module')
def default_authenticator(account_store_realm, credential_resolver):
    da = DefaultAuthenticator()
    account_store_realm.credential_resolver = credential_resolver
    da.realms = (account_store_realm,)
    da.event_bus = event_bus
    return da
