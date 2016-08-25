import pytest

from yosai.core import (
    DefaultAuthenticator,
)

import datetime


@pytest.fixture(scope='function')
def default_authenticator(account_store_realm, credential_resolver, event_bus):
    da = DefaultAuthenticator()
    account_store_realm.credential_resolver = credential_resolver
    da.realms = (account_store_realm,)
    da.event_bus = event_bus
    return da
