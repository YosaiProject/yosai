import pytest

from yosai.core import (
    ModularRealmAuthorizer,
)

@pytest.fixture(scope='function')
def modular_realm_authorizer(account_store_realm, event_bus):
    mra = ModularRealmAuthorizer()
    asr = account_store_realm
    mra.realms = (account_store_realm,)
    mra.event_bus = event_bus
    return mra
