import pytest

from yosai.core import (
    ModularRealmAuthorizer,
    event_bus,
)

@pytest.fixture(scope='module')
def modular_realm_authorizer(account_store_realm): 
    mra = ModularRealmAuthorizer()
    asr = account_store_realm
    mra.realms = (account_store_realm,)
    mra.event_bus = event_bus
    return mra

