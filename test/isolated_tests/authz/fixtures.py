import pytest
import copy
from unittest.mock import create_autospec

from yosai import (
    ModularRealmAuthorizer,
)

from .doubles import (
    MockAuthzAccountStoreRealm,
)


@pytest.fixture(scope='function')
def modular_realm_authorizer():
    return ModularRealmAuthorizer()

@pytest.fixture(scope='function')
def authz_realms_collection():

    dumbmock1 = type('DumbMock1', (object,), {})
    dumbmock2 = type('DumbMock2', (object,), {})
    return {MockAuthzAccountStoreRealm(), MockAuthzAccountStoreRealm(),
            MockAuthzAccountStoreRealm(), dumbmock1(), dumbmock2()}

