import pytest
import copy
from unittest.mock import create_autospec

from yosai import (
    DefaultPermission,
    ModularRealmAuthorizer,
    OrderedSet,
    IndexedAuthorizationInfo,
    SimpleRole,
    WildcardPermission,
)

from .doubles import (
    MockAuthzAccountStoreRealm,
    MockPermission,
)


@pytest.fixture(scope='function')
def authz_realms_collection():
    """
    three authorizing realms
    """
    return (MockAuthzAccountStoreRealm(),
            MockAuthzAccountStoreRealm(),
            MockAuthzAccountStoreRealm())

@pytest.fixture(scope='function')
def modular_realm_authorizer_patched(monkeypatch, authz_realms_collection):
    a = ModularRealmAuthorizer()
    monkeypatch.setattr(a, '_realms', authz_realms_collection)
    return a

@pytest.fixture(scope='function')
def indexed_authz_info():
    return IndexedAuthorizationInfo()

@pytest.fixture(scope='function')
def populated_simple_role():
    name = 'SimpleRole123'
    permissions = OrderedSet([MockPermission(False),
                              MockPermission(False),
                              MockPermission(True)])
    return SimpleRole(name=name, permissions=permissions)

@pytest.fixture(scope='function')
def default_wildcard_permission():
    return WildcardPermission()

@pytest.fixture(scope='function')
def default_domain_permission():
    return DefaultPermission()
