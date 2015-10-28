import pytest
import copy
from unittest.mock import create_autospec

from yosai import (
    DefaultPermission,
    ModularRealmAuthorizer,
    OrderedSet,
    IndexedAuthorizationInfo,
    IndexedPermissionVerifier,
    SimpleRole,
    SimpleRoleVerifier,
    WildcardPermission,
    event_bus,
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
def modular_realm_authorizer_patched(
        monkeypatch, authz_realms_collection, patched_event_bus):
    a = ModularRealmAuthorizer()
    monkeypatch.setattr(a, '_realms', authz_realms_collection)
    monkeypatch.setattr(a, '_event_bus', patched_event_bus)
    return a

@pytest.fixture(scope='function')
def populated_simple_role():
    return SimpleRole(role_identifier='role1')

@pytest.fixture(scope='function')
def default_wildcard_permission():
    return WildcardPermission()

@pytest.fixture(scope='function')
def default_permission():
    return DefaultPermission()

@pytest.fixture(scope='function')
def test_permission_collection():
    perms = {DefaultPermission('domain_a:action_a'),
             DefaultPermission('domain_b:action_b'),
             DefaultPermission('domain_c:action_c')}
    return perms


@pytest.fixture(scope='function')
def indexed_authz_info(permission_collection, role_collection):
    return IndexedAuthorizationInfo(roles=role_collection,
                                    permissions=permission_collection)


@pytest.fixture(scope='function')
def indexed_permission_verifier():
    return IndexedPermissionVerifier()


@pytest.fixture(scope='function')
def simple_role_verifier():
    return SimpleRoleVerifier()
