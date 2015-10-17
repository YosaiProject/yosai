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
def populated_simple_role():
    return SimpleRole(role_identifier='role1')

@pytest.fixture(scope='function')
def default_wildcard_permission():
    return WildcardPermission()

@pytest.fixture(scope='function')
def default_permission():
    return DefaultPermission()

@pytest.fixture(scope='function')
def permission_collection():
    return {DefaultPermission(domain={'domain1'}, action={'action1'}),
            DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
            DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
            DefaultPermission(wildcard_string='*:action5')}

@pytest.fixture(scope='function')
def test_permission_collection():
    perms = {DefaultPermission('domain_a:action_a'),
             DefaultPermission('domain_b:action_b'),
             DefaultPermission('domain_c:action_c')}
    return perms

@pytest.fixture(scope='function')
def role_collection():
    return {SimpleRole(role_identifier='role1'),
            SimpleRole(role_identifier='role2'),
            SimpleRole(role_identifier='role3')}


@pytest.fixture(scope='function')
def indexed_authz_info(permission_collection, role_collection):
    return IndexedAuthorizationInfo(roles=role_collection,
                                    permissions=permission_collection)
