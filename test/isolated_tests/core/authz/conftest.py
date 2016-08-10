import pytest

from yosai.core import (
    DefaultPermission,
    IndexedPermissionVerifier,
    PermissionResolver,
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
def populated_simple_role():
    return SimpleRole('role1')

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
def indexed_permission_verifier():
    ipv = IndexedPermissionVerifier()
    ipv.permission_resolver = PermissionResolver(DefaultPermission)
    return ipv

@pytest.fixture(scope='function')
def simple_role_verifier():
    return SimpleRoleVerifier()
