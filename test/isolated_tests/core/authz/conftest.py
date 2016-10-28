import pytest

from yosai.core import (
    DefaultPermission,
    IndexedPermissionVerifier,
    SimpleRoleVerifier,
    WildcardPermission,
)


@pytest.fixture(scope='function')
def default_wildcard_permission():
    return WildcardPermission()

@pytest.fixture(scope='function')
def default_permission():
    return DefaultPermission()


@pytest.fixture(scope='function')
def test_permission_collection():
    return {'domain_a:action_a', 'domain_b:action_b', 'domain_c:action_c'}


@pytest.fixture(scope='function')
def indexed_permission_verifier():
    return IndexedPermissionVerifier()


@pytest.fixture(scope='function')
def simple_role_verifier():
    return SimpleRoleVerifier()
