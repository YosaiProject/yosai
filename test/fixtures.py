import pytest
from unittest import mock

from yosai.core import (
    AuthzInfoResolver,
    Credential, 
    CredentialResolver,
    DefaultPermission,
    IndexedAuthorizationInfo,
    PermissionResolver,
    RoleResolver,
    SimpleRole,
)


@pytest.fixture(scope='function')
def authz_info_resolver():
    return AuthzInfoResolver(IndexedAuthorizationInfo)


@pytest.fixture(scope='function')
def credential_resolver():
    return CredentialResolver(Credential)


@pytest.fixture(scope='function')
def permission_collection():
    return {DefaultPermission(domain={'domain1'}, action={'action1'}),
            DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
            DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
            DefaultPermission(wildcard_string='*:action5')}


@pytest.fixture(scope='function')
def permission_resolver():
    return PermissionResolver(DefaultPermission)


@pytest.fixture(scope='function')
def role_collection():
    return {SimpleRole(role_identifier='role1'),
            SimpleRole(role_identifier='role2'),
            SimpleRole(role_identifier='role3')}


@pytest.fixture(scope='function')
def role_resolver():
    return RoleResolver(SimpleRole)
