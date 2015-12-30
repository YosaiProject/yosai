import pytest
from yosai.core import (
    AuthzInfoResolver,
    Credential,
    CredentialResolver,
    DefaultPermission,
    IndexedAuthorizationInfo,
    PermissionResolver,
    RoleResolver,
    SimpleRole,
    UsernamePasswordToken,
)

@pytest.fixture(scope='session')
def authz_info_resolver():
    return AuthzInfoResolver(IndexedAuthorizationInfo)


@pytest.fixture(scope='session')
def credential_resolver():
    return CredentialResolver(Credential)


@pytest.fixture(scope='function')
def indexed_authz_info(permission_collection, role_collection):
    return IndexedAuthorizationInfo(roles=role_collection,
                                    permissions=permission_collection)


@pytest.fixture(scope='function')
def permission_collection():
    return {DefaultPermission(domain={'domain1'}, action={'action1'}),
            DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
            DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
            DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
            DefaultPermission(wildcard_string='*:action5')}


@pytest.fixture(scope='session')
def permission_resolver():
    return PermissionResolver(DefaultPermission)


@pytest.fixture(scope='function')
def role_collection():
    return {SimpleRole('role1'),
            SimpleRole('role2'),
            SimpleRole('role3')}


@pytest.fixture(scope='session')
def role_resolver():
    return RoleResolver(SimpleRole)


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user123',
                                 password='secret',
                                 remember_me=False,
                                 host='127.0.0.1')

