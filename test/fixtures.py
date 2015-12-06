import pytest
from passlib.context import CryptContext
import datetime

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

from yosai_alchemystore import (
    Session,
)

from yosai_alchemystore.models.models import (
    Credential,
    User,
)


@pytest.fixture(scope='function')
def authz_info_resolver():
    return AuthzInfoResolver(IndexedAuthorizationInfo)


@pytest.fixture(scope='function')
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


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user123',
                                 password='letsgobowling',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='module')
def user_thedude(request, cache_handler):
    cc = CryptContext(["bcrypt_sha256"])
    credentials = cc.encrypt("letsgobowling")

    session = Session()

    thirty_from_now = datetime.datetime.now() + datetime.timedelta(days=30)

    thedude = User(first_name='Jeffrey',
                   last_name='Lebowski',
                   identifier='thedude')
    
    credential = Credential(user_id=thedude.pk_id,
                            credential=credentials,
                            expiration_dt=thirty_from_now)
    
    session.add_all([thedude, credential])

    session.commit()

    def remove_user():
        nonlocal cache_handler
        cache_handler.delete(domain="credentials",
                             identifier=thedude.identifier)
        cache_handler.delete(domain="authz_info",
                             identifier=thedude.identifier)
        session.delete(thedude)
        session.commit()

    request.addfinalizer(remove_user)

