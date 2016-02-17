import pytest
from marshmallow import Schema, fields

from yosai.core import (
    AccountStoreRealm,
    AuthzInfoResolver,
    Credential,
    CredentialResolver,
    DefaultPermission,
    IndexedAuthorizationInfo,
    NativeSecurityManager,
    PermissionResolver,
    RoleResolver,
    SecurityUtils,
    SimpleRole,
    UsernamePasswordToken,
    event_bus,
)
from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import (
    AlchemyAccountStore,
    Base,
    init_engine,
    init_session,
)


@pytest.fixture(scope='session')
def session(request):
    engine = init_engine()
    Base.metadata.create_all(engine)

    def drop_all():
        Base.metadata.drop_all(engine)

    request.addfinalizer(drop_all)

    return init_session(engine=engine)


@pytest.fixture(scope='session')
def yosai():
    return SecurityUtils()


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


@pytest.fixture(scope='session')
def cache_handler():
    return DPCacheHandler()


@pytest.fixture(scope='session')
def alchemy_store(session):
    return AlchemyAccountStore(session=session)


@pytest.fixture(scope='session')
def account_store_realm(cache_handler, alchemy_store, permission_resolver,
                        role_resolver, authz_info_resolver, credential_resolver):

    asr = AccountStoreRealm(name='AccountStoreRealm',
                            account_store=alchemy_store)

    asr.cache_handler = cache_handler

    asr.credential_resolver = credential_resolver
    asr.permission_resolver = permission_resolver
    asr.authz_info_resolver = authz_info_resolver
    asr.role_resolver = role_resolver

    return asr


@pytest.fixture(scope='session')
def configured_securityutils(native_security_manager, yosai):
    yosai.security_manager = native_security_manager
    return yosai


@pytest.fixture(scope='session')
def native_security_manager(account_store_realm, cache_handler, 
                            yosai):

    class AttributesSchema(Schema):
        name = fields.String()

    nsm = NativeSecurityManager(realms=(account_store_realm,),
                                session_attributes_schema=AttributesSchema)
    nsm.cache_handler = cache_handler
    nsm.event_bus = event_bus
    yosai.security_manager = nsm

    return nsm


