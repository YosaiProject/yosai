import pytest

from yosai.core import (
    AccountStoreRealm,
    AuthzInfoResolver,
    Credential,
    CredentialResolver,
    DefaultPermission,
    IndexedAuthorizationInfo,
    LazySettings,
    NativeSecurityManager,
    PermissionResolver,
    RoleResolver,
    SerializationManager,
    SimpleRole,
    UsernamePasswordToken,
    Yosai,
    event_bus,
)

from yosai.web import (
    WebSecurityManager,
    WebYosai,
)


from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import (
    AlchemyAccountStore,
    init_session,
)

from .doubles import (
    MockWebRegistry,
)

# -----------------------------------------------------------------------------
# Core Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture(scope='function')
def settings():
    return LazySettings(env_var='YOSAI_SETTINGS')


@pytest.fixture(scope='function')
def session(cache_handler, request, settings):
    session_maker = init_session(settings=settings)
    session = session_maker()
    return session


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
    return {SimpleRole('role1'),
            SimpleRole('role2'),
            SimpleRole('role3')}


@pytest.fixture(scope='function')
def role_resolver():
    return RoleResolver(SimpleRole)


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user123',
                                 password='secret',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='function')
def alchemy_store(settings, session):
    return AlchemyAccountStore(settings=settings)


@pytest.fixture(scope='function')
def serialization_manager(attributes_schema):
    return SerializationManager(attributes_schema)


@pytest.fixture(scope='function')
def cache_handler(settings, serialization_manager):
    return DPCacheHandler(settings=settings, serialization_manager=serialization_manager)


@pytest.fixture(scope='function')
def account_store_realm(cache_handler, alchemy_store, permission_resolver,
                        role_resolver, authz_info_resolver, credential_resolver,
                        settings):

    asr = AccountStoreRealm(settings,
                            name='AccountStoreRealm',
                            account_store=alchemy_store)

    asr.cache_handler = cache_handler

    asr.credential_resolver = credential_resolver
    asr.permission_resolver = permission_resolver
    asr.authz_info_resolver = authz_info_resolver
    asr.role_resolver = role_resolver

    return asr


@pytest.fixture(scope='function')
def native_security_manager(account_store_realm, cache_handler,
                            yosai):

    class AttributesSchema:
        def __init__(self):
            self.name = 'Jeffrey Lebowski'

    nsm = NativeSecurityManager(realms=(account_store_realm,),
                                session_attributes_schema=AttributesSchema)
    nsm.cache_handler = cache_handler
    nsm.event_bus = event_bus
    yosai.security_manager = nsm  # why is this here?  TBD.

    return nsm


@pytest.fixture(scope='session')
def attributes_schema():
    class SessionAttributesSchema:

        def __init__(self):
            self.attribute1 = 'attribute1'
            self.attribute2 = None
            self.attribute3 = None

        def __getstate__(self):
            return {'attribute1': self.attribute1,
                    'attribute2': self.attribute2,
                    'attribute3': self.attribute3}

        def __setstate__(self, state):
            self.attribute1 = state['attribute1']
            self.attribute2 = state['attribute2']
            self.attribute3 = state['attribute3']

    return SessionAttributesSchema


@pytest.fixture(scope='function')
def yosai(attributes_schema):
    return Yosai(env_var='YOSAI_SETTINGS',
                 session_attributes_schema=attributes_schema)


@pytest.fixture(scope='function')
def web_yosai(attributes_schema):
    return WebYosai(env_var='YOSAI_SETTINGS',
                    session_attributes_schema=attributes_schema)


@pytest.fixture(scope='function')
def mock_web_registry():
    return MockWebRegistry()
