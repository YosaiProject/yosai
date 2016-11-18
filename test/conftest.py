import pytest

from yosai.core import (
    AccountStoreRealm,
    CachingSessionStore,
    DefaultPermission,
    LazySettings,
    NativeSecurityManager,
    NativeSessionHandler,
    PasslibVerifier,
    SerializationManager,
    TOTPToken,
    UsernamePasswordToken,
    Yosai,
)

from yosai.core import event_bus as eventbus

from yosai.web import (
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
def core_settings():
    return LazySettings(env_var='YOSAI_CORE_SETTINGS')


@pytest.fixture(scope='function')
def web_settings():
    return LazySettings(env_var='YOSAI_WEB_SETTINGS')


@pytest.fixture(scope='function')
def session(cache_handler, request, settings):
    session_maker = init_session(settings=settings)
    session = session_maker()
    return session



@pytest.fixture(scope='function')
def permission_collection():
    return [DefaultPermission(parts=dict(domain={'domain1'}, action={'action1'})),
            DefaultPermission(parts=dict(domain={'domain2'}, action={'action1', 'action2'})),
            DefaultPermission(parts=dict(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'})),
            DefaultPermission(parts=dict(domain={'domain4'}, action={'action1', 'action2'})),
            DefaultPermission(parts=dict(domain={'domain4'}, action={'action3'}, target={'target1'})),
            DefaultPermission(wildcard_string='*:action5')]


@pytest.fixture(scope='function')
def role_collection():
    return {'role1', 'role2', 'role3'}


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user123',
                                 password='secret',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='function')
def totp_token():
    return TOTPToken('123456')


@pytest.fixture(scope='function')
def alchemy_store(settings, session):
    return AlchemyAccountStore(settings=settings)


@pytest.fixture(scope='function')
def serialization_manager(session_attributes):
    return SerializationManager(session_attributes)


@pytest.fixture(scope='function')
def cache_handler(settings, serialization_manager):
    return DPCacheHandler(settings=settings, serialization_manager=serialization_manager)



@pytest.fixture(scope='function')
def passlib_verifier(settings):
    return PasslibVerifier(settings)


@pytest.fixture(scope='function')
def authc_verifiers(passlib_verifier):
    return (passlib_verifier,)


@pytest.fixture(scope='function')
def account_store_realm(cache_handler, alchemy_store, authc_verifiers):
    asr = AccountStoreRealm(name='AccountStoreRealm',
                            account_store=alchemy_store,
                            authc_verifiers=authc_verifiers)
    asr.cache_handler = cache_handler
    return asr


@pytest.fixture(scope='session')
def event_bus():
    return eventbus


@pytest.fixture(scope='function')
def native_security_manager(account_store_realm, cache_handler,
                            yosai, event_bus, settings):

    nsm = NativeSecurityManager(yosai,
                                settings,
                                realms=(account_store_realm,))
    nsm.cache_handler = cache_handler
    nsm.event_bus = event_bus
    yosai.security_manager = nsm  # why is this here?  TBD.

    return nsm

@pytest.fixture(scope='session')
def mock_serializable():
    class MockSerializable:

        def __init__(self, attr1, attr2, attr3):
            self.attribute1 = attr1
            self.attribute2 = attr2
            self.attribute3 = attr3

        def __getstate__(self):
            return {'attribute1': self.attribute1,
                    'attribute2': self.attribute2,
                    'attribute3': self.attribute3}

        def __setstate__(self, state):
            self.attribute1 = state['attribute1']
            self.attribute2 = state['attribute2']
            self.attribute3 = state['attribute3']

    return MockSerializable


@pytest.fixture(scope='session')
def session_attributes(mock_serializable):
    return [mock_serializable]


@pytest.fixture(scope='function')
def yosai(session_attributes):
    return Yosai(env_var='YOSAI_CORE_SETTINGS',
                 session_attributes=session_attributes)


@pytest.fixture(scope='function')
def web_yosai(session_attributes):
    return WebYosai(env_var='YOSAI_WEB_SETTINGS',
                    session_attributes=session_attributes)


@pytest.fixture(scope='function')
def mock_web_registry():
    return MockWebRegistry()


@pytest.fixture(scope='function')
def session_store(cache_handler):
    css = CachingSessionStore()
    css.cache_handler = cache_handler
    return css


@pytest.fixture(scope='function')
def session_handler(session_store, event_bus):
    handler = NativeSessionHandler()
    handler.session_store = session_store
    handler.event_bus = event_bus
    return handler
