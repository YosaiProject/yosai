import pytest
from unittest import mock

from yosai.core import (
    AccountStoreRealm,
    DefaultAuthenticator,
    DefaultEventBus,
    DefaultSubjectContext,
    FirstRealmSuccessfulStrategy,
    ModularRealmAuthorizer,
    SimpleIdentifierCollection,
    UsernamePasswordToken,
)

from .doubles import (
    MockAccountStore,
    MockPubSub,
    MockSecurityManager,
    MockSession,
    MockSubject,
)

from .session.doubles import (
    MockDefaultNativeSessionManager,
)

from .authz.doubles import (
    MockAuthzAccountStoreRealm,
)


@pytest.fixture(scope='function')
def mock_account_store():
    return MockAccountStore()


@pytest.fixture(scope='function')
def mock_pubsub():
    return MockPubSub()


@pytest.fixture(scope='function')
def patched_event_bus(mock_pubsub, monkeypatch):
    eb = DefaultEventBus()
    monkeypatch.setattr(eb, '_event_bus', mock_pubsub)
    return eb


@pytest.fixture(scope="function")
def first_realm_successful_strategy():
    return FirstRealmSuccessfulStrategy()


@pytest.fixture(scope='function')
def default_authenticator(core_settings):
    return DefaultAuthenticator(core_settings)


@pytest.fixture(scope='function')
def mock_default_session_manager(core_settings):
    return MockDefaultNativeSessionManager(core_settings)


@pytest.fixture(scope='function')
def mock_subject_context():
    return mock.create_autospec(DefaultSubjectContext)


@pytest.fixture(scope='function')
def mock_subject():
    return MockSubject()


@pytest.fixture(scope='function')
def mock_session():
    return MockSession()


@pytest.fixture(scope='function')
def mock_security_manager():
    return MockSecurityManager()


@pytest.fixture(scope='function')
def mock_thread_context():
    return MockThreadContext()

@pytest.fixture(scope='function')
def simple_identifier_collection():
    return SimpleIdentifierCollection(source_name='AccountStoreRealm',
                                      identifier='identifier')

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
        monkeypatch, authz_realms_collection, event_bus):
    a = ModularRealmAuthorizer()
    monkeypatch.setattr(a, '_realms', authz_realms_collection)
    monkeypatch.setattr(a, '_event_bus', event_bus)
    return a
