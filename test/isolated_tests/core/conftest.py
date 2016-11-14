import pytest
from unittest import mock

from yosai.core import (
    AccountStoreRealm,
    DefaultAuthenticator,
    SubjectContext,
    DelegatingSubject,
    ModularRealmAuthorizer,
    SimpleIdentifierCollection,
    SimpleSession,
)

from .doubles import (
    MockAccountStore,
    MockPubSub,
    MockSecurityManager,
    MockSubject,
)

from .session.doubles import (
    MockNativeSessionManager,
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
def default_authenticator(core_settings):
    return DefaultAuthenticator(core_settings)


@pytest.fixture(scope='function')
def mock_default_session_manager(core_settings):
    return MockNativeSessionManager(core_settings)


@pytest.fixture(scope='function')
def mock_subject_context():
    return mock.create_autospec(SubjectContext)


@pytest.fixture(scope='function')
def mock_subject():
    return mock.create_autospec(DelegatingSubject) 


@pytest.fixture(scope='function')
def mock_session():
    ms = mock.create_autospec(SimpleSession)
    ms.session_id = 'sessionid123'
    return ms


@pytest.fixture(scope='function')
def mock_security_manager():
    return MockSecurityManager()


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
    monkeypatch.setattr(a, 'realms', authz_realms_collection)
    monkeypatch.setattr(a, 'event_bus', event_bus)
    return a


@pytest.fixture(scope='function')
def sample_authc_info():
    return {'password': {'credential': '$2a$12$Gf.YpcTN8r5vQydvLl9o1O8KoTbeFrYCkR22NaJawMFFfceiQ0XOi',
                         'failed_attempts': [1477077663111]},
            'totp_key': {'credential': 'ZOYHBEXJEFUUGFCPGLJWCZDR3Y6CD43EJQZIGAHB3NRWJYXWY3HQ',
                     'failed_attempts': [],
                     '2fa_info': {'phone_number': '123456789'}}}


@pytest.fixture(scope='function')
def sample_acct_info(sample_authc_info, simple_identifier_collection):
    return dict(account_id=simple_identifier_collection,
                account_locked=None,
                authc_info=sample_authc_info,
                authz_info='authz_info')
