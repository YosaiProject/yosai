import pytest
from unittest import mock

from yosai.core import (
    AccountStoreRealm,
    DefaultAuthenticator,
    DefaultEventBus,
    DefaultSessionContext,
    FirstRealmSuccessfulStrategy,
    PasswordVerifier,
    UsernamePasswordToken,
    SecurityUtils
)

from .doubles import (
    MockAccount,
    MockAccountStore,
    MockCache,
    MockPubSub,
    MockSecurityManager,
    MockSession,
    MockSubject,
    MockSubjectBuilder,
    MockSubjectContext,
    MockThreadContext,
    MockToken,
)

from .session.doubles import (
    MockDefaultSessionManager,
)

@pytest.fixture(scope='function')
def mock_account_state():
    return {'creds': {'password': '$bcrypt-sha256$2a,12$xVPxYhwlLOgStpiHCJNJ9u$wM.B.VVoJ1Lv0WeT4cRFY1PqYWH37WO',
                      'api_key_secret': ' lWxOiKqKPNwJmSldbiSkEbkNjgh2uRSNAb+AEXAMPLE'},
            'identifier_s': {'givenname': 'Napolean',
                            'surname': 'Dynamite',
                            'email': 'napoleandynamite@example.com',
                            'username': 'napodyna',
                            'api_key_id': '144JVZINOF5EBNCMG9EXAMPLE'}}


@pytest.fixture(scope='function')
def full_mock_account(mock_account_state, role_collection,
                      permission_collection):
    mas = mock_account_state
    return MockAccount(account_id=8675309,
                       credentials=mas['creds'],
                       identifier_s=mas['identifier_s'],
                       roles=role_collection,
                       permissions=permission_collection)


@pytest.fixture(scope='function')
def return_true(**kwargs):
    return True

@pytest.fixture(scope='function')
def default_accountstorerealm():
    return AccountStoreRealm()


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user123',
                                 password='secret',
                                 remember_me=False,
                                 host='127.0.0.1')


@pytest.fixture(scope='function')
def mock_account_store():
    return MockAccountStore()


@pytest.fixture(scope='function')
def mock_token():
    return MockToken()


@pytest.fixture(scope='function')
def default_password_matcher():
    return PasswordVerifier()

@pytest.fixture(scope='function')
def mock_pubsub():
    return MockPubSub()

@pytest.fixture(scope='function')
def patched_event_bus(mock_pubsub, monkeypatch):
    eb = DefaultEventBus()
    monkeypatch.setattr(eb, '_event_bus', mock_pubsub)
    return eb


@pytest.fixture(scope='function')
def mock_cache(full_mock_account):
    return MockCache({'sessionid123': 'session_123',
                      'user123': full_mock_account})


@pytest.fixture(scope="function")
def first_realm_successful_strategy():
    return FirstRealmSuccessfulStrategy()


@pytest.fixture(scope='function')
def default_authenticator(
        first_realm_successful_strategy, monkeypatch, patched_event_bus):
    da = DefaultAuthenticator(first_realm_successful_strategy)
    monkeypatch.setattr(da, '_event_bus', patched_event_bus)
    return da


@pytest.fixture(scope='function')
def mock_default_session_manager():
    return MockDefaultSessionManager()


@pytest.fixture(scope='function')
def mock_subject_context():
    return MockSubjectContext()


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
def default_session_context():
    return DefaultSessionContext(context_map={'attr1': 'attributeOne',
                                              'attr2': 'attributeTwo',
                                              'attr3': 'attributeThree'})


@pytest.fixture(scope='function')
def mock_thread_context():
    return MockThreadContext()


@pytest.fixture(scope='function')
def mock_subject_builder(mock_security_manager):
    return MockSubjectBuilder(security_manager=mock_security_manager)
