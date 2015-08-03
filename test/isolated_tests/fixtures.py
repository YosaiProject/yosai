import pytest
from unittest import mock

from yosai import (
    AccountStoreRealm,
    DefaultAuthenticator,
    DefaultEventBus,
    FirstRealmSuccessfulStrategy,
    PasswordMatcher,
    UsernamePasswordToken,
)

from .doubles import (
    MockAccount,
    MockAccountStore,
    MockCache,
    MockPubSub,
    MockToken,
)

@pytest.fixture(scope='function')
def mock_account_state():
    return {'creds': {'password': '$bcrypt-sha256$2a,12$xVPxYhwlLOgStpiHCJNJ9u$wM.B.VVoJ1Lv0WeT4cRFY1PqYWH37WO', 
                      'api_key_secret': ' lWxOiKqKPNwJmSldbiSkEbkNjgh2uRSNAb+AEXAMPLE'},
            'attrs': {'givenname': 'Napolean',
                      'surname': 'Dynamite',
                      'email': 'napoleandynamite@example.com',
                      'username': 'napodyna',
                      'api_key_id': '144JVZINOF5EBNCMG9EXAMPLE'}}
         

@pytest.fixture(scope='function')
def full_mock_account(mock_account_state):
    mas = mock_account_state
    return MockAccount(account_id=8675309,
                       credentials=mas['creds'],
                       attributes=mas['attrs'])


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
    return PasswordMatcher()

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
def default_authenticator(first_realm_successful_strategy, patched_event_bus):
    return DefaultAuthenticator(patched_event_bus, 
                                first_realm_successful_strategy)
