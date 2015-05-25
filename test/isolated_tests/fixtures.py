import pytest
from unittest import mock

from yosai import (
    AccountStoreRealm,
    PasswordMatcher,
    UsernamePasswordToken,
)

from .doubles import (
    MockAccount,
    MockAccountStore,
    MockToken,
)

@pytest.fixture(scope='function')
def full_mock_account():
    creds = {'cred1': 1, 'cred2': 2}
    attrs = {'attr1': 1, 'attr2': 2, 'attr3': 3}
    return MockAccount(account_id=8675309, credentials=creds, attributes=attrs)


@pytest.fixture(scope='function')
def return_true(**kwargs):
    return True

@pytest.fixture(scope='function')
def default_accountstorerealm():
    return AccountStoreRealm()


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user', 
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
