import pytest

from yosai import (
    DefaultCredentialsCacheHandler,
)

from ..doubles import (
    MockAccount,
    MockCache,
)

from .doubles import (
    MockCredentialsCacheHandler,
    MockCredentialsCacheResolver,
    MockCredentialsCacheKeyResolver,
)

@pytest.fixture(scope='function')
def mock_credentials_cache_resolver():
    return MockCredentialsCacheResolver()

@pytest.fixture(scope='function')
def patched_mock_credentials_cache_resolver(full_mock_account, mock_cache):
    return MockCredentialsCacheResolver(mock_cache)

@pytest.fixture(scope='function')
def patched_mock_credentials_cache_key_resolver():
    return MockCredentialsCacheKeyResolver('user123')

@pytest.fixture(scope='function')
def mock_credentials_cache_key_resolver():
    return MockCredentialsCacheKeyResolver()

@pytest.fixture(scope='function')
def patched_default_credentials_cache_handler(
        mock_credentials_cache_resolver, mock_credentials_cache_key_resolver):
    return DefaultCredentialsCacheHandler(mock_credentials_cache_resolver,
                                          mock_credentials_cache_key_resolver)

@pytest.fixture(scope='function')
def mock_credentials_cache_handler():
    return MockCredentialsCacheHandler(MockAccount(account_id='MACH13579'))


@pytest.fixture(scope='function')
def patched_accountstore_realm(
        default_accountstorerealm, monkeypatch, default_password_matcher, 
        mock_credentials_cache_handler, mock_account_store):
    dasr = default_accountstorerealm
    dasr.credentials_cache_handler = mock_credentials_cache_handler
    dasr.account_store = mock_account_store
    return default_accountstorerealm   
