import pytest

from ..doubles import (
    MockAccount,
)

from .doubles import (
    MockAccountCacheHandler,
)

@pytest.fixture(scope='function')
def mock_account_cache_handler():
    return MockAccountCacheHandler(MockAccount(account_id='MACH13579'))


@pytest.fixture(scope='function')
def patched_accountstore_realm(
        default_accountstorerealm, monkeypatch, default_password_matcher, 
        mock_account_cache_handler, mock_account_store):
    dasr = default_accountstorerealm
    dasr.account_cache_handler = mock_account_cache_handler
    dasr.account_store = mock_account_store
    return default_accountstorerealm   
