import pytest
from unittest import mock

from yosai.core import (
    IncorrectCredentialsException,
    AuthenticationSettings,
    AuthenticationAttempt,
)

from passlib.context import CryptContext


@pytest.fixture(scope="function")
def authc_config():
    return {
        "account_lock_threshold": 3,
        "preferred_algorithm": "bcrypt",
        "hash_algorithms": {
            "bcrypt_sha256": {},
            "sha256_crypt": {
                "default_rounds": 110000,
                "max_rounds": 1000000,
                "min_rounds": 1000,
                "salt_size": 16}},
        "totp": {
            "dispatcher": None,
            "context": {
                "default_tag": None,
                "cost": None,
                "secrets_path": None,
                "secrets": {
                    1476123156: '0X6b7Zi2D9mNUzYJcPK4bKe5JSE6BSvrgseSKG9iXoO'
                }
            }
        }
    }


@pytest.fixture(scope="function")
def authc_settings(core_settings):
    return AuthenticationSettings(core_settings)


@pytest.fixture(scope='function')
def patched_authc_settings(authc_config, monkeypatch, core_settings):
    monkeypatch.setattr(core_settings, 'AUTHC_CONFIG', authc_config)
    return AuthenticationSettings(core_settings)


@pytest.fixture(scope='function')
def accountstorerealm_succeeds(account_store_realm, monkeypatch, sample_acct_info):
    monkeypatch.setattr(account_store_realm, 'authenticate_account', lambda x: sample_acct_info)
    return account_store_realm


@pytest.fixture(scope='function')
def accountstorerealm_fails(account_store_realm, monkeypatch):
    def raiser(authc_token):
        raise IncorrectCredentialsException
    monkeypatch.setattr(account_store_realm, 'authenticate_account', raiser)
    return account_store_realm


@pytest.fixture(scope='function')
def one_accountstorerealm_succeeds(accountstorerealm_succeeds):
    return tuple([accountstorerealm_succeeds])


@pytest.fixture(scope='function')
def one_accountstorerealm_fails(accountstorerealm_fails):
    return tuple([accountstorerealm_fails])


@pytest.fixture(scope='function')
def two_accountstorerealms_succeeds(accountstorerealm_succeeds):
    return tuple([accountstorerealm_succeeds, accountstorerealm_succeeds])


@pytest.fixture(scope='function')
def two_accountstorerealms_fails(accountstorerealm_fails):
    return tuple([accountstorerealm_fails, accountstorerealm_fails])


@pytest.fixture(scope='function')
def default_authc_attempt(username_password_token, one_accountstorerealm_succeeds):
    return AuthenticationAttempt(username_password_token,
                                        one_accountstorerealm_succeeds)


@pytest.fixture(scope='function')
def fail_authc_attempt(username_password_token, one_accountstorerealm_fails):
    return AuthenticationAttempt(username_password_token,
                                        one_accountstorerealm_fails)


@pytest.fixture(scope='function')
def fail_multi_authc_attempt(username_password_token, two_accountstorerealms_fails):
    return AuthenticationAttempt(username_password_token,
                                        two_accountstorerealms_fails)


@pytest.fixture(scope='function')
def realmless_authc_attempt(username_password_token):
    return AuthenticationAttempt(username_password_token, tuple())


@pytest.fixture(scope='function')
def mock_token_attempt(one_accountstorerealm_succeeds):
    mock_token = mock.MagicMock()
    return AuthenticationAttempt(mock_token, one_accountstorerealm_succeeds)


@pytest.fixture(scope='function')
def multirealm_authc_attempt(username_password_token, two_accountstorerealms_succeeds):
    return AuthenticationAttempt(username_password_token,
                                        two_accountstorerealms_succeeds)


@pytest.fixture(scope='function')
def crypt_context():
    return CryptContext(schemes=['sha256_crypt'])


@pytest.fixture(scope='function')
def default_context():
    return {'schemes': ['sha256_crypt'],
            'sha256_crypt__default_rounds': 180000}


@pytest.fixture(scope='function')
def default_encrypted_password():
    # bcrypt hash of 'privatesaltwithcleartext':
    return '$bcrypt-sha256$2a,12$HXuLhfmy1I1cWb46CC4KtO$hGXldB0fsNTwp6sRQJToAQDeUjPMW36'


@pytest.fixture(scope='function')
def default_realm_accountids():
    return {'realm1': 12345, 'realm2': 67890}
