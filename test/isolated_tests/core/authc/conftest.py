import pytest

from yosai.core import (
    AccountStoreRealm,
    IncorrectCredentialsException,
    AllRealmsSuccessfulStrategy,
    AtLeastOneRealmSuccessfulStrategy,
    AuthenticationSettings,
    DefaultAuthenticationAttempt,
)

from passlib.context import CryptContext


@pytest.fixture(scope="function")
def all_realms_successful_strategy():
    return AllRealmsSuccessfulStrategy()


@pytest.fixture(scope="function")
def alo_realms_successful_strategy():
    return AtLeastOneRealmSuccessfulStrategy()


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
            "challenger": None,
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
def first_accountstorerealm_succeeds(core_settings, monkeypatch):
    account_info = None # TBD
    monkeypatch.setattr(AccountStoreRealm, 'authenticate_account', lambda x: account_info)
    return AccountStoreRealm(core_settings, name='AccountStoreRealm1')


@pytest.fixture(scope='function')
def first_accountstorerealm_fails(monkeypatch, core_settings):
    def mock_return(self, token):
        raise IncorrectCredentialsException
    monkeypatch.setattr(AccountStoreRealm, 'authenticate_account', mock_return)
    return AccountStoreRealm(core_settings, name='AccountStoreRealm1')


@pytest.fixture(scope='function')
def second_accountstorerealm_fails(monkeypatch, core_settings):
    def mock_return(self, token):
        raise IncorrectCredentialsException
    monkeypatch.setattr(AccountStoreRealm, 'authenticate_account', mock_return)
    return AccountStoreRealm(core_settings, name='AccountStoreRealm2')


@pytest.fixture(scope='function')
def second_accountstorerealm_succeeds(monkeypatch, core_settings):
    account_info = None  # TBD
    monkeypatch.setattr(AccountStoreRealm, 'authenticate_account', account_info)
    return AccountStoreRealm(core_settings, name='AccountStoreRealm2')


@pytest.fixture(scope='function')
def one_accountstorerealm_succeeds(first_accountstorerealm_succeeds):
    return tuple([first_accountstorerealm_succeeds])


@pytest.fixture(scope='function')
def one_accountstorerealm_fails(first_accountstorerealm_fails):
    return tuple([first_accountstorerealm_fails])


@pytest.fixture(scope='function')
def two_accountstorerealms_succeeds(first_accountstorerealm_succeeds,
                                    second_accountstorerealm_succeeds):
    return tuple([first_accountstorerealm_succeeds, second_accountstorerealm_succeeds])


@pytest.fixture(scope='function')
def two_accountstorerealms_fails(first_accountstorerealm_fails,
                                 second_accountstorerealm_fails):
    return tuple([first_accountstorerealm_fails, second_accountstorerealm_fails])


@pytest.fixture(scope='function')
def default_authc_attempt(username_password_token, one_accountstorerealm_succeeds):
    return DefaultAuthenticationAttempt(username_password_token,
                                        one_accountstorerealm_succeeds)


@pytest.fixture(scope='function')
def fail_authc_attempt(username_password_token, one_accountstorerealm_fails):
    return DefaultAuthenticationAttempt(username_password_token,
                                        one_accountstorerealm_fails)


@pytest.fixture(scope='function')
def fail_multi_authc_attempt(username_password_token, two_accountstorerealms_fails):
    return DefaultAuthenticationAttempt(username_password_token,
                                        two_accountstorerealms_fails)


@pytest.fixture(scope='function')
def realmless_authc_attempt(username_password_token):
    return DefaultAuthenticationAttempt(username_password_token, tuple())


@pytest.fixture(scope='function')
def mock_token_attempt(mock_token, one_accountstorerealm_succeeds):
    return DefaultAuthenticationAttempt(mock_token, one_accountstorerealm_succeeds)


@pytest.fixture(scope='function')
def multirealm_authc_attempt(username_password_token, two_accountstorerealms_succeeds):
    return DefaultAuthenticationAttempt(username_password_token,
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
