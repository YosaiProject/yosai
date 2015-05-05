import pytest
from unittest import mock

from yosai import (
    settings,
)

from yosai.authc import (
    AuthenticationSettings,
    CryptContextFactory,
    DefaultAuthcService,
    DefaultAuthenticationAttempt,
    DefaultHashService,
    DefaultPasswordService,
    UsernamePasswordToken,
)

from passlib.context import CryptContext

@pytest.fixture(scope="function")
def authc_config():
    return {
        "hash_algorithms": {
            "bcrypt_sha256": {
                "default_rounds": 200000,
            },
            "sha256_crypt": {
                "default_rounds": 110000,
                "max_rounds": 1000000,
                "min_rounds": 1000,
                "salt_size": 16}},
        "private_salt": "privatesalt"
    }


@pytest.fixture(scope='function')
def username_password_token():
    return UsernamePasswordToken(username='user', 
                                 password='secret',
                                 remember_me=False, 
                                 host='127.0.0.1') 


@pytest.fixture(scope='function')
def patched_authc_settings(authc_config, monkeypatch):
    monkeypatch.setattr(settings, 'AUTHC_CONFIG', authc_config)
    return AuthenticationSettings()


@pytest.fixture(scope='function')
def default_authc_service():
    return DefaultAuthcService()


@pytest.fixture(scope='function')
def default_realms():
    return set('realm1')  # test dummy

@pytest.fixture(scope='function')
def default_authc_attempt(username_password_token, default_realms):
    return DefaultAuthenticationAttempt(username_password_token, 
                                        default_realms)


@pytest.fixture(scope='function')
def cryptcontext_factory():
    authc_settings = AuthenticationSettings()
    return CryptContextFactory(authc_settings)


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
def default_hash_service():
    return DefaultHashService()


@pytest.fixture(scope='function')
def default_password_service():
    return DefaultPasswordService()


@pytest.fixture(scope='function')
def private_salt():
    return 'privatesaltysnack'

