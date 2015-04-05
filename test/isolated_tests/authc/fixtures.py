import pytest
from unittest import mock

from yosai import (
    DefaultHashService,
    HashRequest,
)

@pytest.fixture(scope="function")
def authc_config():
    return {
        "hash_algorithms": {
            "bcrypt_sha256": {},
            "sha256_crypt": {
                "default_rounds": 110000,
                "max_rounds": 1000000,
                "min_rounds": 1000,
                "salt_size": 16}},
        "private_salt": "privatesalt"
    }

@pytest.fixture(scope='function')
def hash_request():
    algorithm_name = "bcrypt_sha256"
    iterations = None 
    source = "secret"

    return HashRequest(source, iterations, algorithm_name)

@pytest.fixture(scope='function')
def default_hash_service():
    return DefaultHashService()
