from .doubles import (
    MockSerializable,
)

from yosai import(
    SerializationManager,
)

import pytest

@pytest.fixture(scope='function')
def mock_serializable():
    return MockSerializable()

@pytest.fixture(scope='function')
def serialization_manager():
    return SerializationManager()  # defaults to msgpack 
