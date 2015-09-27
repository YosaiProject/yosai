from .doubles import (
    MockSerializable,
)

from yosai import(
    SerializationManager,
)

import pytest

import yosai  # to get serializable classes

@pytest.fixture(scope='function')
def mock_serializable():
    return MockSerializable()

@pytest.fixture(scope='function')
def serialization_manager():
    return SerializationManager()  # defaults to msgpack

@pytest.fixture(scope='function')
def serializable_classes():
    clsmembers = inspect.getmembers(sys.modules['yosai'], inspect.isclass)
    serializables = [member[0] for member in clsmembers if
                     issubclass(member[1], yosai.serialize_abcs.Serializable)]
    return serializables
