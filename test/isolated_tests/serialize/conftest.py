from .doubles import (
    MockSerializable,
)

from yosai.core import(
    SerializationManager,
)

import pytest
import inspect
import sys
import yosai  # to get serializable classes
from collections import defaultdict


@pytest.fixture(scope='function')
def mock_serializable():
    return MockSerializable()


@pytest.fixture(scope='function')
def serialization_manager():
    return SerializationManager()  # defaults to msgpack

# DefaultSessionKey
# SimpleAccount
# MapContext
# SimpleRole
# AllPermission
# WildcardPermission
