import pytest
import msgpack
import datetime
from unittest import mock

from .doubles import (
    MockSerializable,
)
from yosai.core import (
    Credential,
    InvalidSerializationFormatException,
    SerializationException,
    serialize_abcs,
    MSGPackSerializer,
    SerializationManager,
)

# ----------------------------------------------------------------------------
# SerializationManager Tests
# ----------------------------------------------------------------------------

def test_sm_init_default_format(serialization_manager):
    """
    unit tested:  __init__

    test case:
    default format for initialization is msgpack
    """
    sm = serialization_manager
    assert sm.serializer.__name__ == 'MSGPackSerializer'

def test_sm_init_unrecognized_format():
    """
    unit tested:  __init__

    test case:
    an unrecognized serialization format raises an exception
    """
    with pytest.raises(InvalidSerializationFormatException):
        SerializationManager(format='protobufferoni')


# ----------------------------------------------------------------------------
# MSGPackSerializer Tests
# ----------------------------------------------------------------------------

def test_mps_serialize():
    """
    unit tested:  seralize

    test case:
    basic code path exercise-- make sure that packb returns a byte string
    """
    mydict = {'one': 1, 'two': 2, 'three': 3}

    result = MSGPackSerializer.serialize(mydict)
    assert type(result) == bytes


def test_mps_deserialize():
    """
    unit tested:  seralize

    test case:
    basic code path exercise-- make sure that unpackb returns a dict
    """
    mydict = {'one': 1, 'two': 2, 'three': 3}
    mybytes = b'\x83\xa3one\x01\xa3two\x02\xa5three\x03'
    result = MSGPackSerializer.deserialize(mybytes)
    assert result == mydict


# ----------------------------------------------------------------------------
# abc.Serializable Tests
# ----------------------------------------------------------------------------

def test_serializable_serialize(full_mock_account, mock_account_state):
    """
    unit tested:  serialize

    test case:
    serializes an object according to its marshmallow schema
    """
    serialized = full_mock_account.serialize()
    assert serialized['account_id'] == 'identifier'


def test_serializable_deserialize():
    """
    unit tested:  deserialize

    test case:
    converts a dict into an object instance
    """
    dumbstate = {'myname': 'Mock Serializable', 'myage': 12}
    newobj = MockSerializable.deserialize(dumbstate)
    print(newobj)
    assert isinstance(newobj, MockSerializable) and hasattr(newobj, 'myname')
