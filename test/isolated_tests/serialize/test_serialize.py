import pytest
import msgpack
from unittest import mock

from .doubles import (
    MockSerializable,
)

from yosai import (
    InvalidSerializationFormatException,
    SerializationException,
    serialize_abcs,
)

from yosai.serialize.serialize import (
    MSGPackSerializer,
    SerializationManager,
)

from ..matcher import (
    DictMatcher,
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

def test_sm_serialize_serializable(
        serialization_manager, mock_serializable, monkeypatch):
    """
    unit tested:  serialize

    test case:
    Confirms that 
    Conducts a partial match between the dict sent to MSGPackSerializer and
    my test dictionary.  The reason a partial match is used is that I won't 
    be able to match on record_dt. 
    """

    sm = serialization_manager

    test_dict = {'class': 'MockSerializable', 'name': 'Mock Serialize'}
    dict_matcher = DictMatcher(test_dict, ['class', 'name'])
  
    monkeypatch.setattr(mock_serializable, 'serialize', lambda: test_dict)

    with mock.patch.object(MSGPackSerializer, 'serialize') as mp_ser:
        mp_ser.return_value = None
        
        sm.serialize(mock_serializable)
        mp_ser.assert_called_with(dict_matcher)

def test_sm_serialize_nonserializable(serialization_manager):
    """
    unit tested:  serialize

    test case:
    an object instance of a class that is not a subclass of ISerializable 
    raises an exception
    """
    DumbClass = type('DumbClass', (object,), {'dumb': 'dumb'})
    sm = serialization_manager

    with pytest.raises(SerializationException):
        sm.serialize(DumbClass())


def test_sm_deserialize(serialization_manager, monkeypatch):
    """
    unit tested:  deserialize

    test case:
    decodes (unpacks) the message and then calls the respective class's
    deserialize method that will create (return) a new instance
    """
    sm = serialization_manager

    unpacked = {'myname': 'Mock Serialize', 'myage': 12, 
                'cls': 'MockSerializable'}
    yosai = __import__('yosai')
    # inject a class for testing:
    monkeypatch.setattr(yosai, 'MockSerializable', MockSerializable, raising=False) 

    with mock.patch.object(MSGPackSerializer, 'deserialize') as mp_deser:
        mp_deser.return_value = unpacked 
        result = sm.deserialize(MockSerializable())
        assert isinstance(result, MockSerializable)

# ----------------------------------------------------------------------------
# MSGPackSerializer Tests
# ----------------------------------------------------------------------------

def test_mps_serialize():
    """
    unit tested:  seralize

    test case:
    basic code path exercise-- make sure that packb returns a byte string 
    """
    class DumbClass: 
        def __serialize__(self):
            return {'one': 1, 'two': 2, 'three': 3}

    result = MSGPackSerializer.serialize(DumbClass())
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
    assert (serialized['credentials'] == mock_account_state['creds'] and 
            serialized['attributes'] == mock_account_state['attrs'])


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
