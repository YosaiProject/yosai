import pytest
import msgpack
from unittest import mock

from yosai import (
    InvalidSerializationFormatException,
    SerializationException,
)

from yosai.serialize.serialize import (
    MSGPackSerializer,
    SerializationManager,
)

from ..matcher import (
    DictMatcher,
)

import yosai.serialize.abcs as serialize_abcs

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

def test_sm_serialize_serializable(serialization_manager, mock_serializable):
    """
    unit tested:  serialize

    test case:
    Conducts a partial match between the dict sent to MSGPackSerializer and
    my test dictionary.  The reason a partial match is used is that I won't 
    be able to match on record_dt. 
    """

    sm = serialization_manager

    test_dict = {'class': 'MockSerializable', 'name': 'Mock Serialize'}
    dict_matcher = DictMatcher(test_dict, ['class', 'name'])
    
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


def test_sm_deserialize(serialization_manager):
    """
    unit tested:  deserialize

    test case:
    basic code path exercise 
    """
    sm = serialization_manager

    with mock.patch.object(MSGPackSerializer, 'deserialize') as mp_deser:
        mp_deser.return_value = None
        sm.deserialize('arbitrary')
        assert mp_deser.called

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

def test_serializable_materialize():

    class DumbClass(serialize_abcs.Serializable): 
        def __serialize__(self):
            return {'one': 1, 'two': 2, 'three': 3}

    mydict = {'one': 1, 'two': 2, 'three': 3}

    newobj = DumbClass.materialize(mydict)

    assert (isinstance(newobj, DumbClass) and hasattr(newobj, 'one') and
            hasattr(newobj, 'two') and hasattr(newobj, 'three'))
