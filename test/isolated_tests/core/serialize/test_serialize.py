import pytest
from unittest import mock

from yosai.core import (
    SerializationManager,
)
from yosai.core.serialize.serialize import msgpack


@mock.patch.object(SerializationManager, 'register_serializables')
def test_sm_init(mock_sm_rs):
    """
    - serializer attribute is set
    - register_serializables is called with session_attributes_schema
    """
    sm = SerializationManager('attributes_schema', serializer_scheme='msgpack')
    mock_sm_rs.assert_called_once_with('attributes_schema')
    assert isinstance(sm.serializer, msgpack.MsgpackSerializer)


def test_sm_register_serializables(serialization_manager):
    sm = serialization_manager

    class TestSerializable:
        def __init__(self):
            self.attributeA = 'Aaaaaa!!!'

        def __getstate__(self):
            return {'attributeA': self.attributeA}

        def __setstate__(self, state):
            self.attributeA = state['attributeA']

    ts = TestSerializable()

    with mock.patch.object(sm.serializer, 'register_custom_type') as mock_rct:
        sm.register_serializables([ts])

        assert mock_rct.called


def test_sm_serialize(serialization_manager, monkeypatch):

    sm = serialization_manager
    monkeypatch.setattr(sm.serializer, 'serialize', lambda x: x)
    result = sm.serialize('testing')
    assert result == 'testing'


def test_sm_deserialize(serialization_manager, monkeypatch):
    sm = serialization_manager
    monkeypatch.setattr(sm.serializer, 'deserialize', lambda x: x)
    result = sm.deserialize('testing')
    assert result == 'testing'


def test_sm_deserialize_returns_none(serialization_manager, monkeypatch):
    sm = serialization_manager
    with mock.patch.object(sm.serializer, 'deserialize') as mock_deser:
        mock_deser.side_effect = Exception
        result = sm.deserialize(None)
        assert result is None


def test_sm_deserialize_raises(serialization_manager, monkeypatch):
    sm = serialization_manager
    with mock.patch.object(sm.serializer, 'deserialize') as mock_deser:
        mock_deser.side_effect = Exception

        with pytest.raises(Exception):
            result = sm.deserialize('testing')
