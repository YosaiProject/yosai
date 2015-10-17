from yosai import (
    serialize_abcs,
)
from marshmallow import Schema, fields, post_load


class MockSerializable(serialize_abcs.Serializable):

    def __init__(self):
        self.myname = 'Mock Serialize'
        self.myage = 12

    def __repr__(self):
        return "MockSerializable(myname={0},myage={1})".format(self.myname,self.myage)

    @classmethod
    def serialization_schema(self):
        class SerializationSchema(Schema):
            myname = fields.Str()
            myage = fields.Integer()

            @post_load
            def make_mock(self, data):
                cls = MockSerializable 
                instance = cls.__new__(cls)
                instance.__dict__.update(data)
                return instance
        return SerializationSchema

