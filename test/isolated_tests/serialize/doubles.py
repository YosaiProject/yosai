import yosai.serialize.abcs as serialize_abcs
from marshmallow import Schema, fields


class MockSerializable(serialize_abcs.Serializable):

    def __init__(self):
        self.myname = 'Mock Serialize'
        self.myage = 12

    @classmethod
    def serialization_schema(self):
        class SerializationSchema(Schema):
            myname = fields.Str()
            myage = fields.Integer()

            def make_object(self, data):
                cls = MockSerializable 
                instance = cls.__new__(cls)
                instance.__dict__.update(data)
                return instance
        return SerializationSchema

