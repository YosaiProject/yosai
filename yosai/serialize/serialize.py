from yosai import (
    SerializationException,
    settings,
)

import abcs
import msgpack


class Serializer():
    """
    Serializer proxies serialization requests.  It is designed so to support
    multiple serialization methods.
    """
    def __init__(self, format='msgpack'):
        self.format = format
        self.serializers = {'msgpack': MSGPackSerializer}
        self.serializer = self.serializers.get(self.format, None)
    
    def serialize(self, obj, *args, **kwargs):
        if isinstance(obj, abcs.Serialize):
            return self.serializer.serialize(obj.__serialize__(), 
                                             *args, **kwargs)
        else:
            raise SerializationException('Must implement ISerialize')

    def deserialize(self, message, *args, **kwargs):
        return self.serializer.deserialize(message, *args, **kwargs)


class MSGPackSerializer(abcs.Serializer):
    
    @classmethod
    def serialize(self, obj, *args, **kwargs):
        return msgpack.packb(obj.__serialize__())

    @classmethod
    def deserialize(self, message, *args, **kwargs): 
        return msgpack.unpackb(message, encoding='utf-8')
