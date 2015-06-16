from yosai import (
    SerializationException,
)

from yosai.serialize import abcs
import msgpack
import datetime


class SerializationManager:
    """
    Serializer proxies serialization requests.  It is designed so to support
    multiple serialization methods.
    """
    def __init__(self, format='msgpack'):
        self.format = format
        self.serializers = {'msgpack': MSGPackSerializer}
        self.serializer = self.serializers.get(self.format, None)
    
    def serialize(self, obj, *args, **kwargs):
        if isinstance(obj, abcs.Serializable):
            newdict = {}
            newdict.update({'class': obj.__class__.__name__,
                            'record_dt': datetime.datetime.utcnow().isoformat()})
            newdict.update(obj.__serialize__()) 
            return self.serializer.serialize(newdict, *args, **kwargs)
        else:
            raise SerializationException('Must implement ISerializable')

    def deserialize(self, message, *args, **kwargs):
        return self.serializer.deserialize(message, *args, **kwargs)


class MSGPackSerializer(abcs.Serializer):
    
    @classmethod
    def serialize(self, obj, *args, **kwargs):
        return msgpack.packb(obj.__serialize__())

    @classmethod
    def deserialize(self, message, *args, **kwargs): 
        return msgpack.unpackb(message, encoding='utf-8')
