from yosai import (
    InvalidSerializationFormatException,
    SerializationException,
)

from yosai.serialize import abcs
import msgpack
import datetime


class SerializationManager:
    """
    SerializationManager proxies serialization requests.  It is non-opinionated,
    designed so as to support multiple serialization methods.  MSGPack is 
    the default encoding scheme.

    TO-DO:  configure serialization scheme from yosai settings json
    """
    def __init__(self, format='msgpack'):
        self.format = format

        # add encoders here:
        self.serializers = {'msgpack': MSGPackSerializer}

        try:
            self.serializer = self.serializers[self.format]
        except KeyError:
            msg = ('Could not locate serialization format: ', format)
            raise InvalidSerializationFormatException(msg)
    
    def serialize(self, obj):
        try:
            newdict = {}
            newdict.update({'cls': obj.__class__.__name__,
                            'record_dt': datetime.datetime.utcnow().isoformat()})
            newdict.update(obj.serialize()) 
            return newdict

        except AttributeError: 
            raise SerializationException('Only serialize Serializable objects')

    def deserialize(self, message):
        # initially, supporting deserialization of one object, until support of
        # a collection is needed
        unpacked = self.serializer.deserialize(message)
        # NOTE:  unpacked is expected to be a dict

        yosai = __import__('yosai')
        cls = getattr(yosai, unpacked['cls'])
        try:
            return cls.deserialize(unpacked)()
        except AttributeError:
            raise SerializationException('Only de-serialize Serializable objects')

class MSGPackSerializer(abcs.Serializer):
    
    @classmethod
    def serialize(self, obj, *args, **kwargs):
        return msgpack.packb(obj.__serialize__())

    @classmethod
    def deserialize(self, message, *args, **kwargs): 
        return msgpack.unpackb(message, encoding='utf-8')
