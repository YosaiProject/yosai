"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""
import time
from yosai.core import (
    memoized_property,
    serialize_abcs,
    SerializationException,
    InvalidSerializationFormatException,
)
import msgpack
import rapidjson
import copy
from marshmallow import fields, missing
from yosai.core.serialize.serializers import (
    cbor,
    #msgpack,
    #json,
)


class SerializationManager:
    """
    SerializationManager proxies serialization requests.  It is non-opinionated,
    designed so as to support multiple serialization methods.  MSGPack is
    the default encoding scheme.

    TO-DO:  configure serialization scheme from yosai.core.settings json
    """
    def __init__(self, format='msgpack'):
        self.format = format

        # add encoders here:
        self.serializers = {'msgpack': MSGPackSerializer,
                            'json': JSONSerializer}

        try:
            self.serializer = self.serializers[self.format]
        except KeyError:
            msg = ('Could not locate serialization format: ', format)
            raise InvalidSerializationFormatException(msg)

        self._serializer = cbor.CBORSerializer()
        self.register_serializables()

    def register_serializables(self):
        def all_subclasses(cls):
            return cls.__subclasses__() + [g for s in cls.__subclasses__()
                                           for g in all_subclasses(s)]

        for serializable in all_subclasses(serialize_abcs.Serializable):
            self._serializer.register_custom_type(serializable)

    def new_serialize(self, obj):
        """
        :type obj: a Serializable object or a list of Serializable objects
        :returns: an encoded, serialized object
        """
        # this isn't doing much at the moment but is where validation will happen
        return self._serializer.serialize(obj)

    def new_deserialize(self, message):
        # this isn't doing much at the moment but is where validation will happen
        return self._serializer.deserialize(message)

    def serialize(self, obj):
        """
        :type obj: a Serializable object or a list of Serializable objects
        :returns: an encoded, serialized object
        """
        newdict = {}
        now = round(time.time() * 1000),
        serialization_attrs = {'serialized_record_dt': now}
        newdict.update(serialization_attrs)
        newdict.update(obj.serialize())
        newdict['serialized_cls'] = obj.__class__.__name__
        newobj = newdict

        return self.serializer.serialize(newobj)

    def deserialize(self, message):
        unpacked = self.serializer.deserialize(message)

        if not unpacked:
            return None

        yosai = __import__('yosai.core')
        try:
            cls = getattr(yosai.core, unpacked['serialized_cls'])
            return cls.deserialize(unpacked)
        except (AttributeError, TypeError):
            cls = getattr(yosai.web, unpacked['serialized_cls'])
            return cls.deserialize(unpacked)


class JSONSerializer(serialize_abcs.Serializer):

    @classmethod
    def serialize(self, obj):
        return bytes(rapidjson.dumps(obj), 'utf-8')

    @classmethod
    def deserialize(self, message):
        try:
            return rapidjson.loads(message, encoding='utf-8')
        except:
            return None


class MSGPackSerializer(serialize_abcs.Serializer):

    @classmethod
    def serialize(self, obj):
        return msgpack.packb(obj)

    @classmethod
    def deserialize(self, message):
        try:
            return msgpack.unpackb(message, encoding='utf-8')
        except:
            return None


# remove this class once serialization refactored:
class CollectionDict(fields.Dict):

    def __init__(self, child, *args, **kwargs):
        self.child = child
        super().__init__(*args, **kwargs)

    @staticmethod
    def accessor(key, obj, default=missing):
        """Custom accessor that only handles list and tuples.
        """
        try:
            return obj[key]
        except IndexError:
            return default

    def _serialize(self, value, attr, obj):
        ret = super()._serialize(copy.copy(value), attr, obj)
        for key, collection in ret.items():
            lvalue = list(collection)
            ret[key] = [
                self.child.serialize(i, lvalue, accessor=self.accessor)
                for i in range(len(lvalue))
            ]
        return ret

    def _deserialize(self, value, attr, data):
        ret = super()._deserialize(value, attr, data)
        for key, collection in value.items():
            ret[key] = set([
                self.child.deserialize(each, i, collection)
                for i, each in enumerate(collection)
            ])
        return ret
