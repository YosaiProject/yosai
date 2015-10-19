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

from yosai import (
    serialize_abcs,
    InvalidSerializationFormatException,
    SerializationException,
)

import msgpack
import datetime
import rapidjson
import pkg_resources
import copy
from marshmallow import fields, missing
import pprint

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
        """
        :type obj: a Serializable object or a list of Serializable objects
        :returns: an encoded, serialized object
        """
        try:
            dist_version = pkg_resources.get_distribution('yosai').version

        except pkg_resources.DistributionNotFound:
            dist_version = 'N/A'

        try:
            newdict = {}
            now = datetime.datetime.utcnow().isoformat()
            serialization_attrs = {'serialized_dist_version': dist_version,
                                   'serialized_record_dt': now}
            newdict.update(serialization_attrs)
            newdict.update(obj.serialize())
            newdict['serialized_cls'] = obj.__class__.__name__
            newobj = newdict

        except AttributeError:
            try:
                # assume that its an iterable of Serializables
                newobj = []
                for element in obj:
                    mydict = copy.copy(newdict)
                    mydict['serialized_cls'] = element.__class__.__name__
                    mydict.update(element.serialize())
                    newobj.append(mydict)

                # at this point, newobj is either a list of dicts or a dict

            except AttributeError:
                msg = 'Only serialize Serializable objects or list of Serializables'
                raise SerializationException(msg)

        return self.serializer.serialize(newobj)

    def deserialize(self, message):
        # NOTE:  unpacked is expected to be a dict or list of dicts

        try:
            unpacked = self.serializer.deserialize(message)
            yosai = __import__('yosai')

            try:
                cls = getattr(yosai, unpacked['serialized_cls'])
                return cls.deserialize(unpacked)  # only serializables wont raise
            except (AttributeError, TypeError):
                # assume that its a list of Serializables
                newlist = []
                for element in unpacked:
                    cls = getattr(yosai, element['serialized_cls'])
                    newlist.append(cls.deserialize(element))
                return newlist

        except AttributeError:
            msg = 'Only de-serialize Serializable objects or list of Serializables'
            raise SerializationException(msg)


class JSONSerializer(serialize_abcs.Serializer):

    @classmethod
    def serialize(self, obj):
        return bytes(rapidjson.dumps(obj), 'utf-8')

    @classmethod
    def deserialize(self, message):
        return rapidjson.loads(message, encoding='utf-8')


class MSGPackSerializer(serialize_abcs.Serializer):

    @classmethod
    def serialize(self, obj):
        return msgpack.packb(obj)

    @classmethod
    def deserialize(self, message):
        return msgpack.unpackb(message, encoding='utf-8')


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
        ret = super()._serialize(value, attr, obj)
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
