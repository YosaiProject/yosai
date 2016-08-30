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

from yosai.core import serialize_abcs

from yosai.core.serialize.serializers import (
    json,
    msgpack,
    cbor,
)


class SerializationManager:
    """
    SerializationManager proxies serialization requests.

    TO-DO:  configure serialization scheme from yosai.core.settings json
    """
    def __init__(self, session_attributes, serializer_scheme='cbor'):
        """
        :type session_attributes: list
        """
        # add encoders here:
        self.serializers = {'cbor': cbor.CBORSerializer,
                            'msgpack': msgpack.MsgpackSerializer,
                            'json': json.JSONSerializer}

        self.serializer = self.serializers[serializer_scheme]()
        self.register_serializables(session_attributes)

    def register_serializables(self, session_attributes):

        def all_subclasses(cls):
            return cls.__subclasses__() + [g for s in cls.__subclasses__()
                                           for g in all_subclasses(s)]
        # manual registration required because it isn't a Serializable subclass:
        if session_attributes:
            for attribute in session_attributes:
                self.serializer.register_custom_type(attribute)

        for serializable in all_subclasses(serialize_abcs.Serializable):
            self.serializer.register_custom_type(serializable)

    def serialize(self, obj):
        """
        :type obj: a Serializable object or a list of Serializable objects
        :returns: an encoded, serialized object
        """
        # this isn't doing much at the moment but is where validation will happen
        return self.serializer.serialize(obj)

    def deserialize(self, message):
        # this isn't doing much at the moment but is where validation will happen
        try:
            return self.serializer.deserialize(message)
        except Exception as exc:
            if message is None:
                return None
            raise exc
