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

from abc import ABCMeta, abstractmethod
from yosai.core import DeserializationException


class Serializable(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def serialization_schema(cls):
        """
        Each serializable class must define its respective Schema (marshmallow)
        and its @post_load 'make_object' method.

        :returns: a SerializationSchema class
        """
        pass

    def serialize(self):
        """
        :returns: a dict
        """
        schema = self.serialization_schema()()
        return schema.dump(self).data

    @classmethod
    def deserialize(cls, data):
        """
        :returns: a deserialized object
        """
        schema = cls.serialization_schema()()
        result = schema.load(data=data)
        if result.errors:
            msg = 'Failed to de-serialize:  data={0}, errors={1}'.\
                  format(result.data, result.errors)
            raise DeserializationException(msg)
        return result.data

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

    @classmethod
    def get_subclasses(cls):
        import yosai.web # needed to get Serializable subclasses
        for subclass in cls.__subclasses__():
            yield from subclass.get_subclasses()
            yield subclass


class Serializer(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def serialize(self, obj):
        pass

    @classmethod
    @abstractmethod
    def deserialize(self, message):
        pass

# taken from asphalt.serialization
class Serializer(metaclass=ABCMeta):
    """
    This abstract class defines the serializer API.

    Each serializer is required to support the serialization of the following Python types,
    at minimum:

    * :class:`str`
    * :class:`int`
    * :class:`float`
    * :class:`list`
    * :class:`dict` (with ``str`` keys)

    A subclass may support a wider range of types, along with hooks to provide serialization
    support for custom types.
    """

    @abstractmethod
    def serialize(self, obj):
        """Serialize a Python object into bytes."""

    @abstractmethod
    def deserialize(self, payload):
        """Deserialize bytes into a Python object."""

    @property
    @abstractmethod
    def mimetype(self):
        """Return the MIME type for this serialization format."""


# taken from asphalt.serialization
class CustomizableSerializer(Serializer):
    """
    This abstract class defines an interface for registering custom types on a serializer so that
    the the serializer can be extended to (de)serialize a broader array of classes.
    """

    @abstractmethod
    def register_custom_type(self, cls, marshaller, unmarshaller, typename):
        """
        Register a marshaller and/or unmarshaller for the given class.

        The state object returned by the marshaller and passed to the unmarshaller can be any
        serializable type. Usually a dictionary mapping of attribute names to values is used.

        .. warning:: Registering marshallers/unmarshallers for any custom type will override any
            serializer specific encoding/decoding hooks (respectively) already in place!

        :param cls: the class to register
        :param marshaller: a callable that takes the object to be marshalled as the argument and
              returns a state object
        :param unmarshaller: a callable that takes an uninitialized object and its state object
            as arguments and restores the state of the object
        :param typename: a unique identifier for the type (defaults to the ``module:varname``
            reference to the class)
        """
