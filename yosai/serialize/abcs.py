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


class Serializable(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def serialization_schema(cls):
        """
        Each serializable class must define its respective Schema (marshmallow)
        and its make_object method.

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
        :returns: a dict
        """
        schema = cls.serialization_schema()()
        return schema.load(data=data).data


class Serializer(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def serialize(self, obj):
        pass

    @classmethod
    @abstractmethod
    def deserialize(self, message):
        pass
