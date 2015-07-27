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
