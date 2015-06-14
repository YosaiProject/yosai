from abc import ABCMeta, abstractmethod


class ISerialize(metaclass=ABCMeta):

    @classmethod 
    def materialize(cls, deserialized):
        """
        Materializes an object from its de-serialized parts, essentially
        restoring the state of an object prior to its serialization.

        Note about de-serialized schema:
        To reduce overhead, Yosai does not validate nor filter the contents 
        of deserialized.  Regardless of whatever the contents may be, a class 
        will assume them as attributes.  A library such as Colander could be
        used to enforce schema.

        :param deserialized: the deserialized message
        :type deserialized: dict
        """
        instance = cls.__new__(cls)
        instance.__dict__.update(deserialized)

        return instance

    @abstractmethod
    def __serialize__(self):
        """
        Define the attributes to be serialized:
            {'attributeA': self.attributeA, 
             'attributeB': self.attributeB,
                    . . . .  }

        :returns: a dict
        """
        pass


class ISerializer(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def serialize(self, obj, *args, **kwargs):
        pass

    @classmethod
    @abstractmethod
    def deserialize(self, message, *args, **kwargs):
        pass
