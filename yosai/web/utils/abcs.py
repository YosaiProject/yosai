from abc import ABCMeta, abstractmethod


class WebDescriptor(metaclass=ABCMeta):

    @abstractmethod
    def __get__(self, instance, cls):
        pass

    @abstractmethod
    def __set__(self, instance, value):
        pass

    @abstractmethod
    def __delete__(self, instance):
        pass
