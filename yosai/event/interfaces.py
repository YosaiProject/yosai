from abc import ABCMeta, abstractmethod


class IEventBus(metaclass=ABCMeta):

    @abstractmethod
    def publish(self, event):
        pass

    @abstractmethod
    def register(self, subscriber):
        pass

    @abstractmethod
    def unregister(self, subscriber):
        pass


class IEventBusAware(metaclass=ABCMeta):
    
    @property
    @abstractmethod
    def eventbus():
        pass

    @eventbus.setter
    @abstractmethod
    def eventbus(self, eventbus):
        pass
