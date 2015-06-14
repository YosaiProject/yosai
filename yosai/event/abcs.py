from abc import ABCMeta, abstractmethod


class EventBus(metaclass=ABCMeta):

    @abstractmethod
    def publish(self, event):
        pass

    @abstractmethod
    def register(self, subscriber):
        pass

    @abstractmethod
    def unregister(self, subscriber):
        pass


class EventBusAware(metaclass=ABCMeta):
    
    @property
    @abstractmethod
    def event_bus():
        pass

    @event_bus.setter
    @abstractmethod
    def event_bus(self, eventbus):
        pass
