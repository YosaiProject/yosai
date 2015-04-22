from abc import ABCMeta, abstractmethod

class IEventBusAware(metaclass=ABCMeta):
    
    @property
    @abstractmethod
    def eventbus():
        pass

    @eventbus.setter
    @abstractmethod
    def eventbus(self, eventbus):
        pass
