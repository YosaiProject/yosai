
from abc import ABCMeta, abstractmethod


# new to yosai:
class CookiePolicy(metaclass=ABCMeta):

    @abstractmethod
    @property
    def cookie(self):
        pass

    @abstractmethod
    @cookie.setter
    def cookie(self, cookie):
        pass

    @abstractmethod
    @cookie.deleter
    def cookie(self):
        pass
