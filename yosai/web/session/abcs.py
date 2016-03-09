from abc import abstractmethod


from yosai.core import (
    session_abcs,
)


class WebSessionContext(session_abcs.SessionContext):

    @property
    @abstractmethod
    def web_registry(self):
        pass

    @web_registry.setter
    @abstractmethod
    def web_registry(self, web_registry):
        pass


class WebSessionManager(session_abcs.SessionManager):

    @property
    @abstractmethod
    def web_registry(self):
        pass

    @web_registry.setter
    @abstractmethod
    def web_registry(self, web_registry):
        pass
