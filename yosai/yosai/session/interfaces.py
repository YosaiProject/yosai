from abc import ABCMeta, abstractmethod


class ISessionStorageEvaluator(metaclass=ABCMeta):

    @abstractmethod
    def is_session_storage_enabled(self, subject):
        pass

