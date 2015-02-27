from abc import ABCMeta, abstractmethod


class IAccountId(metaclass=ABCMeta):

    @abstractmethod
    def __str__(self):
        pass


class IAccount(metaclass=ABCMeta):

    @property 
    @abstractmethod
    def account_id(self):  # DG:  renamed from id
        pass

    @property 
    @abstractmethod
    def credentials(self):
        pass

    @property 
    @abstractmethod
    def attributes(self):
        pass


class IAccountStore(metaclass=ABCMeta):

    @abstractmethod
    def get_account(self, authc_token=None, account_id=None):
        pass
