from abc import ABCMeta, abstractmethod


class AccountId(metaclass=ABCMeta):

    @abstractmethod
    def __repr__(self):
        pass


class Account(metaclass=ABCMeta):

    @property 
    @abstractmethod
    def account_id(self):  # DG:  renamed 
        pass

    @property 
    @abstractmethod
    def credentials(self):
        pass

    @property 
    @abstractmethod
    def attributes(self):
        pass


class AccountStore(metaclass=ABCMeta):

    @abstractmethod
    def get_account(self, authc_token=None, account_id=None):
        pass
