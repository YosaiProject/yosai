from abc import ABCMeta, abstractmethod

from yosai.account import abcs as account_abcs
from yosai.authc import abcs as authc_abcs

class AccountCacheHandler(metaclass=ABCMeta):

    @abstractmethod
    def get_cached_account(self, authc_token):
        pass

    @abstractmethod
    def cache_account(self, authc_token, account):
        pass

    @abstractmethod
    def clear_cached_account(self, account_id):
        pass


class AccountCacheKeyResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_cache_key(self, authc_token=None, account=None, 
                              account_id=None):
        pass


class AccountCacheResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_cache(self, authc_token=None, 
                          account=None, account_id=None):
        pass


class AccountPermissionResolver(metaclass=ABCMeta):
    pass


class AccountRolePermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_role_permissions(self, account, role_name):
        pass


class AccountRoleResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_role_names(self, account):
        pass


class AuthorizationCacheHandler(metaclass=ABCMeta):

    @abstractmethod
    def get_cached_authorization_info(self, account_id):
        pass

    @abstractmethod
    def cache_authorization_info(self, account_id, authz_info):
        pass


class RealmAccount(account_abcs.Account):

    @property
    @abstractmethod
    def realm_name(self):
        pass


class RealmFactory(metaclass=ABCMeta):

    @property
    @abstractmethod
    def realms(self):
        pass


class Realm(authc_abcs.Authenticator):
    
    # DG:  omitted name accessor method for pythonic reasons

    @abstractmethod
    def supports(self, authc_token):
        pass
