from abc import ABCMeta, abstractmethod

from yosai import (
    IAccount,
    IAuthenticator,
)

class IAccountCacheHandler(metaclass=ABCMeta):

    @abstractmethod
    def get_cached_account(self, authc_token):
        pass

    @abstractmethod
    def cache_account(self, authc_token, account):
        pass

    @abstractmethod
    def clear_cached_account(self, account_id):
        pass


class IAccountCacheKeyResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_cache_key(self, authc_token=None, account=None, 
                              account_id=None):
        pass


class IAccountCacheResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_cache(self, authc_token=None, 
                          account=None, account_id=None):
        pass


class IAccountPermissionResolver(metaclass=ABCMeta):
    pass


class IAccountRolePermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_role_permissions(self, account, role_name):
        pass


class IAccountRoleResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_role_names(self, account):
        pass


class IAuthorizationCacheHandler(metaclass=ABCMeta):

    @abstractmethod
    def get_cached_authorization_info(self, account_id):
        pass

    @abstractmethod
    def cache_authorization_info(self, account_id, authz_info):
        pass


class IRealmAccount(IAccount):

    @property
    @abstractmethod
    def realm_name(self):
        pass


class IRealmFactory(metaclass=ABCMeta):

    @property
    @abstractmethod
    def realms(self):
        pass


class IRealm(IAuthenticator):
    
    # DG:  omitted name accessor method for pythonic reasons

    @abstractmethod
    def supports(self, authc_token):
        pass
