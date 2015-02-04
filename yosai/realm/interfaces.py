from abc import ABCMeta, abstractmethod

import org.apache.shiro.account.Account
import org.apache.shiro.account.AccountId
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authz.AuthorizationInfo
import org.apache.shiro.cache.Cache
import org.apache.shiro.authz.Permission
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.Authenticator


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
    def get_account_cache_key(self, 
                              authc_token=None, account=None, accountid=None):
        pass


class IAccountCacheResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_account_cache(self,
                          authc_token=None, account=None, accountid=None):
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


class IRealmAccount(Account, metaclass=ABCMeta):

    @property
    @abstractmethod
    def realm_name(self):
        pass


class IRealmFactory(metaclass=ABCMeta):

    @property
    @abstractmethod
    def realms(self):
        pass


class IRealm(Authenticator, metaclass=ABCMeta): 
    
    @property
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def supports(self, authc_token):
        pass
