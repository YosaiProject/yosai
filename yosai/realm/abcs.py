"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

from abc import ABCMeta, abstractmethod

from yosai import (
    account_abcs,
    authc_abcs,
)

# yosai renamed AccountCache to CredentialsCache (shiro diff)

class CredentialsCacheHandler(metaclass=ABCMeta):

    @abstractmethod
    def get_cached_credentials(self, authc_token):
        pass

    @abstractmethod
    def cache_credentials(self, authc_token, account):
        pass

    @abstractmethod
    def clear_cached_credentials(self, account_id):
        pass


class CacheKeyResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_cache_key(self, authc_token=None, account=None, account_id=None):
        pass


class CacheResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_cache(self, authc_token=None, account=None, account_id=None):
        pass


class PermissionResolver(metaclass=ABCMeta):
    pass


class RolePermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_role_permissions(self, account, role_name):
        pass


class RoleResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_role_names(self, account):
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


# new to yosai:
class Realm(metaclass=ABCMeta):

    @abstractmethod
    def do_clear_cache(self, identifiers):
        pass


# new to yosai:
class AuthenticatingRealm(Realm, authc_abcs.Authenticator):

    @property
    @abstractmethod
    def credentials_matcher(self):
        pass

    @credentials_matcher.setter
    @abstractmethod
    def credentials_matcher(self, credentialsmatcher):
        pass

    @property
    @abstractmethod
    def credentials_cache_handler(self):
        pass

    @credentials_cache_handler.setter
    @abstractmethod
    def credentials_cache_handler(self, credentialscachehandler):
        pass

    @abstractmethod
    def supports(self, authc_token):
        pass

    # new to yosai, considered a counterpart of get_authorization_info    
    @abstractmethod
    def get_credentials(self, authc_token):
        pass

    @abstractmethod
    def authenticate_account(self, authc_token):
        pass

    @abstractmethod
    def assert_credentials_match(self, authc_token, account):
        pass


# new to yosai:
class AuthorizingRealm(Realm):

    @property
    @abstractmethod
    def authorization_cache_handler(self):
        pass

    @authorization_cache_handler.setter
    @abstractmethod
    def authorization_cache_handler(self, authzcachehandler):
        pass

    @property
    @abstractmethod
    def permission_resolver(self):
        pass

    @permission_resolver.setter
    @abstractmethod
    def permission_resolver(self, permissionresolver):
        pass

    @abstractmethod
    def get_authorization_info(self, identifiers):
        pass

    @abstractmethod
    def get_permissions(self, account):
        pass

    @abstractmethod
    def resolve_permissions(self, string_perms):
        pass

    @abstractmethod
    def is_permitted(self, identifiers, permission_s):
        pass

    @abstractmethod
    def is_permitted_all(self, identifiers, permission_s):
        pass

    @abstractmethod
    def check_permission(self, identifiers, permission_s):
        pass

    @abstractmethod
    def has_role(self, identifiers, roleid_s):
        pass

    @abstractmethod
    def has_all_roles(self, identifiers, roleid_s):
        pass

    @abstractmethod
    def check_role(self, identifiers, roleid_s):
        pass

    # By default, Yosai does not support resolution of Role to Permission:
    # @property
    # @abstractmethod
    # def role_permission_resolver(self):
    #    pass
    #
    # @permission_resolver.setter
    # @abstractmethod
    # def role_permission_resolver(self, permissionresolver):
    #    pass
    #
    # @abstractmethod
    # def resolve_role_permission(self, role_names):
    #    pass
