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
