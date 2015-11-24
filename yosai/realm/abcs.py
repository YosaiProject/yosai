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


class PermissionResolver(metaclass=ABCMeta):
    pass


# yosai does not support role->permission resolution, but the interface is
# provided for guidance:
class RolePermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_role_permissions(self, account, role_name):
        pass


class RoleResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_role_names(self, account):
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
    def do_clear_cache(self, identifier_s):
        pass


# new to yosai:
class AuthenticatingRealm(Realm, authc_abcs.Authenticator):

    @property
    @abstractmethod
    def credentials_verifier(self):
        pass

    @credentials_verifier.setter
    @abstractmethod
    def credentials_verifier(self, credentialsmatcher):
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
    def permission_verifier(self):
        pass

    @permission_verifier.setter
    @abstractmethod
    def permission_verifier(self, verifier):
        pass

    @property
    @abstractmethod
    def role_verifier(self):
        pass

    @role_verifier.setter
    @abstractmethod
    def role_verifier(self, verifier):
        pass

    @abstractmethod
    def get_authorization_info(self, identifier_s):
        pass

    @abstractmethod
    def is_permitted(self, identifier_s, permission_s):
        pass

    @abstractmethod
    def has_role(self, identifier_s, roleid_s):
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
