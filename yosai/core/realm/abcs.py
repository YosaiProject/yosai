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

from yosai.core import (
    account_abcs,
    authc_abcs,
)


class Realm(metaclass=ABCMeta):
    """
    A ``Realm`` access application-specific security entities such as accounts,
    roles, and permissions to perform authentication and authorization operations.

    ``Realm``s usually have a 1-to-1 correlation with an ``AccountStore``,
    such as a NoSQL or relational database, file system, or other similar resource.
    However, since most Realm implementations are nearly identical, except for
    the account query logic, a default realm implementation, ``AccountStoreRealm``,
    is provided, allowing you to configure it with the data API-specific
    ``AccountStore`` instance.

    Because most account stores usually contain Subject information such as
    usernames and passwords, a Realm can act as a pluggable authentication module
    in a <a href="http://en.wikipedia.org/wiki/Pluggable_Authentication_Modules">PAM</a>
    configuration.  This allows a Realm to perform *both* authentication and
    authorization duties for a single account store, catering to most
    application needs.  If for some reason you don't want your Realm implementation
    to participate in authentication, override the ``supports(authc_token)`` method
    to always return False.

    Because every application is different, security data such as users and roles
    can be represented in any number of ways.  Yosai tries to maintain a
    non-intrusive development philosophy whenever possible -- it does not require
    you to implement or extend any *User*, *Group* or *Role* interfaces or classes.

    Instead, Yosai allows applications to implement this interface to access
    environment-specific account stores and data model objects.  The
    implementation can then be plugged in to the application's Yosai configuration.
    This modular technique abstracts away any environment/modeling details and
    allows Yosai to be deployed in practically any application environment.

    Most users will not implement this ``Realm`` interface directly, but will
    instead use an ``AccountStoreRealm`` instance configured with an underlying
    ``AccountStore``. This setup implies that there is an ``AccountStoreRealm``
    instance per ``AccountStore`` that the application needs to access.

    Yosai introduces two additional Realm interfaces in order to separate authentication
    and authorization responsibilities.
    """

    @abstractmethod
    def do_clear_cache(self, identifiers):
        """
        :type identifiers:  SimpleRealmCollection
        """
        pass


# new to yosai.core:
class AuthenticatingRealm(Realm, authc_abcs.Authenticator):
    """
    required attributes:
        authc_verifiers
    """

    @property
    @abstractmethod
    def supported_authc_tokens(self):
        """
        :rtype: list
        :returns: a list of authentication token classes verifiable by the realm
        """
        pass

    @abstractmethod
    def get_authentication_info(self, identifier):
        pass

    @abstractmethod
    def authenticate_account(self, authc_token):
        pass

    @abstractmethod
    def assert_credentials_match(self, authc_token, account):
        pass

    @abstractmethod
    def clear_cached_authc_info(self, identifiers):
        pass


class TOTPAuthenticatingRealm(AuthenticatingRealm):

    @abstractmethod
    def generate_totp_token(self, totp_key):
        pass


# new to yosai.core:
class AuthorizingRealm(Realm):
    """
    required attributes:
        permission_verifier
        role_verifier
    """

    @abstractmethod
    def get_authzd_permissions(self, identitier, domain):
        pass

    @abstractmethod
    def get_authzd_roles(self, identitier):
        pass

    @abstractmethod
    def is_permitted(self, identifiers, permission_s):
        """
        :type identifiers:  SimpleRealmCollection
        """
        pass

    @abstractmethod
    def has_role(self, identifiers, role_s):
        """
        :type identifiers:  SimpleRealmCollection
        """
        pass

    @abstractmethod
    def clear_cached_authorization_info(self, identifiers):
        pass


class LockingRealm(Realm):

    @abstractmethod
    def lock_account(self, account):
        pass

    @abstractmethod
    def unlock_account(self, account):
        pass
