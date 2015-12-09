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

from yosai.core import (
    account_abcs,
)

from abc import ABCMeta, abstractmethod


# replaced AuthenticationEvents with an event schema:  a) type b) topic

class AuthenticationListener(metaclass=ABCMeta):
    """
     An AuthenticationListener listens for notifications while Subjects
     authenticate with the system.
    """

    @abstractmethod
    def on_success(self, authc_token, account):
        """
        Callback triggered when an authentication attempt for a Subject
        succeeds

        :param authc_token: the authentication token submitted during the
                            Subject (user)'s authentication attempt
        :param account:  the authentication-related account data acquired
                         after authentication for the corresponding Subject
        """
        pass

    @abstractmethod
    def on_failure(self, authc_token, authc_exception):
        """
        Callback triggered when an authentication attempt for a Subject fails

        :param authc_token: the authentication token submitted during the
                            Subject (user)'s authentication attempt
        :param authc_exception: the AuthenticationException that occurred as
                                a result of the attempt
        """
        pass

    @abstractmethod
    def on_logout(self, identifiers):
        """
        Callback triggered when a {@code Subject} logs-out of the system.

        This method will only be triggered when a Subject explicitly logs-out
        of the session.  It will not be triggered if their Session times out.

        :param identifiers: the identifying identifiers of the Subject logging
                           out.
        :type identifiers:  SimpleIdentifierCollection
        """
        pass


class AuthenticationToken(metaclass=ABCMeta):
    """
    An AuthenticationToken is a consolidation of an account's identifiers and
    supporting credentials submitted by a user during an authentication
    attempt.

    The token is submitted to an Authenticator via the
    authenticate_account(token) method.  The Authenticator then executes the
    authentication/log-in process.

    Common implementations of an AuthenticationToken would have
    username/password pairs, X.509 Certificate, PGP key, or anything else you
    can think of.  The token can be anything needed by an Authenticator to
    authenticate properly.

    Because applications represent user data and credentials in different ways,
    implementations of this interface are application-specific.  You are free
    to acquire a user's identifiers and credentials however you wish (e.g. web
    form, Swing form, fingerprint identification, etc) and then submit them to
    the Yosai framework in the form of an implementation of this interface.

    >If your application's authentication process is  username/password based
    (like most), instead of implementing this interface yourself, take a look
    at the UsernamePasswordToken class, as it is probably sufficient for your
    needs.

    RememberMe services are enabled for a token if they implement a
    sub-interface of this one, called RememberMeAuthenticationToken.  Implement
    that interface if you need RememberMe services (the UsernamePasswordToken
    already implements this interface).

    If you are familiar with JAAS, an AuthenticationToken replaces the concept
    of a Callback, and  defines meaningful behavior (Callback is just a marker
    interface, and of little use).  We also think the name AuthenticationToken
    more accurately reflects its true purpose in a login framework, whereas
    Callback is less obvious.
    """

    @property
    @abstractmethod
    def identifiers(self):
        """
        Returns the account identity submitted during the authentication
        process.
        """
        pass

    @property
    @abstractmethod
    def credentials(self):
        """
        Returns the credentials submitted by the user during the authentication
        process that verifies the submitted Identifier account identity.
        """
        pass


class Authenticator(metaclass=ABCMeta):
    """
    Authenticates an account based on the submitted AuthenticationToken.
    """

    @abstractmethod
    def authenticate_account(self, authc_token):
        """
        Authenticates an account based on the submitted AuthenticationToken
        """
        pass


class CompositeAccountId(account_abcs.AccountId):

    @abstractmethod
    def get_realm_account_id(self, realm_name):
        pass


class CompositeAccount(account_abcs.Account):

    @property
    @abstractmethod
    def realm_names(self):
        pass

    @abstractmethod
    def append_realm_account(self, realm_name, account):
        pass

    @abstractmethod
    def get_realm_attributes(self, realm_name):
        pass


class CredentialsVerifier(metaclass=ABCMeta):

    @abstractmethod
    def credentials_match(authc_token, account):
        pass


class HostAuthenticationToken(AuthenticationToken):

    @property
    @abstractmethod
    def host(self):
        pass


class LogoutAware(metaclass=ABCMeta):

    @abstractmethod
    def on_logout(self, identifiers):
        """
        :type identifiers:  SimpleIdentifierCollection
        """
        pass


class PasswordService(metaclass=ABCMeta):

    @abstractmethod
    def encrypt_password(self, plaintext_password):
        pass

    @abstractmethod
    def passwords_match(self, submitted_plaintext, encrypted):
        pass


class HashingPasswordService(PasswordService):

    @abstractmethod
    def hash_password(self, plaintext_password):
        pass

    @abstractmethod
    def passwords_match(self, plaintext_password, saved_password_hash):
        pass


class RememberMeAuthenticationToken(AuthenticationToken):

    @property
    @abstractmethod
    def is_remember_me(self):
        pass


class AuthenticationAttempt(metaclass=ABCMeta):

    @property
    @abstractmethod
    def authentication_token(self):
        pass

    @property
    @abstractmethod
    def realms(self):
        pass


class AuthenticationStrategy(metaclass=ABCMeta):
    """
    A AuthenticationStrategy implementation attempts to authenticate an account
    by consulting one or more Realms. This interface enables the
    <a href="http://en.wikipedia.org/wiki/Strategy_pattern">Strategy Design Pattern</a>
    for authentication, allowing a Yosai user to customize an Authenticator's
    authentication processing logic.

    Most Yosai users will find one of the existing Strategy implementations
    suitable for most needs, but if those are not sufficient, custom logic can
    be performed by implementing this interface.
    """
    @abstractmethod
    def execute(self, attempt):
        pass


class CredentialResolver(metaclass=ABCMeta):

    @abstractmethod
    def resolve(self, credential):
        pass


# new to yosai.core.
class CredentialResolverAware(metaclass=ABCMeta):

    @property
    @abstractmethod
    def credential_resolver(self):
        pass

    @credential_resolver.setter
    @abstractmethod
    def credential_resolver(self, credentialresolver):
        pass
