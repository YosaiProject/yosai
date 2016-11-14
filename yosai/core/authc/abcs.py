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


class AuthenticationToken(metaclass=ABCMeta):
    """
    An ``AuthenticationToken`` is a consolidation of an account's identifiers and
    supporting credentials submitted by a user during an authentication
    attempt.

    The token is submitted to an ``Authenticator`` via the
    ``authenticate_account(authc_token)`` method.  The ``Authenticator`` then
    executes the authentication/log-in process.

    Common implementations of an ``AuthenticationToken`` would have
    username/password pairs, X.509 Certificate, PGP key, or anything else you
    can think of.  The token can be anything needed by an Authenticator to
    authenticate properly.

    Because applications represent user data and credentials in different ways,
    implementations of this interface are application-specific.  You are free
    to acquire a user's identifiers and credentials however you wish (e.g. web
    form, a form, fingerprint identification, etc) and then submit them to
    the Yosai framework in the form of an implementation of this interface.

    If your application's authentication process is username/password based
    (like most), rather than implementing this interface yourself take a look
    at the ``UsernamePasswordToken`` class, as it is probably sufficient for your
    needs.

    ``RememberMe`` services are enabled for a token if they implement a
    sub-interface of this one, called ``RememberMeAuthenticationToken``.  Implement
    that interface if you need ``RememberMe`` services (the UsernamePasswordToken
    already implements this interface).
    """

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
    An Authenticator is responsible for authenticating accounts.

    Although not a requirement, there is usually a single 'master' Authenticator
    configured for an application.  Enabling Pluggable Authentication Module (PAM)
    behavior (Two Phase Commit, etc.) is usually achieved by the master
    ``Authenticator`` coordinating and interacting with an application-configured
    set of ``Realm``s.

    Note that most Yosai users will not interact with an ``Authenticator``
    instance directly. Yosai's default architecture is based on an overall
    ``SecurityManager`` which typically wraps an ``Authenticator`` instance.
    """

    @abstractmethod
    def authenticate_account(self, authc_token):
        """
        Authenticates an account based on the submitted ``AuthenticationToken``.

        If the authentication is successful, the ``Account`` instance representing
        data relevant to Yosai is returned.  The returned account is used by
        higher-level components to construct a ``Subject`` representing a more
        complete security-specific 'view' of an account that also allows access to
        a ``Session``.

        :param authc_token: any representation of an account's identifiers and
                            credentials submitted during an authentication attempt

        :returns the authenticated account
        :raises AuthenticationException: if there is any problem during the authentication process

          - See the specific exceptions listed below to as examples of what could happen
            in order to accurately handle these problems and to notify the user in an
            appropriate manner why the authentication attempt failed.  Realize an
            implementation of this interface may or may not throw those listed or may
            throw other AuthenticationExceptions, but the list shows the most common ones.
        """
        pass


class CredentialsVerifier(metaclass=ABCMeta):

    @abstractmethod
    def verify_credentials(authc_token, account):
        pass


class MFADispatcher(metaclass=ABCMeta):

    @abstractmethod
    def dispatch(self, mfa_info, token):
        pass
