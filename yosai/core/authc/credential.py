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

import logging

from yosai.core import (
    CryptContextFactory,
    IllegalStateException,
    MissingCredentialsException,
    PasswordMatchException,
    PasswordVerifierInvalidAccountException,
    PasswordVerifierInvalidTokenException,
    authc_abcs,
)

logger = logging.getLogger(__name__)


class DefaultPasswordService:

    def __init__(self, settings):
        # using default algorithm when generating crypt context:
        self.crypt_context = CryptContextFactory(settings).\
            create_crypt_context()

        # in Yosai, hash formatting is taken care of by passlib

    def passwords_match(self, password, saved):
        """
        :param password: the password requiring authentication, passed by user
        :type password: bytes

        :param saved: the password saved for the corresponding account, in
                      the MCF Format as created by passlib

        :returns: a Boolean confirmation of whether plaintext equals saved

        Unlike Shiro:
            - Yosai expects saved to be a str and never a binary Hash
            - passlib determines the format and compatability
        """
        try:
            return self.crypt_context.verify(password, saved)

        except (AttributeError, TypeError):
            raise PasswordMatchException('unrecognized attribute type')


class PasswordVerifier(authc_abcs.CredentialsVerifier):
    """ DG:  Dramatic changes made here while adapting to passlib and python"""

    def __init__(self, settings):
        self.password_service = DefaultPasswordService(settings)

    def credentials_match(self, authc_token, account):
        self.ensure_password_service()
        submitted_password = self.get_submitted_password(authc_token)

        # stored_credentials should either be bytes or unicode:
        stored_credentials = self.get_stored_password(account)

        return self.password_service.passwords_match(submitted_password,
                                                     stored_credentials)

    def ensure_password_service(self):
        if (not self.password_service):
            msg = "Required PasswordService has not been configured."
            raise IllegalStateException(msg)

    def get_submitted_password(self, authc_token):
        try:
            creds = authc_token.credentials
        except AttributeError:
            raise PasswordVerifierInvalidTokenException

        if not creds:
            raise PasswordVerifierInvalidTokenException('A password is required.')

        return creds

    def get_stored_password(self, account):
        try:
            return account.credentials.credential
        except AttributeError:
            raise PasswordVerifierInvalidAccountException


class SimpleCredentialsVerifier(authc_abcs.CredentialsVerifier):

    def __init__(self):
        pass

    def get_credentials(self, credential_source):
        """
        :type credential_source: an AuthenticationToken or Account object
        :param credential_source:  an object that manages state of credentials
        """
        try:
            return credential_source.credentials
        except (AttributeError, TypeError):
            raise MissingCredentialsException  # new to Yosai

    def credentials_match(self, authc_token, account):
        try:
            return self.equals(authc_token.credentials, account.credentials)
        except (AttributeError, TypeError):
            raise MissingCredentialsException  # new to Yosai

    def equals(self, token_credentials, account_credentials):
        """
        returns bool confirming whether the token_credentials are equal to the
        account_credentials
        """
        msg = ("Performing credentials equality check for tokenCredentials "
               "of type [{0}] and accountCredentials of type [{1}]".
               format(token_credentials.__class__.__name__,
                      account_credentials.__class__.__name__))
        logger.debug(msg)

        if (isinstance(token_credentials, str)):
            token_credentials = bytearray(token_credentials, 'utf-8')
        if (isinstance(account_credentials, str)):
            account_credentials = bytearray(account_credentials, 'utf-8')

        return token_credentials == account_credentials


class AllowAllCredentialsVerifier(authc_abcs.CredentialsVerifier):

    def credentials_match(self, authc_token, account):
        return True
