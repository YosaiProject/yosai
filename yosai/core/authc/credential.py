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
from passlib.context import CryptContext
from passlib.totp import OTPContext, TokenError

from yosai.core import (
    AuthenticationSettings,
    InsufficientAuthcInfoException,
    PasswordMatchException,
    TOTPToken,
    UnsupportedTokenException,
    UsernamePasswordToken,
    authc_abcs,
)

logger = logging.getLogger(__name__)


class PasslibVerifier(authc_abcs.CredentialsVerifier):

    def __init__(self, settings):
        authc_settings = AuthenticationSettings(settings)
        self.password_cc = self.create_password_crypt_context(authc_settings)
        self.totp = self.create_totp(authc_settings)
        self.cc_token_resolver = {UsernamePasswordToken: self.password_cc,
                                  TOTPToken: self.totp}
        self.credential_resolver = {UsernamePasswordToken: 'password',
                                    TOTPToken: 'totp_key'}
        self.supported_tokens = self.cc_token_resolver.keys()

    def verify_credentials(self, authc_token, account):
        submitted = authc_token.credentials
        stored = self.get_stored_credentials(authc_token, account)
        service = self.cc_token_resolver[authc_token.__class__]

        try:
            if isinstance(authc_token, UsernamePasswordToken):
                service.verify(submitted, stored)
            else:
                totp = service(stored)
                totp.verify(submitted)

        except (ValueError, TokenError):
            raise IncorrectCredentialsException(account)

    def get_stored_credentials(self, authc_token, account):
        authc_info = account.authc_info

        try:
            return authc_info[self.credential_resolver[authc_token.__class__]]

        except KeyError as exc:
            if authc_token.__class__ not in self.credential_resolver:
                msg = '{0} does not support {1}.'.format(self.__class__.__name__,
                                                         authc_token.__class__.__name__)
                raise UnsupportedTokenException(msg)

            raise InsufficientAuthcInfoException

    def create_password_crypt_context(self, authc_settings):
        context = dict(schemes=[authc_settings.preferred_algorithm])
        context.update(authc_settings.preferred_algorithm_context)
        return CryptContext(**context)

    def create_totp(self, authc_settings):
        context = authc_settings.totp_context
        return OTPContext(**context).new(type='totp')  # TODO update with kwargs
