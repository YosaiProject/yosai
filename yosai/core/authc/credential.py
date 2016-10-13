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
from passlib.totp import OTPContext, TokenError, TOTP

from yosai.core import (
    AuthenticationSettings,
    IncorrectCredentialsException,
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
        self.totp_cc = self.create_totp_crypt_context(authc_settings)
        self.cc_token_resolver = {UsernamePasswordToken: self.password_cc,
                                  TOTPToken: self.totp_cc}
        self.supported_tokens = self.cc_token_resolver.keys()

    def verify_credentials(self, authc_token, authc_info):
        submitted = authc_token.credentials
        stored = self.get_stored_credentials(authc_token, authc_info)
        service = self.cc_token_resolver[authc_token.__class__]

        try:
            if isinstance(authc_token, UsernamePasswordToken):
                result = service.verify(submitted, stored)
                if not result:
                    raise IncorrectCredentialsException
            else:
                totp = TOTP(key=stored)
                totp.verify(submitted)

        except (ValueError, TokenError):
            raise IncorrectCredentialsException

    def get_stored_credentials(self, authc_token, authc_info):
        # look up the db credential type assigned to this type token:
        cred_type = authc_token.token_info['cred_type']

        try:
            return authc_info[cred_type]['credential']

        except KeyError:
            msg = "{0} is required but unavailable from authc_info".format(cred_type)
            raise InsufficientAuthcInfoException(msg)

    def create_password_crypt_context(self, authc_settings):
        context = dict(schemes=[authc_settings.preferred_algorithm])
        context.update(authc_settings.preferred_algorithm_context)
        return CryptContext(**context)

    def create_totp_crypt_context(self, saved_key):
        pass
        # context = authc_settings.totp_context
        # return OTPContext(**context).new(type='totp')
