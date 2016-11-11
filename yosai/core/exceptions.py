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


class YosaiException(Exception):
    """
    The master root exception that all other exceptions are sub-classed from
    """
    pass


# ---------------------------------------------------------------------------
# ---- Authentication Exceptions
# ---------------------------------------------------------------------------

class AdditionalAuthenticationRequired(YosaiException):
    """
    Raises when prior authentication succeeds and more authentication is
    required (implies second factor authentication)
    """
    def __init__(self, account_id=None):
        self.account_id = account_id


class ConsumedTOTPToken(YosaiException):
    """
    Raises following a successful TOTP authentication as a signal to the
    authenticating method to consume the TOTP token and prevent replay attack
    """
    def __init__(self, totp_match=None):
        self.totp_match = totp_match


class AuthenticationException(YosaiException):
    """
    A sub-root exception type
    """
    pass


class AccountException(AuthenticationException):
    """
    Raises when no account is returned for a given authentication token
    """
    pass


class IncorrectCredentialsException(AuthenticationException):
    def __init__(self, failed_attempts=None):
        """
        a list of unix epoch timestampts of recently failed attempts for user
        """
        self.failed_attempts = failed_attempts


class InvalidAuthenticationSequenceException(AuthenticationException):
    """
    Raises when authentication is attempted out of sequence, usually when
    a tier-2 token is authenticated prior to a tier-1.
    """
    pass


class LockedAccountException(YosaiException):
    pass


class MultiRealmAuthenticationException(AuthenticationException):

    def __init__(self, realm_errors):
        self.realm_errors = realm_errors[0]

# ---------------------------------------------------------------------------
# ---- Authorization Exceptions
# ---------------------------------------------------------------------------


class AuthorizationException(YosaiException):
    """
    A sub-root exception type
    """
    pass


class UnauthenticatedException(AuthorizationException):
    """
    Raises when a subject that isn't authenticated attempts to authorize
    """
    pass


class UnauthorizedException(AuthorizationException):
    """
    Raises when a subject isn't authorized to perform a behavior
    """
    pass


# ---------------------------------------------------------------------------
# ---- Session Management Exceptions
# ---------------------------------------------------------------------------


class SessionException(YosaiException):
    """
    A sub-root exception type
    """
    pass


class InvalidSessionException(SessionException):
    pass


class StoppedSessionException(InvalidSessionException):
    pass


class ExpiredSessionException(StoppedSessionException):
    pass


class IdleExpiredSessionException(ExpiredSessionException):
    pass


class AbsoluteExpiredSessionException(ExpiredSessionException):
    pass
