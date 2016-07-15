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
    pass


class YosaiContextException(YosaiException):
    pass


class FileNotFoundException(YosaiException):
    pass


class GenericException(YosaiException):
    pass


class IdentifierMismatchException(YosaiException):
    pass


class InvalidArgumentException(YosaiException):
    """
    When None is passed as an argument, it is considered a more extreme
    issue than one where an argument of an unexpected type is passed, raising
    an InvalidArgumentException instead.
    """
    pass


class IllegalStateException(YosaiException):
    pass


class UnavailableSecurityManagerException(YosaiException):
    pass


class MisconfiguredException(YosaiException):
    pass


class AbstractMethodException(YosaiException):
    pass


class MissingMethodException(YosaiException):
    pass


# ---------------------------------------------------------------------------
# ---- Authentication Exceptions
# ---------------------------------------------------------------------------

class AuthenticationException(YosaiException):
    pass


class AuthenticationConfigException(YosaiException):
    pass


class AuthenticationStrategyMissingRealmException(AuthenticationException):
    pass


class AccountStoreRealmAuthenticationException(AuthenticationException):
    pass


class AuthenticationSettingsContextException(AuthenticationException):
    pass


class AccountException(AuthenticationException):
    pass


class ConcurrentAccessException(AccountException):
    pass


class CredentialsNotFoundException(AuthenticationException):
    pass


class CredentialsException(AuthenticationException):
    pass


class CryptContextException(YosaiException):
    pass


class DisabledAccountException(AccountException):
    pass


class ExcessiveAttemptsException(AccountException):
    pass


class ExpiredCredentialsException(CredentialsException):
    pass


class IncorrectCredentialsException(CredentialsException):
    pass


class InvalidAuthenticationTokenException(AuthenticationException):
    pass


class InvalidAuthcAttemptRealmsArgumentException(AuthenticationException):
    pass


class InvalidTokenPasswordException(AuthenticationException):
    pass


class LockedAccountException(DisabledAccountException):
    pass


class MissingHashAlgorithmException(YosaiException):
    pass


class MissingCredentialsException(AuthenticationException):
    pass


class MissingPrivateSaltException(YosaiException):
    pass


class MultiRealmAuthenticationException(AuthenticationException):

    def __init__(self, realm_errors):
        msg = ("Multiple authentication problems across various realms.  "
               "Only the first discovered exception will be shown as the cause"
               "; call get_realm_exceptions() to access all of them.")
        super().__init__(msg, next(iter(realm_errors.values())))
        self.realm_errors = realm_errors

    def get_realm_exceptions(self):
        return self.realm_errors


class PasswordMatchException(AuthenticationException):
    pass


class PasswordVerifierInvalidTokenException(AuthenticationException):
    pass


class PasswordVerifierInvalidAccountException(AuthenticationException):
    pass


class PreparePasswordException(YosaiException):
    pass


class RealmAttributesException(AuthenticationException):
    pass


class UnknownAccountException(AccountException):
    pass


class UnsupportedTokenException(YosaiException):
    pass

# ---------------------------------------------------------------------------
# ---- Authorization Exceptions
# ---------------------------------------------------------------------------


class AuthorizationException(YosaiException):
    pass


class AuthzInfoNotFoundException(AuthorizationException):
    pass


class PermissionIndexingException(AuthorizationException):
    pass


class UnauthenticatedException(AuthorizationException):  # DG:  s/b Authen..
    pass


class UnauthorizedException(AuthorizationException):
    pass


class HostUnauthorizedException(UnauthorizedException):
    pass


# ---------------------------------------------------------------------------
# ----  Cache Exceptions
# ---------------------------------------------------------------------------


class CacheException(YosaiException):
    pass


# ---------------------------------------------------------------------------
# ----  EventBus Exceptions
# ---------------------------------------------------------------------------

class EventBusException(YosaiException):
    pass


class EventBusTopicException(EventBusException):
    pass


class EventBusMessageDataException(EventBusException):
    pass


class EventBusSubscriptionException(EventBusException):
    pass


# ---------------------------------------------------------------------------
# ----  Event Exceptions
# ---------------------------------------------------------------------------


class EventException(YosaiException):
    pass


class AuthorizationEventException(EventException):
    pass


class AuthenticationEventException(EventException):
    pass


class LogoutEventException(EventException):
    pass


class SessionEventException(EventException):
    pass


class EventRegistrationException(EventException):
    pass


# ---------------------------------------------------------------------------
# ----  Logging Exceptions
# ---------------------------------------------------------------------------


class LoggingException(YosaiException):
    pass


class LoggingSetupException(LoggingException):
    pass


# ---------------------------------------------------------------------------
# ---- Security Management Exceptions
# ---------------------------------------------------------------------------

class SecurityManagerException(YosaiException):
    pass


class SaveSubjectException(SecurityManagerException):
    pass


class DeleteSubjectException(SecurityManagerException):
    pass


class IncorrectAttributeException(YosaiException):
    pass


class UnrecognizedAttributeException(YosaiException):
    pass


# ---------------------------------------------------------------------------
# ----  Serialization Exceptions
# ---------------------------------------------------------------------------

class SerializationException(YosaiException):
    pass


class DeserializationException(SerializationException):
    pass


class InvalidSerializationFormatException(SerializationException):
    pass

# ---------------------------------------------------------------------------
# ---- Session Management Exceptions
# ---------------------------------------------------------------------------


class SessionException(YosaiException):
    pass


class SessionCacheException(YosaiException):
    pass


class InvalidSessionException(SessionException):
    pass


class StoppedSessionException(InvalidSessionException):
    pass


class ExpiredSessionException(StoppedSessionException):
    pass


class UnknownSessionException(InvalidSessionException):
    pass


class SessionCreationException(SessionException):
    pass


class SessionDeleteException(SessionException):
    pass


class UncacheSessionException(SessionException):
    pass


# ---------------------------------------------------------------------------
# ----  Subject Exceptions
# ---------------------------------------------------------------------------


class SubjectException(YosaiException):
    pass


class IdentifiersNotSetException(SubjectException):
    pass


class SecurityManagerNotSetException(SubjectException):
    pass


class ExecutionException(SubjectException):
    pass


class DisabledSessionException(SubjectException):
    pass


class SubjectContextException(SubjectException):
    pass


class UnrecognizedIdentifierException(SubjectException):
    pass


class UnsupportedOperationException(SubjectException):
    pass
