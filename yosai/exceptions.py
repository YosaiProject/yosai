class YosaiException(Exception):
    pass


class FileNotFoundException(YosaiException):
    pass


class GenericException(YosaiException):
    pass


class IllegalArgumentException(YosaiException):
    pass


class IllegalStateException(YosaiException):
    pass


class UnavailableSecurityManagerException(YosaiException):
    pass


class MisconfiguredException(YosaiException):
    pass


# ---------------------------------------------------------------------------
# ---- Authentication Exceptions
# ---------------------------------------------------------------------------


class AuthenticationException(YosaiException):
    pass


class AccountException(AuthenticationException):
    pass


class ConcurrentAccessException(AccountException):
    pass


class CredentialsException(AuthenticationException):
    pass


class DisabledAccountException(AccountException):
    pass


class ExcessiveAttemptsException(AccountException):
    pass


class ExpiredCredentialsException(CredentialsException):
    pass


class IncorrectCredentialsException(CredentialsException):
    pass


class LockedAccountException(DisabledAccountException):
    pass


class PasswordMatchException(AuthenticationException):
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
# ---- Realm Exceptions
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ---- Security Management Exceptions
# ---------------------------------------------------------------------------


class AuthenticationException(YosaiException):
    pass


class IncorrectAttributeException(YosaiException):
    pass


class InvalidSessionException(YosaiException):
    pass


class UnrecognizedAttributeException(YosaiException):
    pass


# ---------------------------------------------------------------------------
# ---- Session Management Exceptions
# ---------------------------------------------------------------------------


class AbstractMethodException(YosaiException):
    pass


class ExpiredSessionException(YosaiException):
    pass


class MissingMethodException(YosaiException):
    pass


class UnknownSessionException(YosaiException):
    pass


# ---------------------------------------------------------------------------
# ----  Subject Exceptions
# ---------------------------------------------------------------------------


class ExecutionException(YosaiException):
    pass


class DisabledSessionException(YosaiException):
    pass


class NullPointerException(YosaiException):
    pass


class PrimaryPrincipalIntegrityException(YosaiException):
    pass


class SessionException(YosaiException):
    pass


class UnrecognizedPrincipalException(YosaiException):
    pass


class UnsupportedOperationException(YosaiException):
    pass

