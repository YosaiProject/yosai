class YosaiException(Exception):
    pass


class GenericException(Exception):
    pass


class IllegalArgumentException(Exception):
    pass


class IllegalStateException(Exception):
    pass


class UnavailableSecurityManagerException(Exception):
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


class UnknownAccountException(AccountException):
    pass


class YosaiException(Exception):
    pass


class AuthenticationException(YosaiException):
    pass


class AccountException(AuthenticationException):
    pass


class UnsupportedTokenException(Exception):
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


class AuthenticationException(Exception):
    pass


class IncorrectAttributeException(Exception):
    pass


class InvalidSessionException(Exception):
    pass


class UnrecognizedAttributeException(Exception):
    pass


# ---------------------------------------------------------------------------
# ---- Session Management Exceptions
# ---------------------------------------------------------------------------


class AbstractMethodException(Exception):
    pass


class ExpiredSessionException(Exception):
    pass


class MissingMethodException(Exception):
    pass


class UnknownSessionException(Exception):
    pass


# ---------------------------------------------------------------------------
# ----  Subject Exceptions
# ---------------------------------------------------------------------------


class ExecutionException(YosaiException):
    pass


class DisabledSessionException(Exception):
    pass


class NullPointerException(Exception):
    pass


class PrimaryPrincipalIntegrityException(Exception):
    pass


class SessionException(Exception):
    pass


class UnrecognizedPrincipalException(Exception):
    pass


class UnsupportedOperationException(Exception):
    pass

