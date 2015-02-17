class GenericException(Exception):
    pass


class IllegalArgumentException(Exception):
    pass


class IllegalStateException(Exception):
    pass


class UnavailableSecurityManagerException(Exception):
    pass


class ShiroException(RuntimeException):
    pass


class YosaiException(Exception):
    pass

# ---------------------------------------------------------------------------
# ---- Authentication Exceptions
# ---------------------------------------------------------------------------


class AuthenticationException(ShiroException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class AccountException(AuthenticationException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class ConcurrentAccessException(AccountException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class CredentialsException(AuthenticationException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class DisabledAccountException(AccountException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class ExcessiveAttemptsException(AccountException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class ExpiredCredentialsException(CredentialsException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class IncorrectCredentialsException(CredentialsException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class LockedAccountException(DisabledAccountException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class UnknownAccountException(AccountException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class IllegalArgumentException(Exception):
    pass


class YosaiException(Exception):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)  # DG:  not sure about the args..


class AuthenticationException(YosaiException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class AccountException(AuthenticationException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class UnknownAccountException(AccountException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


class ConcurrentAccessException(AccountException):
    def __init__(self, msg=None, cause=None):
        super().__init__(msg, cause)


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


class IllegalArgumentException(Exception):
    pass


class IllegalStateException(Exception):
    pass


# ---------------------------------------------------------------------------
# ----  Cache Exceptions
# ---------------------------------------------------------------------------


class CacheException(YosaiException):
    pass

