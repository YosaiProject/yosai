import ShiroException


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
