

class GenericException(Exception):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class IllegalArgumentException(Exception):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class IllegalStateException(Exception):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class UnavailableSecurityManagerException(Exception):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)


class ShiroException(RuntimeException):

    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)
