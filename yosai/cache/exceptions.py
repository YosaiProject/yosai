import ShiroException


class CacheException(ShiroException):
    def __init__(self, message=None, cause=None):
        """
        :type message: str
        :param message: the reason for the exception
        :type cause: Exception
        :param cause: the underlying Exception that raised this one
        """
        super().__init__(message=message, cause=cause)
