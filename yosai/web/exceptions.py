from yosai.core import (
    YosaiException,
)


class YosaiWebException(YosaiException):
    pass


class WSGIException(YosaiWebException):
    pass

