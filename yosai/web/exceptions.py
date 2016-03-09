from yosai.core import (
    YosaiException,
)


class YosaiWebException(YosaiException):
    pass


class MissingWebRegistryException(YosaiWebException):
    pass
