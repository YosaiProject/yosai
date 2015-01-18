import traceback


class GenericException(Exception):
    pass


class IllegalArgumentException(Exception):
    pass


class IllegalStateException(Exception):
    pass


class UnavailableSecurityManagerException(Exception):
    pass
