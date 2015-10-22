import functools
from yosai import (
    security_utils,
    UnauthenticatedException,
)

def requires_authentication(fn):
    """
    Requires that the calling Subject be authenticated before allowing access.

    :raises UnauthenticatedException: indicating that the decorated method is
                                      not allowed to be executed because the
                                      Subject failed to authenticate
    """

    @functools.wraps(fn)
    def wrap(*args, **kwargs):

        subject = security_utils.get_subject()

        if not subject.authenticated():
            msg = "The current Subject is not authenticated.  ACCESS DENIED."
            raise UnauthenticatedException(msg)

        return fn(*args, **kwargs)
    return wrap


def requires_user(fn):
    """
    Requires that the calling Subject be *either* authenticated *or* remembered
    via RememberMe services before allowing access.

    This method essentially ensures that subject.identifiers IS NOT None

    :raises UnauthenticatedException: indicating that the decorated method is
                                      not allowed to be executed because the
                                      Subject attempted to perform a user-only
                                      operation
    """

    @functools.wraps(fn)
    def wrap(*args, **kwargs):

        subject = security_utils.get_subject()

        if subject.identifiers is None:
            msg = ("Attempting to perform a user-only operation.  The "
                   "current Subject is NOT a user (they haven't been "
                   "authenticated or remembered from a previous login). "
                   "ACCESS DENIED.")
            raise UnauthenticatedException(msg)

        return fn(*args, **kwargs)
    return wrap


def requires_guest(fn):
    """
    Requires that the calling Subject be NOT (yet) recognized in the system as
    a user -- the Subject is not yet authenticated nor remembered through
    RememberMe services.

    This method essentially ensures that subject.identifiers IS None

    :raises UnauthenticatedException: indicating that the decorated method is
                                      not allowed to be executed because the
                                      Subject attempted to perform a guest-only
                                      operation
    """
    @functools.wraps(fn)
    def wrap(*args, **kwargs):

        subject = security_utils.get_subject()

        if subject.identifiers is not None:
            msg = ("Attempting to perform a guest-only operation.  The "
                   "current Subject is NOT a guest (they have either been "
                   "authenticated or remembered from a previous login). "
                   "ACCESS DENIED.")
            raise UnauthenticatedException(msg)

        return fn(*args, **kwargs)
    return wrap
