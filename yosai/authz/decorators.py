import functools


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


def requires_permission(permission_s, logical_operator=all):
    """
    Requires that the calling Subject be authorized to the extent that is
    required to satisfy the permission_s specified and the logical operation
    upon them.

    :param permission_s:   the permission(s) required
    :type permission_s:  a Str or List of Strings

    :param logical_operator:  indicates whether all or at least one permission
                              is true (and, any)
    :type: and OR all (from python standard library)

    Elaborate Example:
        requires_permission(
            permission_s=['domain1:action1,action2', 'domain2:action1'],
            logical_operator=any)

    Basic Example:
        requires_permission('domain1:action1,action2')
    """
    def outer_wrap(fn):
        @functools.wraps(fn)
        def inner_wrap(*args, **kwargs):

            permission_s = list(permission_s)  # in case it's a single string

            subject = security_utils.get_subject()

            subject.check_permission(permission_s, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wrap


def requires_role(roleid_s, logical_operator=all):
    """
    Requires that the calling Subject be authorized to the extent that is
    required to satisfy the roleid_s specified and the logical operation
    upon them.

    :param roleid_s:   a collection of the role(s) required, specified by
                       identifier (such as a role name)
    :type roleid_s:  a Str or List of Strings

    :param logical_operator:  indicates whether all or at least one permission
                              is true (and, any)
    :type: and OR all (from python standard library)

    Elaborate Example:
        requires_role(roleid_s=['sysadmin', 'developer'], logical_operator=any)

    Basic Example:
        requires_role('physician')
    """
    def outer_wrap(fn):
        @functools.wraps(fn)
        def inner_wrap(*args, **kwargs):

            roleid_s = list(roleid_s)  # in case it's a single string

            subject = security_utils.get_subject()

            subject.check_role(roleid_s, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wra


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


def requires_guest():
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
