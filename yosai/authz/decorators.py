import functools

def requires_authentication():

    def wrapped(fn):
        @functools.wraps(fn)
        def wrapped_f(*args, **kwargs):
            return fn(*args, **kwargs)

        # add the yosai pre-authentication code block here

        return wrapped_f
    return wrapped


def requires_permission(permission_s, logical_operator=all):
    """
    :param permission_s:   the permission(s) required
    :type permission_s:  a Str or List of Strings
    :param logical_operator:  indicates whether all or at least one permission
                              is true (and, any)
    :type: and OR all (from python standard library)

    Elaborate Example:
        requires_permissions(
            permission_s=['domain1:action1,action2', 'domain2:action1'],
            logical_operator=any)

    Basic Example:
        requires_permissions('domain1:action1,action2')
    """
    def outer_wrap(fn):
        @functools.wraps(fn)
        def inner_wrap(*args, **kwargs):
            permission_s = list(permission_s)  # in case it's a single string

            # get the current executing subject
            # invoke is_permission(identifiers, permission_s),
            # use the logical_operator

            # results is a frozenset of tuples:
            results = subject.is_permitted(identifers, permission_s)
            permits = [is_permitted for perm, is_permitted in results]
            is_permitted = logical_operator(permits)
            if is_permitted:
                return fn(*args, **kwargs)
            else:
                raise ?????????????
        return inner_wrap
    return outer_wrap


#def requires_roles

def requires_user(fn):
    """
    Requires that the calling Subject is *either* authenticated *or* remembered
    via RememberMe services before allowing access.

    This method essentially ensures that subject.identifiers is not None
    """

    @functools.wraps(fn)
    def wrap(*args, **kwargs):
        if subject.identifiers is None:
            msg = ("Attempting to perform a user-only operation.  The "
                   "current Subject is NOT a user (they haven't been "
                   "authenticated or remembered from a previous login). "
                   "ACCESS DENIED.")
            raise UnauthenticatedException(msg)

        return fn(*args, **kwargs)
    return wrap

#def requires_guest
