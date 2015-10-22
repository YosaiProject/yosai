import functools
from yosai import (
    security_utils,
)


def requires_permission(_permission_s, logical_operator=all):
    """
    Requires that the calling Subject be authorized to the extent that is
    required to satisfy the permission_s specified and the logical operation
    upon them.

    :param permissions:   the permission(s) required
    :type permissions:  a Str or List of Strings

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

            permission_s = list(_permission_s)  # in case it's a single

            subject = security_utils.get_subject()

            subject.check_permission(permission_s, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wrap


def requires_role(_roleid_s, logical_operator=all):
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

            roleid_s = list(_roleid_s)  # in case it's a single string

            subject = security_utils.get_subject()

            subject.check_role(roleid_s, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wrap
