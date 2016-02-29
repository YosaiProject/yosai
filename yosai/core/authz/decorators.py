import functools
from yosai.core import (
    get_current_lib,
)


def requires_permission(permission_s, logical_operator=all):
    """
    Requires that the calling Subject be authorized to the extent that is
    required to satisfy the permission_s specified and the logical operation
    upon them.

    :param permission_s:   the permission(s) required
    :type permission_s:  a List of Strings or List of Permission instances

    :param logical_operator:  indicates whether all or at least one permission
                              is true (and, any)
    :type: and OR all (from python standard library)

    :raises  AuthorizationException:  if the user does not have sufficient
                                      permission

    Elaborate Example:
        requires_permission(
            permission_s=['domain1:action1,action2', 'domain2:action1'],
            logical_operator=any)

    Basic Example:
        requires_permission(['domain1:action1,action2'])
    """
    def outer_wrap(fn):
        @functools.wraps(fn)
        def inner_wrap(*args, **kwargs):

            yosai = get_current_lib()
            subject = yosai.subject

            subject.check_permission(permission_s, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wrap


def requires_dynamic_permission(permission_s, logical_operator=all):
    """
    This method requires that the calling Subject be authorized to the extent
    that is required to satisfy the dynamic permission_s specified and the logical
    operation upon them.  Unlike ``requires_permission``, which uses statically
    defined permissions, this function derives a permission from arguments
    specified at declaration.

    Dynamic permissioning requires that the dynamic arguments be keyword
    arguments of the decorated method.

    :param permission_s:   the permission(s) required
    :type permission_s:  a List of Strings or List of Permission instances

    :param logical_operator:  indicates whether all or at least one permission
                              is true (and, any)
    :type: and OR all (from python standard library)

    :raises  AuthorizationException:  if the user does not have sufficient
                                      permission

    Elaborate Example:
        requires_permission(
            permission_s=['{kwarg1.domainid}:action1,action2',
                           '{kwarg2.domainid}:action1'],
            logical_operator=any)

    Basic Example:
        requires_permission(['{kwarg.domainid}:action1,action2'])
    """
    def outer_wrap(fn):
        @functools.wraps(fn)
        def inner_wrap(*args, **kwargs):
            newperms = [perm.format(**kwargs) for perm in permission_s]

            yosai = get_current_lib()
            subject = yosai.subject

            subject.check_permission(newperms, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wrap


def requires_role(roleid_s, logical_operator=all):
    """
    Requires that the calling Subject be authorized to the extent that is
    required to satisfy the roleid_s specified and the logical operation
    upon them.

    :param roleid_s:   a collection of the role(s) required, specified by
                       identifiers (such as a role name)
    :type roleid_s:  a List of Strings

    :param logical_operator:  indicates whether all or at least one permission
                              is true (and, any)
    :type: and OR all (from python standard library)

    :raises  AuthorizationException:  if the user does not have sufficient
                                      role membership

    Elaborate Example:
        requires_role(roleid_s=['sysadmin', 'developer'], logical_operator=any)

    Basic Example:
        requires_role('physician')
    """
    def outer_wrap(fn):
        @functools.wraps(fn)
        def inner_wrap(*args, **kwargs):

            yosai = get_current_lib()
            subject = yosai.subject

            subject.check_role(roleid_s, logical_operator)

            return fn(*args, **kwargs)
        return inner_wrap
    return outer_wrap
