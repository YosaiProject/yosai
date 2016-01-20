# Authorization API Reference

Yosai provides role-level and permission-level access control.

Both levels of access control can be performed using two styles:
- The **Declarative Style** of authorization involves use of a decorator that performs one of the two levels of access control (role or permission).  The wrapped method is never called if authorization fails.

- The **Imperative Style** of authorization involves in-line access control within the operation that requires authorization.


## Declarative-Style Authorization

Declarative-style authorization allows you to itemize access requirements for a function call.  There are two declarative-style "authorizers", one for permission-level and another for role-level access control.  An ``AuthorizationException`` is raised when a user fails to meet specified access requirements. Following is the API you may use for declarative-style
```Python
requires_permission(permission_s, logical_operator=all)

requires_role(roleid_s, logical_operator=all)
```

``logical_operator``, the second parameter of both declarative-style authorizers, can be either ``any`` or ``all`` functions from the python standard library.  Use ``any`` when you want to evaluate each item *independently* of the others and ``all`` when you want to evaluate items *collectively*.


### Example 1:  All Permissions are Required

The following permissions are required, collectively, to call this_function.
When this_function is called, the caller of this_function should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @requires_permission(['domain1:action1', 'domain2:action2'], all)
    def this_function(...):
        ...
```

### Example 2:  Any Permission Specified is Acceptable

The following permissions are required, each independently satisfying the access control requirement, to call this_function. When this_function is called, the caller should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @requires_permission(['domain1:action1', 'domain2:action2'], any)
    def this_function(...):
        ...
```

### Example 3:  All Roles are Required

The following roles are required, collectively, to call this_function.
When this_function is called, the caller of this_function should be ready to handle an AuthorizationException if the user is denied access:
```Python
    @requires_role(['role1', 'role2'], all)
    def this_function(...):
        ...
```

### Example 4:  Any Role Specified is Acceptable

The following roles are required, each independently satisfying the access control requirement, to call this_function. When this_function is called, the caller should be ready to handle an AuthorizationException if the user is denied access:
```Python
@requires_role(['role1', 'role2'], any)
def this_function(...):
    ...
```


## Imperative-Style Authorization

Imperative-Style authorization is used when you want to control access from within your source code, step by step, with more control over the process of checking access and responding to authorization results.  It is the more "granular" of the two styles.

Following is the API you may use for imperative-style authorization:
```Python
is_permitted(permission_s)
is_permitted_collective(permission_s, logical_operator)
check_permission(permission_s, logical_operator)

has_role(roleid_s)
has_role_collective(roleid_s, logical_operator)
check_role(role_ids, logical_operator)
```

You will notice that some of the methods in the imperative-style authorization API include a second parameter, ``logical_operator``.  This parameter can be one of two values: either ``any`` or ``all`` functions from the python standard library.  Use ``any`` when you want to evaluate each item *independently* of the others and ``all`` when you want to evaluate items *collectively*.


### Example 1:  is_permitted
```Python
    current_user = subject.get_subject()
    results = current_user.is_permitted(['domain1:action1', 'domain2:action2'])

    if any(is_permitted for permission, is_permitted in results):
        print('any permission is granted')

    if all(is_permitted for permission, is_permitted in results):
        print('all permission is granted, too!')

```
``results`` (above) is a list of tuples, each containing a Permission object and a Boolean value indicating whether access is granted (True) or denied (False)


### Example 2:  is_permitted_collective
```Python
    current_user = subject.get_subject()
    any_result_check = current_user.is_permitted_collective(['domain1:action1',
                                                             'domain2:action2'], any)
    if any_result_check:
        print('any permission is granted')

    all_result_check = current_user.is_permitted_collective(['domain1:action1',
                                                             'domain2:action2'], all)

    if all_result_check:
        print('all permission is granted, too!')
```
``any_result_check`` and ``all_result_check`` are Boolean values


### Example 3:  check_permission
```Python
    current_user = subject.get_subject()
    try:
        current_user.check_permission(['domain1:action1',
                                       'domain2:action2'],
                                      any)
    except AuthorizationException:
        print('any permission denied')
    else:
        print('any permission granted')

    try:
        current_user.check_permission(['domain1:action1',
                                       'domain2:action2'],
                                      all)
    except AuthorizationException:
        print('all permission denied')
    else:
        print('all permission granted')
```
``check_permission`` succeeds quietly else raises an AuthorizationException


### Example 1:  has_role
```Python
    current_user = subject.get_subject()
    results = current_user.has_role(['role1', 'role2'])

    if any(has_role for role, has_role in results):
        print('any role is confirmed')

    if all(has_role for role, has_role in results):
        print('all role is confirmed, too!')

```
``results`` (above) is a list of tuples, each containing a Role and a Boolean value indicating whether role membership is confirmed (True if so)


### Example 2:  has_role_collective
```Python
    current_user = subject.get_subject()
    any_result_check = current_user.has_role_collective(['role1', 'role2'], any)

    if any_result_check:
        print('any role is confirmed')

    all_result_check = current_user.has_role_collective(['role1', 'role2'], all)

    if all_result_check:
        print('all role is confirmed, too!')
```
``any_result_check`` and ``all_result_check`` are Boolean values


### Example 3:  check_role
```Python
    current_user = subject.get_subject()
    try:
        current_user.check_role(['role1', 'role2'], any)

    except AuthorizationException:
        print('any role denied')
    else:
        print('any role confirmed')

    try:
        current_user.check_role(['role1', 'role2'], all)

    except AuthorizationException:
        print('all role denied')
    else:
        print('all role confirmed')
```
``check_role`` succeeds quietly else raises an AuthorizationException
