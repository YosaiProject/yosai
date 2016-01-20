# Authorization API Reference
Yosai provides role-level and permission-level access control.

Both levels of access control can be performed using two styles:
- The **declarative style** of authorization involves use of a decorator that performs one of the two levels of access control.  The wrapped method is never called if authorization fails.

- The **imperative style** of authorization involves in-line access control within the operation that requires authorization.


## Declarative-Style Authorization
@requires_permission(permission_s, logical_operator=all)
@requires_role(roleid_s, logical_operator=all)


## Imperative-Style Authorization
current_user.is_permitted(permission_s)
current_user.is_permitted_collective(permission_s, logical_operator)
current_user.check_permission(permission_s, logical_operator)

current_user.has_role(roleid_s)
current_user.has_role_collective(roleid_s, logical_operator)
current_user.check_role(role_ids, logical_operator)
