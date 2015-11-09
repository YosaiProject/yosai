from yosai import (DefaultPermission, PermissionResolver, RoleResolver,
                   SimpleRole, AlchemyAccountStore)


pr = PermissionResolver(DefaultPermission)
rr = RoleResolver(SimpleRole)

account_store = AlchemyAccountStore(permission_resolver=pr, role_resolver=rr)

permissions = account_store.get_authz_info(identifier='walter')

print(permissions)

