from yosai import (DefaultPermission, PermissionResolver, RoleResolver,
                   SimpleRole, AlchemyAccountStore)


pr = PermissionResolver(DefaultPermission)
rr = RoleResolver(SimpleRole)

account_store = AlchemyAccountStore()
account_store.permission_resolver = pr
account_store.role_resolver = rr

authc_token = type('dumb', (object,), {})()
authc_token.identifier = 'thedude'

account = account_store.get_account(authc_token)

print('\nAccount is: ', account)
print('\nCredentials is: ', account.credentials)

