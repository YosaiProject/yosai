from yosai import (DefaultPermission, PermissionResolver, RoleResolver,
                   SimpleRole, AlchemyAccountStore)


pr = PermissionResolver(DefaultPermission)
rr = RoleResolver(SimpleRole)

account_store = AlchemyAccountStore()
account_store.permission_resolver = pr
account_store.role_resolver = rr

authc_token = type('dumb', (object,), {})()
authc_token.identifier = 'thedude'

account = account_store.get_credentials(authc_token)

print('\nCredentials is: ', account.credentials)

