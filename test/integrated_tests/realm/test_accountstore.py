from yosai import (DefaultPermission, PermissionResolver, RoleResolver,
                   SimpleRole, AlchemyAccountStore, AccountStoreRealm)


pr = PermissionResolver(DefaultPermission)
rr = RoleResolver(SimpleRole)


account_store = AlchemyAccountStore()
asr = AccountStoreRealm()

asr.account_store = account_store

asr.permission_resolver = pr
asr.role_resolver = rr

authc_token = type('dumb', (object,), {})()
authc_token.identifier = 'thedude'

account = account_store.get_account(authc_token)

print('\nAccount is: ', account)
print('\nCredentials is: ', account.credentials)
