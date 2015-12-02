from yosai_dpcache.cache import DPCacheHandler
from yosai_alchemystore import AlchemyAccountStore
from yosai import (
    AccountStoreRealm,
    DefaultPermission,
    PermissionResolver,
    SimpleRole,
    RoleResolver,
    IndexedAuthorizationInfo,
    AuthzInfoResolver,
    CredentialResolver,
    Credential,
)

asr = AccountStoreRealm()

asr.account_store = AlchemyAccountStore()
asr.cache_handler = DPCacheHandler()

asr.permission_resolver = PermissionResolver(DefaultPermission)
asr.role_resolver = RoleResolver(SimpleRole)
asr.credential_resolver = CredentialResolver(Credential)
asr.authz_info_resolver = AuthzInfoResolver(IndexedAuthorizationInfo)

