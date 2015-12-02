from yosai_alchemystore import AlchemyAccountStore
from yosai import (
    DefaultPermission,
    PermissionResolver,
    SimpleRole,
    RoleResolver,
    IndexedAuthorizationInfo,
    AuthzInfoResolver,
    CredentialResolver,
    Credential,
)

ass = AlchemyAccountStore()
ass.permission_resolver = PermissionResolver(DefaultPermission)
ass.role_resolver = RoleResolver(SimpleRole)
ass.authz_info_resolver = AuthzInfoResolver(IndexedAuthorizationInfo)
ass.credential_resolver = CredentialResolver(Credential)

