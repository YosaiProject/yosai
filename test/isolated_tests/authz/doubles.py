from yosai import (
    authz_abcs,
    realm_abcs,
)


class MockAuthzAccountStoreRealm(realm_abcs.AuthorizingRealm,
                                 authz_abcs.PermissionResolverAware):

    def __init__(self):
        self._permission_resolver = None

    def has_role(self, identifiers, roleid_s):
        return None

    def has_all_roles(self, identifiers, roleid_s):
        return None

    def is_permitted(self, identifiers, permission_s):
        return None

    def is_permitted_all(self, identifiers, permission_s):
        return None

    @property
    def permission_resolver(self):
        return self._permission_resolver

    @permission_resolver.setter
    def permission_resolver(self, permission_resolver):
        self._permission_resolver = permission_resolver 

    @property
    def authorization_cache_handler(self):
        pass

    def do_clear_cache(self, identifiers):
        pass

    def get_authorization_info(self, identifiers):
        pass
 
    def resolve_permissions(self, string_perms):
        pass

    def __hash__(self):
        return hash(id(self))

    def __eq__(self, other):
        return self is other

    
class MockPermission(authz_abcs.Permission):
   
    # using init to define whether implies is always True or False
    def __init__(self, implied):
        self.implied = implied

    def implies(self, permission):
        return self.implied
