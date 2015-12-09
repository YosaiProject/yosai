from yosai.core import (
    authz_abcs,
    realm_abcs,
)


class MockAuthzAccountStoreRealm(realm_abcs.AuthorizingRealm,
                                 authz_abcs.PermissionResolverAware):

    def __init__(self):
        self._permission_resolver = None

    def has_role(self, identifier, roleid_s):
        return None

    def has_all_roles(self, identifier, roleid_s):
        return None

    def is_permitted(self, identifier, permission_s):
        return None

    def is_permitted_all(self, identifier, permission_s):
        return None

    @property
    def permission_resolver(self):
        return self._permission_resolver

    @permission_resolver.setter
    def permission_resolver(self, permission_resolver):
        self._permission_resolver = permission_resolver 

    @property
    def permission_verifier(self):
        pass
        
    @property
    def role_verifier(self):
        pass

    @property
    def authorization_cache_handler(self):
        pass

    def do_clear_cache(self, identifier):
        pass

    def get_authorization_info(self, identifier):
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
