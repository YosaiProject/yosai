from yosai.authz import (
    IAuthorizer,
    IPermissionResolverAware,
    IRolePermissionResolverAware,
)

class MockAuthzAccountStoreRealm(IAuthorizer,
                                 IPermissionResolverAware,
                                 IRolePermissionResolverAware):

    def __init__(self):
        self.id = id(self)  # required for uniqueness among set members
        self._permission_resolver = None

    def check_permission(self, principals, permission_s):
        pass
    
    def check_role(self, principals, role_s):
        pass

    def has_role(self, principals, roleid_s):
        pass

    def has_all_roles(self, principals, roleid_s):
        pass

    def is_permitted(self, principals, permission_s):
        pass

    def is_permitted_all(self, principals, permission_s):
        pass

    @property
    def permission_resolver(self):
        return self._permission_resolver 

    @permission_resolver.setter
    def permission_resolver(self, permission_resolver):
        self._permission_resolver = permission_resolver 
    
    @property
    def role_permission_resolver(self):
        return self._role_permission_resolver 

    @permission_resolver.setter
    def role_permission_resolver(self, permission_resolver):
        self._role_permission_resolver = permission_resolver 
