from yosai.core import (
    authz_abcs,
    realm_abcs,
)


class MockAuthzAccountStoreRealm(realm_abcs.AuthorizingRealm):

    def has_role(self, identifiers, roleid_s):
        return None

    def has_all_roles(self, identifiers, roleid_s):
        return None

    def is_permitted(self, identifiers, permission_s):
        return None

    def is_permitted_all(self, identifiers, permission_s):
        return None

    @property
    def authorization_cache_handler(self):
        pass

    def do_clear_cache(self, identifiers):
        pass

    def get_authzd_permissions(self, identifier, domain):
        pass

    def get_authzd_roles(self, identifier):
        pass

    def __hash__(self):
        return hash(id(self))

    def __eq__(self, other):
        return self is other

    def clear_cached_authorization_info(self, identifier):
        pass


class MockPermission(authz_abcs.Permission):

    # using init to define whether implies is always True or False
    def __init__(self, implied):
        self.implied = implied

    def implies(self, permission):
        return self.implied
