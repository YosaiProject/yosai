from abc import ABCMeta, abstractmethod
import PrincipalCollection


class IAuthorizationInfo(metaclass=ABCMeta):

    @property
    @abstractmethod
    def roles(self):
        pass

    @property
    @abstractmethod
    def string_permissions(self):
        pass

    @property
    @abstractmethod
    def object_permissions(self):
        pass


class IAuthorizer(metaclass=ABCMeta):

    @abstractmethod
    def is_permitted(self, principals, permissions):
        pass

    @abstractmethod
    def is_permitted_all(self, principals, permissions):
        pass

    @abstractmethod
    def has_role(self, principals, role_identifiers):
        pass

    @abstractmethod
    def has_all_roles(self, principals, role_identifiers):
        pass


class IPermission(metaclass=ABCMeta):

    @abstractmethod
    def implies(self, permission):
        pass


class IPermissionResolverAware(metaclass=ABCMeta):

    @property
    @abstractmethod
    def permission_resolver(self):
        pass

    @permission_resolver.setter
    @abstractmethod
    def permission_resolver(self, permission_resolver):
        pass


class IPermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def resolve_permission(self, permission_string):
        pass


class IRolePermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def resolve_permissions_in_role(self, role_string):
        pass


class IRolePermissionResolverAware(metaclass=ABCMeta):

    @property
    @abstractmethod
    def role_permission_resolver(self):
        pass

    @role_permission_resolver.setter
    @abstractmethod
    def role_permission_resolver(self, role_permission_resolver):
        pass

