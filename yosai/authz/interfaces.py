from abc import ABCMeta, abstractmethod


class IAuthorizationInfo(metaclass=ABCMeta):

    @property
    @abstractmethod
    def roles(self):
        """
        The names of all roles assigned to a corresponding Subject
        """
        pass

    @property
    @abstractmethod
    def get_string_permissions(self):  # doesn't seem pythonic, does it?
        """
        Returns all string-based permissions assigned to the corresponding
        Subject.  The permissions here plus those returned from
        get_object_permissions() represent the total set of permissions
        assigned.  The aggregate set is used to perform a permission
        authorization check.

        This method is a convenience mechanism that allows Realms to represent
        permissions as Strings, if specified.  When performing a security
        check, a Realm MAY first converts these strings to Permission objects
        through a PermissionResolver and then uses the resulting Permission 
        objects to verify permissions.  Converting to Permission objects first
        is not a requirement, of course, because Realm can check security in 
        whatever manner deemed necessary.  Nonetheless, the process of first
        converting to Permission objects is one that most Shiro Realms 
        execute for string-based permission checks -- it gets run one way or 
        the other.

        :returns: all string-based permissions assigned to the corresponding 
                  Subject
        """
        pass

    @property
    @abstractmethod
    def get_object_permissions(self):
        """ 
        Returns all Permissions assigned to the corresponding Subject.  The 
        permissions returned from this method plus any
        returned from get_string_permissions()
        represent the total set of permissions.  The aggregate set is used to
        perform a permission authorization check.
       
        :returns: all Permission objects assigned to the corresponding Subject
        """
        pass


class IAuthorizer(metaclass=ABCMeta):

    @abstractmethod
    def check_permission(self, principals, permission_s):
        pass

    @abstractmethod
    def is_permitted(self, principals, permission_s):
        pass

    @abstractmethod
    def is_permitted_all(self, principals, permission_s):
        pass

    @abstractmethod
    def has_role(self, principals, roleid_s):
        pass

    @abstractmethod
    def has_all_roles(self, principals, roleid_s):
        pass

    @abstractmethod
    def check_role(self, principals, role_s):
        pass

class IPermission(metaclass=ABCMeta):

    """
    From Shiro documentation, replacing 'Yosai', respectively:
    A Permission represents the ability to perform an action or access a
    resource.  A Permission is the most granular, or atomic, unit in a system's
    security policy and is the cornerstone upon which fine-grained security
    models are built.

    It is important to understand a Permission instance only represents
    functionality or access - it does not grant it. Granting access to an
    application functionality or a particular resource is done by the
    application's security configuration, typically by assigning Permissions to
    users, roles and/or groups.

    Most typical systems are what the Shiro team calls role-based in nature,
    where a role represents common behavior for certain user types. For
    example, a system might have an Aministrator role, a User or Guest roles,
    etc.

    But if you have a dynamic security model, where roles can be created and
    deleted at runtime, you can't hard-code role names in your code. In this
    environment, roles themselves aren't aren't very useful. What matters is
    what permissions are assigned to these roles.

    Under this paradigm, permissions are immutable and reflect an application's
    raw functionality (opening files, accessing a web URL, creating users, etc).
    This is what allows a system's security policy to be dynamic: because
    Permissions represent raw functionality and only change when the
    application's source code changes, they are immutable at runtime - they
    represent 'what' the system can do. Roles, users, and groups are the 'who'
    of the application. Determining 'who' can do 'what' then becomes a simple
    exercise of associating Permissions to roles, users, and groups in some
    way.

    Most applications do this by associating a named role with permissions
    (i.e. a role 'has a' collection of Permissions) and then associate users
    with roles (i.e. a user 'has a' collection of roles) so that by transitive
    association, the user 'has' the permissions in their roles. There are
    numerous variations on this theme (permissions assigned directly to users,
    or assigned to groups, and users added to groups and these groups in turn
    have roles, etc, etc). When employing a permission-based security model
    instead of a role-based one, users, roles, and groups can all be created,
    configured and/or deleted at runtime.  This enables an extremely powerful
    security model.

    A benefit to Yosai is that, although it assumes most systems are based on
    these types of static role or dynamic role w/ permission schemes, it does
    not require a system to model their security data this way - all Permission
    checks are relegated to Realm implementations, and only those
    implementations really determine how a user 'has' a permission or not. The
    Realm could use the semantics described here, or it could utilize some
    other mechanism entirely - it is always up to the application developer.

    Yosai provides a very powerful default implementation of this interface in
    the form of the WildcardPermission. We highly recommend that you
    investigate this class before trying to implement your own Permissions.
    """

    @abstractmethod
    def implies(self, permission):
        """
        Returns True if this current instance implies all of the functionality 
        and/or resource access described by the specified Permission argument, 
        returning False otherwise.
         
        That is, this current instance must be exactly equal to or a
        superset of the functionalty and/or resource access described by the
        given Permission argument.  Yet another way of saying this is:
           - If permission1 implies permission2, then any Subject granted 
             permission1 would have ability greater than or equal to that 
             defined by permission2.
     
        :returns: bool
        """
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

