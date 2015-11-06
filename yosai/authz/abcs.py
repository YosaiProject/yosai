"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""

from abc import ABCMeta, abstractmethod


# differs from shiro in that it does not support string-based permissions:
class AuthorizationInfo(metaclass=ABCMeta):

    @property
    @abstractmethod
    def roles(self):
        """
        The names of all roles assigned to a corresponding Subject
        """
        pass

    @property
    @abstractmethod
    def permissions(self):
        """
        Returns all permissions assigned to the corresponding
        Subject.
        """


class Authorizer(metaclass=ABCMeta):

    """
    An Authorizer performs authorization (access control) operations
    for any given Subject (aka 'application user').

    Each method requires a subject identifier to perform the action for the
    corresponding Subject/user.

    This identifier argument is usually an object representing a user database
    primary key or a String username or something similar that uniquely
    identifies an application user.  The runtime value of the this identifier
    is application-specific and provided by the application's configured
    Realms.

    Note that the Permission methods in this interface accept either String
    arguments or Permission instances. This provides convenience in allowing
    the caller to use a String representation of a Permission if one is so
    desired.  Most implementations of this interface will simply convert these
    String values to Permission instances and then just call the corresponding
    type-safe method.  (Yosai's default implementations do String-to-Permission
    conversion for these methods using PermissionResolver(s)
    """

    @abstractmethod
    def is_permitted(self, identifier_s, permission_s):
        """
        Returns True if the corresponding subject/user is permitted to perform
        an action or access a resource summarized by the specified permission.

        More specifically, this method determines whether any Permission(s)
        associated with the subject imply the specified permission.

        :param identifier_s: the application-specific subject/user identifier(s)
        :type identifier_s: a set

        :param permission_s: the permission(s) being checked
        :type permission_s: List of Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the Permission and a Boolean
                  indicating whether the permission is granted, True if the
                  corresponding Subject/user is permitted, False otherwise
        """
        pass

    @abstractmethod
    def is_permitted_collective(self, identifier_s, permission_s, logical_operator):
        pass

    @abstractmethod
    def check_permission(self, identifier_s, permission_s, logical_operator):
        pass

    @abstractmethod
    def has_role(self, identifier_s, roleid_s):
        pass

    @abstractmethod
    def has_role_collective(self, identifier_s, roleid_s, logical_operator):
        pass

    @abstractmethod
    def check_role(self, identifier_s, role_s, logical_operator):
        pass


class Permission(metaclass=ABCMeta):

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


class PermissionResolverAware(metaclass=ABCMeta):

    @property
    @abstractmethod
    def permission_resolver(self):
        pass

    @permission_resolver.setter
    @abstractmethod
    def permission_resolver(self, permission_resolver):
        pass


class PermissionResolver(metaclass=ABCMeta):

    @abstractmethod
    def resolve(self, permission_s):
        pass


class RolePermissionResolver(metaclass=ABCMeta):
    """
    The RolePermissionResolver resolves roles into permissions.

    A RolePermissionResolver resolves a Role, represented as a String value,
    into a Collection of Permission instances.  A mapping of Role->Permission
    associations is required to facilitate the role->permission resolution.
    These Role->Permission associations are obtained from a data store, such a
    local database, and may be cached.

    The notion of converting role names to permissions is very application
    specific.  Therefore, Yosai does NOT include a default implementation of it.

    Evaluating Role Membership:
        Let Role R1 consists of elements Permission p1, Permission p2, and Permission p3:
         r1 = {p1, p2, p3}

        Suppose that a user's permissions were obtained from an AccountStore.  If
        and only if the collections of permissions obtained from the Store were
        to include p1, p2, and p3 then a user would satisfy the criteria for
        Role membership of R1.  Only one missing Permission is sufficient to
        fail the test for membership (if, for instance the user was assigned
        p1 and p2 but not p3).

    """
    @abstractmethod
    def resolve_permissions_in_role(self, role_string):
        pass


class RolePermissionResolverAware(metaclass=ABCMeta):

    @property
    @abstractmethod
    def role_permission_resolver(self):
        pass

    @role_permission_resolver.setter
    @abstractmethod
    def role_permission_resolver(self, role_permission_resolver):
        pass


class PermissionVerifier(metaclass=ABCMeta):

    @abstractmethod
    def get_authzd_permissions(self, authz_info, permission):
        """
        :param permission: a Permission that has already been resolved (if needed)
        :type permission: a Permission object

        Queries a collection of permissions in authz_info for
        related permissions (those that potentially imply privilege).

        :returns: frozenset
        """
        pass

    @abstractmethod
    def is_permitted(self, identifier_s, permission_s):
        """
        :param permission_s: a collection of one or more Permission objects
        :type permission_s: set

        :yields: (Permission, Boolean)
        """
        pass


class RoleVerifier(metaclass=ABCMeta):

    @abstractmethod
    def has_role(self, authz_info, roleid_s):
        """
        Confirms whether a subject is a member of one or more roles.

        :param roleid_s: a collection of 1..N Role identifier_s
        :type roleid_s: Set of String(s)

        :yields: tuple(roleid, Boolean)
        """
        pass
