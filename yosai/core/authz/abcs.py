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


class Authorizer(metaclass=ABCMeta):

    """
    An ``Authorizer`` performs authorization (access control) operations
    for any given Subject (aka 'application user').

    Each method requires a subject identifiers to perform the action for the
    corresponding Subject/user.

    This identifiers argument is usually an object representing a user database
    primary key or a String username or something similar that uniquely
    identifies an application user.  The runtime value of the this identifiers
    is application-specific and provided by the application's configured
    Realms.

    Note that the ``Permission`` methods in this interface accept either String
    arguments or Permission instances. This provides convenience in allowing
    the caller to use a String representation of a Permission if one is so
    desired.  Most implementations of this interface will simply convert these
    String values to Permission instances and then just call the corresponding
    method.
    """

    @abstractmethod
    def is_permitted(self, identifiers, permission_s):
        """
        Determines whether any Permission(s) associated with the subject
        implies the requested Permission(s) provided.

        :param identifiers: the application-specific subject/user identifiers(s)
        :type identifiers: subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the Permission and a Boolean
                  indicating whether the permission is granted, True if the
                  corresponding Subject/user is permitted, False otherwise
        """
        pass

    @abstractmethod
    def is_permitted_collective(self, identifiers, permission_s, logical_operator):
        """
        This method determines whether the requested Permission(s) are
        collectively granted authorization.  The Permission(s) associated with
        the subject are evaluated to determine whether authorization is implied
        for each Permission requested.  Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        If operator=ANY: returns True if any requested permission is implied permission
        If operator=ALL: returns True if all requested permissions are implied permission
        Else returns False

        :param identifiers: the application-specific subject/user identifiers(s)
        :type identifiers: subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :rtype:  bool
        """
        pass

    @abstractmethod
    def check_permission(self, identifiers, permission_s, logical_operator):
        """
        This method determines whether the requested Permission(s) are
        collectively granted authorization.  The Permission(s) associated with
        the subject are evaluated to determine whether authorization is implied
        for each Permission requested.  Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        This method is similar to is_permitted_collective except that it raises
        an AuthorizationException if collectively False else does not return any
        value.

        :param identifiers: the application-specific subject/user identifiers(s)
        :type identifiers: subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions, all of the same type
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          permission
        """
        pass

    @abstractmethod
    def has_role(self, identifiers, role_s):
        """
        Determines whether a ``Subject`` is a member of the Role(s) requested

        :param identifiers: the application-specific subject/user identifiers(s)
        :type identifiers: subject_abcs.IdentifierCollection

        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :returns: a set of tuple(s), each containing the Role identifier
                  requested and a Boolean indicating whether the subject is
                  a member of that Role
                  - the tuple format is: (role, Boolean)
        """
        pass

    @abstractmethod
    def has_role_collective(self, identifiers, role_s, logical_operator):
        """
        This method determines whether the Subject's role membership
        collectively grants authorization for the roles requested.  The
        Role(s) associated with the subject are evaluated to determine
        whether the roles requested are sufficiently addressed by those that
        the Subject is a member of. Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        If operator=ANY, returns True if any requested role membership is
                         satisfied
        If operator=ALL: returns True if all of the requested permissions are
                         implied permission
        Else returns False

        :param identifiers: the application-specific subject/user identifiers(s)
        :type identifiers: subject_abcs.IdentifierCollection

        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :rtype:  bool
        """
        pass

    @abstractmethod
    def check_role(self, identifiers, role_s, logical_operator):
        """
        This method determines whether the Subject's role membership
        collectively grants authorization for the roles requested.  The
        Role(s) associated with the subject are evaluated to determine
        whether the roles requested are sufficiently addressed by those that
        the Subject is a member of. Results are collectively evaluated using
        the logical operation provided: either ANY or ALL.

        This method is similar to has_role_collective except that it raises
        an AuthorizationException if collectively False else does not return any

        :param identifiers: the application-specific subject/user identifiers(s)
        :type identifiers: subject_abcs.IdentifierCollection

        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          role membership
        """
        pass


class Permission(metaclass=ABCMeta):

    """
    A ``Permission`` represents the ability to perform an action or access a
    resource.  A ``Permission`` is the most granular, or atomic, unit in a system's
    security policy and is the cornerstone upon which fine-grained security
    models are built.

    It is important to understand a ``Permission`` instance only represents
    functionality or access - it does not grant it. Granting access to an
    application functionality or a particular resource is done by the
    application's security configuration, typically by assigning Permissions to
    users, roles and/or groups.

    Most typical systems are role-based in nature, where a role represents
    common behavior for certain user types. For example, a system might have an
    Aministrator role, a User or Guest roles, etc. However, if you have a dynamic
    security model, where roles can be created and deleted at runtime, you
    can't hard-code role names in your code. In this environment, roles
    themselves aren't aren't very useful. What matters is what permissions are
    assigned to these roles.

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
