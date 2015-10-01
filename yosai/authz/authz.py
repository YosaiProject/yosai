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

from yosai import (
    AuthorizationException,
    HostUnauthorizedException,
    IllegalArgumentException,
    IllegalStateException,
    LogManager,
    UnauthenticatedException,
    UnauthorizedException,
    authz_abcs,
    serialize_abcs,
)

import copy
import collections


class AllPermission:

    def __init__(self):
        pass

    def implies(self, permission):
        return True


class WildcardPermission(serialize_abcs.Serializable):
    """
    The standardized permission wildcard syntax is:  DOMAIN:ACTION:INSTANCE

    reference:  https://shiro.apache.org/permissions.html

    Note:  Yosai changed self.parts to a dict
    """

    WILDCARD_TOKEN = '*'
    PART_DIVIDER_TOKEN = ':'
    SUBPART_DIVIDER_TOKEN = ','
    DEFAULT_CASE_SENSITIVE = False

    def __init__(self, wildcard_string=None,
                 case_sensitive=DEFAULT_CASE_SENSITIVE):

        self.case_sensitive = case_sensitive
        self.parts = {}
        if wildcard_string:
            self.set_parts(wildcard_string, case_sensitive)

    def set_parts(self, wildcard_string,
                  case_sensitive=DEFAULT_CASE_SENSITIVE):
        if (not wildcard_string):
            msg = ("Wildcard string cannot be None or empty. Make sure "
                   "permission strings are properly formatted.")
            print(msg)
            # log here
            raise IllegalArgumentException(msg)

        wildcard_string = wildcard_string.strip()

        if not any(x != self.PART_DIVIDER_TOKEN for x in wildcard_string):
            msg = ("Wildcard string cannot contain JUST dividers. Make "
                   "sure permission strings are properly formatted.")
            print(msg)
            raise IllegalArgumentException(msg)

        if (not self.case_sensitive):
            wildcard_string = wildcard_string.lower()

        parts = wildcard_string.split(self.PART_DIVIDER_TOKEN)

        part_indices = {0: 'domain', 1: 'actions', 2: 'targets'}

        for index, part in enumerate(parts):
            if not any(x != self.SUBPART_DIVIDER_TOKEN for x in part):
                msg = ("Wildcard string cannot contain parts consisting JUST "
                       "of sub-part dividers. Make sure permission strings "
                       "are properly formatted.")
                print(msg)
                raise IllegalArgumentException(msg)

            myindex = part_indices.get(index)

            # NOTE:  Shiro uses LinkedHashSet objects to maintain order and
            #        Uniqueness. Unlike Shiro, Yosai disregards order as it
            #        presents seemingly unecessary additional overhead (TBD)
            self.parts[myindex] = set()

            subparts = part.split(self.SUBPART_DIVIDER_TOKEN)
            for sp in subparts:
                self.parts[myindex].add(sp)

    def implies(self, permission):
        """
        :type permission:  Permission object
        """
        # By default only supports comparisons with other WildcardPermissions
        if (not isinstance(permission, WildcardPermission)):
            return False

        myparts = [token for token in
                   [self.parts.get('domain'),
                    self.parts.get('actions'),
                    self.parts.get('targets')] if token]

        otherparts = [token for token in
                      [permission.parts.get('domain'),
                       permission.parts.get('actions'),
                       permission.parts.get('targets')] if token]

        index = 0

        for other_part in otherparts:
            # If this permission has less parts than the other permission,
            # everything after the number of parts contained in this
            # permission is automatically implied, so return true
            if (len(myparts) - 1 < index):
                return True
            else:
                part = myparts[index]  # each subpart is a Set
                if ((self.WILDCARD_TOKEN not in part) and
                   not (other_part <= part)):  # not(part contains otherpart)
                    return False
                index += 1

        # If this permission has more parts than the other parts,
        # only imply it if all of the other parts are wildcards
        for i in range(index, len(myparts)):
            if (self.WILDCARD_TOKEN not in myparts[i]):
                return False

        return True

    def __repr__(self):
        return ':'.join([str(value) for key, value in self.parts.items()])

    def __eq__(self, other):
        if (isinstance(other, WildcardPermission)):
            return self.parts == other.parts

        return False

    def hash_code(self):
        return id(self.parts)

    @classmethod
    def serialization_schema(cls):
        class WildcardPartsSchema(Schema):
                domain = fields.List(fields.Str)
                action = fields.List(fields.Str)
                instance = fields.List(fields.Str)

        class SerializationSchema(Schema):
            parts = field.Nested(WildcardPartsSchema)

            @post_load
            def make_wildcard_permission(self, data):
                mycls = WildcardPermission
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                return instance

            # prior to serializing, convert a dict of sets to a dict of lists
            # because sets cannot be serialized
            @post_dump
            def convert_sets(self, data):
                for attribute, value in data['parts'].items():
                    data['parts'][attribute] = list(value)
                return data

            # revert to the original dict of sets format
            @pre_load
            def revert_sets(self, data):
                newdata = copy.copy(data)

                for attribute, value in data['parts'].items():
                    newdata['parts'][attribute] = set(value)

                return newdata


        return SerializationSchema


class WildcardPermissionResolver:

    # new to yosai is the use of classmethod, and no need for instantiation
    @classmethod
    def resolve_permission(self, permission_string):
        return WildcardPermission(permission_string)


class DefaultPermission(WildcardPermission):
    """
    This class is known in Shiro as DomainPermission.  It has been renamed
    and refactored a bit for Yosai.

    Differences include:
    - Unlike Shiro's DomainPermission, DefaultPermission obtains its domain
      attribute by argument (rather than by using class name (and subclassing)).
    - Set order is removed (no OrderedSet) until it is determined that using
      ordered set will improve performance (TBD).
    - refactored interactions between set_parts and encode_parts

    This class can be used as a base class for ORM-persisted (SQLAlchemy)
    permission model(s).  The ORM model maps the parts of a permission
    string to separate table columns (e.g. 'domain', 'actions' and 'targets'
    columns) and is subsequently used in querying strategies.
    """
    def __init__(self, domain, actions=None, targets=None):
        """
        :type domain: str
        :type actions: str or set of strings
        :type targets: str or set of strings

        After initializing, the state of a DomainPermission object includes:
            self.results = a list populated by WildcardPermission.set_results
            self._domain = a Str
            self._actions = a set, or None
            self._targets = a set, or None
        """
        super().__init__()
        if domain is None:
            raise IllegalArgumentException('Domain cannot be None')
        self.set_parts(domain=domain, actions=actions, targets=targets)
        self._domain = self.parts.get('domain')
        self._actions = self.parts.get('actions')
        self._targets = self.parts.get('targets')

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, domain):
        self._domain = domain
        self.set_parts(domain=self._domain,
                       actions=getattr(self, '_actions', None),
                       targets=getattr(self, '_targets', None))

    @property
    def actions(self):
        return self._actions

    @actions.setter
    def actions(self, actions):
        self.set_parts(domain=self._domain,
                       actions=actions,
                       targets=getattr(self, '_targets', None))
        self._actions = self.parts.get('actions', None)

    @property
    def targets(self):
        return self._targets

    @targets.setter
    def targets(self, targets):
        self.set_parts(domain=self._domain,
                       actions=getattr(self, '_actions', None),
                       targets=targets)
        self._targets = self.parts.get('targets', None)

    def encode_parts(self, domain, actions, targets):
        """
        Yosai redesigned encode_parts to return permission, rather than
        pass it to set_parts as a wildcard

        :type domain:  str
        :type actions: a subpart-delimeted str
        :type targets: a subpart-delimeted str
        """

        # Yosai sets None to Wildcard
        permission = self.PART_DIVIDER_TOKEN.join(
            x if x is not None else self.WILDCARD_TOKEN
            for x in [domain, actions, targets])

        return permission

    # overrides WildcardPermission.set_parts:
    def set_parts(self, domain, actions, targets):
        """
        Shiro uses method overloading to determine as to whether to call
        either this set_parts or that of the parent WildcardPermission.  The
        closest that I will accomodate that design is with default parameter
        values and the first condition below.

        The control flow is as follow:
            If wildcard_string is passed, call super's set_parts
            Else process the orderedsets

        :type actions:  either a Set of strings or a subpart-delimeted string
        :type targets:  an Set of Strings or a subpart-delimeted string
        """

        # default values
        actions_string = actions
        targets_string = targets
        if isinstance(actions, set):
            actions_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in actions])

        if isinstance(targets, set):
            targets_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in targets])

        permission = self.encode_parts(domain=domain,
                                       actions=actions_string,
                                       targets=targets_string)

        super().set_parts(wildcard_string=permission)

    # removed getDomain

class ModularRealmAuthorizer(authz_abcs.Authorizer,
                             authz_abcs.PermissionResolverAware,
                             authz_abcs.RolePermissionResolverAware):

    """
    A ModularRealmAuthorizer is an Authorizer implementation that consults
    one or more configured Realms during an authorization operation.

    the funky naming convention where a parameter ends with '_s' denotes
    one-or-more; in English, this is expressed as '(s)', eg: duck(s)
    indicates one or more ducks


    note:  Yosai implements a different policy than Shiro does during
           authorization requests in that Yosai accepts the first Boolean value
           provided rather than continue attempting to obtain permission from
           other realms. The first Boolean is the final word on permission.

    :type realms:  Tuple
    """
    def __init__(self, realms=None):
        self._realms = tuple()
        self._permission_resolver = None
        self._role_permission_resolver = None

    @property
    def realms(self):
        return self._realms

    @realms.setter
    def realms(self, realms):
        """
        :type realms: Tuple
        """
        self._realms = realms
        self.apply_permission_resolver_to_realms()
        self.apply_role_permission_resolver_to_realms()

    @property
    def authorizing_realms(self):
        """
        new to Yosai: a generator expression filters out non-authz realms
        """
        return (realm for realm in self._realms
                if isinstance(realm, authz_abcs.Authorizer))

    @property
    def permission_resolver(self):
        """
        This is the permission resolver that is used on EVERY configured
        realm wrapped by the ModularRealmAuthorizer.  A permission_resolver
        equal to None indicates that each individual realm is accountable for
        configuring its permission resolver.
        """
        return self._permission_resolver

    @permission_resolver.setter
    def permission_resolver(self, resolver):
        """
        the permission resolver set here is applied to EVERY realm that is
        wrapped by the ModularRealmAuthorizer
        """
        self._permission_resolver = resolver
        self.apply_permission_resolver_to_realms()

    def apply_permission_resolver_to_realms(self):
        resolver = copy.copy(self._permission_resolver)
        realms = copy.copy(self._realms)
        if (resolver and realms):
            for realm in realms:
                # interface contract validation:
                if isinstance(realm, authz_abcs.PermissionResolverAware):
                    realm.permission_resolver = resolver
            self._realms = realms

    @property
    def role_permission_resolver(self):
        return self._role_permission_resolver

    @role_permission_resolver.setter
    def role_permission_resolver(self, resolver):
        self._role_permission_resolver = resolver
        self.apply_role_permission_resolver_to_realms()

    def apply_role_permission_resolver_to_realms(self):
        """
        This method is called after setting a role_permission_resolver
        attribute in this ModularRealmAuthorizer.  It is also called after
        setting the self.realms attribute, giving the newly available realms
        the role_permission_resolver already in use by self.
        """
        role_perm_resolver = self.role_permission_resolver
        realms = copy.copy(self._realms)
        if (role_perm_resolver and realms):
            for realm in realms:
                if isinstance(realm, authz_abcs.RolePermissionResolverAware):
                    realm.role_permission_resolver = role_perm_resolver
            self._realms = realms

    def assert_realms_configured(self):
        if (not self.realms):
            msg = ("Configuration error:  No realms have been configured! "
                   "One or more realms must be present to execute an "
                   "authorization operation.")
            print(msg)
            # log here
            raise IllegalStateException(msg)

    # Yosai refactors isPermitted and hasRole extensively, making use of
    # generators so as to optimize processing and improve readability

    # new to Yosai:
    def _has_role(self, identifiers, roleid):
        for realm in self.authorizing_realms:
            result = realm.has_role(identifiers, roleid)
            if result is not None:
                return result
        return None

    # new to Yosai:
    def _role_collection(self, identifiers, roleids):
        if isinstance(roleids, collections.Iterable):
            for roleid in roleids:
                yield (roleid, self._has_role(identifiers, roleid))
        else:
            yield (roleids, self._has_role(identifiers, roleids))

    # new to Yosai:
    def _is_permitted(self, identifiers, permission):
        for realm in self.authorizing_realms:
            result = realm.is_permitted(identifiers, permission)
            if result is not None:   # faster than checking if bool
                return result
        return None

    # new to Yosai:
    def _permit_collection(self, identifiers, permissions):
        for permission in permissions:
            yield (permission, self._is_permitted(identifiers, permission))

    def is_permitted(self, identifiers, permission_s):
        """
        Yosai differs from Shiro in how it handles String-typed Permission
        parameters.  Rather than supporting *args of String-typed Permissions,
        Yosai supports a list of Strings.  Yosai remains true to Shiro's API
        while determining permissions a bit more pythonically.  This may
        be refactored later.

        :param identifiers: a collection of identifiers
        :type identifiers: Set

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the Permission and a Boolean
                  indicating whether the permission is granted
        """

        self.assert_realms_configured()

        if isinstance(permission_s, collections.Iterable):
            return [(permission, permit) for (permission, permit) in
                    self._permit_collection(identifiers, permission_s)]

        return [permission_s, self._is_permitted(identifiers, permission_s)]

    def is_permitted_all(self, identifiers, permission_s):
        """
        :param identifiers: a Set of Identifier objects
        :param permission_s:  a List of Permission objects

        :returns: a Boolean
        """
        self.assert_realms_configured()

        if isinstance(permission_s, collections.Iterable):
            # using a generator in order to fail immediately
            for (permission, permitted) in self._permit_collection(
                    identifiers, permission_s):
                if not permitted:
                    return False
            return True

        # else:
        return self._is_permitted(identifiers, permission_s)  # 1 Bool

    # yosai consolidates check_permission functionality to one method:
    def check_permission(self, identifiers, permission_s):
        """
        like Yosai's authentication process, the authorization process will
        raise an Exception to halt further authz checking once Yosai determines
        that a Subject is unauthorized to receive the requested permission

        :param identifiers: a collection of identifiers
        :type identifiers: Set

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission objects or Strings

        :raises UnauthorizedException: if any permission is unauthorized
        """
        self.assert_realms_configured()
        permitted = self.is_permitted_all(identifiers, permission_s)
        if not permitted:
            msg = "Subject does not have permission(s)"
            print(msg)
            # log here
            raise UnauthorizedException(msg)

    # yosai consolidates has_role functionality to one method:
    def has_role(self, identifiers, roleid_s):
        """
        :param identifiers: a collection of identifiers
        :type identifiers: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings

        :returns: a tuple containing the roleid and a boolean indicating
                  whether the role is assigned (this is different than Shiro)
        """
        self.assert_realms_configured()

        if isinstance(roleid_s, collections.Iterable):
            return [(roleid, hasrole) for (roleid, hasrole) in
                    self._role_collection(identifiers, roleid_s)]

        return [(roleid_s, self._has_role(identifiers, roleid_s))]

    def has_all_roles(self, identifiers, roleid_s):
        """
        :param identifiers: a collection of identifiers
        :type identifiers: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings

        :returns: a Boolean
        """
        self.assert_realms_configured()

        for (roleid, hasrole) in \
                self._role_collection(identifiers, roleid_s):
            if not hasrole:
                return False
        return True

    def check_role(self, identifiers, roleid_s):
        """
        :param identifiers: a collection of identifiers
        :type identifiers: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings

        :raises UnauthorizedException: if Subject not assigned to all roles
        """
        self.assert_realms_configured()
        has_role_s = self.has_all_roles(identifiers, roleid_s)
        if not has_role_s:
            msg = "Subject does not have role(s)"
            print(msg)
            # log here
            raise UnauthorizedException(msg)


class SimpleAuthorizationInfo:
    """
    Simple implementation of the authz_abcs.AuthorizationInfo interface that stores
    roles and permissions as internal attributes.
    """

    def __init__(self, roles=set()):
        """
        :type roles: Set
        """
        self.roles = roles
        self.string_permissions = set()
        self.object_permissions = set()

    # yosai combines add_role with add_roles
    def add_role(self, role_s):
        """
        :type role_s: set
        """
        if (self.roles is None):
            self.roles = set()

        for item in role_s:
            self.roles.add(item)  # adds in order received

    # yosai combines add_string_permission with add_string_permissions
    def add_string_permission(self, permission_s):
        """
        :type permission_s: set of string-based permissions
        """
        if (self.string_permissions is None):
            self.string_permissions = set()

        for item in permission_s:
            self.string_permissions.add(item)  # adds in order received

    # yosai combines add_object_permission with add_object_permissions
    def add_object_permission(self, permission_s):
        """
        :type permission_s: set of Permission objects
        """
        if (self.object_permissions is None):
            self.object_permissions = set()

        for item in permission_s:
            self.object_permissions.add(item)  # adds in order received


class SimpleRole:

    def __init__(self, name=None, permissions=set()):
        self.name = name
        self.permissions = permissions

    def add(self, permission):
        """
        :type permission: a Permission object
        """
        permissions = self.permissions
        if (permissions is None):
            self.permissions = set()
        self.permissions.add(permission)

    def add_all(self, permissions):
        """
        :type permissions: an set of Permission objects
        """
        if (self.permissions is None):
            self.permissions = set()

        for item in permissions:
            self.permissions.add(item)  # adds in order received

    def is_permitted(self, permission):
        """
        :type permission: Permission object
        """
        if (self.permissions):
            for perm in self.permissions:
                if (perm.implies(permission)):
                    return True
        return False

    def hash_code(self):
        # TBD:  not sure about this..
        if self.name:
            return id(self.name)
        return 0

    def __eq__(self, other):

        if (isinstance(other, SimpleRole)):
            return self.name == other.name

        return False

    def __repr__(self):
        return self.name
