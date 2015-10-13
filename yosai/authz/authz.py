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
import ipdb
import itertools

from yosai import (
    AuthorizationException,
    CollectionDict,
    HostUnauthorizedException,
    IllegalArgumentException,
    IllegalStateException,
    LogManager,
    PermissionIndexingException,
    UnauthenticatedException,
    UnauthorizedException,
    authz_abcs,
    serialize_abcs,
)

import copy
import collections
from marshmallow import Schema, fields, post_load, post_dump, pre_load

class AllPermission:

    def __init__(self):
        pass

    def implies(self, permission):
        return True


class WildcardPermission(serialize_abcs.Serializable):
    """
    The standardized permission wildcard syntax is:  DOMAIN:ACTION:TARGET

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
        self.parts = {'domain': {'*'}, 'action': {'*'}, 'target': {'*'}}
        if wildcard_string:
            self.setparts(wildcard_string, case_sensitive)

    def setparts(self, wildcard_string,
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

        part_indices = {0: 'domain', 1: 'action', 2: 'target'}

        for index, part in enumerate(parts):
            if not any(x != self.SUBPART_DIVIDER_TOKEN for x in part):
                msg = ("Wildcard string cannot contain parts consisting JUST "
                       "of sub-part dividers or nothing at all. Ensure that "
                       "permission strings are properly formatted.")
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

        # final step is to make it immutable:
        self.parts.update((k, frozenset(v)) for k, v in self.parts.items())

    def implies(self, permission):
        """
        :type permission:  Permission object
        """
        # By default only supports comparisons with other WildcardPermissions
        if (not isinstance(permission, WildcardPermission)):
            return False

        myparts = [token for token in
                   [self.parts.get('domain'),
                    self.parts.get('action'),
                    self.parts.get('target')] if token]

        otherparts = [token for token in
                      [permission.parts.get('domain'),
                       permission.parts.get('action'),
                       permission.parts.get('target')] if token]

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
        return ("{0}:{1}:{2}".format(self.parts.get('domain'),
                                     self.parts.get('action'),
                                     self.parts.get('target')))

    def __hash__(self):
        return hash(frozenset(self.parts.items()))

    def __eq__(self, other):
        if (isinstance(other, WildcardPermission)):
            return self.parts == other.parts

        return False

    @classmethod
    def serialization_schema(cls):
        class WildcardPartsSchema(Schema):
                domain = fields.List(fields.Str)
                action = fields.List(fields.Str)
                target = fields.List(fields.Str)

        class SerializationSchema(Schema):
            parts = fields.Nested(WildcardPartsSchema)

            @post_load
            def make_wildcard_permission(self, data):
                mycls = WildcardPermission
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)

                # have to convert to set from post_load due to the
                # WildcardPartsSchema
                for key, val in instance.parts.items():
                    instance.parts[key] = frozenset(val)
                return instance

            # prior to serializing, convert a dict of sets to a dict of lists
            # because sets cannot be serialized
            @post_dump
            def convert_sets(self, data):
                for attribute, value in data['parts'].items():
                    data['parts'][attribute] = list(value)
                return data

        return SerializationSchema


class WildcardPermissionResolver:

    # new to yosai is the use of classmethod, and no need for instantiation
    @classmethod
    def resolve_permission(self, permission_string):
        return WildcardPermission(permission_string)

# new to yosai:
class DefaultPermissionResolver:

    @classmethod
    def resolve_permission(self, permission_string):
        return DefaultPermission(permission_string)


class DefaultPermission(WildcardPermission):
    """
    This class is known in Shiro as DomainPermission.  It has been renamed
    and refactored a bit for Yosai.

    Differences include:
    - Unlike Shiro's DomainPermission, DefaultPermission obtains its domain
      attribute by argument (rather than by using class name (and subclassing)).
    - Set order is removed (no OrderedSet) until it is determined that using
      ordered set will improve performance (TBD).
    - refactored interaction between set_parts and encode_parts

    This class can be used as a base class for ORM-persisted (SQLAlchemy)
    permission model(s).  The ORM model maps the parts of a permission
    string to separate table columns (e.g. 'domain', 'action' and 'target'
    columns) and is subsequently used in querying strategies.
    """
    def __init__(self, domain=None, action=None, target=None,
                 wildcard_string=None):
        """
        :type domain: str
        :type action: str or set of strings
        :type target: str or set of strings
        :type wildcard_permission: str

        After initializing, the state of a DomainPermission object includes:
            self.results = a list populated by WildcardPermission.set_results
            self._domain = a Str, or None
            self._action = a set, or None
            self._target = a set, or None
        """
        if wildcard_string is not None:
            super().__init__(wildcard_string=wildcard_string)
        else:
            super().__init__()
            self.set_parts(domain=domain, action=action, target=target)
        self._domain = self.parts.get('domain')
        self._action = self.parts.get('action')
        self._target = self.parts.get('target')

    @property
    def domain(self):
        return self._domain

    @domain.setter
    def domain(self, domain):
        self._domain = domain
        self.set_parts(domain=self._domain,
                       action=getattr(self, '_action', None),
                       target=getattr(self, '_target', None))

    @property
    def action(self):
        return self._action

    @action.setter
    def action(self, action):
        self.set_parts(domain=self._domain,
                       action=action,
                       target=getattr(self, '_target', None))
        self._action = self.parts.get('action', None)

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, target):
        self.set_parts(domain=self._domain,
                       action=getattr(self, '_action', None),
                       target=target)
        self._target = self.parts.get('target', None)

    def encode_parts(self, domain, action, target):
        """
        Yosai redesigned encode_parts to return permission, rather than
        pass it to set_parts as a wildcard

        :type domain:  str
        :type action: a subpart-delimeted str
        :type target: a subpart-delimeted str
        """

        # Yosai sets None to Wildcard
        permission = self.PART_DIVIDER_TOKEN.join(
            x if x is not None else self.WILDCARD_TOKEN
            for x in [domain, action, target])

        return permission

    # overrides WildcardPermission.set_parts:
    def set_parts(self, domain, action, target):
        """
        Shiro uses method overloading to determine as to whether to call
        either this set_parts or that of the parent WildcardPermission.  The
        closest that I will accomodate that design is with default parameter
        values and the first condition below.

        The control flow is as follow:
            If wildcard_string is passed, call super's set_parts
            Else process the orderedsets

        :type action:  either a Set of strings or a subpart-delimeted string
        :type target:  an Set of Strings or a subpart-delimeted string
        """

        # default values
        domain_string = domain
        action_string = action
        target_string = target

        if isinstance(domain, set):
            domain_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in domain])

        if isinstance(action, set):
            action_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in action])

        if isinstance(target, set):
            target_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in target])

        permission = self.encode_parts(domain=domain_string,
                                       action=action_string,
                                       target=target_string)

        super().setparts(wildcard_string=permission)

    # removed getDomain

    @classmethod
    def serialization_schema(cls):
        class PermissionPartsSchema(Schema):
                domain = fields.List(fields.Str)
                action = fields.List(fields.Str)
                target = fields.List(fields.Str)

        class SerializationSchema(Schema):
            parts = fields.Nested(PermissionPartsSchema)

            @post_load
            def make_default_permission(self, data):
                mycls = DefaultPermission
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)

                # have to convert to set from post_load due to the
                # WildcardPartsSchema
                for key, val in instance.parts.items():
                    instance.parts[key] = frozenset(val)
                return instance

            # prior to serializing, convert a dict of sets to a dict of lists
            # because sets cannot be serialized
            @post_dump
            def convert_sets(self, data):
                for attribute, value in data['parts'].items():
                    data['parts'][attribute] = list(value)
                return data

        return SerializationSchema



class ModularRealmAuthorizer(authz_abcs.Authorizer,
                             authz_abcs.PermissionResolverAware):

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

        # by default, yosai does not support role -> permission resolution

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

    def assert_realms_configured(self):
        if (not self.realms):
            msg = ("Configuration error:  No realms have been configured! "
                   "One or more realms must be present to execute an "
                   "authorization operation.")
            print(msg)
            # log here
            raise IllegalStateException(msg)

    # Yosai refactors isPermitted and hasRole extensively, making use of
    # generators and sub-generators so as to optimize processing w/ each realm
    # and improve code readability

    # new to Yosai:
    def _has_role(self, identifiers, roleid_s):
        for realm in self.authorizing_realms:
            # the realm's has_role returns a generator
            yield from realm.has_role(identifiers, roleid_s)

    # new to Yosai:
    def _is_permitted(self, identifiers, permission_s):
        for realm in self.authorizing_realms:
            # the realm's is_permitted returns a generator
            yield from realm.is_permitted(identifiers, permission_s)

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

        results = collections.defaultdict(bool)  # defaults to False

        for permit in self._is_permitted(identifiers, permission_s):
            # permit expected format is: (Permission, Boolean)
            # As long as one realm returns True for a Permission, that Permission
            # is granted.  Given that (True or False == True), assign accordingly:
            results[permit[0]] = results[permit[0]] or permit[1]

        return [(perm, permitted) for perm, permitted in results.items()]

    def is_permitted_all(self, identifiers, permission_s):
        """
        :param identifiers: a Set of Identifier objects
        :param permission_s:  a List of Permission objects

        :returns: a Boolean
        """
        self.assert_realms_configured()

        for (perm, permitted) in self.is_permitted(identifiers, permission_s):
            if not permitted:
                return False
        return True

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

        :param roleid_s: a collection of 1..N Role identifiers
        :type roleid_s: List of String(s)

        :returns: a List of tuple(s), containing the roleid and a Boolean
                  indicating whether role membership is assigned
        """
        self.assert_realms_configured()

        results = collections.defaultdict(bool)  # defaults to False

        for checkrole in self._has_role(identifiers, roleid_s):
            # checkrole expected format is: (roleid, Boolean)
            # As long as one realm returns True for a roleid, a subject is
            # considered a member of that Role.
            # Given that (True or False == True), assign accordingly:
            results[checkrole[0]] = results[checkrole[0]] or checkrole[1]

        return [(roleid, hasrole) for roleid, hasrole in results.items()]

    def has_all_roles(self, identifiers, roleid_s):
        """
        :param identifiers: a collection of identifiers
        :type identifiers: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings

        :returns: a Boolean
        """
        self.assert_realms_configured()

        for (roleid, hasrole) in self.has_role(identifiers, roleid_s):
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


# new to yosai, deprecates shiro's SimpleAuthorizationInfo
class IndexedAuthorizationInfo(authz_abcs.AuthorizationInfo,
                               serialize_abcs.Serializable):
    """
    This is an implementation of the authz_abcs.AuthorizationInfo interface that
    stores roles and permissions as internal attributes, indexing permissions
    to facilitate is_permitted requests.
    """
    def __init__(self, roles=set(), permissions=set()):
        """
        :type roles: set of Role objects
        :type perms: set of DefaultPermission objects
        """
        self._roles = roles
        self._permissions = collections.defaultdict(set)
        self.index_permission(permissions)

    @property
    def roles(self):
        return self._roles

    @roles.setter
    def roles(self, roles):
        """
        :type roles: a set of Role objects
        """
        self._roles = roles

    @property
    def permissions(self):
        return set(itertools.chain.from_iterable(self._permissions.values()))

    @permissions.setter
    def permissions(self, perms):
        """
        :type perms: a set of DefaultPermission objects
        """
        self._permissions.clear()
        self.index_permission(perms)

    # yosai combines add_role with add_roles
    def add_role(self, role_s):
        """
        :type role_s: set
        """
        self._roles.update(role_s)

    # yosai combines add_string_permission with add_string_permissions
    def add_permission(self, permission_s):
        """
        :type permission_s: set of DefaultPermission objects
        """
        self.index_permission(permission_s)

    def index_permission(self, permission_s):
        """
        Indexes permissions because indexes can be quickly queried to facilitate
        is_permitted requests.

        Indexing is by a Permission's domain attribute.  One limitation of this
        design is that it requires that Permissions be modeled by domain, one
        domain per Permission.  This is a generally acceptable limitation.

        """
        for permission in permission_s:
            domain = next(iter(permission.domain))  # should only be ONE domain
            self._permissions[domain].add(permission)

        self.assert_permissions_indexed(permission_s)

    def get_permission(self, domain):
        return self._permissions.get(domain, set())

    def assert_permissions_indexed(self, permission_s):
        """
        Ensures that all permission_s passed were indexed.

        :raises PermissionIndexingException: when the permission_index fails to
                                             index every permission provided
        """
        if not (permission_s <= self.permissions):
            perms = ','.join(str(perm) for perm in permission_s)
            msg = "Failed to Index All Permissions: " + perms
            raise PermissionIndexingException(msg)

    def __len__(self):
        return len(self.permissions) + len(self.roles)

    def __repr__(self):
        perms = ','.join(str(perm) for perm in self.permissions)
        return ("IndexedAuthorizationInfo(permissions={0}, roles={1})".
                format(perms, self.roles))

    @classmethod
    def serialization_schema(cls):

        class SerializationSchema(Schema):
            _roles = fields.Nested(SimpleRole.serialization_schema(), many=True)
            _permissions = CollectionDict(fields.Nested(
                DefaultPermission.serialization_schema()))

            # sets can't be serialized so convert to list
            # @post_dump
            # def convert_roles(self, data):
            #     data['_roles'] = list(data['_roles'])

            @post_load
            def make_authz_info(self, data):
                mycls = IndexedAuthorizationInfo
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                instance._roles = set(instance._roles)
                return instance

        return SerializationSchema


class SimpleRole(serialize_abcs.Serializable):

    def __init__(self, name=None, permissions=set()):
        self.name = name

        # note:  yosai doesn't support role->permission resolution by default
        #        and so permissions and the permission methods won't be used
        # self.permissions = permissions

    # def add(self, permission):
    #    """
    #    :type permission: a Permission object
    #    """
    #    permissions = self.permissions
    #    if (permissions is None):
    #        self.permissions = set()
    #    self.permissions.add(permission)

    # def add_all(self, permissions):
    #    """
    #    :type permissions: an set of Permission objects
    #    """
    #    if (self.permissions is None):
    #        self.permissions = set()

    #   for item in permissions:
    #        self.permissions.add(item)  # adds in order received

    # def is_permitted(self, permission):
    #    """
    #    :type permission: Permission object
    #    """
    #    if (self.permissions):
    #        for perm in self.permissions:
    #            if (perm.implies(permission)):
    #                return True
    #    return False

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if (isinstance(other, SimpleRole)):
            return self.name == other.name
        return False

    def __repr__(self):
        return "SimpleRole(name={0})".format(self.name)

    @classmethod
    def serialization_schema(cls):

        class SerializationSchema(Schema):
            name = fields.Str()

            @post_load
            def make_authz_info(self, data):
                mycls = SimpleRole
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema
