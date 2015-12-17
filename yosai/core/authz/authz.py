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
import itertools

from yosai.core import (
    AuthorizationEventException,
    CollectionDict,
    Event,
    IllegalArgumentException,
    IllegalStateException,
    LogManager,
    PermissionIndexingException,
    UnauthorizedException,
    authz_abcs,
    event_abcs,
    realm_abcs,
    serialize_abcs,
)

import copy
import collections
from marshmallow import Schema, fields, post_load, post_dump


class AllPermission:

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
        """
        :type wildcard_string:  String
        :case_sensitive:  Boolean
        """
        self.case_sensitive = case_sensitive
        self.parts = {'domain': {'*'}, 'action': {'*'}, 'target': {'*'}}
        if wildcard_string:
            self.setparts(wildcard_string, case_sensitive)

    def setparts(self, wildcard_string, case_sensitive=DEFAULT_CASE_SENSITIVE):
        """
        :type wildcard_string:  String
        :case_sensitive:  Boolean
        """
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
        :type permission:  authz_abcs.Permission
        :returns:  Boolean
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
        """
        :returns:  marshmallow.Schema
        """
        class WildcardPartsSchema(Schema):
                domain = fields.List(fields.Str, allow_none=True)
                action = fields.List(fields.Str, allow_none=True)
                target = fields.List(fields.Str, allow_none=True)

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


class AuthzInfoResolver(authz_abcs.AuthzInfoResolver):

    def __init__(self, authz_info_class):
        """
        :param: the class injected for AuthorizationInfo conversion
        :type authz_info_class:  type
        """
        self.authz_info_class = authz_info_class

    def resolve(self, roles, permissions):
        pass  # is never called

    def __call__(self, roles, permissions):
        """
        :type roles: Set of authz_abcs.Role
        :type permissions: Set of authz_abcs.Permission
        """
        return self.authz_info_class(roles=roles, permissions=permissions)

    def __repr__(self):
        return "AuthzInfoResolver({0})".format(self.authz_info_class)


class PermissionResolver(authz_abcs.PermissionResolver):

    # using dependency injection to define which Permission class to use
    def __init__(self, permission_class):
        """
        :param permission_class: expecting either a WildcardPermission or
                                 DefaultPermission class
        :type permission_class: type
        """
        self.permission_class = permission_class

    def resolve(self, permission_s):
        """
        :param permission_s: a collection of 1..N permissions expressed in
                             String or Permission form
        :type permission_s: List of authz_abcs.Permission

        :returns: a Set of authz_abcs.Permission instances
        """
        # the type of the first element in permission_s implies the type of the
        # rest of the elements -- no commingling!
        if isinstance(next(iter(permission_s)), str):
            perms = {self.permission_class(perm) for perm in permission_s}
            return perms
        else:  # assumption is that it's already a collection of Permissions
            return permission_s

    def __call__(self, permission):
        """
        :type permission: String
        :returns: authz_abcs.Permission instance
        """
        return self.permission_class(permission)

    def __repr__(self):
        return "PermissionResolver({0})".format(self.permission_class)


class RoleResolver(authz_abcs.RoleResolver):

    # using dependency injection to define which Role class to use
    def __init__(self, role_class):
        """
        :param role_class:  a SimpleRole or other Role class
        :type role_class:  type
        """
        self.role_class = role_class

    def resolve(self, role_s):
        """
        :param role_s: a collection of 1..N roles expressed in
                       String or authz_abcs.Role form
        :type role_s: List

        :returns: a set of Role object(s)
        """
        # the type of the first element in roles_s implies the type of the
        # rest of the elements -- no commingling!
        if isinstance(next(iter(role_s)), str):
            roles = {self.role_class(role) for role in role_s}
            return roles
        else:  # assumption is that it's already a collection of Roles
            return role_s

    def __call__(self, role):
        """
        :type role: String
        :returns: authz_abcs.Role
        """
        return self.role_class(role)

    def __repr__(self):
        return "RoleResolver({0})".format(self.role_class)


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
    def __init__(self, wildcard_string=None,
                 domain=None, action=None, target=None):
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
        self.set_parts(domain=domain,
                       action=getattr(self, '_action'),
                       target=getattr(self, '_target'))
        self._domain = self.parts.get('domain')

    @property
    def action(self):
        return self._action

    @action.setter
    def action(self, action):
        self.set_parts(domain=getattr(self, '_domain'),
                       action=action,
                       target=getattr(self, '_target'))
        self._action = self.parts.get('action')

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, target):
        self.set_parts(domain=getattr(self, '_domain'),
                       action=getattr(self, '_action'),
                       target=target)
        self._target = self.parts.get('target')

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

        if (isinstance(domain, set) or isinstance(domain, frozenset)):
            domain_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in domain])

        if (isinstance(action, set) or isinstance(action, frozenset)):
            action_string = self.SUBPART_DIVIDER_TOKEN.\
                join([token for token in action])

        if (isinstance(target, set) or isinstance(target, frozenset)):
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
                domain = fields.List(fields.Str, allow_none=True)
                action = fields.List(fields.Str, allow_none=True)
                target = fields.List(fields.Str, allow_none=True)

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
                             event_abcs.EventBusAware):

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
    def __init__(self):
        """
        :type realms: tuple
        """
        self._realms = None
        self._event_bus = None
        # yosai omits resolver setting, leaving it to securitymanager instead
        # by default, yosai.core.does not support role -> permission resolution

    @property
    def event_bus(self):
        return self._event_bus

    @event_bus.setter
    def event_bus(self, eventbus):
        self._event_bus = eventbus

    @property
    def realms(self):
        return self._realms

    @realms.setter
    def realms(self, realms):
        """
        :type realms: Tuple
        """
        # this eliminates the need for an authorizing_realms attribute:
        self._realms = tuple(realm for realm in realms
                             if isinstance(realm, realm_abcs.AuthorizingRealm))
        self.register_cache_clear_listener()

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
        """
        :type identifiers:  SimpleIdentifierCollection
        :type roleid_s: Set of String(s)
        """
        for realm in self.realms:
            # the realm's has_role returns a generator
            yield from realm.has_role(identifiers, roleid_s)

    # new to Yosai:
    def _is_permitted(self, identifiers, permission_s):
        """
        :type identifiers:  SimpleIdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)
        """

        for realm in self.realms:
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
        :type identifiers:  SimpleIdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :returns: a frozenset of tuple(s), containing the Permission and a Boolean
                  indicating whether the permission is granted
        """
        self.assert_realms_configured()

        results = collections.defaultdict(bool)  # defaults to False

        is_permitted_results = self._is_permitted(identifiers, permission_s)

        for permission, is_permitted in is_permitted_results:
            # permit expected format is: (Permission, Boolean)
            # As long as one realm returns True for a Permission, that Permission
            # is granted.  Given that (True or False == True), assign accordingly:
            results[permission] = results[permission] or is_permitted

        results = frozenset(results.items())
        self.notify_results(identifiers, results)  # for audit trail
        return results

    # yosai.core.refactored is_permitted_all to support ANY or ALL operations
    def is_permitted_collective(self, identifiers,
                                permission_s, logical_operator):
        """
        :param identifiers: a collection of Identifier objects
        :type identifiers:  SimpleIdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :returns: a Boolean
        """
        self.assert_realms_configured()

        # interim_results is a frozenset of tuples:
        interim_results = self.is_permitted(identifiers, permission_s)

        results = logical_operator(is_permitted for perm, is_permitted
                                   in interim_results)

        if results:
            self.notify_success(identifiers, permission_s)
        else:
            self.notify_failure(identifiers, permission_s)

        return results

    # yosai.core.consolidates check_permission functionality to one method:
    def check_permission(self, identifiers, permission_s, logical_operator):
        """
        like Yosai's authentication process, the authorization process will
        raise an Exception to halt further authz checking once Yosai determines
        that a Subject is unauthorized to receive the requested permission

        :param identifiers: a collection of identifiers
        :type identifiers:  SimpleIdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission objects or Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :raises UnauthorizedException: if any permission is unauthorized
        """
        self.assert_realms_configured()
        permitted = self.is_permitted_collective(identifiers,
                                                 permission_s,
                                                 logical_operator)
        if not permitted:
            msg = "Subject lacks permission(s) to satisfy logical operation"
            print(msg)
            # log here
            raise UnauthorizedException(msg)

    # yosai.core.consolidates has_role functionality to one method:
    def has_role(self, identifiers, roleid_s):
        """
        :param identifiers: a collection of identifiers
        :type identifiers:  SimpleIdentifierCollection

        :param roleid_s: a collection of 1..N Role identifiers
        :type roleid_s: Set of String(s)

        :returns: a frozenset of tuple(s), containing the roleid and a Boolean
                  indicating whether the user is a member of the Role
        """
        self.assert_realms_configured()

        results = collections.defaultdict(bool)  # defaults to False

        for roleid, has_role in self._has_role(identifiers, roleid_s):
            # checkrole expected format is: (roleid, Boolean)
            # As long as one realm returns True for a roleid, a subject is
            # considered a member of that Role.
            # Given that (True or False == True), assign accordingly:
            results[roleid] = results[roleid] or has_role

        results = frozenset(results.items())
        self.notify_results(identifiers, results)
        return results

    def has_role_collective(self, identifiers, roleid_s, logical_operator):
        """
        :param identifiers: a collection of identifiers
        :type identifiers:  SimpleIdentifierCollection

        :param roleid_s: a collection of 1..N Role identifiers
        :type roleid_s: Set of String(s)

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :returns: a Boolean
        """
        self.assert_realms_configured()

        # interim_results is a frozenset of tuples:
        interim_results = self.has_role(identifiers, roleid_s)

        results = logical_operator(has_role for roleid, has_role
                                   in interim_results)

        if results:
            self.notify_success(identifiers, roleid_s)
        else:
            self.notify_failure(identifiers, roleid_s)

        return results

    def check_role(self, identifiers, roleid_s, logical_operator):
        """
        :param identifiers: a collection of identifiers
        :type identifiers:  SimpleIdentifierCollection

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or Set of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :raises UnauthorizedException: if Subject not assigned to all roles
        """
        self.assert_realms_configured()
        has_role_s = self.has_role_collective(identifiers,
                                              roleid_s, logical_operator)
        if not has_role_s:
            msg = "Subject does not have role(s) assigned."
            print(msg)
            # log here
            raise UnauthorizedException(msg)

    # --------------------------------------------------------------------------
    # Event Communication
    # --------------------------------------------------------------------------

    def clear_cache(self, event=None):
        identifiers = event.results.identifiers
        identifier = identifiers.primary_identifier
        for realm in self.realms:
            realm.clear_cached_authorization_info(identifier)

    def register_cache_clear_listener(self):
        if self.event_bus:
            self.event_bus.register(self.clear_cache, 'SESSION.STOP')
            self.event_bus.is_registered(self.clear_cache, 'SESSION.STOP')
            self.event_bus.register(self.clear_cache, 'SESSION.EXPIRE')
            self.event_bus.is_registered(self.clear_cache, 'SESSION.EXPIRE')
            self.event_bus.register(self.clear_cache, 'AUTHENTICATION.SUCCEEDED')
            self.event_bus.is_registered(self.clear_cache, 'AUTHENTICATION.SUCCEEDED')

    # notify_results is intended for audit trail
    def notify_results(self, identifiers, results):
        """
        :param results:  permission or role based results, created by
                         is_permitted or has_role, respectively
        """
        try:
            event = Event(source=self.__class__.__name__,
                          event_topic='AUTHORIZATION.RESULTS',
                          identifiers=identifiers,
                          results=results)
            self.event_bus.publish(event.event_topic, event=event)
        except AttributeError:
            msg = "Could not publish AUTHORIZATION.RESULTS event"
            raise AuthorizationEventException(msg)

    def notify_success(self, identifiers, items):
        try:
            event = Event(source=self.__class__.__name__,
                          event_topic='AUTHORIZATION.GRANTED',
                          identifiers=identifiers,
                          items=items)
            self.event_bus.publish(event.event_topic, event=event)
        except AttributeError:
            msg = "Could not publish AUTHORIZATION.GRANTED event"
            raise AuthorizationEventException(msg)

    def notify_failure(self, identifiers, items):
        try:
            event = Event(source=self.__class__.__name__,
                          event_topic='AUTHORIZATION.DENIED',
                          identifiers=identifiers,
                          items=items)
            self.event_bus.publish(event.event_topic, event=event)
        except AttributeError:
            msg = "Could not publish AUTHORIZATION.DENIED event"
            raise AuthorizationEventException(msg)

    # --------------------------------------------------------------------------

    def __repr__(self):
        return ("ModularRealmAuthorizer(realms={0})".
                format(self.realms))


class IndexedPermissionVerifier(authz_abcs.PermissionVerifier,
                                authz_abcs.PermissionResolverAware):

    def __init__(self):
        self._permission_resolver = None  # setter-injected after init

    @property
    def permission_resolver(self):
        return self._permission_resolver

    @permission_resolver.setter
    def permission_resolver(self, permissionresolver):
        self._permission_resolver = permissionresolver

    def get_authzd_permissions(self, authz_info, permission):
        """
        :type authz_info:  IndexedAuthorizationInfo

        :param permission: a Permission that has already been resolved (if needed)
        :type permission: a Permission object

        Queries an indexed collection of permissions in authz_info for
        related permissions (those that potentially imply privilege).  Those
        that are related include:
            1) permissions with a wildcard domain
            2) permissions of the same domain as the requested permission

        :returns: frozenset
        """

        wildcard_perms = authz_info.get_permission('*')

        requested_domain = next(iter(permission.domain))
        domain_perms = authz_info.get_permission(requested_domain)

        return frozenset(itertools.chain(wildcard_perms, domain_perms))

    def is_permitted(self, authz_info, permission_s):
        """
        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :yields: (Permission, Boolean)
        """

        requested_perms = self.permission_resolver.resolve(permission_s)

        for reqstd_perm in requested_perms:
            is_permitted = False
            authorized_perms = self.get_authzd_permissions(authz_info,
                                                           reqstd_perm)
            for authz_perm in authorized_perms:
                if authz_perm.implies(reqstd_perm):
                    is_permitted = True
                    break
            yield (reqstd_perm, is_permitted)


class SimpleRoleVerifier(authz_abcs.RoleVerifier):

    def has_role(self, authz_info, roleid_s):
        """
        Confirms whether a subject is a member of one or more roles.

        :param roleid_s: a collection of 1..N Role identifiers
        :type roleid_s: Set of String(s)

        :yields: tuple(roleid, Boolean)
        """
        authzinfo_roleids = authz_info.roleids
        for roleid in roleid_s:
            hasrole = ({roleid} <= authzinfo_roleids)
            yield (roleid, hasrole)


# new to yosai.core. deprecates shiro's SimpleAuthorizationInfo
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
    def roleids(self):
        return {role.identifier for role in self._roles}

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

    # yosai.core.combines add_role with add_roles
    def add_role(self, role_s):
        """
        :type role_s: set
        """
        self._roles.update(role_s)

    # yosai.core.combines add_string_permission with add_string_permissions
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
            _roles = fields.Nested(SimpleRole.serialization_schema(), many=True,
                                   allow_none=True)
            _permissions = CollectionDict(fields.Nested(
                DefaultPermission.serialization_schema()), allow_none=True)

            @post_load
            def make_authz_info(self, data):
                mycls = IndexedAuthorizationInfo
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                instance._roles = set(instance._roles)
                return instance

        return SerializationSchema


class SimpleRole(serialize_abcs.Serializable):

    def __init__(self, role_identifier):

        self.identifier = role_identifier
        # note:  yosai.core.doesn't support role->permission resolution by default
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
        return hash(self.identifier)

    def __eq__(self, other):
        if (isinstance(other, SimpleRole)):
            return self.identifier == other.identifier
        return False

    def __repr__(self):
        return "SimpleRole(identifier={0})".format(self.identifier)

    @classmethod
    def serialization_schema(cls):

        class SerializationSchema(Schema):
            identifier = fields.Str(allow_none=True)

            @post_load
            def make_authz_info(self, data):
                mycls = SimpleRole
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema
