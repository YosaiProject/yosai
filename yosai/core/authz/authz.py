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
import logging

from yosai.core import (
    SerializationManager,
    UnauthorizedException,
    authz_abcs,
    realm_abcs,
    serialize_abcs,
)

import collections

logger = logging.getLogger(__name__)


class WildcardPermission(serialize_abcs.Serializable):
    """
    A ``WildcardPermission`` is a very flexible permission construct supporting
    multiple levels of permission matching. However, despite its flexibility,
    most people will probably follow some standard conventions as explained below.

    Simple Usage
    ----------------
    In the simplest form, ``WildcardPermission`` can be used as a simple permission
    string. You could grant a user an 'editBlogPost' permission and then check
    that the user has the editBlogPost permission by calling:::

        subject.is_permitted(['editBlogPost'])

    This is (mostly) equivalent to:::

        subject.is_permitted([WildcardPermission('editBlogPost')])

    ..but more on that later

    The simple permission string may work for simple applications, but it
    requires that you have permissions such as 'viewBlogPost', 'deleteBlogPost',
    'createBlogPost', etc. You can also grant a user '*' permissions
    using the wildcard character (giving this class its name), meaning that
    the user has *every* permission. However, with the wildcard '*' approach
    there's no way to state that a user has 'all blogpost permissions'

    For this reason, WildcardPermission supports multiple *levels* of permissioning.

    Multiple Levels
    -----------------
    ``WildcardPermission`` supports the concept of multiple *levels*.  For example,
    you could restructure the previous simple example by granting a user the
    permission: ``'blogpost:edit'``.

    The colon in this example is a special character used by the
    ``WildcardPermission`` that delimits the next token in the permission.

    In this example, the first token is the *domain* that is being operated on
    and the second token is the *action* that is performed. Each level can contain
    multiple values.  Given support for multiple values, you could simply grant
    a user the permission 'blogpost:view,edit,create', granting the user
    access to perform ``view``, ``edit``, and ``create`` actions in the ``blogpost``
    *domain*. Then you could check whether the user has the ``'blogpost:create'``
    permission by calling:::

        subject.is_permitted(['blogpost:create'])

    (which would return true)

    In addition to granting multiple permissions using a single string, you can
    grant all permission for a particular level:

        * If you want to grant a user permission to perform all actions in the
        ``blogpost`` domain, you could simply grant the user ``'blogpost:*'``.
        With this permission granted, any permission check for ``'blogpost:XXX'```
        will return ``True``.

        * It is also possible to use the wildcard token at the domain
        level (or both levels), granting a user the ``'view'`` action across all
        domains: ``'*:view'``.


    Instance-level Access Control
    -----------------------------
    Another common usage of the ``WildcardPermission`` is to model instance-level
    Access Control Lists (ACLs). In this scenario, you use three tokens:
        * the first token is the *domain*
        * the second token is the *action*
        * the third token is the *instance* that is acted upon

    For example, suppose you grant a user ``'blogpost:edit:12,13,18'``.
    In this example, assume that the third token contains system identifiers of
    blogposts. That would allow the user to edit blogpost with id ``12``, ``13``, and ``18``.
    Representing permissions in this manner is an extremely powerful way to
    express permissions as you can state permissions like:
        *``'blogpost:*:13'``, granting a user permission to perform all actions for blogpost ``13``,
        *``'blogpost:view,create,edit:*'``, granting a user permission to ``view``, ``create``, or ``edit`` *any* blogpost
        *``'blogpost:*:*'``, granting a user permission to perform *any* action on *any* blogpost

    To perform checks against these instance-level permissions, the application
    should include the instance ID in the permission check like so:::

        subject.is_permitted(['blogpost:edit:13'])

    There is no limit to the number of tokens that can be used in a permission.
    How a permission is modeled for your application is left to your imagination and ambition.
    However, common usages shown above can help you get started and provide
    consistency across the Yosai community.  Again, a typical permission wildcard
    syntax is:  ``'domain:action:target'``.
    """
    WILDCARD_TOKEN = '*'
    PART_DIVIDER_TOKEN = ':'
    SUBPART_DIVIDER_TOKEN = ','

    def __init__(self, wildcard_string=None, case_sensitive=False):
        """
        :type wildcard_string:  String
        :case_sensitive:  Boolean
        """
        self.case_sensitive = case_sensitive
        self.parts = {'domain': {'*'}, 'action': {'*'}, 'target': {'*'}}
        if wildcard_string:
            self.setparts(wildcard_string, case_sensitive)

    def setparts(self, wildcard_string, case_sensitive=False):
        """
        :type wildcard_string:  str
        :case_sensitive:  bool
        """
        if (not wildcard_string):
            msg = ("Wildcard string cannot be None or empty. Make sure "
                   "permission strings are properly formatted.")
            raise ValueError(msg)

        wildcard_string = wildcard_string.strip()

        if not any(x != self.PART_DIVIDER_TOKEN for x in wildcard_string):
            msg = ("Wildcard string cannot contain JUST dividers. Make "
                   "sure permission strings are properly formatted.")
            raise ValueError(msg)

        if (not self.case_sensitive):
            wildcard_string = wildcard_string.lower()

        parts = wildcard_string.split(self.PART_DIVIDER_TOKEN)

        part_indices = {0: 'domain', 1: 'action', 2: 'target'}

        for index, part in enumerate(parts):
            if not any(x != self.SUBPART_DIVIDER_TOKEN for x in part):
                msg = ("Wildcard string cannot contain parts consisting JUST "
                       "of sub-part dividers or nothing at all. Ensure that "
                       "permission strings are properly formatted.")
                raise ValueError(msg)

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
        :rtype:  bool
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

    def __getstate__(self):
        parts = {part: list(items) for part, items in self.parts.items()}
        return {
            'parts': parts,
            'case_sensitive': self.case_sensitive
        }

    def __setstate__(self, state):
        parts = {part: frozenset(items) for part, items in state['parts'].items()}
        self.parts = parts
        self.case_sensitive = state['case_sensitive']

class DefaultPermission(WildcardPermission):
    """
    This class is known in Shiro as DomainPermission.  It has been renamed
    and refactored a bit for Yosai.  It is a 'plain vanilla' permission.

    Differences between yosai and shiro implementations include:
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
    def set_parts(self, domain=None, action=None, target=None):
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

    def __getstate__(self):
        parts = {part: list(items) for part, items in self.parts.items()}
        return {
            'parts': parts,
            'case_sensitive': self.case_sensitive
        }

    def __setstate__(self, state):
        self.parts = {part: frozenset(items) for part, items in state['parts'].items()}
        self._domain = self.parts.get('domain')
        self._action = self.parts.get('action')
        self._target = self.parts.get('target')
        self.case_sensitive = state['case_sensitive']


class ModularRealmAuthorizer(authz_abcs.Authorizer):

    """
    A ModularRealmAuthorizer is an Authorizer implementation that consults
    one or more configured Realms during an authorization operation.

    :type realms:  Tuple
    """
    def __init__(self):
        """
        :type realms: tuple
        """
        self.realms = None
        self.event_bus = None

    def init_realms(self, realms):
        """
        :type realms: tuple
        """
        # this eliminates the need for an authorizing_realms attribute:
        self.realms = tuple(realm for realm in realms
                            if isinstance(realm, realm_abcs.AuthorizingRealm))
        self.register_cache_clear_listener()

    def assert_realms_configured(self):
        if (not self.realms):
            msg = ("Configuration error:  No realms have been configured! "
                   "One or more realms must be present to execute an "
                   "authorization operation.")
            raise ValueError(msg)

    # Yosai refactors isPermitted and hasRole extensively, making use of
    # generators and sub-generators so as to optimize processing w/ each realm
    # and improve code readability

    # new to Yosai:
    def _has_role(self, identifiers, role_s):
        """
        :type identifiers:  subject_abcs.IdentifierCollection
        :type role_s: Set of String(s)
        """
        for realm in self.realms:
            # the realm's has_role returns a generator
            yield from realm.has_role(identifiers, role_s)

    # new to Yosai:
    def _is_permitted(self, identifiers, permission_s):
        """
        :type identifiers:  subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)
        """

        for realm in self.realms:
            # the realm's is_permitted returns a generator
            yield from realm.is_permitted(identifiers, permission_s)

    def is_permitted(self, identifiers, permission_s, log_results=True):
        """
        Yosai differs from Shiro in how it handles String-typed Permission
        parameters.  Rather than supporting *args of String-typed Permissions,
        Yosai supports a list of Strings.  Yosai remains true to Shiro's API
        while determining permissions a bit more pythonically.  This may
        be refactored later.

        :param identifiers: a collection of identifiers
        :type identifiers:  subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :param log_results:  states whether to log results (True) or allow the
                             calling method to do so instead (False)
        :type log_results:  bool

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

        if log_results:
            self.notify_results(identifiers, list(results.items()))  # before freezing

        results = frozenset(results.items())
        return results

    # yosai.core.refactored is_permitted_all to support ANY or ALL operations
    def is_permitted_collective(self, identifiers,
                                permission_s, logical_operator):
        """
        :param identifiers: a collection of Identifier objects
        :type identifiers:  subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python standard library)

        :returns: a Boolean
        """
        self.assert_realms_configured()

        # interim_results is a frozenset of tuples:
        interim_results = self.is_permitted(identifiers, permission_s,
                                            log_results=False)

        results = logical_operator(is_permitted for perm, is_permitted
                                   in interim_results)

        if results:
            self.notify_success(identifiers, permission_s, logical_operator)
        else:
            self.notify_failure(identifiers, permission_s, logical_operator)

        return results

    # yosai.core.consolidates check_permission functionality to one method:
    def check_permission(self, identifiers, permission_s, logical_operator):
        """
        like Yosai's authentication process, the authorization process will
        raise an Exception to halt further authz checking once Yosai determines
        that a Subject is unauthorized to receive the requested permission

        :param identifiers: a collection of identifiers
        :type identifiers:  subject_abcs.IdentifierCollection

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission objects or Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python standard library)

        :raises UnauthorizedException: if any permission is unauthorized
        """
        self.assert_realms_configured()
        permitted = self.is_permitted_collective(identifiers,
                                                 permission_s,
                                                 logical_operator)
        if not permitted:
            msg = "Subject lacks permission(s) to satisfy logical operation"
            raise UnauthorizedException(msg)

    # yosai.core.consolidates has_role functionality to one method:
    def has_role(self, identifiers, role_s, log_results=True):
        """
        :param identifiers: a collection of identifiers
        :type identifiers:  subject_abcs.IdentifierCollection

        :param role_s: a collection of 1..N Role identifiers
        :type role_s: Set of String(s)

        :param log_results:  states whether to log results (True) or allow the
                             calling method to do so instead (False)
        :type log_results:  bool

        :returns: a frozenset of tuple(s), containing the role and a Boolean
                  indicating whether the user is a member of the Role
        """
        self.assert_realms_configured()

        results = collections.defaultdict(bool)  # defaults to False

        for role, has_role in self._has_role(identifiers, role_s):
            # checkrole expected format is: (role, Boolean)
            # As long as one realm returns True for a role, a subject is
            # considered a member of that Role.
            # Given that (True or False == True), assign accordingly:
            results[role] = results[role] or has_role

        if log_results:
            self.notify_results(identifiers, list(results.items()))  # before freezing
        results = frozenset(results.items())
        return results

    def has_role_collective(self, identifiers, role_s, logical_operator):
        """
        :param identifiers: a collection of identifiers
        :type identifiers:  subject_abcs.IdentifierCollection

        :param role_s: a collection of 1..N Role identifiers
        :type role_s: Set of String(s)

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python standard library)

        :returns: a Boolean
        """
        self.assert_realms_configured()

        # interim_results is a frozenset of tuples:
        interim_results = self.has_role(identifiers, role_s, log_results=False)

        results = logical_operator(has_role for role, has_role
                                   in interim_results)

        if results:
            self.notify_success(identifiers, role_s, logical_operator)
        else:
            self.notify_failure(identifiers, role_s, logical_operator)

        return results

    def check_role(self, identifiers, role_s, logical_operator):
        """
        :param identifiers: a collection of identifiers
        :type identifiers:  subject_abcs.IdentifierCollection

        :param role_s: 1..N role identifiers
        :type role_s:  a String or Set of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python standard library)

        :raises UnauthorizedException: if Subject not assigned to all roles
        """
        self.assert_realms_configured()
        has_role_s = self.has_role_collective(identifiers,
                                              role_s, logical_operator)
        if not has_role_s:
            msg = "Subject does not have role(s) assigned."
            raise UnauthorizedException(msg)

    # --------------------------------------------------------------------------
    # Event Communication
    # --------------------------------------------------------------------------

    def session_clears_cache(self, items=None):
        """
        :type items: namedtuple
        """
        try:
            identifier = items.identifier
            for realm in self.realms:
                realm.clear_cached_authorization_info(identifier)
        except AttributeError:
            msg = ('Could not clear authz_info from cache after event. '
                   'items: ' + str(items))
            logger.warn(msg)

    def authc_clears_cache(self, identifier=None):
        """
        :type items: namedtuple
        """
        try:
            for realm in self.realms:
                realm.clear_cached_authorization_info(identifier)
        except AttributeError:
            msg = ('Could not clear authc_info from cache after event. '
                   'identifiers: ' + identifiers)
            logger.warn(msg)

    def register_cache_clear_listener(self):
        if self.event_bus:
            self.event_bus.register(self.session_clears_cache, 'SESSION.STOP')
            self.event_bus.is_registered(self.session_clears_cache, 'SESSION.STOP')
            self.event_bus.register(self.session_clears_cache, 'SESSION.EXPIRE')
            self.event_bus.is_registered(self.session_clears_cache, 'SESSION.EXPIRE')
            self.event_bus.register(self.authc_clears_cache, 'AUTHENTICATION.SUCCEEDED')
            self.event_bus.is_registered(self.authc_clears_cache, 'AUTHENTICATION.SUCCEEDED')

    # notify_results is intended for audit trail
    def notify_results(self, identifiers, items):
        """
        :type identifiers:  subject_abcs.IdentifierCollection

        :param items:  either  a collection of 1..N Role identifiers or
                       a collection of 1..N permissions
        """
        try:
            self.event_bus.publish('AUTHORIZATION.RESULTS',
                                   identifiers=identifiers,
                                   items=items)

        except AttributeError:
            msg = "Could not publish AUTHORIZATION.RESULTS event"
            raise AttributeError(msg)

    def notify_success(self, identifiers, items, logical_operator):
        """
        :type identifiers:  subject_abcs.IdentifierCollection

        :param items:  either  a collection of 1..N Role identifiers or
                       a collection of 1..N permissions

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)
        """
        try:
            self.event_bus.publish('AUTHORIZATION.GRANTED',
                                   identifiers=identifiers,
                                   items=items,
                                   logical_operator=logical_operator)

        except AttributeError:
            msg = "Could not publish AUTHORIZATION.GRANTED event"
            raise AttributeError(msg)

    def notify_failure(self, identifiers, items, logical_operator):
        """
        :param items:  either  a collection of 1..N Role identifiers or
                       a collection of 1..N permissions

        :type identifiers:  subject_abcs.IdentifierCollection

        :param logical_operator:  any or all
        :type logical_operator:  function  (stdlib)
        """
        try:
            self.event_bus.publish('AUTHORIZATION.DENIED',
                                   identifiers=identifiers,
                                   items=items,
                                   logical_operator=logical_operator)

        except AttributeError:
            msg = "Could not publish AUTHORIZATION.DENIED event"
            raise AttributeError(msg)

    # --------------------------------------------------------------------------

    def __repr__(self):
        return ("ModularRealmAuthorizer(realms={0})".
                format(self.realms))


class IndexedPermissionVerifier(authz_abcs.PermissionVerifier):

    def get_authzd_permissions(self, authz_info, permission):
        """
        :type authz_info:  IndexedAuthorizationInfo
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
        :type authz_info:  authz_abacs.AuthorizationInfo

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :yields: (Permission, Boolean)
        """

        if isinstance(next(iter(permission_s)), str):
            requested_perms = {DefaultPermission(perm) for perm in permission_s}
        else:  # assumption is that it's already a collection of Permissions
            requested_perms = permission_s

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

    def has_role(self, authz_info, role_s):
        """
        Confirms whether a subject is a member of one or more roles.

        :type authz_info:  authz_abacs.AuthorizationInfo

        :param role_s: a collection of 1..N Role identifiers
        :type role_s: Set of String(s)

        :yields: tuple(role, Boolean)
        """
        for role in role_s:
            hasrole = ({role} <= authz_info.roles)
            yield (role, hasrole)


# new to yosai.core. deprecates shiro's SimpleAuthorizationInfo
class IndexedAuthorizationInfo(serialize_abcs.Serializable):
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
        self.roles = roles
        self._permissions = collections.defaultdict(set)
        self.index_permission(permissions)

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
        self.roles.update(role_s)

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
        try:
            for permission in permission_s:
                domain = next(iter(permission.domain))  # should only be ONE domain
                self._permissions[domain].add(permission)
            self.assert_permissions_indexed(permission_s)

        except TypeError:
            logger.debug(self.__class__.__name__ + ': No permissions to index.')

    def get_permission(self, domain):
        """
        :type domain:  str
        """
        return self._permissions.get(domain, set())

    def assert_permissions_indexed(self, permission_s):
        """
        Ensures that all permission_s passed were indexed.

        :raises ValueError: when the permission_index fails to
                            index every permission provided
        """
        if not (permission_s <= self.permissions):
            perms = ','.join(str(perm) for perm in permission_s)
            msg = "Failed to Index All Permissions: " + perms
            raise ValueError(msg)

    def __len__(self):
        return len(self.permissions) + len(self.roles)

    def __repr__(self):
        perms = ','.join(str(perm) for perm in self.permissions)
        return ("IndexedAuthorizationInfo(permissions={0}, roles={1})".
                format(perms, self.roles))

    def __getstate__(self):
        return {'roles': list(self.roles),
                '_permissions': {key: list(val) for key, val in self._permissions.items()}
                }

    def __setstate__(self, state):
        self.roles = set(state['roles'])
        self._permissions = {key: set(val) for key, val in state['_permissions'].items()}


class AllPermission:

    def implies(self, permission):
        return True
