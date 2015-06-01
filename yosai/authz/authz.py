from yosai import (
    AuthorizationException, 
    HostUnauthorizedException,
    IllegalArgumentException,
    IllegalStateException,
    LogManager,
    UnauthenticatedException,
    UnauthorizedException,
)

from . import (
    IAuthorizer, 
    IPermissionResolverAware, 
    IRolePermissionResolverAware, 
)

import copy
import collections

class AllPermission(object):

    def __init__(self):
        pass

    def implies(self, permission):
        return True 


class WildcardPermission(object):
    """
    standardized permission wildcard syntax is:  domain:action:instance
    """

    WILDCARD_TOKEN = "*"
    PART_DIVIDER_TOKEN = ":"
    SUBPART_DIVIDER_TOKEN = ","
    DEFAULT_CASE_SENSITIVE = False 

    def __init__(self, wildcard_string=None, 
                 case_sensitive=DEFAULT_CASE_SENSITIVE):
        try:
            if (wildcard_string is None):
                raise IllegalArgumentException
        except IllegalArgumentException:
            print('WildcardPermission: invalid arguments for init!')

        else:
            self.set_parts(wildcard_string, case_sensitive)
                  
    def set_parts(self, wildcard_string, 
                  case_sensitive=DEFAULT_CASE_SENSITIVE):
        try: 
            if (not wildcard_string):
                raise IllegalArgumentException
        except IllegalArgumentException:
            msg = ("Wildcard string cannot be null or empty. Make sure "
                   "permission strings are properly formatted.")
            print(msg)
            return

        wildcardstring = wildcard_string.strip()
        myparts = wildcardstring.split(self.PART_DIVIDER_TOKEN)

        self.parts = []  # will be a List of Sets containing Strings
        try:
            for part in myparts:
                if (not self.case_sensitive):
                    part = part.lower()

                subparts = set{part.split(self.SUBPART_DIVIDER_TOKEN)}
                
                if (not subparts):
                    raise IllegalArgumentException
                
                self.parts.append(subparts)

            if (not self.parts):
                raise IllegalArgumentException
            
        except IllegalArgumentException:
            msg = ("Wildcard string cannot contain parts with only "
                   "dividers. Make sure permission strings are properly "
                   "formatted.")

            print('WildcardPermission.set_parts Exception:', msg)

    def implies(self, permission):
        # By default only supports comparisons with other WildcardPermissions
        if (not isinstance(permission, WildcardPermission)):
            return False
        
        otherparts = permission.parts  # a List of Sets containing Strings
        index = 0
        for i, other_part in enumerate(otherparts):
            # If this permission has less parts than the other permission,
            # everything after the number of parts contained in this 
            # permission is automatically implied, so return true
            if (len(self.parts) - 1 < i):
                return True
            else: 
                part = self.parts[i]
                if ((self.WILDCARD_TOKEN not in part) and
                   not (other_part <= part)):  # not(part contains otherpart)
                    return False
                index += 1
                
        # If this permission has more parts than the other parts, 
        # only imply it if all of the other parts are wildcards
        for i in range(index, len(self.parts)):
            if (self.WILDCARD_TOKEN not in self.parts[i]): 
                return False

        return True

    def __repr__(self): 
        return ':'.join([str(token) for token in self.parts])

    def __eq__(self, other):
        if (isinstance(other, WildcardPermission)):
            return self.parts == other.parts
        
        return False

    def hash_code(self):
        return id(self.parts)


class WildcardPermissionResolver(object):

    def __init__(self):
        pass

    def resolve_permission(self, permission_string):
        return WildcardPermission(permission_string)


class DomainPermission(WildcardPermission):

    def __init__(self, actions=None, targets=None):

        domain = self.get_domain(self.__class__)

        if (actions is None and targets is None):
            self.domain = domain
            self.set_parts(self.domain)

        elif isinstance(actions, str):
                self._actions = set{actions.split(self.SUBPART_DIVIDER_TOKEN)}

                if (isinstance(targets, str)):
                    self.domain = domain
                    self._targets = set{targets.split(
                        self.SUBPART_DIVIDER_TOKEN)}
       
                self.encode_parts(domain, actions, targets)

        elif (isinstance(targets, set) and isinstance(actions, set)):
            self.domain = domain
            self.set_parts(domain, actions, targets)

        else:
            self.set_parts(domain)
            
    def encode_parts(self, domain, actions, targets):
        try:
            if (not domain):
                msg = "domain argument cannot be null or empty."
                raise IllegalArgumentException(msg)
        except IllegalArgumentException as ex:
            print('DomainPermission.encode_parts: ', ex)

        else:
            permission = self.PART_DIVIDER_TOKEN.join(
                x if x is not None else self.WILDCARD_TOKEN
                for x in [domain, actions, targets])

            self.set_parts(permission)

    def set_parts(self, domain, actions, targets):
        """
            Input:
                actions = a Set of Strings
                targets = a Set of Strings
        """
        actions_string = self.SUBPART_DIVIDER_TOKEN.\
            join([str(token) for token in actions])
        targets_string = self.SUBPART_DIVIDER_TOKEN.\
            join([str(token) for token in targets])

        self.encode_parts(domain, actions_string, targets_string)
        self.domain = domain
        self._actions = actions
        self._targets = targets
    
    def get_domain(self, clazz=None):
        if clazz is None:
            return self.domain

        domain = clazz.__name__.lower()
        # strip any trailing 'permission' text from the name (as all subclasses
        # should have been named):
        suffix = 'permission'
        if domain.endswith(suffix): 
            domain = domain[:-len(suffix)] 

        return domain

    def set_domain(self, domain):
        if (self.domain and self.domain == domain):
            return
        
        self.domain = domain
        self.set_parts(self.domain, self._actions, self._targets)
   
    @property
    def actions(self):
        return self._actions

    @actions.setter
    def actions(self, actions):
        if (self._actions is not None and self._actions == actions):
            return
        
        self._actions = actions
        self.set_parts(self.domain, self._actions, self._targets)

    @property
    def targets(self):
        return self._targets

    @targets.setter
    def targets(self, targets):
        if (self._targets is not None and self._targets == targets):
            return
        self._targets = targets
        self.set_parts(self.domain, self._actions, self._targets)


class ModularRealmAuthorizer(IAuthorizer,
                             IPermissionResolverAware,
                             IRolePermissionResolverAware,
                             object):
    """
    A ModularRealmAuthorizer is an Authorizer implementation that consults 
    one or more configured Realms during an authorization operation.

    the funky naming convention where a parameter ends with '_s' denotes 
    one-or-more; in English, this is expressed as '(s)', eg: duck(s)
    indicates one or more ducks
    """
    def __init__(self, realms=None):
        self._realms = set() 
        self._permission_resolver = None
        self._role_permission_resolver = None

    @property
    def realms(self):
        return self._realms

    @realms.setter
    def realms(self, realms):
        """
        :type realms: set
        """
        self._realms = realms
        self.apply_permission_resolver_to_realms()
        self.apply_role_permission_resolver_to_realms()
   
    @property
    def authorizing_realms(self):
        """ 
        new to Yosai: a generator expression filters out non-authz realms 
        """
        return (realm for realm in self.realms 
                if isinstance(realm, IAuthorizer))

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
        resolver = self._permission_resolver
        realms = copy.copy(self._realms)
        if (resolver and realms):
            for realm in realms: 
                # interface contract validation: 
                if isinstance(realm, IPermissionResolverAware):
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
                if isinstance(realm, IRolePermissionResolverAware):
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
    def _has_role(principals, roleid): 
        for realm in self.authorizing_realms:
            if realm.has_role(principals, roleid): 
                return True
        return False 
    
    # new to Yosai:
    def _role_collection(principals, roleids): 
        for roleid in roleids:
            yield (roleid, self._has_role(principals, roleid))

    # new to Yosai:
    def _is_permitted(principals, permission):
        for realm in self.authorizing_realms:
            if realm.is_permitted(principals, permission):
                return True
        return False 

    # new to Yosai:
    def _permit_collection(principals, permissions):
        for permission in permissions:
            yield (permission, self._is_permitted(principals, permission))
    
    def is_permitted(self, principals, permission_s):
        """
        Yosai differs from Shiro in how it handles String-typed Permission 
        parameters.  Rather than supporting *args of String-typed Permissions, 
        Yosai supports a list of Strings.  Yosai remains true to Shiro's API
        while determining permissions a bit more pythonically.

        :param principals: a collection of principals
        :type principals: Set

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :returns: either a single Boolean or a List of tuples, each containin
                  the Permission and a Boolean indicating whether the permission
                  is granted
        """

        self.assert_realms_configured()

        if isinstance(permission_s, collections.Iterable):
            return [(permission, permit) for (permission, permit) in 
                    self._permit_collection(principals, permission_s)]

        return self._is_permitted(principals, permission_s)  # just 1 Bool

    def is_permitted_all(self, principals, permission_s):
        """
        :param principals: a Set of Principal objects
        :param permission_s:  a List of Permission objects

        :returns: a Boolean
        """
        self.assert_realms_configured()

        if isinstance(permission_s, collections.Iterable):
            # using a generator in order to fail immediately
            for (permission, permitted) in self._permit_collection(
                    principals, permission_s):
                if not permitted:
                    return False
            return True

        # else:    
        return self._is_permitted(principals, permission_s)  # 1 Bool

    # yosai consolidates check_permission functionality to one method:
    def check_permission(self, principals, permission_s):
        """
        like Yosai's authentication process, the authorization process will 
        raise an Exception to halt further authz checking once Yosai determines
        that a Subject is unauthorized to receive the requested permission

        :param principals: a collection of principals
        :type principals: Set

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission objects or Strings

        :returns: a List of Booleans corresponding to the permission elements
        """
        self.assert_realms_configured()
        permitted = self.is_permitted_all(principals, permission_s)
        if not permitted:
            msg = "Subject does not have permission(s)"
            print(msg)
            # log here
            raise UnauthorizedException(msg)
    
    # yosai consolidates has_role functionality to one method:
    def has_role(self, principals, roleid_s):
        """
        
        :param principals: a collection of principals
        :type principals: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings 

        :returns: a tuple containing the roleid and a boolean indicating 
                  whether the role is assigned (this is different than Shiro)
        """
        self.assert_realms_configured()

        if isinstance(roleid_s, collections.Iterable):
            return [(roleid, hasrole) for (roleid, hasrole) in 
                    self._role_collection(principals, roleid_s)]

        return self._has_role(principals, roleid_s)  # just 1 Bool

    def has_all_roles(self, principals, roleid_s):

        self.assert_realms_configured()

        for (roleid, hasrole) in \
                self._role_collection(principals, roleid_s):
            if not hasrole: 
                return False
        return True

    def check_role(self, principals, role_s):
        self.assert_realms_configured()
        has_role_s = self.has_all_roles(principals, role_s) 
        if not has_role_s: 
            msg = "Subject does not have role(s)" 
            print(msg)
            # log here
            raise UnauthorizedException(msg)
    

class SimpleAuthorizationInfo(object):
    # DG:  removed string permission related functionality

    def __init__(self, roles):
        """
            Input:
                roles = a Set
        """
        self.roles = roles  

    def add_role(self, role): 
        if (self.roles is None):
            self.roles = set() 
        
        self.roles.add(role)

    def add_roles(self, roles):
        """
            Input:
                roles = a Set
        """
        self.roles.update(roles)

    @property
    def object_permissions(self):
        return self._object_permissions

    @object_permissions.setter
    def object_permissions(self, objectpermissions):
        self._object_permissions = objectpermissions

    def add_object_permission(self, permission):
        """
        Input:
            permission = a Tuple
        """
        if (self._object_permissions is None):
            self._object_permissions = set()
        
        self._object_permissions.add(permission)

    def add_object_permissions(self, permissions):
        """
        Input:
            permissions = a Set of permission Tuples
        """
        if (self._object_permissions is None):
            self._object_permissions = set()
        
        self._object_permissions.update(permissions)


class SimpleRole(object):

    def __init__(self, name, permissions=None): 
        self.name = name
        self.permissions = permissions 

    def add(self, permission):
        """
        Input:
            permission = a Tuple
        """
        permissions = self.permissions
        if (permissions is None): 
            self.permissions = set()
        self.permissions.add([permission])

    def add_all(self, perms):
        """
        Input:
            perms = a Set of permission Tuples
        """
        if (perms):
            if (self.permissions is None):
                self.permissions = set()
            self.permissions.update(perms)

    def is_permitted(self, permission):
        for perm in self.permissions:
            if (perm.implies(permission)):
                return True 
        return False

    @property
    def hash_code(self):
        return id(self) 

    def __eq__(self, other):
        if (self == other):
            return True
        
        if (isinstance(other, SimpleRole)):
            # only check name, since role names should be unique across an 
            # entire application
            return (self.name == other.name)
        
        return False
    
    def __repr__(self):
        return self.name


