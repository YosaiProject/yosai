class IllegalArgumentException(Exception):
    pass


class IllegalStateException(Exception):
    pass


class AllPermission(object):

    def __init__(self):
        pass

    def implies(self, permission)
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

                subparts = set(part.split(self.SUBPART_DIVIDER_TOKEN))
                
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
                self._actions = set(actions.split(self.SUBPART_DIVIDER_TOKEN))

                if (isinstance(targets, str)):
                    self.domain = domain
                    self._targets = set(targets.split(
                        self.SUBPART_DIVIDER_TOKEN))
       
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


class ModularRealmAuthorizer(object):

    def __init__(self, realms):
        self._realms = realms
   
    @property
    def realms(self):
        return self._realms

    @realms.setter
    def realms(self, realms):
        self._realms = realms
        self.apply_permission_resolver_to_realms()
        self.apply_role_permission_resolver_to_realms()
    
    @property
    def permission_resolver(self):
        return self._permission_resolver
    
    @permission_resolver.setter
    def permission_resolver(self, resolver):
        self._permission_resolver = resolver 
        self.apply_permission_resolver_to_realms()
    
    def apply_permission_resolver_to_realms(self):
        resolver = self._permission_resolver
        realms = self._realms 
        if (resolver and realms):
            for realm in realms: 
                # DG:  refactored LBYL to EAFP:
                realm.permission_resolver = resolver

    @property
    def role_permission_resolver(self):
        return self._role_permission_resolver

    @role_permission_resolver.setter
    def role_permission_resolver(self, resolver):
        self._role_permission_resolver = resolver 
        self.apply_role_permission_resolver_to_realms()

    def apply_role_permission_resolver_to_realms(self):
        role_perm_resolver = self.role_permission_resolver
        realms = self._realms
        if (role_perm_resolver and realms): 
            for realm in realms: 
                # DG:  refactored LBYL to EAFP:
                realm.role_permission_resolver = role_perm_resolver

    def assert_realms_configured(self):
        try:
            realms = self._realms 
            if (not realms):
                # log here
                msg = ("Configuration error:  No realms have been configured! "
                       "One or more realms must be present to execute an "
                       "authorization operation.")
                print(msg)
                raise IllegalStateException(msg)
        except IllegalStateException as ex:
            print('assert_realms_configured IllegalStateException: ', ex)

    # DG:  refactored isPermitted, consolidating to a single method
    def is_permitted(self, principals, permissions):
        """
        Input:
            principals = a Set of Principal objects
            permissions = a List of Permission objects

        Output:
            a List of Booleans corresponding to the permission elements
        """
        results = []
        self.assert_realms_configured()
        for index, permission in enumerate(permissions):
            for realm in self.realms:
                # DG:  must LBYL (need an Authorizing realm)
                if (hasattr(realm, 'is_permitted')):  
                    try:
                        results[index] = \
                            realm.is_permitted(principals, permission)
                    except:
                        raise

        return results 

    def is_permitted_all(self, principals, permissions):
        """
        Input:
            principals = a Set of Principal objects
            permissions = a List of Permission objects

        Output:
            a Boolean 
        """
        self.assert_realms_configured()
        for result in self.is_permitted(principals, permissions):
            if (result is False):
                return False
        return True

    # DG:  omitting checkPermission -- seems redundant
    
    def has_role(self, principals, role_ids):
        pass  # will implement later

    def has_all_roles(self, principals, role_ids):
        pass  # will implement later

    # DG: omitting checkRole -- seems redundant


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


