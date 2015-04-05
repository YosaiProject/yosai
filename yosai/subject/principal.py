from collections import defaultdict
from yosai import UnrecognizedPrincipalException


class SimplePrincipalCollection(object):
    """
    DG:
    I excluded:
        - asList, asSet
        - the serialization methods, because jsonpickle does it automatically?
    """
    def __init__(self, realm_principals=None, principals=None, realm=None):
        """
        You can initialize a SimplePrincipalCollection in two ways:
            1) by passing a realm_principals Dict of Sets, where realms
               are the keys and each set contains corresponding principals
            2) by instantiating a local instance of realm_principals using
               realm and principals parameters

        Input:
            realm_principals = a Dict of Sets
            principals = a Set
            realm = a String
        """
        self.realm_principals = defaultdict(set)  # my realmprincipals 'map'

        if (realm_principals):
            self.realm_principals = realm_principals  # DG: overwrites, I know

        elif (realm and principals):

            """realm_principals is a Dict of Sets:
                1) realm name is the dict key
                2) each Set contains Principal objects
            """
            self.realm_principals[realm] = principals

        self.primary_principal = None

    def __eq__(self, other):
        if type(other) == type(self):
            return (self.realm_principals == other.realm_principals)
        return False

    def __repr__(self):
        return ','.join([str(key) + '=' + str(value) for (key, value) in 
                        self.realm_principals.items()])

    @property
    def hash_code(self):  # DG:  implementing this for consistency with shiro
        return id(self)

    @property
    def primary_principal(self):
        if (not self._primary_principal):
            try:
                # DG:  shiro arbitrarily selects for missing primary principal
                primary_principal = next(iter(self.realm_principals.values())) 
            except:
                print('failed to arbitrarily obtain primary principal')
                return None
            else:
                self._primary_principal = primary_principal
                return primary_principal
        return self._primary_principal
  
    def add(self, principals=None, realm_name=None):  # DG: includes addAll
        """
            Inputs:
                principals = a Set of Principal object(s)
                realm_name = a String

         principals is a defaultdict, so I can always add a principal to 
         a realm, even if the realm doesn't yet exist
        """
        if (realm_name):
            self.realm_principals[realm_name].update(principals)
        elif (principals.get_realm_names()):
            for realm_name in principals.get_realm_names():
                for principal in principals.from_realm(realm_name):
                    self.add(principal, realm_name)
        
    def by_type(self, principal_class):
        """ returns all occurances of a type of principal """
        _principals = set() 
        for principal_collection in self.realm_principals.values():
            for principal in principal_collection: 
                if (isinstance(principal, principal_class)):
                    _principals.update(principal)
        return _principals if _principals else None 

    def add_realm_principal(self, realm, principle_key, principal):
        self.realm_principals[realm].update({principle_key: principal})

    def clear(self):
        self.realm_principals = None

    def delete_realm_principal(self, realm, principal):
        return self.realm_principals[realm].pop(principal, None)

    def delete_realm(self, realm):
        return self.realm_principals.pop(realm, None)
    
    def from_realm(self, realm_name):
        return self.realm_principals.get(realm_name, set())
    
    def get_all_principals(self):
        return self.realm_principals

    def get_principals_lazy(self, realm_name):
        if (self.realm_principals is None): 
            self.realm_principals = defaultdict(set) 
        
        principals = self.realm_principals.get(realm_name, None)
        if (not principals):  # an empty set
            self.realm_principals[realm_name].update(principals)
        
        return principals
    
    def get_realm_names(self):
        return set(self.realm_principals.keys())
    
    def is_empty(self):
        return (not self.realm_principals.keys())
    
    def one_by_type(self, principal_class):
        """ gets the first-found principal of a type """
        if (not self.realm_principals):
            return None
        for principal_collection in self.realm_principals.values():
            for principal in principal_collection: 
                if (isinstance(principal, principal_class)):
                    return principal
        return None

    def set_primary_principal(self, principal):
        """ DG:  not sure whether shiro's logic makes sense for this.. 
                they seem to grab an arbitrary principal from any realm..
                not sure whether my logic below will apply, either"""
        exists = False
        try:
            for realm in self._principals.keys():
                for _principal in realm.keys():
                    if (_principal == principal):
                        exists = True
            if(exists is False):
                raise UnrecognizedPrincipalException
        except UnrecognizedPrincipalException:
            print('Could not locate principal requested as primary. ')
        else:
            self._primary_principal = principal 

