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

from collections import defaultdict
from yosai import UnrecognizedIdentifierException


class SimpleIdentifierCollection:
    """
    DG:
    I excluded:
        - asList, asSet
        - the serialization methods, because jsonpickle does it automatically?
    """
    def __init__(self, realm_identifiers=None, identifiers=None, realm=None):
        """
        You can initialize a SimpleIdentifierCollection in two ways:
            1) by passing a realm_identifiers Dict of Sets, where realms
               are the keys and each set contains corresponding identifiers
            2) by instantiating a local instance of realm_identifiers using
               realm and identifiers parameters

        Input:
            realm_identifiers = a Dict of Sets
            identifiers = a Set
            realm = a String
        """
        self.realm_identifiers = defaultdict(set)  # my realmidentifiers 'map'

        if (realm_identifiers):
            self.realm_identifiers = realm_identifiers  # DG: overwrites, I know

        elif (realm and identifiers):

            """realm_identifiers is a Dict of Sets:
                1) realm name is the dict key
                2) each Set contains Identifier objects
            """
            self.realm_identifiers[realm] = identifiers

        self.primary_identifier = None

    def __eq__(self, other):
        if type(other) == type(self):
            return (self.realm_identifiers == other.realm_identifiers)
        return False

    def __repr__(self):
        return ','.join([str(key) + '=' + str(value) for (key, value) in 
                        self.realm_identifiers.items()])

    @property
    def hash_code(self):  # DG:  implementing this for consistency with shiro
        return id(self)

    @property
    def primary_identifier(self):
        if (not self._primary_identifier):
            try:
                # DG:  shiro arbitrarily selects for missing primary identifier
                primary_identifier = next(iter(self.realm_identifiers.values())) 
            except:
                print('failed to arbitrarily obtain primary identifier')
                return None
            else:
                self._primary_identifier = primary_identifier
                return primary_identifier
        return self._primary_identifier
  
    def add(self, identifiers=None, realm_name=None):  # DG: includes addAll
        """
            Inputs:
                identifiers = a Set of Identifier object(s)
                realm_name = a String

         identifiers is a defaultdict, so I can always add a identifier to 
         a realm, even if the realm doesn't yet exist
        """
        if (realm_name):
            self.realm_identifiers[realm_name].update(identifiers)
        elif (identifiers.get_realm_names()):
            for realm_name in identifiers.get_realm_names():
                for identifier in identifiers.from_realm(realm_name):
                    self.add(identifier, realm_name)
        
    def by_type(self, identifier_class):
        """ returns all occurances of a type of identifier """
        _identifiers = set() 
        for identifier_collection in self.realm_identifiers.values():
            for identifier in identifier_collection: 
                if (isinstance(identifier, identifier_class)):
                    _identifiers.update(identifier)
        return _identifiers if _identifiers else None 

    def add_realm_identifier(self, realm, principle_key, identifier):
        self.realm_identifiers[realm].update({principle_key: identifier})

    def clear(self):
        self.realm_identifiers = None

    def delete_realm_identifier(self, realm, identifier):
        return self.realm_identifiers[realm].pop(identifier, None)

    def delete_realm(self, realm):
        return self.realm_identifiers.pop(realm, None)
    
    def from_realm(self, realm_name):
        return self.realm_identifiers.get(realm_name, set())
    
    def get_all_identifiers(self):
        return self.realm_identifiers

    def get_identifiers_lazy(self, realm_name):
        if (self.realm_identifiers is None): 
            self.realm_identifiers = defaultdict(set) 
        
        identifiers = self.realm_identifiers.get(realm_name, None)
        if (not identifiers):  # an empty set
            self.realm_identifiers[realm_name].update(identifiers)
        
        return identifiers
    
    def get_realm_names(self):
        return {self.realm_identifiers.keys()}
    
    def is_empty(self):
        return (not self.realm_identifiers.keys())
    
    def one_by_type(self, identifier_class):
        """ gets the first-found identifier of a type """
        if (not self.realm_identifiers):
            return None
        for identifier_collection in self.realm_identifiers.values():
            for identifier in identifier_collection: 
                if (isinstance(identifier, identifier_class)):
                    return identifier
        return None

    def set_primary_identifier(self, identifier):
        """ DG:  not sure whether shiro's logic makes sense for this.. 
                they seem to grab an arbitrary identifier from any realm..
                not sure whether my logic below will apply, either"""
        exists = False
        try:
            for realm in self._identifiers.keys():
                for _identifier in realm.keys():
                    if (_identifier == identifier):
                        exists = True
            if(exists is False):
                raise UnrecognizedIdentifierException
        except UnrecognizedIdentifierException:
            print('Could not locate identifier requested as primary. ')
        else:
            self._primary_identifier = identifier 

