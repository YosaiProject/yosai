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
from yosai.serialize.abcs import Serializable

# not pythonic, will change later:
class AccountId(metaclass=ABCMeta):
    @abstractmethod
    def __repr__(self):
        pass

class Account(Serializable, metaclass=ABCMeta):

    """
    An Account is a unique identity within an AccountStore  that has a set of
    attributes.  An account may represent a human being, but this is not
    required - an account could represent a host, a server, a daemon -
    basically anything with an identity that might need to be authenticated or
    authorized to perform behavior.
     
    Implementation Warning
    ----------------------
    Since Yosai sometimes logs account operations, please ensure your Account's
    __repr__ implementation does *not* print out account CREDENTIALS 
    (password, etc), as these might be viewable to someone reading your logs.
    This is good practice anyway, and account principals should rarely (if
    ever) be printed out for any reason.

    Yosai's default implementations of this interface only ever print account 
    attributes.

    Serialization Specifications
    ----------------------------
    Requires two (marshmallow) Schemas:
        1) the default SerializationSchema 
        2) AccountCredentialsSchema:
            - its make_object method should return a newly populated dict
        3) AccountAttributesSchema:  
            - its make_object method should return a newly populated dict
    """ 

    @property 
    @abstractmethod
    def account_id(self):  # DG:  renamed 
        """ 
        Returns an identifier unique compared to any other Account found in the
        same account store.  For example, this can be a store-wide unique
        username or email address, database primary key, UUID, GUID, etc.
    
        After an account is authenticated, Shiro will use this id for all
        future access to the account: for caching the account (if caching is
        enabled), for future lookups from the account store, and any lookups
        for authorization.
        
        :returns: an identifier unique compared to any other Account found in
                  the same account store
        """ 
        pass

    @property 
    @abstractmethod
    def credentials(self):
        """ 
        Returns the stored credentials associated with the corresponding
        Account.  Credentials, such as a password or private key, verifies one
        or more submitted identities during authentication.
       
        Shiro references credentials during the authentication process to
        ensure that submitted credentials during a login attempt match exactly
        the Account's stored credentials returned via this method.
       
        :returns: the credentials associated with the corresponding Subject
        """
        pass

    @property 
    @abstractmethod
    def attributes(self):
        """ 
        Returns an *immutable* view of the Account's IDENTIFYING attributes 
        accessible to the application.  Once the account is obtained, an application
        developer can access them as desired, for example:
        
            username = account.attributes.get('username')
            print("Welcome, " + username + "!")

        :returns: the Account's attributes accessible to the application

        Requires a corresponding AccountAttributesSchema class that defines its
        (marshmallow) serialization schema.
        """
        pass


class AccountStore(metaclass=ABCMeta):

    @abstractmethod
    def get_account(self, authc_token=None, account_id=None):
        pass
