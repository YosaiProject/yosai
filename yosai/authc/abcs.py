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

from yosai.account import abcs as account_abcs

from abc import ABCMeta, abstractmethod


# replaced AuthenticationEvents with an event schema:  a) type b) topic
    
class AuthenticationListener(metaclass=ABCMeta):
    """
     An AuthenticationListener listens for notifications while Subjects 
     authenticate with the system.
    """

    @abstractmethod
    def on_success(self, authc_token, authc_info):
        """
        Callback triggered when an authentication attempt for a Subject  
        succeeds
         
        :param authc_token: the authentication token submitted during the 
                            Subject (user)'s authentication attempt
        :param authc_info:  the authentication-related account data acquired
                            after authentication for the corresponding Subject
        """
        pass

    @abstractmethod
    def on_failure(self, authc_token, authc_exception):
        """
        Callback triggered when an authentication attempt for a Subject fails 
        
        :param authc_token: the authentication token submitted during the
                            Subject (user)'s authentication attempt
        :param authc_exception: the AuthenticationException that occurred as 
                                a result of the attempt
        """
        pass

    @abstractmethod
    def on_logout(self, principals):
        """
        Callback triggered when a {@code Subject} logs-out of the system.
        
        This method will only be triggered when a Subject explicitly logs-out
        of the session.  It will not be triggered if their Session times out.
      
        :param principals: the identifying principals of the Subject logging
                           out.
        """
        pass


class AuthenticationToken(metaclass=ABCMeta):
   
    @property
    @abstractmethod
    def principal(self):
        """
        Returns the account identity submitted during the authentication
        process.  
        """
        pass

    @property
    @abstractmethod
    def credentials(self):
        """
        Returns the credentials submitted by the user during the authentication
        process that verifies the submitted principal account identity.
        """
        pass


class Authenticator(metaclass=ABCMeta):
    """
    Authenticates an account based on the submitted AuthenticationToken.
    """
 
    @abstractmethod
    def authenticate_account(self, authc_token):
        """
        Authenticates an account based on the submitted AuthenticationToken
        """
        pass


class CompositeAccountId(account_abcs.AccountId):

    @abstractmethod
    def get_realm_account_id(self, realm_name):
        pass


class CompositeAccount(account_abcs.Account):

    @property
    @abstractmethod
    def realm_names(self):
        pass

    @abstractmethod
    def append_realm_account(self, realm_name, account):
        pass

    @abstractmethod
    def get_realm_attributes(self, realm_name):
        pass


class CredentialsMatcher(metaclass=ABCMeta):

    @abstractmethod
    def credentials_match(authc_token, account):
        pass


class HostAuthenticationToken(AuthenticationToken):

    @property
    @abstractmethod
    def host(self):
        pass
        

class LogoutAware(metaclass=ABCMeta):

    @abstractmethod
    def on_logout(self, principals):
        pass


class PasswordService(metaclass=ABCMeta):

    @abstractmethod
    def encrypt_password(self, plaintext_password):
        pass

    @abstractmethod
    def passwords_match(self, submitted_plaintext, encrypted):
        pass


class HashingPasswordService(PasswordService):

    @abstractmethod
    def hash_password(self, plaintext_password):
        pass

    @abstractmethod
    def passwords_match(self, plaintext_password, saved_password_hash):
        pass


class RememberMeAuthenticationToken(AuthenticationToken):

    @property
    @abstractmethod
    def is_remember_me(self):
        pass


class AuthenticationAttempt(metaclass=ABCMeta):

    @property
    @abstractmethod
    def authentication_token(self):
        pass

    @property
    @abstractmethod
    def realms(self):
        pass


class AuthenticationStrategy(metaclass=ABCMeta):

    @abstractmethod
    def execute(self, attempt):
        pass

