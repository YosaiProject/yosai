from yosai import (
    IAccountId,
    IAccount,
    Event,
)

from abc import ABCMeta, abstractmethod


class ABCAuthenticationEvent(Event, metaclass=ABCMeta):

    def __init__(self, source, authc_token):
        super().__init__(source)
        self.authc_token = authc_token


class IAuthenticationListener(metaclass=ABCMeta):
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


class IAuthenticationToken(metaclass=ABCMeta):
   
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


class IAuthenticator (metaclass=ABCMeta):
    """
    Authenticates an account based on the submitted AuthenticationToken.
    """
 
    @abstractmethod
    def authenticate_account(self, authc_token):
        """
        Authenticates an account based on the submitted AuthenticationToken
        """
        pass


class ICompositeAccountId(IAccountId, metaclass=ABCMeta):

    @abstractmethod
    def get_realm_account_id(self, realm_name):
        pass


class ICompositeAccount(IAccount, metaclass=ABCMeta):

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


class IHostAuthenticationToken(IAuthenticationToken, metaclass=ABCMeta):

    @property
    @abstractmethod
    def host(self):
        pass
        

class ILogoutAware(metaclass=ABCMeta):

    @abstractmethod
    def on_logout(self, principals):
        pass


class IPasswordService(metaclass=ABCMeta):

    @abstractmethod
    def encrypt_password(self, plaintext_password):
        pass

    @abstractmethod
    def passwords_match(self, submitted_plaintext, encrypted):
        pass


class IHashingPasswordService(IPasswordService, metaclass=ABCMeta):

    @abstractmethod
    def hash_password(self, plaintext):
        pass

    @abstractmethod
    def passwords_match(self, plaintext, saved_password_hash):
        pass


class IRememberMeAuthenticationToken(IAuthenticationToken, metaclass=ABCMeta):

    @property
    @abstractmethod
    def is_remember_me(self):
        pass


class IAuthenticationAttempt(metaclass=ABCMeta):

    @property
    @abstractmethod
    def authentication_token(self):
        pass

    @property
    @abstractmethod
    def realms(self):
        pass


class IAuthenticationStrategy(metaclass=ABCMeta):

    @abstractmethod
    def execute(self, attempt):
        pass


