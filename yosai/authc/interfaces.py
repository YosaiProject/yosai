import org.apache.shiro.account.AccountId
import org.apache.shiro.account.Account
import org.apache.shiro.authc.AuthenticationException
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.realm.Realm
import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.subject.PrincipalCollection
from abc import ABCMeta, abstractmethod


class ABCAuthenticationEvent(Event, metaclass=ABCMeta):

    def __init__(self, source, authc_token):
        super().__init__(source)
        self.authc_token = token


class IAuthenticationListener(metaclass=ABCMeta):

    @abstractmethod
    def on_success(self, authc_token, authc_info):
        pass

    @abstractmethod
    def on_failure(self, authc_token, authc_exception):
        pass

    @abstractmethod
    def on_logout(self, principals):
        pass


class IAuthenticationToken(metaclass=ABCMeta):
   
    @property
    @abstractmethod
    def principal(self):
        pass

    @property
    @abstractmethod
    def credentials(self):
        pass


class IAuthenticator (metaclass=ABCMeta):
 
    @abstractmethod
    def authenticate_account(self, authc_token):
        pass


class ICompositeAccountId(AccountId, metaclass=ABCMeta):

    @abstractmethod
    def get_realm_account_id(self, realm_name):
        pass


class ICompositeAccount(Account, metaclass=ABCMeta):

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


class IHostAuthenticationToken(AuthenticationToken, metaclass=ABCMeta):

    @property
    @abstractmethod
    def host(self):
        pass
        

class ILogoutAware(metaclass=ABCMeta):

    @abstractmethod
    def on_logout(self, principals):
        pass


class IRememberMeAuthenticationToken(AuthenticationToken, metaclass=ABCMeta):

    @property
    @abstractmethod
    def is_remember_me(self):
        pass


class ICredentialsMatcher(metaclass=ABCMeta):

    @abstractmethod
    def credentials_match(self, authc_token, account):
        pass


class IHashingPasswordService(PasswordService, metaclass=ABCMeta):

    @abstractmethod
    def hash_password(self, plaintext):
        pass

    @abstractmethod
    def passwords_match(self, plaintext, saved_password_hash):
        pass


class IPasswordService(metaclass=ABCMeta):

    @abstractmethod
    def encrypt_password(self, plaintext_password):
        pass

    @abstractmethod
    def passwords_match(self, submitted_plaintext, encrypted):
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

