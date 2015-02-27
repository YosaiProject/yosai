from abc import ABCMeta, abstractmethod
from authc.interfaces import IAuthenticator
from authz.interfaces import IAuthorizer
from session.interfaces import ISessionManager


class IRememberMeManager(metaclass=ABCMeta):

    @abstractmethod
    def get_remembered_principals(self, subject_context):
        pass

    @abstractmethod
    def forget_identity(self, subject_context):
        pass

    @abstractmethod
    def on_successful_login(self, subject, authc_token, auth_info):
        pass

    @abstractmethod
    def on_failed_login(self, subject, token, auth_exc):
        pass

    @abstractmethod
    def on_logout(self, subject):
        pass


class ISecurityManager(IAuthenticator, IAuthorizer, ISessionManager,
                       metaclass=ABCMeta):

    def login(self, subject, authc_token): 
        pass

    def logout(self, subject):
        pass

    def create_subject(self, subject_context):
        pass

