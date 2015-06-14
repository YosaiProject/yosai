from abc import ABCMeta, abstractmethod
import yosai.authc.abcs as authc_abcs
import yosai.authz.abcs as authz_abcs
import yosai.session.abcs as session_abcs


class RememberMeManager(metaclass=ABCMeta):

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


class SecurityManager(authc_abcs.Authenticator, authz_abcs.Authorizer, 
                      session_abcs.SessionManager):

    @abstractmethod
    def login(self, subject, authc_token): 
        pass

    @abstractmethod
    def logout(self, subject):
        pass

    @abstractmethod
    def create_subject(self, subject_context):
        pass

