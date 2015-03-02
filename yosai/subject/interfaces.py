
from abc import ABCMeta, abstractmethod
from exceptions import InvalidArgumentException, IllegalArgumentException


class IMutablePrincipalCollection(PrincipalCollection, metaclass=ABCMeta):

    @abstractmethod
    def add(self, principal, realm_name):
        pass

    @abstractmethod
    def addAll(self, principals=None, realm_name=None):
        pass

    @abstractmethod
    def clear(self):
        pass


class IPrincipalCollection(metaclass=ABCMeta):

    @property
    @abstractmethod
    def primary_principal(self):
        pass

    @abstractmethod
    def one_by_type(self, principal_type):
        pass

    @abstractmethod
    def by_type(self, principal_type):
        pass

    @abstractmethod
    def from_realm(self, realm_name):
        pass

    @property
    @abstractmethod
    def realm_names(self):
        pass

    @property
    @abstractmethod
    def is_empty(self):
        pass


class IPrincipalMap(PrincipalCollection, metaclass=ABCMeta):

    @abstractmethod
    def get_realm_principals(self, realm_name):
        pass

    @abstractmethod
    def set_realm_principals(self, realm_name, principals):
        pass

    @abstractmethod
    def set_realm_principal(self, realm_name, principal_name, principal):
        pass

    @abstractmethod
    def get_realm_principal(self, realm_name, realm_principal):
        pass

    @abstractmethod
    def remove_realm_principal(self, realm_name, principal_name):
        pass


class ISubjectContext(metaclass=ABCMeta):

    @property
    @abstractmethod
    def security_manager(self):
        pass

    @security_manager.setter
    @abstractmethod
    def security_manager(self, securitymanager):
        pass

    @abstractmethod
    def resolve_security_manager(self):
        pass

    @property
    @abstractmethod
    def session_id(self):
        pass

    @session_id.setter
    @abstractmethod
    def session_id(self, sessionid):
        pass

    @property
    @abstractmethod
    def subject(self):
        pass

    @subject.setter
    @abstractmethod
    def subject(self, subject):
        pass

    @property
    @abstractmethod
    def principals(self):
        pass
    
    @principals.setter
    @abstractmethod
    def principals(self, principals):
        pass

    @abstractmethod
    def resolve_principals(self):
        pass

    @property
    @abstractmethod
    def session(self):
        pass

    @session.setter
    @abstractmethod
    def session(self, session):
        pass

    @abstractmethod
    def resolve_session(self):
        pass

    @property
    @abstractmethod
    def authenticated(self):
        pass
    
    @authenticated.setter
    @abstractmethod
    def authenticated(self, authc):
        pass

    @abstractmethod
    def resolve_authenticated(self):
        pass

    @property
    @abstractmethod
    def session_creation_enabled(self):
        pass

    @session_creation_enabled.setter
    @abstractmethod
    def session_creation_enabled(self, enabled):
        pass

    @property
    @abstractmethod
    def authentication_info(self):
        pass

    @authentication_info.setter
    @abstractmethod
    def authentication_info(self, authc_info):
        pass

    @property
    @abstractmethod
    def authentication_token(self):
        pass

    @authentication_token.setter
    @abstractmethod
    def authentication_token(self, authc_token):
        pass

    @property
    @abstractmethod
    def host(self):
        pass

    @host.setter
    @abstractmethod
    def host(self, host):
        pass

    @abstractmethod
    def resolve_host(self):
        pass


class ISubject(metaclass=ABCMeta):

    @property
    @abstractmethod
    def principal(self):
        pass

    @property
    @abstractmethod
    def principals(self):
        pass

    @abstractmethod
    def is_permitted(self, permissions):
        pass

    @abstractmethod
    def is_permitted_all(self, permissions):
        pass

    @abstractmethod
    def check_permission(self, permissions):
        pass

    @abstractmethod
    def has_role(self, role_identifiers):
        pass

    @abstractmethod
    def has_all_roles(self, role_identifiers):
        pass

    @abstractmethod
    def check_role(self, role_identifiers):
        pass

    @abstractmethod
    def login(self, auth_token):
        pass

    @property
    @abstractmethod
    def is_authenticated(self):
        pass

    @property
    @abstractmethod
    def is_remembered(self):
        pass

    @abstractmethod
    def get_session(self, create=None):
        pass

    @abstractmethod
    def logout(self):
        pass

    @abstractmethod
    def execute(self, x_able):
        pass

    @abstractmethod
    def associate_with(self, x_able):
        pass

    @abstractmethod
    def run_as(self, principals):
        pass

    @abstractmethod
    def is_run_as(self):
        pass

    @abstractmethod
    def get_previous_principals(self):
        pass

    @abstractmethod
    def release_run_as(self):
        pass

    class Builder(object):

        def __init__(self,
                     securitymanager=SecurityUtils.get_security_manager()):

            if (securitymanager is None):
                msg = "SecurityManager method argument cannot be null."
                raise InvalidArgumentException(msg)
            
            self.security_manager = securitymanager
            self.subject_context = self.new_subject_context_instance()
            if (self.subject_context is None):
                msg = ("Subject instance returned from" 
                       "'new_subject_context_instance' cannot be null.")
                raise IllegalStateException(msg)
            self.subject_context.security_manager = securitymanager

        def new_subject_context_instance(self):
                return DefaultSubjectContext()

        def session_id(self, session_id):
            if (session_id):
                self.subject_context.session_id = session_id
            return self

        def host(self, host):
            if (host):
                self.subject_context.host = host
            return self
            
        def session(self, session):
            if (session):
                self.subject_context.session = session
            return self

        def principals(self, principals):
            if (principals):
                self.subject_context.principals = principals
            return self

        def session_creation_enabled(self, enabled):
            if (enabled):
                self.subject_context.set_session_creation_enabled = enabled
            return self

        def authenticated(self, authenticated):
            if (authenticated):
                self.subject_context.authenticated = authenticated
            return self

        def context_attribute(self, attribute_key, attribute_value):
            if (not attribute_key):
                msg = "Subject context map key cannot be null."
                raise IllegalArgumentException(msg) 
            elif (not attribute_value):
                self.subject_context.remove(attribute_key)
            else:
                self.subject_context.put(attribute_key, attribute_value)
            return self

        def build_subject(self):
            return self._security_manager.create_subject(self.subject_context)


class ISubjectDAO(metaclass=ABCMeta):

    @abstractmethod
    def save(self, subject):
        pass

    @abstractmethod
    def delete(self, subject):
        pass


class ISubjectFactory(metaclass=ABCMeta):

    def create_subject(self, context):
        pass
