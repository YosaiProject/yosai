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
from yosai import (
    InvalidArgumentException,
    IllegalArgumentException,
    IllegalStateException,
)


class IdentifierCollection(metaclass=ABCMeta):

    @property
    @abstractmethod
    def primary_identifier(self):
        pass

    @abstractmethod
    def by_type(self, identifier_type):
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

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)


class MutableIdentifierCollection(IdentifierCollection):

    @abstractmethod
    def add(self, identifier_s, realm_name, identifier_collection):
        pass

    @abstractmethod
    def clear(self):
        pass


class IdentifierMap(IdentifierCollection):

    @abstractmethod
    def get_realm_identifier_s(self, realm_name):
        pass

    @abstractmethod
    def set_realm_identifier_s(self, realm_name, identifier_s):
        pass

    @abstractmethod
    def set_realm_identifier(self, realm_name, identifier_name, identifier):
        pass

    @abstractmethod
    def get_realm_identifier(self, realm_name, realm_identifier):
        pass

    @abstractmethod
    def remove_realm_identifier(self, realm_name, identifier_name):
        pass


class SubjectContext(metaclass=ABCMeta):

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
    def identifier_s(self):
        pass

    @identifier_s.setter
    @abstractmethod
    def identifier_s(self, identifier_s):
        pass

    @abstractmethod
    def resolve_identifier_s(self):
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
    def account(self):
        pass

    @account.setter
    @abstractmethod
    def account(self, account):
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

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)



class Subject(metaclass=ABCMeta):

    @property
    @abstractmethod
    def identifier(self):
        pass

    @property
    @abstractmethod
    def identifier_s(self):
        pass

    @abstractmethod
    def is_permitted(self, permissions):
        pass

    @abstractmethod
    def is_permitted_collective(self, permissions, logical_operator):
        pass

    @abstractmethod
    def check_permission(self, permissions, logical_operator):
        pass

    @abstractmethod
    def has_role(self, role_identifier_s):
        pass

    @abstractmethod
    def has_role_collective(self, role_identifier_s, logical_operator):
        pass

    @abstractmethod
    def check_role(self, role_identifier_s, logical_operator):
        pass

    @abstractmethod
    def login(self, auth_token):
        pass

    @property
    @abstractmethod
    def authenticated(self):
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

    # TBD:  commenting out until concurrency is decided:
    # @abstractmethod
    # def execute(self, x_able):
    #    pass

    # TBD:  commenting out until concurrency is decided:
    # @abstractmethod
    # def associate_with(self, x_able):
    #    pass

    @abstractmethod
    def run_as(self, identifier_s):
        pass

    @abstractmethod
    def is_run_as(self):
        pass

    @abstractmethod
    def get_previous_identifier_s(self):
        pass

    @abstractmethod
    def release_run_as(self):
        pass

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)

# moved from /mgt:
class SubjectStore(metaclass=ABCMeta):
    """
    A SubjectStore is responsible for persisting a Subject instance's internal
    state such that the Subject instance can be recreated at a later time if
    necessary.

    Shiro's default SecurityManager implementations typically use a SubjectStore
    in conjunction with a SubjectFactory after the SubjectFactory creates a
    Subject instance, the SubjectStore is used to persist that subject's state
    such that it can be accessed later if necessary.

    Usage
    --------
    Note that this component is used by SecurityManager implementations to
    manage Subject state persistence.  It does *not* make Subject instances
    accessible to the application (e.g. via security_utils.subject).
    """
    @abstractmethod
    def save(self, subject):
        """
        Persists the specified Subject's state for later access.  If there is
        a no existing state persisted, this persists it if possible (i.e. a
        create operation).  If there is existing state for the specified
        Subject, this method updates the existing state to reflect the
        current state (i.e. an update operation).

        :param subject: the Subject instance for which its state will be
                        created or updated
        :returns: the Subject instance to use after persistence is complete
                  - this can be the same as the method argument if the
                    underlying implementation does not need to make any Subject
                    changes
        """
        pass

    @abstractmethod
    def delete(self, subject):
        """
        Removes any persisted state for the specified Subject instance.
        This is a delete operation such that the Subject's state will not be
        accessible at a later time.

        :param subject: the Subject instance for which any persistent state
                        should be deleted
        """
        pass


# moved from /mgt:
class SubjectFactory(metaclass=ABCMeta):
    """
    A SubjectFactory is responsible for constructing Subject instances as
    needed
    """

    def create_subject(self, context):
        """
        Creates a new Subject instance reflecting the state of the specified
        contextual data.  The data would be anything required to required to
        construct a Subject instance and its contents can vary based on
        environment.

        Any data supported by Shiro core will be accessible by one of the
        SubjectContext(s) accessor properties or methods.  All other data is
        available as map attributes.

        :param context: the contextual data to be used by the implementation
                        to construct an appropriate Subject instance
        :returns: a Subject instance created based on the specified context
        """
        pass
