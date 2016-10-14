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

from yosai.core import (
    authc_abcs,
    authz_abcs,
    session_abcs,
)


class RememberMeManager(metaclass=ABCMeta):
    """
    A RememberMeManager is responsible for remembering a Subject's identity
    across that Subject's sessions within the application.
    """

    @abstractmethod
    def get_remembered_identifiers(self, subject_context):
        """
        Based on the specified subject context map being used to build a
        Subject instance, returns any previously remembered identifier for the
        subject for automatic identity association (aka 'Remember Me').

        The context map is usually populated by a Subject.Builder
        implementation.  See the SubjectFactory class constants for
        Yosai's known map keys.

        :param subject_context: the contextual data, usually provided by a
                                Builder implementation, that is being used to
                                construct a Subject instance

        :returns: the remembered identifier or None if none could be acquired
        """
        pass

    @abstractmethod
    def forget_identity(self, subject_context):
        """
        Forgets any remembered identity corresponding to the subject context
        map being used to build a subject instance.

        The context map is usually populated by a Subject.Builder
        implementation.

        See the SubjectFactory class constants for Shiro's known map keys.

        :param subject_context: the contextual data, usually provided by a
                                Subject.Builder implementation, that
                                is being used to construct a Subject instance
        """
        pass

    @abstractmethod
    def on_successful_login(self, subject, authc_token, account):

        """
        Reacts to a successful authentication attempt, typically saving the
        identifier to be retrieved ('remembered') for future system access.

        :param subject: the subject that executed a successful authentication
                        attempt
        :param token:   the authentication token submitted resulting in a
                        successful authentication attempt
        :param account: the account returned as a result of the
                        successful authentication attempt
        """
        pass

    @abstractmethod
    def on_failed_login(self, subject, token, auth_exc):
        """
        Reacts to a failed authentication attempt, typically by forgetting any
        previously remembered identifier for the Subject.

        :param subject: the subject that executed the failed authentication
                        attempt
        :param token:  the authentication token submitted resulting in the
                       failed authentication attempt
        :param auth_exc:  the authentication exception thrown as a result of
                          the failed authentication attempt
        """
        pass

    @abstractmethod
    def on_logout(self, subject):
        """
        Reacts to a Subject logging out of the application, typically by
        forgetting any previously remembered identifier for the Subject.

        :param subject: the subject logging out
        """
        pass


class SecurityManager(metaclass=ABCMeta):
    """
    A SecurityManager executes ALL security operations for ALL Subjects (aka users)
    across a single application.

    The interface itself primarily exists as a convenience - it extends the
    Authenticator, Authorizer, and SessionManager abc-interfaces, thereby
    consolidating these behaviors into a single point of reference.  For most
    Yosai usages, this simplifies configuration and tends to be a more
    convenient approach than referencing Authenticator, Authorizer, and
    SessionManager instances individually.  Instead, one only needs to interact
    with a single SecurityManager instance.

    In addition to the above three interfaces, this interface provides a number
    of methods supporting the behavior of Subject(s). A Subject executes
    authentication, authorization, and session operations for a *single* user,
    and as such can only be managed by A SecurityManager that is aware of all
    three functions.  The three parent interfaces on the other hand do not
    'know' about Subject(s) so as to ensure a clean separation of concerns.

    Usage Note
    ----------
    In actuality, the large majority of application programmers won't interact
    with a SecurityManager very often, if at all.  *Most* application
    programmers only care about security operations for the currently executing
    user, usually obtained from the yosai.subject attribute.

    Framework developers, however, might find working directly with a
    SecurityManager useful.
    """

    @abstractmethod
    def login(self, subject, authc_token):
        """
        Logs in the specified Subject using the given authc_token, returning
        an updated Subject instance that reflects the authenticated state when
        authentication is successful or raising an AuthenticationException if
        authentication is not.

        Note that most application developers should probably not call this
        method directly unless they have a good reason for doing so.  The
        preferred way to log in a Subject is to call subject.login(authc_token)
        after acquiring the Subject from yosai.subject.

        Framework developers, however, may find that directly calling this
        method useful in certain cases.

        :param subject: the subject against which the authentication attempt
                        will occur
        :param authenticationToken: the token representing the Subject's
                                    identifier(s) and credential(s)
        :returns: the subject instance reflecting the authenticated state after
                  a successful attempt
        :raises AuthenticationException: if the login attempt failed
        """
        pass

    @abstractmethod
    def logout(self, subject):
        """
        Logs out the specified Subject from the system.

        Note that most application developers should not call this method
        unless they have a good reason for doing so.  The preferred way to
        logout a Subject is to call Subject.logout(), and not call the
        SecurityManager's logout directly.

        Framework developers, however, may find directly calling this method
        useful in certain cases.

        :param subject: the subject to log out
        """
        pass

    @abstractmethod
    def create_subject(self, authc_token=None, account_id=None, existing_subject=None, subject_context=None):
        """
        Creates a Subject instance that reflects the specified contextual data.

        The context can be anything needed by this SecurityManager to
        construct a Subject instance.  Most Yosai end-users will never call
        this method -- it exists primarily for framework development and to
        support any underlying custom SubjectFactory implementations
        that may be used by the SecurityManager.

        Usage
        ----------
        After calling this method, the returned instance is *not* bound to the
        application for further use.  Callers are expected to know that
        Subject instances have local scope only and any other further use
        beyond the calling method must be managed explicitly.

        :param context: any data needed to direct how the Subject should be
                        constructed
        :returns: the Subject instance that reflects the specified
                  initialization data
        """
        pass
