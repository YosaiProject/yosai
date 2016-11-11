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
import functools
import logging
from contextlib import contextmanager

from yosai.core import (
    SessionStorageEvaluator,
    LazySettings,
    SecurityManagerSettings,
    SerializationManager,
    SessionException,
    ThreadStateManager,
    UnauthenticatedException,
    subject_abcs,
)

logger = logging.getLogger(__name__)


class SubjectContext(subject_abcs.SubjectContext):
    """
    A SubjectContext assists a SecurityManager and SubjectFactory with the
    configuration of new Subject instances.  It employs a number of heuristics
    to acquire data for its attributes, exhausting all available resources at
    its disposal (heuristic resolution of data).

    Most Yosai users will never instantiate a SubjectContext object directly
    but rather will use a SubjectBuilder, which internally uses a SubjectContext,
    to build Subject instances.
    """
    def __init__(self, yosai, security_manager):
        self.account_id = None
        self.authentication_token = None
        self.authenticated = None
        self.identifiers = None
        self.host = None
        self.security_manager = security_manager
        self.yosai = yosai
        self.session = None
        self.session_id = None
        self.session_creation_enabled = True
        self.subject = None

    def resolve_security_manager(self):
        security_manager = self.security_manager
        if (security_manager is None):
            msg = ("No SecurityManager available in subject context.  " +
                   "Falling back to Yosai.security_manager for" +
                   " lookup.")
            logger.debug(msg)

            try:
                security_manager = self.yosai.security_manager
            except AttributeError:
                msg = ("SubjectContext.resolve_security_manager cannot "
                       "obtain security_manager! No SecurityManager available "
                       "via Yosai.  Heuristics exhausted.")
                logger.debug(msg, exc_info=True)

        return security_manager

    def resolve_identifiers(self, session):
        identifiers = self.identifiers

        if not identifiers:
            # account_id is a SimpleIdentifierCollection:
            try:
                identifiers = self.account_id
            except AttributeError:
                pass

        if not identifiers:
            try:
                identifiers = self.subject.identifiers
            except AttributeError:
                pass

        # otherwise, use the session key as the identifier:
        if not identifiers:
            try:
                identifiers = session.get_internal_attribute('identifiers_session_key')
            except AttributeError:
                identifiers = None
        return identifiers

    def resolve_session(self):
        session = self.session
        if session is None:
            try:
                session = self.subject.get_session(False)
            except AttributeError:
                pass
        return session

    def resolve_authenticated(self, session):
        authc = self.authenticated

        if authc is None:
            #  presence of one indicates a successful authentication attempt:
            #  See whethere there is an AccountID
            try:
                authc = self.account_id
            except AttributeError:
                pass
        if authc is None:
            #  fall back to a session check:

            try:
                authc = session.get_internal_attribute('authenticated_session_key')
            except AttributeError:
                authc = None

        return bool(authc)

    def resolve_host(self, session):
        host = self.host
        if host is None:
            # check to see if there is an AuthenticationToken from which to
            # retrieve it:
            try:
                host = self.authentication_token.host
            except AttributeError:
                pass

        if host is None:
            try:
                host = session.host
            except AttributeError:
                pass

        return host

    def __repr__(self):
        return "{0}(subject={1})".format(self.__class__.__name__, self.subject)


class DelegatingSubject(subject_abcs.Subject):
    """
    A ``DelegatingSubject`` delegates method calls to an underlying ``SecurityManager``
    instance for security checks.  It is essentially a ``SecurityManager`` proxy,
    just as ``DelegatingSession`` is to ``NativeSessionManager``.

    This implementation does not maintain security-related state such as roles and
    permissions. Instead, it asks the underlying SecurityManager to check
    authorization. However, Subject-specific state, such as username, is
    saved.  Furthermore, if you are using the WebDelegatingSubject derivative, the
    WebRegistry object is saved.

    A common misconception in using this implementation is that an EIS resource
    (RDBMS, etc) would be 'hit' every time a method is called.  This is not
    necessarily the case and is up to the implementation of the underlying
    SecurityManager instance.  If caching of authorization data is desired
    (to eliminate EIS round trips and therefore improve database performance),
    it is considered much more elegant to let the underlying SecurityManager
    implementation or its delegate components manage caching, not this class.
    A ``SecurityManager`` is considered a business-tier component, where caching
    strategies are better managed.

    Run-As
    --------
    Yosai includes 'Run-As' functionality.  A Run-As scenario is one where
    a user, such as an Admin or Developer, assumes the identity of another
    user so that the Admin/Developer may experience Yosai as the target user
    would (as if the target had logged in).  This helps w/ customer support,
    debugging, etc.

    Concurrency
    -------------
    Shiro uses multithreading.  Yosai's approach to concurrency will be decided
    once CPU and IO statistics have been collected from the synchronous version.
    Until then, I've commented out the ported multithreading-related methods.

    :type authenticated: bool
    """

    def __init__(self,
                 identifiers=None,
                 remembered=False,
                 authenticated=False,
                 host=None,
                 session=None,
                 session_creation_enabled=True,
                 security_manager=None):

        self.security_manager = security_manager
        self.identifiers = identifiers
        self.remembered = remembered
        self.authenticated = authenticated
        self.host = host

        if (session is not None):
            session.stop_session_callback = self.session_stopped
            self.session = session
        else:
            self.session = None

        self.session_creation_enabled = session_creation_enabled
        self.run_as_identifiers_session_key = 'run_as_identifiers_session_key'

    # this is a placeholder for subclasses, which use more elaborate checking:
    def is_session_creation_enabled(self):
        return self.session_creation_enabled

    # new to yosai.core.
    # security_manager is required for certain operations
    def check_security_manager(self):
        if self.security_manager is None:
            msg = "DelegatingSubject requires that a SecurityManager be set"
            raise ValueError(msg)

    @property
    def has_identifiers(self):
        return bool(self.identifiers)

    @property
    def primary_identifier(self):
        try:
            return self.identifiers.primary_identifier
        except:
            return None

    @property
    def identifiers(self):
        # expecting a List of IdentifierCollection objects:
        run_as_identifiers = self.get_run_as_identifiers_stack()

        if (not run_as_identifiers):
            return self._identifiers
        else:
            return run_as_identifiers[-1]

    @identifiers.setter
    def identifiers(self, identifiers):
        """
        :type identifiers:  subject_abcs.IdentifierCollection
        """
        if (isinstance(identifiers, subject_abcs.IdentifierCollection) or
                identifiers is None):
            self._identifiers = identifiers
        else:
            raise ValueError('must use IdentifierCollection')

    def is_permitted(self, permission_s):
        """
        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the authz_abcs.Permission and a
                  Boolean indicating whether the permission is granted
        """
        if self.authorized:
            self.check_security_manager()
            return (self.security_manager.is_permitted(
                    self.identifiers, permission_s))

        msg = 'Cannot check permission when user isn\'t authenticated nor remembered'
        raise ValueError(msg)

    # refactored is_permitted_all:
    def is_permitted_collective(self, permission_s, logical_operator=all):
        """
        :param permission_s:  a List of authz_abcs.Permission objects

        :param logical_operator:  indicates whether *all* or at least one
                                  permission check is true, *any*
        :type: any OR all (functions from python stdlib)

        :returns: a Boolean
        """
        sm = self.security_manager
        if self.authorized:
            return sm.is_permitted_collective(self.identifiers,
                                              permission_s,
                                              logical_operator)

        msg = 'Cannot check permission when user isn\'t authenticated nor remembered'
        raise ValueError(msg)

    def assert_authz_check_possible(self):
        if not self.identifiers:
            msg = (
                "This subject is anonymous - it does not have any " +
                "identification and authorization operations " +
                "required an identity to check against.  A Subject " +
                "instance will acquire these identifying identifier " +
                "automatically after a successful login is performed be " +
                "executing " + self.__class__.__name__ +
                ".login(Account) or when 'Remember Me' " +
                "functionality is enabled by the SecurityManager.  " +
                "This exception can also occur when a previously " +
                "logged-in Subject has logged out which makes it " +
                "anonymous again.  Because an identity is currently not " +
                "known due to any of these conditions, authorization is " +
                "denied.")
            raise UnauthenticatedException(msg)

    def check_permission(self, permission_s, logical_operator=all):
        """
        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of authz_abcs.Permission objects or Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python stdlib)

        :raises UnauthorizedException: if any permission is unauthorized
        """
        self.assert_authz_check_possible()
        if self.authorized:
            self.security_manager.check_permission(self.identifiers,
                                                   permission_s,
                                                   logical_operator)
        else:
            msg = 'Cannot check permission when user isn\'t authenticated nor remembered'
            raise ValueError(msg)

    def has_role(self, role_s):
        """
        :param role_s: 1..N role identifiers (strings)
        :type role_s:  Set of Strings

        :returns: a set of tuple(s), containing the role and a Boolean
                  indicating whether the user is a member of the Role
        """
        if self.authorized:
            return self.security_manager.has_role(self.identifiers, role_s)
        msg = 'Cannot check permission when identifiers aren\'t set!'
        raise ValueError(msg)

    # refactored has_all_roles:
    def has_role_collective(self, role_s, logical_operator=all):
        """
        :param role_s: 1..N role identifier
        :type role_s:  a Set of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python standard library)

        :returns: a Boolean
        """
        if self.authorized:
            return self.security_manager.has_role_collective(self.identifiers,
                                                              role_s,
                                                              logical_operator)
        else:
            msg = 'Cannot check permission when identifiers aren\'t set!'
            raise ValueError(msg)

    def check_role(self, role_ids, logical_operator=all):
        """
        :param role_ids:  1 or more RoleIds
        :type role_ids: a Set of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python stdlib)

        :raises UnauthorizedException: if Subject not assigned to all roles
        """
        if self.authorized:
            self.security_manager.check_role(self.identifiers,
                                             role_ids,
                                             logical_operator)
        else:
            msg = 'Cannot check permission when identifiers aren\'t set!'
            raise ValueError(msg)

    def login(self, authc_token):
        """
        :type authc_token: authc_abcs.AuthenticationToken

        authc_token's password is cleartext that is stored as a bytearray.
        The authc_token password is cleared in memory, within the authc_token,
        when authentication is successful.
        """
        self.clear_run_as_identities_internal()
        # login raises an AuthenticationException if it fails to authenticate:
        subject = self.security_manager.login(subject=self,
                                              authc_token=authc_token)
        identifiers = None
        host = None
        if isinstance(subject, DelegatingSubject):
            # directly reference the attributes in case there are assumed
            # identities (Run-As) -- we don't want to lose the 'real' identifiers
            identifiers = subject._identifiers
            host = subject.host
        else:
            identifiers = subject.identifiers  # use the property accessor

        if not identifiers:
            msg = ("Identifiers returned from security_manager.login(authc_token" +
                   ") returned None or empty value. This value must be" +
                   " non-None and populated with one or more elements.")
            raise ValueError(msg)

        self._identifiers = identifiers
        self.authenticated = True

        if not host:
            try:
                host = authc_token.host
            except AttributeError:  # likely not using a HostAuthenticationToken
                host = None
        self.host = host

        session = subject.get_session(False)
        if session:
            session.stop_session_callback = self.session_stopped
            self.session = session
        else:
            self.session = None

    @property
    def authorized(self):
        return self.remembered or self.authenticated

    def get_session(self, create=True):
        """
        :type create:  bool
        """
        msg = ("{0} attempting to get session; create = {1}; \'session is None\' ="
               "{2} ; \'session has id\' = {3}".
               format(self.__class__.__name__, create, (self.session is None), str(
                      self.session is not None and bool(self.session.session_id))))
        logger.debug(msg)

        if self.session and not create:  # touching a new session is redundant
            self.session.touch()  # this is used to reset the idle timer (new to yosai)
            return self.session

        if (not self.session and create):
            if (not self.is_session_creation_enabled()):
                msg = ("Session creation is disabled for the current subject. "
                       "This exception indicates that there is "
                       "either a programming error (using a session when "
                       "it should never be used) or that Yosai's "
                       "configuration needs to be adjusted to allow "
                       "Sessions to be created for the current Subject.")
                raise ValueError(msg)

            msg = ("Starting session for host ", str(self.host))
            logger.debug(msg)

            session_context = self.create_session_context()
            session = self.security_manager.start(session_context)
            session.stop_session_callback = self.session_stopped
            self.session = session

        return self.session

    def create_session_context(self):
        session_context = {}
        session_context['host'] = self.host
        return session_context

    def clear_run_as_identities_internal(self):
        try:
            self.clear_run_as_identities()
        except SessionException:
            msg = ("clearrunasidentitiesinternal: Encountered session "
                   "exception trying to clear 'runAs' identities during "
                   "logout.  This can generally safely be ignored.")
            logger.debug(msg, exc_info=True)

    def logout(self):
        try:
            self.clear_run_as_identities_internal()
            self.security_manager.logout(self)
        finally:
            self.session = None
            self._identifiers = None
            self.authenticated = False

    def session_stopped(self):
        self.session = None

    def run_as(self, identifiers):
        """
        :type identifiers:  subject_abcs.IdentifierCollection
        """
        if (not self.has_identifiers):
            msg = ("This subject does not yet have an identity.  Assuming the "
                   "identity of another Subject is only allowed for Subjects "
                   "with an existing identity.  Try logging this subject in "
                   "first, or using the DelegatingSubject.Builder "
                   "to build ad hoc Subject instances with identities as "
                   "necessary.")
            raise ValueError(msg)
        self.push_identity(identifiers)

    @property
    def is_run_as(self):
        return bool(self.get_run_as_identifiers_stack())

    def get_previous_identifiers(self):
        """
        :returns: SimpleIdentifierCollection
        """
        previous_identifiers = None
        stack = self.get_run_as_identifiers_stack()  # TBD:  must confirm logic

        if stack:
            if (len(stack) == 1):
                previous_identifiers = self.identifiers
            else:
                # always get the one behind the current
                previous_identifiers = stack[1]
        return previous_identifiers

    def release_run_as(self):
        return self.pop_identity()

    def get_run_as_identifiers_stack(self):
        """
        :returns: an IdentifierCollection
        """
        session = self.get_session(False)

        try:
            return session.get_internal_attribute(self.run_as_identifiers_session_key)
        except AttributeError:
            return None

    def clear_run_as_identities(self):
        session = self.get_session(False)
        if (session is not None):
            session.remove_internal_attribute(
                self.run_as_identifiers_session_key)

    def push_identity(self, identifiers):
        """
        :type identifiers: subject_abcs.IdentifierCollection
        """
        if (not identifiers):
            msg = ("Specified Subject identifiers cannot be None or empty "
                   "for 'run as' functionality.")
            raise ValueError(msg)

        stack = self.get_run_as_identifiers_stack()

        if (not stack):
            stack = []

        stack.append(identifiers)
        session = self.get_session()
        session.set_internal_attribute(self.run_as_identifiers_session_key, stack)

    def pop_identity(self):
        """
        :returns: SimpleIdentifierCollection
        """
        popped = None
        stack = self.get_run_as_identifiers_stack()

        if (stack):
            popped = stack.pop()
            if (stack):
                # persist the changed stack to the session
                session = self.get_session()
                session.set_internal_attribute(self.run_as_identifiers_session_key, stack)

            else:
                # stack is empty, remove it from the session:
                self.clear_run_as_identities()
        return popped

    def __repr__(self):
        return "{0}(_identifiers={1}, authenticated={2})".\
            format(self.__class__.__name__, self._identifiers, self.authenticated)


# migrated from /mgt:
class SubjectStore:

    """
    This is known as /mgt/SubjectDAO in Shiro.

    This is the default ``SubjectStore`` implementation for storing ``Subject`` state.
    The default behavior is to save ``Subject`` state into the Subject's ``Session``.
    Note that the storing of the ``Subject`` state into the ``Session`` is considered
    a default behavior of Yosai but this behavior can be disabled -- see below.

    Once a Subject's state is stored in a Session, a ``Subject`` instance can be
    re-created at a later time by first acquiring the Subject's session.  A
    Subject's session is typically acquired through interaction with a
    SessionManager, referencing a ``Session`` by session_id or
    session_key, and then instantiating/building a Subject instance using
    Session attributes.

    Controlling How Sessions are Used
    ---------------------------------
    Whether a Subject's ``Session`` is used to persist the Subject's state is
    controlled on a per-Subject basis.

    Disabling Session Persistence Entirely
    --------------------------------------
    You can disable Session usage for Subject state entirely by setting
    the Subject Store's session_storage_enabled attribute:

        session_store.session_storage_evaluator.session_storage_enabled = False

    or, for example, when initializing the SecurityManager:::

        SecurityManager.subject_store.session_storage_evaluator.session_storage_enabled = False

    However, Note: ONLY do this if your application is 100% stateless and you
    *DO NOT* need subjects to be remembered across remote invocations, or in a web
    environment across HTTP requests.

    Supporting Both Stateful and Stateless Subject paradigms
    --------------------------------------------------------
    Perhaps your application needs to support a hybrid approach of both
    stateful and stateless Subjects:

        - Stateful: Stateful subjects might represent web end-users that need
          their identity and authentication state to be remembered from page to
          page.

        - Stateless: Stateless subjects might represent API clients (e.g. REST
          clients) that authenticate on every request, and therefore don't need
          authentication state to be stored across requests in a session.
    """
    def __init__(self, ss_evaluator=SessionStorageEvaluator()):
        self.session_storage_evaluator = ss_evaluator
        self.dsc_isk = 'identifiers_session_key'
        self.dsc_ask = 'authenticated_session_key'

    def is_session_storage_enabled(self, subject):
        """
        :type subject:  subject_abcs.Subject
        Determines whether the subject's ``Session`` will be used to persist
        subject state.  This default implementation merely delegates to the
        internal ``SessionStorageEvaluator``.
        """
        return self.session_storage_evaluator.\
            is_session_storage_enabled(subject)

    def save(self, subject):
        """
        Saves the subject's state to the subject's ``Session`` only
        if session storage is enabled for the subject.  If session storage is
        not enabled for the specific Subject, this method does nothing.

        In either case, the argument Subject is returned directly (a new
        ``Subject`` instance is not created).

        :param subject: the Subject instance for which its state will be
                        created or updated
        :type subject:  subject_abcs.Subject

        :returns: the same Subject passed in (a new Subject instance is
                  not created).
        """
        if (self.is_session_storage_enabled(subject)):
            self.merge_identity(subject)
        else:
            msg = ("Session storage of subject state for Subject [{0}] has "
                   "been disabled: identity and authentication state are "
                   "expected to be initialized on every request or "
                   "invocation.".format(subject))
            logger.debug(msg)

        return subject

    # yosai consolidates merge_principals and merge_authentication_state
    def merge_identity(self, subject):
        """
        Merges the Subject's identifying attributes (principals) and authc status
        into the Subject's session

        :type subject:  subject_abcs.Subject
        """
        current_identifiers = None

        if subject.is_run_as:
            # avoid the other steps of attribute access when referencing by
            # property by referencing the underlying attribute directly:
            current_identifiers = subject._identifiers

        if not current_identifiers:
            # if direct attribute access did not work, use the property-
            # decorated attribute access method:
            current_identifiers = subject.identifiers

        session = subject.get_session(False)

        if not session:
            to_set = []

            if current_identifiers or subject.authenticated:
                session = subject.get_session()

                to_set.append([self.dsc_isk, current_identifiers])
                to_set.append([self.dsc_ask, True])

                msg = ('merge_identity _DID NOT_ find a session for current subject '
                       'and so created a new one (session_id: {0}). Now merging '
                       'internal attributes: {1}'.format(session.session_id, to_set))
                logger.debug(msg)
                session.set_internal_attributes(to_set)
        else:
            self.merge_identity_with_session(current_identifiers, subject, session)

    def merge_identity_with_session(self, current_identifiers, subject, session):
            msg = 'merge_identity _DID_ find a session for current subject.'
            logger.debug(msg)

            to_remove = []
            to_set = []
            internal_attributes = session.get_internal_attributes()

            existing_identifiers = internal_attributes.get(self.dsc_isk)

            if (not current_identifiers):
                if (existing_identifiers):
                    to_remove.append(self.dsc_isk)
                # otherwise both are null or empty - no need to update session
            else:
                if not (current_identifiers == existing_identifiers):
                    to_set.append([self.dsc_isk, current_identifiers])
                # otherwise they're the same - no need to update the session

            existing_authc = internal_attributes.get(self.dsc_ask)

            if (subject.authenticated):
                if (existing_authc is None):  # either doesnt exist or set None
                    to_set.append([self.dsc_ask, True])
                # otherwise authc state matches - no need to update the session
            else:
                if (existing_authc is not None):
                    # existing doesn't match the current state - remove it:
                    to_remove.append(self.dsc_ask)
                # otherwise not in the session and not authenticated and
                # no need to update the session

            if to_set:
                session.set_internal_attributes(to_set)

            if to_remove:
                session.remove_internal_attributes(to_remove)

    def delete(self, subject):
        """
        :type subject:  subject_abcs.Subject
        """
        session = subject.get_session(False)
        if (session):
            session.remove_internal_attribute(self.dsc_ask)
            session.remove_internal_attribute(self.dsc_isk)


# moved from its own yosai module so as to avoid circular importing:
class Yosai:

    def __init__(self, env_var=None, file_path=None, session_attributes=None):
        """
        :type session_attributes: tuple
        """
        # you can configure LazySettings in one of two ways: env or file_path
        self.settings = LazySettings(env_var=env_var, file_path=file_path)
        self.security_manager = \
            self.generate_security_manager(self.settings, session_attributes)

    def generate_security_manager(self, settings, session_attributes):
        # don't forget to pass default_cipher_key into the WebSecurityManager
        mgr_builder = SecurityManagerCreator()
        return mgr_builder.create_manager(self, settings, session_attributes)

    def _get_subject(self):
        """
        Returns the currently accessible Subject available to the calling code
        depending on runtime environment.

        :returns: the Subject currently accessible to the calling code
        """
        subject_context = SubjectContext(yosai=self,
                                                security_manager=self.security_manager)
        subject = self.security_manager.create_subject(subject_context=subject_context)
        global_subject_context.stack.append(subject)
        return subject

    @staticmethod
    @contextmanager
    def context(yosai):
        global_yosai_context.stack.append(yosai)

        try:
            yield
        except:
            raise
        finally:
            global_yosai_context.stack = []
            global_subject_context.stack = []

    @staticmethod
    def get_current_subject():
        try:
            subject = global_subject_context.stack[-1]
            msg = ('A subject instance DOES exist in the global context. '
                   'Touching and then returning it.')
            logger.debug(msg)
            subject.get_session().touch()
            return subject

        except IndexError:
            msg = 'A subject instance _DOES NOT_ exist in the global context.  Creating one.'
            logger.debug(msg)

            subject = Yosai.get_current_yosai()._get_subject()

            global_subject_context.stack.append(subject)
            return subject

    @staticmethod
    def get_current_yosai():
        try:
            return global_yosai_context.stack[-1]
        except IndexError:
            msg = 'A yosai instance does not exist in the global context.'
            raise IndexError(msg)

    @staticmethod
    def requires_authentication(fn):
        """
        Requires that the calling Subject be authenticated before allowing access.

        :raises UnauthenticatedException: indicating that the decorated method is
                                          not allowed to be executed because the
                                          Subject failed to authenticate
        """

        @functools.wraps(fn)
        def wrap(*args, **kwargs):
            subject = Yosai.get_current_subject()

            if not subject.authenticated:
                msg = "The current Subject is not authenticated.  ACCESS DENIED."
                raise UnauthenticatedException(msg)

            return fn(*args, **kwargs)
        return wrap

    @staticmethod
    def requires_user(fn):
        """
        Requires that the calling Subject be *either* authenticated *or* remembered
        via RememberMe services before allowing access.

        This method essentially ensures that subject.identifiers IS NOT None

        :raises UnauthenticatedException: indicating that the decorated method is
                                          not allowed to be executed because the
                                          Subject attempted to perform a user-only
                                          operation
        """
        @functools.wraps(fn)
        def wrap(*args, **kwargs):

            subject = Yosai.get_current_subject()

            if subject.identifiers is None:
                msg = ("Attempting to perform a user-only operation.  The "
                       "current Subject is NOT a user (they haven't been "
                       "authenticated or remembered from a previous login). "
                       "ACCESS DENIED.")
                print('\n\n', msg)
                raise UnauthenticatedException(msg)

            return fn(*args, **kwargs)
        return wrap

    @staticmethod
    def requires_guest(fn):
        """
        Requires that the calling Subject be NOT (yet) recognized in the system as
        a user -- the Subject is not yet authenticated nor remembered through
        RememberMe services.

        This method essentially ensures that subject.identifiers IS None

        :raises UnauthenticatedException: indicating that the decorated method is
                                          not allowed to be executed because the
                                          Subject attempted to perform a guest-only
                                          operation
        """
        @functools.wraps(fn)
        def wrap(*args, **kwargs):

            subject = Yosai.get_current_subject()

            if subject.identifiers is not None:
                msg = ("Attempting to perform a guest-only operation.  The "
                       "current Subject is NOT a guest (they have either been "
                       "authenticated or remembered from a previous login). "
                       "ACCESS DENIED.")
                raise UnauthenticatedException(msg)

            return fn(*args, **kwargs)
        return wrap

    @staticmethod
    def requires_permission(permission_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the permission_s specified and the logical operation
        upon them.

        :param permission_s:   the permission(s) required
        :type permission_s:  a List of Strings or List of Permission instances

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          permission

        Elaborate Example:
            requires_permission(
                permission_s=['domain1:action1,action2', 'domain2:action1'],
                logical_operator=any)

        Basic Example:
            requires_permission(['domain1:action1,action2'])
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):

                subject = Yosai.get_current_subject()
                subject.check_permission(permission_s, logical_operator)

                return fn(*args, **kwargs)
            return inner_wrap
        return outer_wrap

    @staticmethod
    def requires_dynamic_permission(permission_s, logical_operator=all):
        """
        This method requires that the calling Subject be authorized to the extent
        that is required to satisfy the dynamic permission_s specified and the logical
        operation upon them.  Unlike ``requires_permission``, which uses statically
        defined permissions, this function derives a permission from arguments
        specified at declaration.

        Dynamic permissioning requires that the dynamic arguments be keyword
        arguments of the decorated method.

        :param permission_s:   the permission(s) required
        :type permission_s:  a List of Strings or List of Permission instances

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          permission

        Elaborate Example:
            requires_permission(
                permission_s=['{kwarg1.domainid}:action1,action2',
                               '{kwarg2.domainid}:action1'],
                logical_operator=any)

        Basic Example:
            requires_permission(['{kwarg.domainid}:action1,action2'])
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):
                newperms = [perm.format(**kwargs) for perm in permission_s]

                subject = Yosai.get_current_subject()

                subject.check_permission(newperms, logical_operator)

                return fn(*args, **kwargs)
            return inner_wrap
        return outer_wrap

    @staticmethod
    def requires_role(role_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the role_s specified and the logical operation
        upon them.

        :param role_s:   a collection of the role(s) required, specified by
                           identifiers (such as a role name)
        :type role_s:  a List of Strings

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        :raises  AuthorizationException:  if the user does not have sufficient
                                          role membership

        Elaborate Example:
            requires_role(role_s=['sysadmin', 'developer'], logical_operator=any)

        Basic Example:
            requires_role('physician')
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):

                subject = Yosai.get_current_subject()

                subject.check_role(role_s, logical_operator)

                return fn(*args, **kwargs)
            return inner_wrap
        return outer_wrap

    def __eq__(self, other):
        return self._security_manager == other._security_manager


# new to yosai
class SecurityManagerCreator:

    def _init_realms(self, settings, realms):
        try:
            return tuple(realm(account_store=account_store(settings=settings), **verifiers)
                         for realm, account_store, verifiers in realms)

        except (AttributeError, TypeError) as exc:
            msg = 'Failed to initialize realms during SecurityManager Setup'
            raise exc.__class__(msg)

    def _init_cache_handler(self, settings, cache_handler, serialization_manager):
        try:
            return cache_handler(settings=settings,
                                 serialization_manager=serialization_manager)
        except TypeError:
            return None

    def _init_session_attributes(self, session_attributes, attributes):
        if session_attributes:
            return session_attributes

        try:
            sas = attributes['session_attributes']
            if sas:
                return sas

        except (TypeError, KeyError):
            return None

    def create_manager(self, yosai, settings, session_attributes):
        """
        Order of execution matters.  The sac must be set before the cache_handler is
        instantiated so that the cache_handler's serialization manager instance
        registers the sac.
        """
        mgr_settings = SecurityManagerSettings(settings)
        attributes = mgr_settings.attributes

        realms = self._init_realms(settings, attributes['realms'])

        session_attributes = self._init_session_attributes(session_attributes, attributes)

        serialization_manager =\
            SerializationManager(session_attributes,
                                 serializer_scheme=attributes['serializer'])

        # the cache_handler doesn't initialize a cache_realm until it gets
        # a serialization manager, which is assigned within the SecurityManager
        cache_handler = self._init_cache_handler(settings,
                                                 attributes['cache_handler'],
                                                 serialization_manager)

        manager = mgr_settings.security_manager(yosai,
                                                settings,
                                                realms=realms,
                                                cache_handler=cache_handler,
                                                serialization_manager=serialization_manager)

        return manager

# Set Global State Managers
global_yosai_context = ThreadStateManager()
global_subject_context = ThreadStateManager()
