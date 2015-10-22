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
import collections

# Concurrency is TBD:  Shiro uses multithreading whereas Yosai...
# from concurrency import (Callable, Runnable, SubjectCallable, SubjectRunnable,
#                         Thread)

from yosai import (
    MapContext,
    DefaultSessionContext,
    DefaultSessionStorageEvaluator,
    DisabledSessionException,
    ExecutionException,
    IdentifiersNotSetException,
    IllegalArgumentException,
    IllegalStateException,
    InvalidSessionException,
    LogManager,
    ProxiedSession,
    SecurityManagerNotSetException,
    SessionException,
    UnauthenticatedException,
    UnavailableSecurityManagerException,
    UnsupportedOperationException,
    concurrency_abcs,
    mgt_abcs,
    session_abcs,
    subject_abcs,
)
import copy


class DefaultSubjectContext(MapContext, subject_abcs.SubjectContext):
    """
    Yosai notes:  Shiro uses the getTypedValue method to validate objects
                  as it obtains them from the MapContext.  I've decided that
                  this checking is unecessary overhead in Python and to
                  instead *assume* that objects are mapped correctly within
                  the MapContext.  Exceptions will raise further down the
                  call stack should a mapping be incorrect.
    """
    def __init__(self, security_utils, context={}):
        """
        :param context: context's schema of reserved attributes must be named
                        according to the property names below
        """

        self.security_utils = security_utils

        # to set reserved attributes correctly (using the property setters),
        # context must be set accordingly:
        super().__init__(context)
        for key, value in self.context.items():
            if hasattr(self, key):
                setattr(self, key, value)  # uses the property setters
                self.context.pop(key)

    # new to yosai is this helper method:
    def get_key(self, key):
        return "{0}.{1}".format(self.__class__.__name__, key)

    @property
    def security_manager(self):
        return self.get(self.get_key('SECURITY_MANAGER'))

    @security_manager.setter
    def security_manager(self, securitymanager):
        self.none_safe_put(self.get_key('SECURITY_MANAGER'), securitymanager)

    def resolve_security_manager(self):
        security_manager = self.security_manager
        if (security_manager is None):
            msg = ("No SecurityManager available in subject context map.  " +
                   "Falling back to SecurityUtils.security_manager for" +
                   " lookup.")
            print(msg)
            #  log debug here

            try:
                security_manager = self.security_utils.security_manager
            except UnavailableSecurityManagerException as ex:
                msg = ("DefaultSubjectContext.resolve_security_manager cannot "
                       "obtain security_manager! No SecurityManager available "
                       "via SecurityUtils.  Heuristics exhausted.", ex)
                print(msg)
                # log debug here, including exc_info=ex

        return security_manager

    @property
    def session_id(self):
        return self.get(self.get_key('SESSION_ID'))

    @session_id.setter
    def session_id(self, session_id):
        self.none_safe_put(self.get_key('SESSION_ID'), session_id)

    @property
    def subject(self):
        return self.get(self.get_key('SUBJECT'))

    @subject.setter
    def subject(self, subject):
            self.none_safe_put(self.get_key('SUBJECT'), subject)

    @property
    def identifiers(self):
        return self.get(self.get_key('IDENTIFIERS'))

    @identifiers.setter
    def identifiers(self, identifiers):
        self.none_safe_put(self.get_key('IDENTIFIERS'), identifiers)

    def resolve_identifiers(self):
        identifiers = self.identifiers

        if not identifiers:
            # note that the sequence matters:
            for entity in [self.account, self.subject]:
                try:
                    identifiers = entity.identifiers
                except AttributeError:
                    continue
                else:
                    break
        # otherwise, use the session key as the identifier:
        if not identifiers:
            session = self.resolve_session()
            try:
                identifiers = session.get_attribute(
                    self.get_key('IDENTIFIERS_SESSION_KEY'))
            except AttributeError:
                pass

        return identifiers

    @property
    def session(self):
        return self.get(self.get_key('SESSION'))

    @session.setter
    def session(self, session):
        self.none_safe_put(self.get_key('SESSION'), session)

    def resolve_session(self):
        session = self.session
        if session is None:
            try:
                session = self.subject.get_session(False)
            except AttributeError:
                pass
        return self.session

    # yosai renamed so to match property accessor with mutator:
    @property
    def session_creation_enabled(self):
        val = self.get(self.get_key('SESSION_CREATION_ENABLED'))
        return (val is None or val)

    @session_creation_enabled.setter
    def session_creation_enabled(self, enabled):
        self.none_safe_put(
            self.get_key('SESSION_CREATION_ENABLED'), enabled)

    # yosai renamed from is_authenticated:
    @property
    def authenticated(self):
        """
        :returns: Boolean
        """
        authc = self.get(self.get_key('AUTHENTICATED'))
        return authc

    @authenticated.setter
    def authenticated(self, authc):
        self.put(self.get_key('AUTHENTICATED'), authc)

    def resolve_authenticated(self):
        authc = self.authenticated
        if authc is None:
            #  presence of one indicates a successful authentication attempt:
            #  See whethere there is an Account object.  If one exists, the very
            authc = self.account
        if authc is None:
            #  fall back to a session check:
            session = self.resolve_session()
            if (session is not None):
                authc = session.get_attribute(
                    self.get_key('AUTHENTICATED_SESSION_KEY'))

        return bool(authc)

    # yosai renamed AuthenticationInfo to Account:
    @property
    def account(self):
        return self.get(self.get_key('ACCOUNT'))

    @account.setter
    def account(self, account):
        self.none_safe_put(self.get_key('ACCOUNT'), account)

    @property
    def authentication_token(self):
        return self.get(self.get_key('AUTHENTICATION_TOKEN'))

    @authentication_token.setter
    def authentication_token(self, token):
        self.none_safe_put(self.get_key('AUTHENTICATION_TOKEN'), token)

    @property
    def host(self):
        return self.get(self.get_key('HOST'))

    @host.setter
    def host(self, host):
        self.put(self.get_key('HOST'), host)

    def resolve_host(self):
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
                session = self.resolve_session()
                host = session.host
            except AttributeError:
                pass

        return host


class DelegatingSubject(subject_abcs.Subject):
    """
    Implementation of the Subject interface that delegates method calls to an
    underlying SecurityManager instance for security checks.  It is essentially
    a SecurityManager proxy.

    This implementation does not maintain state such as roles and permissions
    (only Subject identifiers, such as usernames or user primary keys) for
    better performance in a stateless architecture.  It instead asks the
    underlying SecurityManager every time to perform the authorization check.

    A common misconception in using this implementation is that an EIS resource
    (RDBMS, etc) would be 'hit' every time a method is called.  This is not
    necessarily the case and is up to the implementation of the underlying
    SecurityManager instance.  If caching of authorization data is desired
    (to eliminate EIS round trips and therefore improve database performance),
    it is considered much more elegant to let the underlying SecurityManager
    implementation or its delegate components manage caching, not this class.
    A SecurityManager is considered a business-tier component, where caching
    strategies are better managed.

    Applications from large and clustered to simple and local all benefit from
    stateless architectures.  This implementation plays a part in the stateless
    programming paradigm and should be used whenever possible.

    Run-As
    --------
    Yosai includes 'Run-As' functionality.  A Run-As scenario is one where
    a user, such as an Admin or Developer, assumes the identity of another
    user so that the Admin/Developer may experience Yosai as the target user
    would (as if the target had logged in).  This helps w/ customer support or
    debugging, etc.

    Concurrency
    -------------
    Shiro uses multithreading.  Yosai's approach to concurrency will be decided
    once CPU and IO statistics have been collected from the synchronous version.
    Until then, I've commented out the ported multithreading-related methods.
    """

    def __init__(self,
                 identifiers=None,
                 authenticated=False,
                 host=None,
                 session=None,
                 session_creation_enabled=True,
                 security_manager=None):

        self.security_manager = security_manager
        self.identifiers = identifiers
        self.authenticated = authenticated
        self.host = host

        if (session is not None):
            self.session = self.decorate(session)  # shiro's decorate
        else:
            self.session = None

        self.session_creation_enabled = session_creation_enabled
        self.run_as_identifiers_session_key = (
            self.__class__.__name__ + ".RUN_AS_IDENTIFIERS_SESSION_KEY")

    def decorate(self, session):
        if isinstance(session, session_abcs.Session):
            return DelegatingSubject.StoppingAwareProxiedSession(session, self)
        return None

    @property
    def security_manager(self):
        if not hasattr(self, '_security_manager'):
            self._security_manager = None
        return self._security_manager

    @security_manager.setter
    def security_manager(self, security_manager):
        if (isinstance(security_manager, mgt_abcs.SecurityManager) or
                security_manager is None):
            self._security_manager = security_manager
        else:
            raise IllegalArgumentException('must use SecurityManager')

    # new to yosai:
    # security_manager is required for certain operations
    def check_security_manager(self):
        if self.security_manager is None:
            msg = "DelegatingSubject requires that a SecurityManager be set"
            raise SecurityManagerNotSetException(msg)

    @property
    def has_identifiers(self):
        return (self._identifiers is not None)

    def get_primary_identifier(self, identifiers):
        try:
            return identifiers.primary_identifier
        except:
            return None

    @property
    def identifier(self):
        self.get_primary_identifier(self.identifiers)

    @property
    def identifiers(self):
        # expecting a List of IdentifierCollection objects:
        run_as_identifiers = self.get_run_as_identifiers_stack()
        if (not run_as_identifiers):
            if not hasattr(self, '_identifiers'):
                self._identifiers = None
            return self._identifiers
        else:
            return run_as_identifiers[0]

    @identifiers.setter
    def identifiers(self, identifiers):
        if (isinstance(identifiers, subject_abcs.IdentifierCollection) or
                identifiers is None):
            self._identifiers = identifiers
        else:
            raise IllegalArgumentException('must use IdentifierCollection')

    def is_permitted(self, permission_s):
        """
        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the Permission and a Boolean
                  indicating whether the permission is         """

        if self.has_identifiers:
            self.check_security_manager()
            return (self.security_manager.is_permitted(
                    self.identifiers, permission_s))

        msg = 'Cannot check permission when identifiers aren\'t set!'
        raise IdentifiersNotSetException(msg)

    def is_permitted_collective(self, permission_s, logical_operator):
        """
        :param permission_s:  a List of Permission objects

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :returns: a Boolean
        """
        sm = self.security_manager
        if self.has_identifiers:
            return sm.is_permitted_collective(self.identifiers,
                                              permission_s,
                                              logical_operator)

        msg = 'Cannot check permission when identifiers aren\'t set!'
        raise IdentifiersNotSetException(msg)

    def assert_authz_check_possible(self):
        if not self.identifiers:
            msg = (
                "This subject is anonymous - it does not have any " +
                "identifying identifiers and authorization operations " +
                "required an identity to check against.  A Subject " +
                "instance will acquire these identifying identifiers " +
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

    def check_permission(self, permission_s, logical_operator):
        """
        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission objects or Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :raises UnauthorizedException: if any permission is unauthorized
        """
        self.assert_authz_check_possible()
        if self.has_identifiers:
            self.security_manager.check_permission(self.identifiers,
                                                   permission_s,
                                                   logical_operator)
        else:
            msg = 'Cannot check permission when identifiers aren\'t set!'
            raise IdentifiersNotSetException(msg)

    def has_role(self, roleid_s, logical_operator):
        """
        :param roleid_s: 1..N role identifiers (string)
        :type roleid_s:  a String or List of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :returns: a tuple containing the roleid and a boolean indicating
                  whether the role is assigned (this is different than Shiro)
        """

        if self.has_identifiers:
            return self.security_manager.has_role(self.identifiers,
                                                  roleid_s, logical_operator)
        msg = 'Cannot check roles when identifiers aren\'t set!'
        raise IdentifiersNotSetException(msg)

    def has_all_roles(self, roleid_s):
        """
        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings

        :returns: a Boolean
        """
        if self.has_identifiers:
            return (self.has_identifiers and
                    self.security_manager.has_all_roles(self.identifiers, roleid_s))
        else:
            msg = 'Cannot check roles when identifiers aren\'t set!'
            raise IdentifiersNotSetException(msg)

    def check_role(self, role_ids, logical_operator):
        """
        :param role_ids:  1 or more RoleIds
        :type role_ids: an individual or List of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: and OR all (from python standard library)

        :raises UnauthorizedException: if Subject not assigned to all roles
        """
        if self.has_identifiers:
            self.security_manager.check_role(self.identifiers,
                                             role_ids,
                                             logical_operator)
        else:
            msg = 'Cannot check roles when identifiers aren\'t set!'
            raise IdentifiersNotSetException(msg)

    def login(self, authc_token):

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
            raise IllegalStateException(msg)

        self.identifiers = identifiers
        self.authenticated = True

        if not host:
            try:
                host = authc_token.host
            except AttributeError:  # likely not using a HostAuthenticationToken
                host = None
        self.host = host

        session = subject.get_session(False)
        if session:
            self.session = self.decorate(session)
        else:
            self.session = None

    @property
    def authenticated(self):
        if not hasattr(self, '_authenticated'):
            self._authenticated = None
        return self._authenticated

    @authenticated.setter
    def authenticated(self, authc):
        if (isinstance(authc, bool) or authc is None):
            self._authenticated = authc
        else:
            msg = ('DelegatingSubject.authenticated.setter:  wrong objtype')
            print(msg)
            raise IllegalArgumentException(msg)

    @property
    def is_remembered(self):
        return (bool(self.identifiers) and (not self.authenticated))

    @property
    def session(self):
        if not hasattr(self, '_session'):
            self._session = None
        return self._session

    @session.setter
    def session(self, session):
        """
        :type session:  Session object
        """
        if (isinstance(session, session_abcs.Session) or session is None):
            self._session = session
        else:
            raise IllegalArgumentException('must use Session object')

    def get_session(self, create=True):
        msg = ("attempting to get session; create = " + str(create) +
               "; \'session is None\' = " + str(self.session is None) +
               "; \'session has id\' = " +
               str(self.session is not None and bool(self.session.session_id)))
        print(msg)
        # log trace here

        if (not self.session and create):
            if (not self.session_creation_enabled):
                msg = ("Session creation has been disabled for the current"
                       " subject. This exception indicates that there is "
                       "either a programming error (using a session when "
                       "it should never be used) or that Yosai's "
                       "configuration needs to be adjusted to allow "
                       "Sessions to be created for the current Subject.")
                raise DisabledSessionException(msg)

            msg = ("Starting session for host ", str(self.host))
            print(msg)
            # log trace here

            session_context = self.create_session_context()
            session = self.security_manager.start(session_context)
            self.session = self.decorate(session)

        return self.session

    def create_session_context(self):
        session_context = DefaultSessionContext()
        if (self.host):
            session_context.host = self.host
        return session_context

    def clear_run_as_identities_internal(self):
        try:
            self.clear_run_as_identities()
        except SessionException as ex:
            msg = ("clearrunasidentitiesinternal: Encountered session "
                   "exception trying to clear 'runAs' identities during "
                   "logout.  This can generally safely be ignored.", ex)
            print(msg)
            # log debug here, including exc_info=ex

    def logout(self):
        try:
            self.clear_run_as_identities_internal()
            self.security_manager.logout(self)
        finally:
            self._session = None
            self._identifiers = None
            self._authenticated = False

            # Don't set securityManager to None here - the Subject can still be
            # used, it is just considered anonymous at this point.
            # The SecurityManager instance is necessary if the subject would
            # log in again or acquire a new session.

    def session_stopped(self):
        self._session = None

    # --------------------------------------------------------------------------
    # Concurrency is TBD:  Shiro uses multithreading whereas Yosai...
    # --------------------------------------------------------------------------
    # def execute(self, _able):
    #    """
    #    :param _able:  a Runnable or Callable
    #    """
    #    associated = self.associate_with(_able)
    #
    #    if isinstance(_able, concurrency_abcs.Callable):
    #        try:
    #            return associated.call()
    #        except Exception as ex:
    #            raise ExecutionException(ex)
    #
    #    elif isinstance(_able, concurrency_abcs.Runnable):
    #        associated.run()

    # --------------------------------------------------------------------------
    # Concurrency is TBD:  Shiro uses multithreading whereas Yosai...
    # --------------------------------------------------------------------------
    # def associate_with(self, _able):
    #    if isinstance(_able, Thread):
    #        msg = ("This implementation does not support Thread args."
    #               "Instead, the method argument should be a "
    #               "non-Thread Runnable and the return value from "
    #               "this method can then be given to an "
    #               "ExecutorService or another Thread.")
    #        raise UnsupportedOperationException(msg)
    #
    #    if isinstance(_able, Runnable):
    #        return SubjectRunnable(self, _able)
    #
    #    if isinstance(_able, Callable):
    #        return SubjectCallable(self, _able)

    def run_as(self, identifiers):
        if (not self.has_identifiers):
            msg = ("This subject does not yet have an identity.  Assuming the "
                   "identity of another Subject is only allowed for Subjects "
                   "with an existing identity.  Try logging this subject in "
                   "first, or using the DelegatingSubject.Builder "
                   "to build ad hoc Subject instances with identities as "
                   "necessary.")
            raise IllegalStateException(msg)
        self.push_identity(identifiers)

    @property
    def is_run_as(self):
        return bool(self.get_run_as_identifiers_stack())

    def get_previous_identifiers(self):
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
        stack = collections.deque()
        rapkey = session.get_attribute(self.run_as_identifiers_session_key)

        if rapkey:  # don't insert None
            stack.appendleft(rapkey)

        return stack

    def clear_run_as_identities(self):
        session = self.get_session(False)
        if (session is not None):
            session.remove_attribute(self.run_as_identifiers_session_key)

    def push_identity(self, identifiers):
        """
        :type identifiers: IdentifierCollection
        """
        if (not identifiers):
            msg = ("Specified Subject identifiers cannot be None or empty "
                   "for 'run as' functionality.")
            raise IllegalArgumentException(msg)

        stack = self.get_run_as_identifiers_stack()
        if (not stack):
            stack = collections.deque()

        stack.appendleft(identifiers)
        session = self.get_session()
        session.set_attribute(self.run_as_identifiers_session_key, stack)

    def pop_identity(self):
        popped = None
        stack = self.get_run_as_identifiers_stack()

        if (stack):
            popped = stack.popleft()
            if (stack):
                # persist the changed stack to the session
                session = self.get_session()
                session.set_attribute(self.run_as_identifiers_session_key, stack)

            else:
                # stack is empty, remove it from the session:
                self.clear_run_as_identities()
        return popped

    # inner class:
    class StoppingAwareProxiedSession(ProxiedSession):

        def __init__(self, target_session, owning_subject):
            super().__init__(target_session)
            self.owner = owning_subject

        def stop(self):
            """
            :raises InvalidSessionException:
            """
            super().stop()
            self.owner.session_stopped()

    def __repr__(self):
        return "DelegatingSubject()"

# migrated from /mgt:
class DefaultSubjectStore:

    """
    This is formerly known as /mgt/DefaultSubjectDAO.

    This is the default SubjectStore implementation for storing Subject state.
    The default behavior is to save Subject state into the Subject's Session.
    Note that the storing of the Subject state into the Session is considered
    a default behavior of Yosai but this behavior can be disabled -- see below.

    Once a Subject's state is stored in a Session, a Subject instance can be
    re-created at a later time by first acquiring the Subject's session.  A
    Subject's session is typically acquired through interaction with a
    SessionManager, referencing a Session by session_id or
    session_key, and then instantiating/building a Subject instance using
    Session attributes.

    Controlling How Sessions are Used
    ---------------------------------
    Whether a Subject's Session is used to persist the Subject's state is
    controlled on a per-Subject basis.  This is accomplish by configuring
    a SessionStorageEvaluator.

    The default "Evaluator" is a DefaultSessionStorageEvaluator.  This evaluator
    supports enabling or disabling session usage for Subject persistence at a
    global level for all subjects (and defaults to allowing sessions to be
    used).

    Disabling Session Persistence Entirely
    --------------------------------------
    Because the default SessionStorageEvaluator instance is a
    DefaultSessionStorageEvaluator, you can disable Session usage for Subject
    state entirely by configuring that instance directly, e.g.:

        SessionStore.session_storage_evaluator.session_storage_enabled = False

    or, for example, within yosai_settings.json  (TBD)

        securityManager.subjectStore.sessionStorageEvaluator.sessionStorageEnabled = False

    However, *Note:*
    ONLY do this if your application is 100% stateless and you *DO NOT* need
    subjects to be remembered across remote invocations, or in a web
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

    To support the hybrid *per-Subject* approach, you will need to create your
    own implementation of the SessionStorageEvaluator interface and configure
    it by setting your session_storage_evaluator property-attribute or
    by using a settings file such as yosai_settings.json:

        myEvaluator = CustomSessionStorageEvaluator
        securityManager.subjectStore.sessionStorageEvaluator = myEvaluator

    Unless overridden, the default evaluator is a
    DefaultSessionStorageEvaluator, which enables session usage for Subject
    state by default.
    """

    def __init__(self):
        self._session_storage_evaluator = DefaultSessionStorageEvaluator()

        self.dsc_isk = 'DefaultSubjectContext.IDENTIFIERS_SESSION_KEY'
        self.dsc_ask = 'DefaultSubjectContext.AUTHENTICATED_SESSION_KEY'

    def is_session_storage_enabled(self, subject):
        """
        Determines whether the subject's session will be used to persist
        subject state.  This default implementation merely delegates to the
        internal DefaultSessionStorageEvaluator.
        """
        return self.session_storage_evaluator.\
            is_session_storage_enabled(subject)

    @property
    def session_storage_evaluator(self):
        return self._session_storage_evaluator

    @session_storage_evaluator.setter
    def session_storage_evaluator(self, sse):
        self._session_storage_evaluator = sse

    def save(self, subject):
        """
        Saves the subject's state to the subject's session only
        if session storage is enabled for the subject.  If session storage is
        not enabled for the specific Subject, this method does nothing.

        In either case, the argument Subject is returned directly (a new
        Subject instance is not created).

        :param subject: the Subject instance for which its state will be
                        created or updated
        :returns: the same Subject passed in (a new Subject instance is
                  not created).
        """
        if (self.is_session_storage_enabled(subject)):
            self.save_to_session(subject)
        else:
            msg = ("Session storage of subject state for Subject [{0}] has "
                   "been disabled: identity and authentication state are "
                   "expected to be initialized on every request or "
                   "invocation.".format(subject))
            print(msg)
            # log trace here
        return subject

    def save_to_session(self, subject):

        """
        Saves the subject's state (it's identifying attributes (identifiers) and
        authentication state) to its session.  The session can be retrieved at
        a later time (typically from a SessionManager) and used to re-create
        the Subject instance.

        :param subject: the subject for which state will be persisted to a
                        session
        """
        # performs merge logic, only updating the Subject's session if it
        # does not match the current state:
        self.merge_identifiers(subject)
        self.merge_authentication_state(subject)

    # was mergePrincipals:
    def merge_identifiers(self, subject):
        """
        Merges the Subject's identifying attributes with those that are
        saved in the Subject's session.  This method only updates the Subject's
        session when the session's identifiers are different than those of the
        Subject instance.

        :param subject: the Subject whose identifying attributes will
                        potentially merge with those in the Subject's session
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

        if (not session):
            if (current_identifiers):
                session = subject.get_session(True)
                session.set_attribute(self.dsc_isk, current_identifiers)
            # otherwise no session and no identifiers - nothing to save
        else:
            existing_identifiers = session.get_attribute(self.dsc_isk)

            if (not current_identifiers):
                if (existing_identifiers):
                    session.remove_attribute(self.dsc_isk)
                # otherwise both are null or empty - no need to update session
            else:
                if not (current_identifiers == existing_identifiers):
                    session.set_attribute(self.dsc_isk, current_identifiers)
                # otherwise they're the same - no need to update the session

    def merge_authentication_state(self, subject):
        session = subject.get_session(False)

        if (not session):
            if (subject.authenticated):
                session = subject.get_session()
                session.set_attribute(self.dsc_ask, True)
            # otherwise no session and not authenticated - nothing to save
        else:
            existing_authc = session.get_attribute(self.dsc_ask)

            if (subject.authenticated):
                if (existing_authc is None):  # either doesnt exist or set None
                    session.set_attribute(self.dsc_ask, True)
                # otherwise authc state matches - no need to update the session
            else:
                if (existing_authc is not None):
                    # existing doesn't match the current state - remove it:
                    session.remove_attribute(self.dsc_ask)
                # otherwise not in the session and not authenticated and
                # no need to update the session

    def remove_from_session(self, subject):
        session = subject.get_session(False)
        if (session):
            session.remove_attribute(self.dsc_ask)
            session.remove_attribute(self.dsc_isk)

    def delete(self, subject):
        self.remove_from_session(subject)


class SubjectBuilder:
    """
    Shiro uses the Builder design pattern for this class, including it as an
    inner class of the Subject interface.  Unlike Shiro, Yosai separates the
    SubjectBuilder from the Subject abc -- it is independent of the other.
    Further, Yosai uses python's support for default keyword arguments to provide
    the same flexibility in Subject creation as provided by the Builder pattern.
    """

    def __init__(self,
                 security_utils,
                 security_manager=None,
                 subject_context=None,
                 host=None,
                 session_id=None,
                 session=None,
                 identifiers=None,
                 session_creation_enabled=True,
                 authenticated=False,
                 **context_attributes):
        """
        :type subject_context:  DefaultSubjectContext
        """

        if security_manager is None:
            self.security_manager = security_utils.security_manager
        else:
            self.security_manager = security_manager

        if subject_context is None:
            self.subject_context = DefaultSubjectContext(security_utils)
            self.subject_context.security_manager = self.security_manager
            self.subject_context.host = host
            self.subject_context.session_id = session_id
            self.subject_context.session = session
            self.subject_context.identifiers = identifiers
            self.subject_context.session_creation_enabled = session_creation_enabled
            self.subject_context.authenticated = authenticated

            for key, val in context_attributes.items():
                self.context_attribute(key, val)
        else:
            self.subject_context = subject_context

    def context_attribute(self, attribute_key, attribute_value=None):

        """
        Allows custom attributes to be added to the underlying context Map used
        to construct the Subject instance.

        A None key throws an IllegalArgumentException.
        A None value effectively removes any previously stored attribute under
        the given key from the context map.

        NOTE: This method is only useful when configuring Yosai with a custom
        SubjectFactory implementation.  This method allows end-users to append
        additional data to the context map which the SubjectFactory
        implementation can use when building custom Subject instances. As such,
        this method is only useful when a custom SubjectFactory implementation
        has been configured.

        :param attribute_key:  the key under which the corresponding value will
                               be stored in the context Map
        :param attribute_value: the value to store in the context map under the
                                specified attribute_key
        :raises IllegalArgumentException: if the attribute_key is None
        """
        if (not attribute_key):
            msg = "Subject context map key cannot be None"
            raise IllegalArgumentException(msg)
        if (not attribute_value):
            self.subject_context.remove(attribute_key)
        else:
            self.subject_context.put(attribute_key, attribute_value)

    def build_subject(self):
        return self.security_manager.create_subject(self.subject_context)


# moved from /mgt, reconciled, ready to test:
class DefaultSubjectFactory(subject_abcs.SubjectFactory):

    def __init__(self):
        pass

    def create_subject(self, subject_context):
        security_manager = subject_context.resolve_security_manager()
        session = subject_context.resolve_session()
        session_creation_enabled = subject_context.session_creation_enabled
        identifiers = subject_context.resolve_identifiers()
        authenticated = subject_context.resolve_authenticated()
        host = subject_context.resolve_host()

        return DelegatingSubject(identifiers, authenticated, host, session,
                                 session_creation_enabled, security_manager)
