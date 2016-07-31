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

        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)
        print('called by:', calframe[1][3])

"""
import copy
import inspect
import pdb

import collections
import logging
from contextlib import contextmanager

from yosai.core import (
    MapContext,
    DefaultSessionContext,
    DefaultSessionStorageEvaluator,
    DisabledSessionException,
    IdentifiersNotSetException,
    InvalidArgumentException,
    IllegalStateException,
    InvalidArgumentException,
    ProxiedSession,
    SecurityManagerNotSetException,
    SessionException,
    ThreadStateManager,
    UnauthenticatedException,
    UnavailableSecurityManagerException,
    YosaiContextException,
    mgt_abcs,
    session_abcs,
    subject_abcs,
    memoized_property,
)

logger = logging.getLogger(__name__)


class DefaultSubjectContext(MapContext, subject_abcs.SubjectContext):
    """
    A SubjectContext assists a SecurityManager and SubjectFactory with the
    configuration of new Subject instances.  It employs a number of heuristics
    to acquire data for its attributes, exhausting all available resources at
    its disposal (heuristic resolution of data).

    Most Yosai users will never instantiate a SubjectContext object directly
    but rather will use a SubjectBuilder, which internally uses a SubjectContext,
    to build Subject instances.

    Yosai notes:  Shiro uses the getTypedValue method to validate objects
                  as it obtains them from the MapContext.  I've decided that
                  this checking is unecessary overhead in Python and to
                  instead *assume* that objects are mapped correctly within
                  the MapContext.  Exceptions will raise further down the
                  call stack should a mapping be incorrect.
    """
    def __init__(self, security_utils, security_manager, context={}):
        """
        :param context: context's schema of reserved attributes must be named
                        according to the property names below
        :type context: dict
        """
        super().__init__(context)

        self.security_utils = security_utils
        self.security_manager = security_manager

        # to set reserved attributes correctly (using the property setters),
        # context must be set accordingly:
        for key, value in self.context.items():
            if hasattr(self, key):
                setattr(self, key, value)  # uses the property setters
                self.context.pop(key)

    # new to yosai.core.is this helper method:
    def get_key(self, key):
        """
        :type key: string
        """
        return "{0}.{1}".format(self.__class__.__name__, key)

    @property
    def security_manager(self):
        return self.get(self.get_key('SECURITY_MANAGER'))

    @security_manager.setter
    def security_manager(self, securitymanager):
        """
        :type securitymanager:  mgt_abcs.SecurityManager
        """
        self.none_safe_put(self.get_key('SECURITY_MANAGER'), securitymanager)

    def resolve_security_manager(self):
        security_manager = self.security_manager
        if (security_manager is None):

            msg = ("No SecurityManager available in subject context map.  " +
                   "Falling back to Yosai.security_manager for" +
                   " lookup.")
            logger.debug(msg)

            try:
                security_manager = self.security_utils.security_manager
            except UnavailableSecurityManagerException:

                msg = ("DefaultSubjectContext.resolve_security_manager cannot "
                       "obtain security_manager! No SecurityManager available "
                       "via Yosai.  Heuristics exhausted.")
                logger.debug(msg, exc_info=True)

        return security_manager

    @property
    def session_id(self):
        return self.get(self.get_key('SESSION_ID'))

    @session_id.setter
    def session_id(self, session_id):
        """
        :type session_id:  string
        """
        self.none_safe_put(self.get_key('SESSION_ID'), session_id)

    @property
    def subject(self):
        return self.get(self.get_key('SUBJECT'))

    @subject.setter
    def subject(self, subject):
        """
        :type subject:  subject_abcs.Subject
        """
        self.none_safe_put(self.get_key('SUBJECT'), subject)

    @property
    def identifiers(self):
        return self.get(self.get_key('IDENTIFIERS'))

    @identifiers.setter
    def identifiers(self, identifiers):
        """
        :type identifier_s: subject_abcs.IdentifierCollection
        """
        self.none_safe_put(self.get_key('IDENTIFIERS'), identifiers)

    def resolve_identifiers(self, session):
        identifiers = self.identifiers

        if not identifiers:
            # account.account_id is a SimpleIdentifierCollection:
            try:
                identifiers = self.account.account_id
                print('\n------> ', self.__class__.__name__, '.account_id identifiers: ', identifiers, '\n')
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

    @property
    def session(self):
        return self.get(self.get_key('SESSION'))

    @session.setter
    def session(self, session):
        """
        :type session:  session_abcs.Session
        """
        self.none_safe_put(self.get_key('SESSION'), session)

    def resolve_session(self):
        session = self.session
        if session is None:
            try:
                session = self.subject.get_session(False)
            except AttributeError:
                pass
        return session

    # yosai.core.renamed so to match property accessor with mutator:
    @property
    def session_creation_enabled(self):
        val = self.get(self.get_key('SESSION_CREATION_ENABLED'))
        return (val is None or val)

    @session_creation_enabled.setter
    def session_creation_enabled(self, enabled):
        """
        :type enabled:  bool
        """
        self.none_safe_put(
            self.get_key('SESSION_CREATION_ENABLED'), enabled)

    # yosai.core.renamed from is_authenticated:
    @property
    def authenticated(self):
        """
        :returns: Boolean
        """
        return self.get(self.get_key('AUTHENTICATED'))

    @authenticated.setter
    def authenticated(self, authc):
        """
        :type authc:  bool
        """
        self.put(self.get_key('AUTHENTICATED'), authc)

    def resolve_authenticated(self, session):
        authc = self.authenticated

        if authc is None:
            #  presence of one indicates a successful authentication attempt:
            #  See whethere there is an Account object.  If one exists, the very
            try:
                authc = self.account.account_id
            except AttributeError:
                pass
        if authc is None:
            #  fall back to a session check:

            try:
                authc = session.get_internal_attribute('authenticated_session_key')
            except AttributeError:
                authc = None

        return bool(authc)

    # yosai.core.renamed AuthenticationInfo to Account:
    @property
    def account(self):
        return self.get(self.get_key('ACCOUNT'))

    @account.setter
    def account(self, account):
        """
        :type account:  account_abcs.Account
        """
        self.none_safe_put(self.get_key('ACCOUNT'), account)

    @property
    def authentication_token(self):
        return self.get(self.get_key('AUTHENTICATION_TOKEN'))

    @authentication_token.setter
    def authentication_token(self, token):
        """
        :type token:  authc_abcs.AuthenticationToken
        """
        self.none_safe_put(self.get_key('AUTHENTICATION_TOKEN'), token)

    @property
    def host(self):
        return self.get(self.get_key('HOST'))

    @host.setter
    def host(self, host):
        """
        :type host: string
        """
        self.put(self.get_key('HOST'), host)

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
    just as ``DelegatingSession`` is to ``DefaultNativeSessionManager``.

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

        self._session_creation_enabled = session_creation_enabled
        self.run_as_identifiers_session_key = 'run_as_identifiers_session_key'

    def decorate(self, session):
        """
        :type session:  session_abcs.Session
        """
        if not isinstance(session, session_abcs.Session):
            raise InvalidArgumentException('incorrect session argument passed')
        return self.StoppingAwareProxiedSession(session, self)

    @property
    def security_manager(self):
        if not hasattr(self, '_security_manager'):
            self._security_manager = None
        return self._security_manager

    @security_manager.setter
    def security_manager(self, security_manager):
        """
        :type security_manager:  mgt_abcs.SecurityManager
        """
        if (isinstance(security_manager, mgt_abcs.SecurityManager) or
                security_manager is None):
            self._security_manager = security_manager
        else:
            raise InvalidArgumentException('must use SecurityManager')

    @property
    def session_creation_enabled(self):
        return self._session_creation_enabled

    @session_creation_enabled.setter
    def session_creation_enabled(self, enabled):
        self._session_creation_enabled = enabled

    # new to yosai.core.
    # security_manager is required for certain operations
    def check_security_manager(self):
        if self.security_manager is None:
            msg = "DelegatingSubject requires that a SecurityManager be set"
            raise SecurityManagerNotSetException(msg)

    @property
    def has_identifiers(self):
        return bool(self.identifiers)

    def get_primary_identifier(self, identifiers):
        """
        :type identifiers:  subject_abcs.IdentifierCollection
        """
        try:
            return identifiers.primary_identifier
        except:
            return None

    @property
    def primary_identifier(self):
        self.get_primary_identifier(self.identifiers)

    @property
    def identifiers(self):
        # expecting a List of IdentifierCollection objects:
        run_as_identifiers = self.get_run_as_identifiers_stack()

        if (not run_as_identifiers):
            return self._identifiers
        else:
            return run_as_identifiers[0]

    @identifiers.setter
    def identifiers(self, identifiers):
        """
        :type identifiers:  subject_abcs.IdentifierCollection
        """
        if (isinstance(identifiers, subject_abcs.IdentifierCollection) or
                identifiers is None):
            self._identifiers = identifiers
        else:
            raise InvalidArgumentException('must use IdentifierCollection')

    def is_permitted(self, permission_s):
        """
        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of authz_abcs.Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the authz_abcs.Permission and a
                  Boolean indicating whether the permission is granted
        """
        if self.has_identifiers:
            self.check_security_manager()
            return (self.security_manager.is_permitted(
                    self.identifiers, permission_s))

        msg = 'Cannot check permission when identifiers aren\'t set!'
        raise IdentifiersNotSetException(msg)

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
        if self.has_identifiers:
            self.security_manager.check_permission(self.identifiers,
                                                   permission_s,
                                                   logical_operator)
        else:
            msg = 'Cannot check permission when identifiers aren\'t set!'
            raise IdentifiersNotSetException(msg)

    def has_role(self, roleid_s):
        """
        :param roleid_s: 1..N role identifiers (strings)
        :type roleid_s:  Set of Strings

        :returns: a frozenset of tuple(s), containing the roleid and a Boolean
                  indicating whether the user is a member of the Role
        """
        if self.has_identifiers:
            return self.security_manager.has_role(self.identifiers,
                                                  roleid_s)
        msg = 'Cannot check roles when identifiers aren\'t set!'
        raise IdentifiersNotSetException(msg)

    # refactored has_all_roles:
    def has_role_collective(self, roleid_s, logical_operator=all):
        """
        :param roleid_s: 1..N role identifier
        :type roleid_s:  a Set of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python standard library)

        :returns: a Boolean
        """
        if self.has_identifiers:
            return (self.has_identifiers and
                    self.security_manager.has_role_collective(self.identifiers,
                                                              roleid_s,
                                                              logical_operator))
        else:
            msg = 'Cannot check roles when identifiers aren\'t set!'
            raise IdentifiersNotSetException(msg)

    def check_role(self, role_ids, logical_operator=all):
        """
        :param role_ids:  1 or more RoleIds
        :type role_ids: a Set of Strings

        :param logical_operator:  indicates whether all or at least one
                                  permission check is true (any)
        :type: any OR all (from python stdlib)

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
            raise IllegalStateException(msg)

        self._identifiers = identifiers
        self._authenticated = True

        if not host:
            try:
                host = authc_token.host
            except AttributeError:  # likely not using a HostAuthenticationToken
                host = None
        self.host = host

        session = subject.get_session(False)
        if session:
            self._session = self.decorate(session)
        else:
            self._session = None

    @property
    def authenticated(self):
        return self._authenticated

    @authenticated.setter
    def authenticated(self, authc):
        """
        :type authc: bool
        """
        if not isinstance(authc, bool):
            raise InvalidArgumentException('authenticated must be Boolean')
        self._authenticated = authc

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
        :type session:  session_abcs.Session
        """
        if (isinstance(session, session_abcs.Session) or session is None):
            self._session = session
        else:
            raise InvalidArgumentException('must use Session object')

    def get_session(self, create=True):
        """
        :type create:  bool
        """
        msg = ("{0} attempting to get session; create = " + str(create) +
               "; \'session is None\' = " + str(self.session is None) +
               "; \'session has id\' = ".format(self.__class__.__name__) +
               str(self.session is not None and bool(self.session.session_id)))
        logger.debug(msg)

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
            logger.debug(msg)

            session_context = self.create_session_context()
            session = self.security_manager.start(session_context)
            self.session = self.decorate(session)

        return self.session

    def create_session_context(self):
        session_context = DefaultSessionContext()
        session_context.host = self.host
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
            raise IllegalStateException(msg)
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
            return session.get_internal_attribute(
                self.run_as_identifiers_session_key)
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
            raise InvalidArgumentException(msg)

        stack = self.get_run_as_identifiers_stack()
        if (not stack):
            stack = collections.deque()

        stack.appendleft(identifiers)
        session = self.get_session()
        session.set_internal_attribute(self.run_as_identifiers_session_key, stack)

    def pop_identity(self):
        """
        :returns: SimpleIdentifierCollection
        """
        popped = None
        stack = self.get_run_as_identifiers_stack()

        if (stack):
            popped = stack.popleft()
            if (stack):
                # persist the changed stack to the session
                session = self.get_session()
                session.set_internal_attribute(self.run_as_identifiers_session_key, stack)

            else:
                # stack is empty, remove it from the session:
                self.clear_run_as_identities()
        return popped

    def __repr__(self):
        return "{0}(_identifiers={1}, _authenticated={2})".\
            format(self.__class__.__name__, self._identifiers, self._authenticated)

    # inner class:
    class StoppingAwareProxiedSession(ProxiedSession):

        def __init__(self, target_session, owning_subject):
            """
            :type target_session:  session_abcs.Session
            :type owning_subject:  subject_abcs.Subject
            """
            super().__init__(target_session)
            self.owner = owning_subject

        def stop(self, identifiers):
            """
            :type identifiers:  subject_abcs.IdentifierCollection
            :raises InvalidSessionException:
            """
            super().stop(identifiers)
            self.owner.session_stopped()

        def __repr__(self):
            return "StoppingAwareProxiedSession()"


# migrated from /mgt:
class DefaultSubjectStore:

    """
    This is known as /mgt/DefaultSubjectDAO in Shiro.

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
    controlled on a per-Subject basis.  This is accomplish by configuring
    a ``SessionStorageEvaluator``.

    The default "Evaluator" is a ``DefaultSessionStorageEvaluator``.  This evaluator
    supports enabling or disabling session usage for ``Subject`` persistence at a
    global level for all subjects (and defaults to allowing sessions to be
    used).

    Disabling Session Persistence Entirely
    --------------------------------------
    Because the default ``SessionStorageEvaluator`` instance is a
    ``DefaultSessionStorageEvaluator``, you can disable Session usage for Subject
    state entirely by configuring that instance directly, e.g.:::

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

    To support the hybrid *per-Subject* approach, you will need to create your
    own implementation of the ``SessionStorageEvaluator`` interface and configure
    it by setting your session_storage_evaluator property-attribute

    Unless overridden, the default evaluator is a
    ``DefaultSessionStorageEvaluator``, which enables session usage for ``Subject``
    state by default.
    """

    def __init__(self):

        # used to determine whether session state may be persisted for this
        # subject if the session has not yet been persisted
        self._session_storage_evaluator = DefaultSessionStorageEvaluator()

        self.dsc_isk = 'identifiers_session_key'
        self.dsc_ask = 'authenticated_session_key'

    def is_session_storage_enabled(self, subject):
        """
        :type subject:  subject_abcs.Subject

        Determines whether the subject's ``Session`` will be used to persist
        subject state.  This default implementation merely delegates to the
        internal ``DefaultSessionStorageEvaluator``.
        """
        return self.session_storage_evaluator.\
            is_session_storage_enabled(subject)

    @property
    def session_storage_evaluator(self):
        return self._session_storage_evaluator

    @session_storage_evaluator.setter
    def session_storage_evaluator(self, sse):
        """
        :type sse:  session_abcs.SessionStorageEvaluator
        """
        self._session_storage_evaluator = sse

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
            self.save_to_session(subject)
        else:
            msg = ("Session storage of subject state for Subject [{0}] has "
                   "been disabled: identity and authentication state are "
                   "expected to be initialized on every request or "
                   "invocation.".format(subject))
            logger.debug(msg)

        return subject

    def save_to_session(self, subject):

        """
        Saves the subject's state (it's identifying attributes (identifier) and
        authentication state) to its session.  The session can be retrieved at
        a later time (typically from a ``SessionManager``) and used to re-create
        the Subject instance.

        :param subject: the subject for which state will be persisted to a
                        session
        :type subject:  subject_abcs.Subject
        """
        # performs merge logic, only updating the Subject's session if it
        # does not match the current state.  This process can be refactored
        # and made more efficient by consolidating both requests and updates (TBD)

        # unlike shiro, yosai merges identifiers and authentication state at once
        self.merge_identity(subject)

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
                print('\n\n -=-=-=-=-=- setting internal attributes: ', to_set)
                session.set_internal_attributes(to_set)

            if to_remove:
                print('\n\n -=-=-=-=-=- removing internal attributes: ', to_remove)
                session.remove_internal_attributes(to_remove)

    def remove_from_session(self, subject):
        """
        :type subject:  subject_abcs.Subject
        """
        session = subject.get_session(False)
        if (session):
            session.remove_internal_attribute(self.dsc_ask)
            session.remove_internal_attribute(self.dsc_isk)

    def delete(self, subject):
        self.remove_from_session(subject)


class SubjectBuilder:
    """
    Creates Subject instances in a simplified way without requiring knowledge of
    Yosai's construction techniques.

    NOTE:
    This is provided for framework development support only and should typically
    never be used by application developers.  Subject instances should generally
    be acquired by using ``Yosai.subject``

    The simplest usage of this builder is to construct an anonymous, session-less
    ``Subject`` instance. The returned Subject instance is *not* automatically bound
    to the application (thread) for further use.  That is, ``Yosai.subject``
    will not automatically return the same instance as what is returned by the
    builder.  It is up to the framework developer to bind the built
    Subject for continued use if so desired.

    Shiro uses the Builder design pattern for this class, including it as an
    inner class of the Subject interface.  Unlike Shiro, Yosai doesn't use the
    builder pattern and simplifies builder's responsibilities a bit.

    In future releases, this class may be refactored or removed entirely.  TBD
    """
    def __init__(self, security_utils, security_manager):
        """
        :type subject_context:  DefaultSubjectContext
        """
        self.security_utils = security_utils
        self.security_manager = security_manager

    # yosai omits context_attributes

    # refactored resolve_subject_context:
    def create_subject_context(self):
        return DefaultSubjectContext(security_utils=self.security_utils,
                                     security_manager=self.security_manager)

    def build_subject(self):
        subject_context = self.create_subject_context()
        return self.security_manager.create_subject(subject_context=subject_context)


# the subject factory is used exclusively by the mgt module, so look into
# moving it over (TBD)
class DefaultSubjectFactory(subject_abcs.SubjectFactory):
    def __init__(self):
        pass

    def create_subject(self, subject_context):
        """
        :type subject_context:  subject_abcs.SubjectContext
        """
        security_manager = subject_context.resolve_security_manager()
        session = subject_context.resolve_session()
        session_creation_enabled = subject_context.session_creation_enabled

        # passing the session arg is new to yosai, eliminating redunant
        # get_session calls:
        identifiers = subject_context.resolve_identifiers(session)
        authenticated = subject_context.resolve_authenticated(session)
        host = subject_context.resolve_host(session)

        return DelegatingSubject(identifiers=identifiers,
                                 authenticated=authenticated,
                                 host=host,
                                 session=session,
                                 session_creation_enabled=session_creation_enabled,
                                 security_manager=security_manager)


# moved from its own security_utils module so as to avoid circular importing:
class Yosai:

    def __init__(self, security_manager):
        self.security_manager = security_manager

    @memoized_property
    def subject_builder(self):
        self._subject_builder = SubjectBuilder(security_utils=self,
                                               security_manager=self.security_manager)
        return self._subject_builder

    def _get_subject(self):
        """
        Returns the currently accessible Subject available to the calling code
        depending on runtime environment.

        :returns: the Subject currently accessible to the calling code
        :raises IllegalStateException: if no Subject instance or SecurityManager
                                       instance is available to obtain a Subject
                                       (such an setup is considered an invalid
                                        application configuration because a Subject
                                        should *always* be available to the caller)
        """
        subject = self.subject_builder.build_subject()
        global_subject_context.stack.append(subject)
        return subject

    @property
    def security_manager(self):
        try:
            return self._security_manager
        except AttributeError:
            msg = "No SecurityManager accessible to the calling code."
            raise UnavailableSecurityManagerException(msg)

    @security_manager.setter
    def security_manager(self, security_manager):
        """
        :type security_manager:  mgt_abcs.SecurityManager
        """
        self._security_manager = security_manager
        self._security_manager.security_utils = self
        self.subject_builder.security_manager = security_manager

    @staticmethod
    @contextmanager
    def context(yosai):
        global_yosai_context.stack.append(yosai)  # how to weakref? TBD
        yield yosai
        global_yosai_context.stack.pop()
        try:
            global_subject_context.stack.pop()
        except IndexError:
            logger.debug('Could not pop a subject from the context stack.')

    @staticmethod
    def get_current_subject():
        try:
            subject = global_subject_context.stack[-1]
            msg = 'A subject instance DOES exist in the global context.  Returning it.'
            return subject
        except IndexError:
            msg = 'A subject instance _DOES NOT_ exist in the global context.  Creating one.'
            logger.debug(msg)

            yosai = Yosai.get_current_yosai()
            subject = yosai._get_subject()
            global_subject_context.stack.append(subject)
            return subject

    @staticmethod
    def get_current_yosai():
        try:
            return global_yosai_context.stack[-1]
        except IndexError:
            msg = 'A yosai instance does not exist in the global context.'
            raise YosaiContextException(msg)

# Set Global State Managers
global_yosai_context = ThreadStateManager()
global_subject_context = ThreadStateManager()
