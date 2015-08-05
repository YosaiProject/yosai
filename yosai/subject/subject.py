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

from collections import deque
#from concurrency import (Callable, Runnable, SubjectCallable, SubjectRunnable, 
#                         Thread)

from yosai import (
    MapContext,
    DefaultSessionContext,
    DefaultSessionStorageEvaluator,
    DisabledSessionException,
    ExecutionException,
    IllegalArgumentException,
    IllegalStateException,
    InvalidArgumentException,
    InvalidSessionException,
    LogManager,
    NullPointerException,
    ProxiedSession,
    PrimaryIdentifierIntegrityException,
    SecurityUtils,
    SessionException,
    UnauthenticatedException,
    UnavailableSecurityManagerException,
    UnrecognizedIdentifierException,
    UnsupportedOperationException,
    concurrency_abcs,
    subject_abcs,
    account_abcs,
    authc_abcs,
    subject_abcs,
    mgt_abcs,
    session_abcs,
)

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

# reconciled, ready to test:
class DefaultSubjectContext(MapContext, subject_abcs.SubjectContext):
    """
    Yosai notes:  Shiro uses the getTypedValue method to validate objects 
                  as it obtains them from the MapContext.  I've decided that
                  this checking is unecessary overhead in Python and to 
                  instead *assume* that objects are mapped correctly within
                  the MapContext.  Exceptions will raise further down the
                  call stack should a mapping be incorrect.
    """
    def __init__(self, context={}):
        super().__init__(context)
        # yosai takes a different approach to managing key names:
        self._attributes = self.get_initial_context_attributes()

    # new to yosai:
    def get_initial_context_attributes(self):
        dsc_name = self.__class__.__name__
        return {
            "SECURITY_MANAGER": dsc_name + ".SECURITY_MANAGER",
            "SESSION_ID": dsc_name + ".SESSION_ID",
            "AUTHENTICATION_TOKEN": dsc_name + ".AUTHENTICATION_TOKEN", 
            "ACCOUNT": dsc_name + ".ACCOUNT",
            "SUBJECT": dsc_name + ".SUBJECT",
            "PRINCIPALS": dsc_name + ".PRINCIPALS",
            "SESSION": dsc_name + ".SESSION", 
            "AUTHENTICATED": dsc_name + ".AUTHENTICATED",
            "HOST": dsc_name + ".HOST",
            "SESSION_CREATION_ENABLED": dsc_name + ".SESSION_CREATION_ENABLED",
            "PRINCIPALS_SESSION_KEY": dsc_name + "_PRINCIPALS_SESSION_KEY",
            "AUTHENTICATED_SESSION_KEY": (dsc_name + 
                                          "_AUTHENTICATED_SESSION_KEY")}

    @property
    def security_manager(self):
        return self.get(self._attributes['SECURITY_MANAGER'])

    @security_manager.setter
    def security_manager(self, securitymanager):
        self.none_safe_put(
            self._attributes['SECURITY_MANAGER'], securitymanager)
    
    def resolve_security_manager(self): 
        security_manager = self.security_manager
        if (security_manager is None):
            msg = ("No SecurityManager available in subject context map.  " +
                   "Falling back to SecurityUtils.security_manager for" +
                   " lookup.")
            print(msg)
            #  log debug here

            try: 
                security_manager = SecurityUtils.security_manager
            except UnavailableSecurityManagerException as ex:
                msg = ("DefaultSubjectContext.resolve_security_manager cannot "
                       "obtain security_manager! No SecurityManager available "
                       "via SecurityUtils.  Heuristics exhausted.", ex)
                print(msg)
                # log debug here, including exc_info=ex
        
        return security_manager

    @property
    def session_id(self):
        return self.get(self._attributes['SESSION_ID'])
   
    @session_id.setter
    def session_id(self, session_id):
        self.none_safe_put(self._attributes['SESSION_ID'], session_id)

    @property 
    def subject(self):
        return self.get(self._attributes['SUBJECT'])

    @subject.setter
    def subject(self, subject):
            self.none_safe_put(self._attributes['SUBJECT'], subject)

    @property
    def identifiers(self):
        return self.get(self._attributes['PRINCIPALS'])
        
    @identifiers.setter
    def identifiers(self, identifiers):
        self.none_safe_put(self._attributes['PRINCIPALS'], identifiers)

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
                    self._attributes['PRINCIPALS_SESSION_KEY']) 
            except AttributeError:
                pass
            
        return identifiers

    @property
    def session(self):
        return self.get(self._attributes['SESSION'])

    @session.setter
    def session(self, session):
        self.none_safe_put(self._attributes['SESSION'], session)

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
        val = self.get(self._attributes['SESSION_CREATION_ENABLED'])
        return (val is None or val)

    @session_creation_enabled.setter
    def session_creation_enabled(self, enabled):
        self.none_safe_put(
            self._attributes['SESSION_CREATION_ENABLED'], enabled)
    
    @property
    def authenticated(self):
        authc = self.get(self._attributes['AUTHENTICATED'])
        return bool(authc)

    @authenticated.setter
    def authenticated(self, authc):
        self.put(self._attributes['AUTHENTICATED'], authc)

    def resolve_authenticated(self):
        authc = self.authenticated  # a bool
        if authc is None:
            #  see if there is an AuthenticationInfo object.  If so, the very
            #  presence of one indicates a successful authentication attempt:
            authc = (self.account is not None)
        if (not authc):
            #  fall back to a session check:
            session = self.resolve_session()
            if (session is not None):
                session_authc = session.get_attribute(
                    self._attributes['AUTHENTICATED_SESSION_KEY'])
                authc = bool(session_authc)

        return authc 

    @property
    def account(self):
        return self.get(self._attributes['ACCOUNT'])

    @account.setter
    def account(self, account):
        self.none_safe_put(self._attributes['ACCOUNT'], account)

    @property
    def authentication_token(self):
        return self.get(
            self._attributes['AUTHENTICATION_TOKEN'])

    @authentication_token.setter
    def authentication_token(self, token):
        self.none_safe_put(
            self._attributes['AUTHENTICATION_TOKEN'], token)

    @property
    def host(self):
        return self.get(self._attributes['HOST'])

    @host.setter
    def host(self, host):
        self.put(self._attributes['HOST'], host)

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
    
   
class DefaultSubjectStore:

    def __init__(self):
        self._session_storage_evaluator = DefaultSessionStorageEvaluator()

        # DG:need 2 change DefaultSubjectContext to a dict and pass as an param
        self.dsc_psk = 'DefaultSubjectContext_PRINCIPALS_SESSION_KEY'
        self.dsc_ask = 'DefaultSubjectContext_AUTHENTICATED_SESSION_KEY'

    def is_session_storage_enabled(self, subject):
        return self.session_storage_evaluator.\
            is_session_storage_enabled(subject)

    @property
    def session_storage_evaluator(self):
        return self._session_storage_evaluator

    @session_storage_evaluator.setter
    def session_storage_evaluator(self, sse):
        self._session_storage_evaluator = sse

    def save(self, subject):
        if (self.is_session_storage_enabled(subject)):
            self.save_to_session(subject)
        else:
            # log here
            msg = ("Session storage of subject state for Subject [{0}] has "
                   "been disabled: identity and authentication state are "
                   "expected to be initialized on every request or "
                   "invocation.".format(subject))
            print(msg)
        return subject

    def save_to_session(self, subject):
        # performs merge logic, only updating the Subject's session if it 
        # does not match the current state:
        self.merge_identifiers(subject)
        self.merge_authentication_state(subject)

    def merge_identifiers(self, subject):
        """
        This method tries to obtain the attribute _identifiers from a 
        DelegatingSubject object and if _identifiers is not yet set obtains
        through through the property/method 'identifiers' which obtains the
        identifiers off of a deque 'stack'.
        """
        if (bool(subject.is_run_as) 
           and isinstance(subject, DelegatingSubject)):
            current_identifiers = subject._identifiers  # direct access
        
        if (not current_identifiers):
            current_identifiers = subject.identifiers  # indirect, method-based

        session = subject.get_session(False)
        if (not session):
            if (current_identifiers):
                session = subject.get_session()  # True is default
                setattr(session, self.dsc_psk, current_identifiers)
            # otherwise no session and no identifiers - nothing to save
        else:
            existing_identifiers = session.get_attribute(self.dsc_psk)

            if (not current_identifiers):
                if (existing_identifiers):
                    session.remove_attribute(self.dsc_psk)
                # otherwise both are null or empty - no need to update session
            else:
                if (current_identifiers == existing_identifiers):
                    session.set_attribute(self.dsc_psk, current_identifiers)
                # otherwise they're the same - no need to update the session

    def merge_authentication_state(self, subject):
        session = subject.get_session(False)

        if (not session):
            if (subject.authenticated):
                session = subject.get_session()
                session.set_attribute(self.dsc_ask, bool(True))
            # otherwise no session and not authenticated - nothing to save
        else:
            existing_authc = session.get_attribute(self.dsc_ask)

            if (subject.authenticated):
                if (not existing_authc):
                    session.set_attribute(self.dsc_ask, bool(True))   
                # otherwise authc state matches - no need to update the session
            else:
                if (existing_authc):
                    # existing doesn't match the current state - remove it:
                    session.remove_attribute(self.dsc_ask)
                # otherwise not in the session and not authenticated and 
                # no need to update the session

    def remove_from_session(self, subject):
        session = subject.get_session(False)
        if (session):
            session.remove_attribute(self.dsc_ask)
            session.remove_attribute(self.dsc_psk)

    def delete(self, subject):
        self.remove_from_session(subject)


class DelegatingSubject:
    """
    DelegatingSubject is a facade between a Subject and the underlying
    SecurityManager
    """

    def __init__(self, identifiers=None,
                 authenticated=False, host=None, session=None,
                 session_creation_enabled=True,
                 security_manager=None):
        try:
            if (not security_manager):
                raise IllegalArgumentException
        except IllegalArgumentException as ex:
            print('DelegatingSubject Exception at init:' +
                  'security_manager cannot be null.', ex)
        else:
            self._security_manager = security_manager 
        
        self._identifiers = identifiers
        self._authenticated = authenticated 
        self._host = host 
        if (session is not None):
            self._session = self.decorate_session(session)  # shiro's decorate
        self._session_creation_enabled = session_creation_enabled 
        self._RUN_AS_PRINCIPALS_SESSION_KEY = (
            self.__class__.__name__ + ".RUN_AS_PRINCIPALS_SESSION_KEY")
    
    @property
    def authenticated(self):
        return self._authenticated
    
    @authenticated.setter
    def authenticated(self, authc):
        try:
            if isinstance(authc, bool): 
                self._authenticated = authc    
            else:
                raise TypeError
        except TypeError:
            print('DelegatingSubject.authenticated.setter:  wrong objtype')
    
    @property
    def is_run_as(self):
        return bool(self.get_run_as_identifiers_stack())

    @property
    def has_identifiers(self):
        return (self._identifiers is not None)

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        try:
            if isinstance(host, str) and (host): 
                self._host = host
            else:
                raise TypeError
        except TypeError:
            print('DelegatingSubject.host.setter:  wrong object type')

    @property
    def primary_identifier(self):
        return self._identifiers.primary_identifier

    @property
    def identifiers(self):
        # expecting a List of IdentifierCollection objects:
        run_as_identifiers = self.get_run_as_identifiers_stack()
        if (run_as_identifiers):
            return run_as_identifiers[0]  # DG:  I dont feel good about this!
        else:
            return self._identifiers    

    @identifiers.setter
    def identifiers(self, identifiers):
        try:
            if isinstance(identifiers, subject_abcs.IdentifierCollection):
                self._identifiers = identifiers
            else:
                raise TypeError
        except TypeError:
            print('DelegatingSubject.identifiers.setter:  wrong type of object')

    @property
    def security_manager(self):
        return self._security_manager

    @security_manager.setter
    def security_manager(self, security_manager):
        try:
            if isinstance(security_manager, mgt_abcs.SecurityManager):
                self._security_manager = security_manager
            else:
                raise TypeError
        except TypeError:
            print('DelegatingSubject.security_manager.setter:  wrong objtype')

    @property
    def session(self):
        return self._session

    @session.setter
    def session(self, session):
        try:
            if isinstance(session, session_abcs.Session):
                self._session = session
            else:
                raise TypeError
        except TypeError:
            print('DelegatingSubject.session.setter :  wrong type of object')

    @property
    def session_creation_enabled(self):
        """
        Returns true if this Subject is allowed to create sessions, false 
        otherwise.
        """
        return self.session_creation_enabled
    
    def is_permitted(self, scope, permissions):
        """ 
        DG:  modified shiro specs to include scope because authorization
             is always scope-specific (that is, the context of an authz 
             request matters, and that context is defined by scope)

        Input:
                permissions = a List of permission Tuples:
                (permtype, operation, objectype, objectgroupid, objectid)


            Output:
                a List of Booleans representing whether permission is 
                granted to the corresponding permission Tuple recieved as
                input
        """
        if (self.has_identifiers()):
                return self._security_manager.is_permitted(
                    scope, self.identifiers, permissions)
        else:
            return [False for x in permissions] 

    def is_permitted_all(self, scope, permissions):
        """ 
        DG:  modified shiro specs to include scope because authorization
             is always scope-specific (that is, the context of an authz 
             request matters, and that context is defined by scope)

        Input:
                permissions = a List of permission Tuples:
                (permtype, operation, objectype, objectgroupid, objectid)


            Output:
                a List of Booleans representing whether permission is 
                granted to the corresponding permission Tuple recieved as
                input
        """
        return (self.has_identifiers() and
                self._security_manager.is_permitted_all(
                scope, self.identifiers, permissions))

    def assert_authz_check_possible(self):
        try:
            if (self.identifiers):
                msg = (
                    "This subject is anonymous - it does not have any " +
                    "identifying identifiers and authorization operations " +
                    "required an identity to check against.  A Subject " +
                    "instance will acquire these identifying identifiers " +
                    "automatically after a successful login is performed be " +
                    "executing " + self.__class__.__name__ + 
                    ".login(AuthenticationToken) or when 'Remember Me' " +
                    "functionality is enabled by the SecurityManager.  " +
                    "This exception can also occur when a previously " +
                    "logged-in Subject has logged out which makes it " +
                    "anonymous again.  Because an identity is currently not " +
                    "known due to any of these conditions, authorization is " +
                    "denied.")
                raise UnauthenticatedException(msg)
        except UnauthenticatedException as ex:
            print('DelegatingSubject: ', ex)

    def check_permission(self, permission):
        try:
            self.assert_authz_check_possible()
        except:
            raise
        else:
            self._security_manager.check_permission(self.identifiers,
                                                    permission)
    
    def check_permissions(self, permissions):
        try:
            self.assert_authz_check_possible()
        except:
            raise
        else:
            self._security_manager.check_permissions(self.identifiers,
                                                     permissions)

    # DG:  I am omitting any role-based methods for first release..
    #      no role-level authorization in the system -- only permission-level

    def login(self, auth_token):
        try:
            self.clear_run_as_identities_internal()
            subject = self._security_manager.login(self, auth_token)

            if (isinstance(subject, DelegatingSubject)):
                delegating = subject
                # we localize attributes in case there are assumed 
                # identities --  we don't want to lose the 'real' identifiers:
                identifiers = delegating.identifiers
                host = delegating.host
            else:
                identifiers = subject.identifiers

            if(not identifiers):
                msg = ("Identifiers returned from securityManager.login(token" +
                       ") returned a null or empty value. This value must be" +
                       " non-null and populated with one or more elements.")
                raise IllegalStateException(msg)
            
            self.identifiers = identifiers
            self.authenticated = True

            if isinstance(auth_token, authc_abcs.HostAuthenticationToken):
                host = auth_token.host

            if (host):
                self.host = host

            session = subject.get_session(False)
            if (session):
                self.session = self.decorate_session(session)
            else:
                self.session = None

        except IllegalStateException as ex:
            print('login Exception:', ex)

        except Exception as ex:
            print('DelegatingSubject.login: Unhandled Exception!', ex)

    def get_session(self, create=True):
        # log how you're attempting to create a session, with details
        if (not self.session and create):
            try:
                if (self.session_creation_enabled): 
                    msg = ("Session creation has been disabled for the current" 
                           " subject. This exception indicates that there is "
                           "either a programming error (using a session when " 
                           "it should never be used) or that Shiro's " 
                           "configuration needs to be adjusted to allow " 
                           "Sessions to be created for the current Subject.")
                    raise DisabledSessionException(msg)
            except DisabledSessionException as ex:
                print('DelegatingSubject.get_session: ', ex) 
            else:
                # log here that you're starting session for host xyz
                session_context = self.create_session_context()
                session = self.security_manager.start(session_context)
                self.session = self.decorate_session(session)
        
        return self.session

    def create_session_context(self):
        session_context = DefaultSessionContext()
        if (self.host):
            session_context.host = self.host
        return session_context

    def clear_run_as_identities_internal(self):
        try:
            self.clear_run_as_identities()
        except SessionException as se:
            # log here
            print("clearrunasidentitiesinternal: Encountered session "
                  "exception trying to clear 'runAs' identities during "
                  "logout.  This can generally safely be ignored.", se)

    def logout(self):
        try:
            self.clear_run_as_identities_internal()
            self.security_manager.logout(self)
        except:
            raise
        finally:
            # bypassing the validated setters:
            self._session = None
            self._identifiers = None
            self._authenticated = False
            """
            Don't set securityManager to null here - the Subject can still be
            used, it is just considered anonymous at this point.  
            The SecurityManager instance is necessary if the subject would 
            log in again or acquire a new session. 
            """

    def session_stopped(self):
        # DG: bypassing validated session setter:
        self._session = None

    def execute(self, _able):
        # DG: combined execute and associatewith methods
        try:
            if isinstance(_able, concurrency_abcs.Callable):
                associated = SubjectCallable(self, _able) 
                return associated.call()

            elif isinstance(_able, concurrency_abcs.Runnable):
                if isinstance(_able, Thread):
                    msg = ("This implementation does not support Thread args."
                           "Instead, the method argument should be a "
                           "non-Thread Runnable and the return value from "
                           "this method can then be given to an "
                           "ExecutorService or another Thread.")
                    raise UnsupportedOperationException(msg)
                else:
                    associated = SubjectRunnable(self, _able) 
                    associated.run()
        except UnsupportedOperationException as ex:
            print('DelegatingSubject.execute:  UnsupportedOperationException',
                  ex)
        except ExecutionException:
            print('DelegatingSubject.execute:  ExecutionException')

    def run_as(self, identifiers):
        if (not self.has_identifiers()):
            msg = ("This subject does not yet have an identity.  Assuming the "
                   "identity of another Subject is only allowed for Subjects "
                   "with an existing identity.  Try logging this subject in "
                   "first, or using the " + Subject.Builder.__name__ + 
                   "to build ad hoc Subject instances with identities as "
                   "necessary.")
            raise IllegalStateException(msg)
        else: 
            self.push_identity(identifiers)

    def get_previous_identifiers(self):
        stack = self.get_run_as_identifiers_stack()
        if (not stack):
            stack_size = 0
        else:
            stack_size = len(stack)

        if (stack_size > 0):
            if (stack_size == 1):
                previous_identifiers = self.identifiers
            else:
                # always get the one behind the current
                previous_identifiers = stack[1]
        return previous_identifiers

    def release_run_as(self):
        return self.pop_identity()

    def get_run_as_identifiers_stack(self):
        session = self.get_session(False)
        if (session is not None):
            """
            expecting a List of IdentifierCollection objects:
            """
            return getattr(self._session, self._RUN_AS_PRINCIPALS_SESSION_KEY)
        return None 

    def clear_run_as_identities(self):
        session = self.get_session(False)
        if (session is not None): 
            delattr(session, self._RUN_AS_PRINCIPALS_SESSION_KEY)

    def push_identity(self, identifiers):
        try:
            if (not identifiers):
                msg = ("Specified Subject identifiers cannot be null or empty "
                       "for 'run as' functionality.")
                raise NullPointerException(msg)

        except NullPointerException as ex:
            print('DelegatingSubject.push_identity NullPointerException', ex)

        else: 
            stack = self.get_run_as_identifiers_stack()
            if (not stack):
                stack = deque() 
            stack.appendleft(identifiers)
            session = self.get_session()  # initializes a session if one DNE
            setattr(session, self._RUN_AS_PRINCIPALS_SESSION_KEY, stack)
    
    def pop_identity(self):
        stack = self.get_run_as_identifiers_stack()
        if (stack): 
            popped = stack.popleft()
            if (stack):
                # persist the changed stack to the session
                session = self.get_session()
                setattr(session, self._RUN_AS_PRINCIPALS_SESSION_KEY, stack)
            else: 
                # stack is empty, remove it from the session:
                self.clear_run_as_identities()
        return popped

    def decorate_session(self, session):
        try:
            if (not session):
                raise IllegalArgumentException
        except IllegalArgumentException as ex:
            print('DelegatingSubject.decorate_session:' +
                  'session cannot be null.', ex)
        else:
            return StoppingAwareProxiedSession(session, self)

    class SubjectBuilder:
        
        def __init__(self,
                     securitymanager=SecurityUtils.security_manager):

            if (securitymanager is None):
                msg = "SecurityManager method argument cannot be null."
                raise InvalidArgumentException(msg)
            
            self.security_manager = securitymanager
            self.subject_context = self.newcontext_instance()
            if (self.subject_context is None):
                msg = ("Subject instance returned from" 
                       "'newcontext_instance' cannot be null.")
                raise IllegalStateException(msg)
            self.subject_context.security_manager = securitymanager
      
        def newcontext_instance(self):
                return DefaultSubjectContext()

        def session_id(self, session_id):
            if (session_id):
                self.context.session_id = session_id
            return self

        def host(self, host):
            if (host):
                self.context.host = host
            return self
            
        def session(self, session):
            if (session):
                self.context.session = session
            return self

        def identifiers(self, identifiers):
            if (identifiers):
                self.context.identifiers = identifiers
            return self

        def session_creation_enabled(self, enabled):
            if (enabled):
                self.context.set_session_creation_enabled = enabled
            return self

        def authenticated(self, authenticated):
            if (authenticated):
                self.context.authenticated = authenticated
            return self

        def context_attribute(self, attribute_key, attribute_value):
            if (not attribute_key):
                msg = "Subject context map key cannot be null."
                raise IllegalArgumentException(msg) 
            elif (not attribute_value):
                self.remove(attribute_key)
            else:
                self.put(attribute_key, attribute_value)
            return self

        def build_subject(self):
            return self._security_manager.create_subject(self.subject_context)


class StoppingAwareProxiedSession:

    def __init__(self, target_session, owning_subject): 
        self._proxied_session = ProxiedSession(target_session)
        self._owner = owning_subject

    def stop(self):
        try:
            self._proxied_session.stop()
        except InvalidSessionException:
            pass
        self._owner.session_stopped()

