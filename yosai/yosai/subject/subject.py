from collections import deque
from concurrency import (Callable, Runnable, SubjectCallable, SubjectRunnable, 
                         Thread)

from yosai import (
    AuthenticationInfo, 
    AuthenticationToken, 
    Context,
    DefaultSessionContext,
    DisabledSessionException,
    ExecutionException,
    HostAuthenticationToken,
    LogManager,
    NullPointerException,
    ProxiedSession,
    PrimaryPrincipalIntegrityException,
    PrincipalCollection,
    SecurityManager,
    SecurityUtils,
    Session,
    SessionException,
    Subject,
    UnrecognizedPrincipalException,
    UnsupportedOperationException,
)


class DefaultSubjectContext(object):

    # DG:  using composition rather than inheritance..

    def __init__(self):
        self._attributes = self.get_initial_context_attributes()
        self._subject_context = Context(context_type='SUBJECT')

    def get_initial_context_attributes(self):
        dsc_name = self.__class__.__name__
        return {
            "SECURITY_MANAGER": dsc_name + ".SECURITY_MANAGER",
            "SESSION_ID": dsc_name + ".SESSION_ID",
            "AUTHENTICATION_TOKEN": dsc_name + ".AUTHENTICATION_TOKEN", 
            "AUTHENTICATION_INFO": dsc_name + ".AUTHENTICATION_INFO",
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
        return self._subject_context.get_and_validate(
            self._attributes['SECURITY_MANAGER'], SecurityManager)

    @security_manager.setter
    def security_manager(self, security_manager):
        setattr(self._subject_context, 
                str(self._attributes['SECURITY_MANAGER']), 
                security_manager)

    @property
    def session_id(self):
        return self._subject_context.get_and_validate(
            self._attributes['SESSION_ID'], str)  # was Serializable class
   
    @session_id.setter
    def session_id(self, session_id):
        if isinstance(session_id, str):
            setattr(self._subject_context, 
                    str(self._attributes['SESSION_ID']), 
                    session_id)

    @property 
    def subject(self):
        return self._subject_context.get_and_validate(
            self._attributes['SUBJECT'], Subject)

    @subject.setter
    def subject(self, subject):
        if isinstance(subject, Subject):
            setattr(self._subject_context, 
                    str(self._attributes['SUBJECT']), 
                    subject)

    @property
    def principals(self):
        return self._subject_context.get_and_validate(
            self._attributes['PRINCIPALS'], PrincipalCollection)
        
    @principals.setter
    def principals(self, principals):
        if isinstance(principals, PrincipalCollection):
            setattr(self._subject_context, 
                    str(self._attributes['PRINCIPALS']), 
                    principals)

    @property
    def session(self):
        return self._subject_context.get_and_validate(
            self._attributes['SESSION'], Session)

    @session.setter
    def session(self, session):
        if isinstance(session, Session):
            setattr(self._subject_context, 
                    str(self._attributes['SESSION']), 
                    session)

    def resolve_session(self):
        if (not self.session):
            # try the Subject, if it exists:
            if (self.subject is not None):
                session = self.subject.get_session(False)

        return session

    @property
    def session_creation_enabled(self):
        val = self._subject_context.get_and_validate(
            self._attributes['SESSION_CREATION_ENABLED'], bool)
        return (val is None or val)

    @session_creation_enabled.setter
    def session_creation_enabled(self, enabled):
        if isinstance(enabled, bool):
            setattr(self._subject_context, 
                    str(self._attributes['SESSION_CREATION_ENABLED']), 
                    enabled)

    @property
    def authenticated(self):
        authc = self._subject_context.get_and_validate(
            self._attributes['AUTHENTICATED'], bool)
        return (authc is not None and authc)

    @authenticated.setter
    def authenticated(self, authc):
        if isinstance(authc, bool):
            setattr(self._subject_context, 
                    str(self._attributes['AUTHENTICATED']), 
                    authc)

    @property
    def authentication_info(self):
        return self._subject_context.get_and_validate(
            self._attributes['AUTHENTICATION_INFO'], AuthenticationInfo)

    @authentication_info.setter
    def authentication_info(self, info):
        if isinstance(info, AuthenticationInfo):
            setattr(self._subject_context, 
                    str(self._attributes['AUTHENTICATION_INFO']), 
                    info)

    @property
    def authentication_token(self):
        return self._subject_context.get_and_validate(
            self._attributes['AUTHENTICATION_TOKEN'], AuthenticationToken)

    @authentication_token.setter
    def authentication_token(self, token):
        if isinstance(token, AuthenticationToken):
            setattr(self._subject_context, 
                    str(self._attributes['AUTHENTICATION_TOKEN']), 
                    token)

    @property
    def host(self):
        return self._subject_context.get_and_validate(
            self._attributes['HOST'], str)

    @host.setter
    def host(self, host):
        if (isinstance(host, str) and (host)):
            setattr(self._subject_context, 
                    str(self._attributes['HOST']), 
                    host)

    def resolve_authenticated(self):
        authc = self.authenticated  # a bool
        if (not authc):
            #  see if there is an AuthenticationInfo object.  If so, the very
            #  presence of one indicates a successful authentication attempt:
            authc = (self.authentication_info is not None)
        if (not authc):
            #  fall back to a session check:
            session = self.resolve_session()
            if (session is not None):
                authc = bool(getattr(
                    session, 
                    self._attributes['AUTHENTICATED_SESSION_KEY']))

        return authc 

    def resolve_host(self):
        host = self.host
        if(not host):
            # check to see if there is an AuthenticationToken from which to
            # retrieve it: 
            if (isinstance(self.authentication_token, 
                           HostAuthenticationToken)):
                host = self.authentication_token.host

        if (not host):
            session = self.resolve_session()
            if (session):
                host = session.host

        return host
    
    def resolve_principals(self):
        principals = None 

        # sequence matters:
        sources = [self.principals, self.authentication_info, 
                   self.subject]

        for x in sources:
            if (x):
                if (x.principals):
                    principals = x.principals
                    break

        # otherwise, use the session key as the principal:
        if (not principals):
            session = self.resolve_session()
            principals = getattr(session, 
                                 self._attributes['PRINCIPALS_SESSION_KEY']) 
            
        return principals


    def resolve_security_manager(self): 
        security_manager = self.get_security_manager()
        if (security_manager is None):
            #  add logging here
            print("No SecurityManager available in subject context map.  " +
                  "Falling back to SecurityUtils.get_security_manager() for" +
                  " lookup.")
            try: 
                security_manager = SecurityUtils.get_security_manager()
            except UnavailableSecurityManagerException as ex:
                # log here
                msg = ("DefaultSubjectContext.resolve_security_manager cannot "
                       "obtain security_manager! No SecurityManager available "
                       "via SecurityUtils.  Heuristics exhausted.")
                print(msg, ex)
        
        return security_manager


class DefaultSubjectDAO(object):

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
        self.merge_principals(subject)
        self.merge_authentication_state(subject)

    def merge_principals(self, subject):
        """
        This method tries to obtain the attribute _principals from a 
        DelegatingSubject object and if _principals is not yet set obtains
        through through the property/method 'principals' which obtains the
        principals off of a deque 'stack'.
        """
        if (bool(subject.is_run_as) 
           and isinstance(subject, DelegatingSubject)):
            current_principals = subject._principals  # direct access
        
        if (not current_principals):
            current_principals = subject.principals  # indirect, method-based

        session = subject.get_session(False)
        if (not session):
            if (current_principals):
                session = subject.get_session()  # True is default
                setattr(session, self.dsc_psk, current_principals)
            # otherwise no session and no principals - nothing to save
        else:
            existing_principals = session.get_attribute(self.dsc_psk)

            if (not current_principals):
                if (existing_principals):
                    session.remove_attribute(self.dsc_psk)
                # otherwise both are null or empty - no need to update session
            else:
                if (current_principals == existing_principals):
                    session.set_attribute(self.dsc_psk, current_principals)
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


class DefaultSubjectFactory(object):
    
    def __init__(self):
        pass

    def create_subject(self, subject_context):
        security_manager = subject_context.resolve_security_manager()
        session = subject_context.resolve_session()
        session_creation_enabled = subject_context.session_creation_enabled
        principals = subject_context.resolve_principals()
        authenticated = subject_context.resolve_authenticated()
        host = subject_context.resolve_host()

        return DelegatingSubject(principals, authenticated, host, session,
                                 session_creation_enabled, security_manager)


class DelegatingSubject(object):
    """
    DelegatingSubject is a facade between a Subject and the underlying
    SecurityManager
    """

    def __init__(self, principals=None,
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
        
        self._principals = principals
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
        return bool(self.get_run_as_principals_stack())

    @property
    def has_principals(self):
        return (self._principals is not None)

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
    def primary_principal(self):
        return self._principals.primary_principal

    @property
    def principals(self):
        # expecting a List of PrincipalCollection objects:
        run_as_principals = self.get_run_as_principals_stack()
        if (run_as_principals):
            return run_as_principals[0]  # DG:  I dont feel good about this!
        else:
            return self._principals    

    @principals.setter
    def principals(self, principals):
        try:
            if isinstance(principals, PrincipalCollection):
                self._principals = principals
            else:
                raise TypeError
        except TypeError:
            print('DelegatingSubject.principals.setter:  wrong type of object')

    @property
    def security_manager(self):
        return self._security_manager

    @security_manager.setter
    def security_manager(self, security_manager):
        try:
            if isinstance(security_manager, SecurityManager):
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
            if isinstance(session, Session):
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
        if (self.has_principals()):
                return self._security_manager.is_permitted(
                    scope, self.principals, permissions)
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
        return (self.has_principals() and
                self._security_manager.is_permitted_all(
                scope, self.principals, permissions))

    def assert_authz_check_possible(self):
        try:
            if (self.principals):
                msg = (
                    "This subject is anonymous - it does not have any " +
                    "identifying principals and authorization operations " +
                    "required an identity to check against.  A Subject " +
                    "instance will acquire these identifying principals " +
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
            self._security_manager.check_permission(self.principals,
                                                    permission)
    
    def check_permissions(self, permissions):
        try:
            self.assert_authz_check_possible()
        except:
            raise
        else:
            self._security_manager.check_permissions(self.principals,
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
                # identities --  we don't want to lose the 'real' principals:
                principals = delegating.principals
                host = delegating.host
            else:
                principals = subject.principals

            if(not principals):
                msg = ("Principals returned from securityManager.login(token" +
                       ") returned a null or empty value. This value must be" +
                       " non-null and populated with one or more elements.")
                raise IllegalStateException(msg)
            
            self.principals = principals
            self.authenticated = True

            if isinstance(auth_token, HostAuthenticationToken):
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
            self._principals = None
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
            if isinstance(_able, Callable):
                associated = SubjectCallable(self, _able) 
                return associated.call()

            elif isinstance(_able, Runnable):
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

    def run_as(self, principals):
        if (not self.has_principals()):
            msg = ("This subject does not yet have an identity.  Assuming the "
                   "identity of another Subject is only allowed for Subjects "
                   "with an existing identity.  Try logging this subject in "
                   "first, or using the " + Subject.Builder.__name__ + 
                   "to build ad hoc Subject instances with identities as "
                   "necessary.")
            raise IllegalStateException(msg)
        else: 
            self.push_identity(principals)

    def get_previous_principals(self):
        stack = self.get_run_as_principals_stack()
        if (not stack):
            stack_size = 0
        else:
            stack_size = len(stack)

        if (stack_size > 0):
            if (stack_size == 1):
                previous_principals = self.principals
            else:
                # always get the one behind the current
                previous_principals = stack[1]
        return previous_principals

    def release_run_as(self):
        return self.pop_identity()

    def get_run_as_principals_stack(self):
        session = self.get_session(False)
        if (session is not None):
            """
            expecting a List of PrincipalCollection objects:
            """
            return getattr(self._session, self._RUN_AS_PRINCIPALS_SESSION_KEY)
        return None 

    def clear_run_as_identities(self):
        session = self.get_session(False)
        if (session is not None): 
            delattr(session, self._RUN_AS_PRINCIPALS_SESSION_KEY)

    def push_identity(self, principals):
        try:
            if (not principals):
                msg = ("Specified Subject principals cannot be null or empty "
                       "for 'run as' functionality.")
                raise NullPointerException(msg)

        except NullPointerException as ex:
            print('DelegatingSubject.push_identity NullPointerException', ex)

        else: 
            stack = self.get_run_as_principals_stack()
            if (not stack):
                stack = deque() 
            stack.appendleft(principals)
            session = self.get_session()  # initializes a session if one DNE
            setattr(session, self._RUN_AS_PRINCIPALS_SESSION_KEY, stack)
    
    def pop_identity(self):
        stack = self.get_run_as_principals_stack()
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

    class SubjectBuilder(object):
        
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
                self._subject_context.session_id = session_id
            return self

        def host(self, host):
            if (host):
                self._subject_context.host = host
            return self
            
        def session(self, session):
            if (session):
                self._subject_context.session = session
            return self

        def principals(self, principals):
            if (principals):
                self._subject_context.principals = principals
            return self

        def session_creation_enabled(self, enabled):
            if (enabled):
                self._subject_context.set_session_creation_enabled = enabled
            return self

        def authenticated(self, authenticated):
            if (authenticated):
                self._subject_context.authenticated = authenticated
            return self

        def context_attribute(self, attribute_key, attribute_value):
            if (not attribute_key):
                msg = "Subject context map key cannot be null."
                raise IllegalArgumentException(msg) 
            elif (not attribute_value):
                self._subject_context.remove(attribute_key)
            else:
                self._subject_context.put(attribute_key, attribute_value)
            return self

        def build_subject(self):
            return self._security_manager.create_subject(self.subject_context)


class StoppingAwareProxiedSession(object):

    def __init__(self, target_session, owning_subject): 
        self._proxied_session = ProxiedSession(target_session)
        self._owner = owning_subject

    def stop(self):
        try:
            self._proxied_session.stop()
        except InvalidSessionException:
            pass
        self._owner.session_stopped()

