import copy
from collections import defaultdict

from yosai import(
    Authorizer,
    AuthenticationException,
    CacheManager,
    DefaultAuthenticator,
    DisabledCacheManager,
    DefaultSessionManager,
    DefaultSessionContext,
    DefaultSessionKey,
    DefaultSubjectContext,
    Eventbus,
    IllegalArgumentException,
    IncorrectAttributeException,
    InvalidSessionException,
    LogManager,
    ModularRealmAuthorizer,
    Realm,
    SessionManager,
    SubjectDAO,
    SubjectFactory,
    Subject,
    UnavailableSecurityManagerException,
    UnrecognizedAttributeException,
)

from . import (
    ILogoutAware,
)


class SecurityUtils(object):
    def __init__(self):
        self._security_manager = SecurityManager()

    def get_subject(self):
        subject = ThreadContext.subject
        if (subject is None):
            subject = Subject.Builder().build_subject()
            ThreadContext.bind(subject)
   
    @property
    def security_manager(self):
        try: 
            security_manager = ThreadContext.security_manager
            if (security_manager is None):
                security_manager = self._security_manager
                msg = "No SecurityManager accessible to the calling code."
                raise UnavailableSecurityManagerException(msg)
        except UnavailableSecurityManagerException as ex:
            print(ex)
        else:
            return security_manager
        
    @security_manager.setter
    def security_manager(self, security_manager):
        self._security_manager = security_manager


class ApplicationSecurityManager(object):
    """
    excluded:  any RememberMeManager functionality
    """
    def __init__(self):
        self._realms = defaultdict(list) 
        self._event_bus = EventBus()  # DG:  shiro creates a default ver
        self.set_cache_manager(DisabledCacheManager())
        
        # new to Yosai is the injection of the eventbus:
        self.set_authenticator(DefaultAuthenticator(self._event_bus))

        self.set_authorizer(ModularRealmAuthorizer()) 
        self._session_manager = SessionManager()
        self._subject_DAO = SubjectDAO()
        self._subject_factory = SubjectFactory()

    """
    * ===================================================================== *
    * Getters and Setters                                                   *
    * ===================================================================== *
    """
    @property
    def authenticator(self):
        return self._authenticator

    @authenticator.setter
    def authenticator(self, authenticator):
        try:
            if (authenticator):
                self._authenticator = authenticator

                if (isinstance(self.authenticator, DefaultAuthenticator)):
                    self.authenticator.realms = self.realms  # was set_realms
                
                self.apply_event_bus(self.authenticator)
                self.apply_cache_manager(self.authenticator)
            
            else:
                raise IncorrectAttributeException

        except IncorrectAttributeException:
            print(myself() + ': Incorrect authenticator parameter. ')

    @property
    def authorizer(self):
        return self._authorizer

    @authorizer.setter
    def authorizer(self, authorizer):
        try:
            if (authorizer):
                self._authorizer = authorizer
                self.apply_event_bus(self.authorizer)
                self.apply_cache_manager(self.authorizer)
            else: 
                raise IncorrectAttributeException
        
        except IncorrectAttributeException as ex:
            print(myself() + ': Incorrect parameter. Authorizer cannot be '
                  'None', ex)

    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        try:
            if (cachemanager):
                self._cache_manager = cachemanager
                self.apply_cache_manager(
                    self.get_dependencies_for_injection(self.cache_manager))

            else: 
                raise IncorrectAttributeException
        
        except IncorrectAttributeException as ex:
            print(myself() + ': Incorrect parameter.  If you want to disable'
                  ' caching, configure a disabled cachemanager instance', ex)

    @property
    def event_bus(self):
        return self._event_bus

    @event_bus.setter
    def event_bus(self, eventbus):
        try:
            if (eventbus):
                self._event_bus = eventbus
                self.apply_event_bus(
                    self.get_dependencies_for_injection(self._event_bus))
            else:
                raise IncorrectAttributeException

        except IncorrectAttributeException:
            print(myself() + ': Incorrect parameter. ')

    @property
    def realms(self):
        return self._realms

    @realms.setter
    def realms(self, realms):
        try:
            if (realms):
                immutable_realms_collection = tuple(realms)

                self.realms = immutable_realms_collection
                self.apply_event_bus(self.realms)
                self.apply_cache_manager(self.realms)
                authc = self.authenticator
                if (isinstance(authc, DefaultAuthenticator)):
                    authc.set_realms(immutable_realms_collection)
   
                authz = self.authorizer
                if (isinstance(authz, ModularRealmAuthorizer)):
                    authz.set_realms(immutable_realms_collection)
                
            else: 
                raise IncorrectAttributeException
        
        except IncorrectAttributeException as ex:
            print(myself() + ': Incorrect realms parameter. ', ex)

    @property
    def session_manager(self):
        return self._session_manager

    @session_manager.setter
    def session_manager(self, sessionmanager):
        self._session_manager = sessionmanager
   
    @property
    def subject_factory(self): 
        return self._subject_factory

    @subject_factory.setter
    def subject_factory(self, subjectfactory): 
        self._subject_factory = subjectfactory

    @property
    def subject_DAO(self):
        return self._subject_DAO

    @subject_DAO.setter
    def subject_DAO(self, subjectdao):
        self.subject_DAO = subjectdao

    def apply_cache_manager(self, target):
        if (isinstance(target, set)):
            my_collection = target 
            for element in my_collection:
                self.apply_cache_manager(element)
        
        elif (target.cache_manager):  # DG:  then cache manager aware!
            target.cache_manager = self.cache_manager

    def apply_event_bus(self, target):
        if (isinstance(target, set)):
            my_collection = target
            for item in my_collection: 
                self.apply_event_bus(item)
        
        elif (target.event_bus):
            target.event_bus = self.event_bus

    def get_dependencies_for_injection(self, ignore):
        deps = {self.event_bus, self.cache_manager, self.realms, 
                self.authenticator, self.authorizer,
                self.session_manager, self.subject_DAO,
                self.subject_factory}
        if (ignore is not None):
            deps.remove(ignore)
        
        return deps
    
    """
    * ===================================================================== *
    * Authenticator Methods                                                 *
    * ===================================================================== *
    """
    def authenticate(self, authc_token):
        return self.authenticator.authenticate(authc_token)

    def authenticate_account(self, authc_token):
        return self.authenticator.authenticate_account(authc_token)

    """
    * ===================================================================== *
    * Authorizer Methods                                                    *
    * ===================================================================== *
    """

    def is_permitted(self, principals, permissions):
        """
        Input:
            principals = a List
            permissions = a Set of Permission Tuples

        Output:
            a List of Booleans corresponding to the permission elements
        """
        return self.authorizer.is_permitted(principals, permissions)

    def check_permission(self, principals, permissions):
        return self.authorizer.check_permission(principals, permissions)

    # DG:  I removed the role-related functionality.  It can be added in
    #      later versions.

    """
    * ===================================================================== *
    * session_manager Methods                                                *
    * ===================================================================== *
    """
    def start(self, session_context):  # DG: should rename to start_session
        try:
            return self.session_manager.start(session_context)
        except:
            raise

    def get_session(self, session_key):
        try:
            return self.session_manager.get_session(session_key)
        except:
            raise
    
    """
    * ===================================================================== *
    * security_manager Methods                                               *
    * ===================================================================== *
    """

    def create_subject_context(self):
        return DefaultSubjectContext()

    def create_subject(self, **kwargs): 
        acceptable_args = ['authc_token', 'authc_info', 'existing_subject', 
                           'subject_context']
        try:
            for key in kwargs.keys():
                if key not in acceptable_args:
                    raise UnrecognizedAttributeException(key)
        except UnrecognizedAttributeException as ex: 
            print('create_subject received unrecognized attribute:', ex)
            return

        existing_subject = kwargs.get('existing_subject', None)
        subject_context = kwargs.get('subject_context', None)

        if (subject_context):

            context = copy.deepcopy(subject_context)

            # ensure that the context has a security_manager instance, and if
            # not, add one: 
            context = self.ensure_security_manager(context)

            """
            Resolve an associated Session (usually based on a referenced
            session ID), and place it in the context before sending to the
            subject_factory.  The subject_factory should not need to know how
            to acquire sessions as the process is often environment specific -
            better to shield the SF from these details: """
            context = self.resolve_session(context)

            """
            Similarly, the subject_factory should not require any concept of
            remember_me - translate that here first if possible before handing
            off to the subject_factory:
            """
            context = self.resolve_principals(context)
            subject = self.do_create_subject(context)

            """
            save self subject for future reference if necessary:
            (self is needed here in case remember_me principals were resolved
            and they need to be stored in the session, so we don't constantly
            rehydrate the remember_me principal_collection on every operation).
            """
            self.save(subject)
            return subject
        
        else:

            context = self.create_subject_context()
            context.authenticated = True
            context.authentication_token = kwargs.get('authc_token', None)
            context.authentication_info = kwargs.get('authc_info', None)
            if (existing_subject):
                context.subject = existing_subject 
            return self.create_subject(context)
    
    def login(self, subject, authc_token): 
        """ DG: I removed any trace of remember_me functionality """
        try:
            authc_info = self.authenticate(authc_token)
        except AuthenticationException as ex: 
            raise ex

        logged_in = self.create_subject(authc_token, authc_info, subject)
        return logged_in

    def do_create_subject(self, subject_context):
        return self.get_subject_factory().create_subject(subject_context)

    def save(self, subject):
        self.subject_DAO.save(subject)

    def delete(self, subject):
        self.subject_DAO.delete(subject)

    def ensure_security_manager(self, subject_context):
        if (subject_context.resolve_security_manager() is not None):
            # log here
            msg = ("Subject Context already contains a security_manager "
                   "instance. Returning.")
            print(msg)
            return subject_context
        else:
            # log here
            msg = ("No security_manager found in context.  Adding self "
                   "reference.")
            print(msg)
            subject_context.security_manager = self
            return subject_context

    def resolve_session(self, subject_context):
        if (subject_context.resolve_session() is not None): 
            # log here
            msg = ("Context already contains a session.  Returning.")
            print(msg)
            return subject_context
        
        try:
            """
            Context couldn't resolve it directly, let's see if we can since we
            have direct access to the session manager:
            """
            session = self.resolve_subject_context_session(subject_context)
            if (session is not None): 
                subject_context.session = session
            
        except InvalidSessionException as ex:
            # log here
            msg = ("Resolved subject_subject_context context session is "
                   "invalid.  Ignoring and creating an anonymous "
                   "(session-less) Subject instance.", ex)
            print(msg)
        
        return subject_context
    
    def resolve_context_session(self, subject_context):
        try:
            session_key = self.get_session_key(subject_context)
          
            if (session_key is not None):
                return self.get_session(session_key)
        except:
            raise

        return None

    def get_session_key(self, subject_context):
        session_id = subject_context.session_id
        if (session_id is not None):
            return DefaultSessionKey(session_id)
        return None

    def is_empty(self, principal_collection):
        return bool(principal_collection)

    def resolve_principals(self, subject_context):

        principals = subject_context.resolve_principals()

        if (not principals):
            # log here
            msg = ("No identity (principal_collection) found in the "
                   "subject_context. Returning original subject_context.")
            print(msg)

            # DG:  removed remembered identity functionality

        return subject_context

    def create_session_context(self, subject_context):
        session_context = DefaultSessionContext() 
        if (subject_context):
            session_context.put_all(subject_context)
        session_id = subject_context.session_id
        if (session_id):
            session_context.session_id = session_id
        host = subject_context.resolve_host()
        if (host):
            session_context.host = host
        return session_context

    def logout(self, subject):
        try:
            if (subject is None):
                msg = "Subject method argument cannot be None."
                raise IllegalArgumentException(msg)
        except IllegalArgumentException as ex:
            print('logout exception: ', ex)
            return

        principals = subject.principals
        if (principals):
            # log here
            msg = ("Logging out subject with primary principal {0}".format(
                   principals.primary_principal))
            authc = self.authenticator
            if (isinstance(authc, ILogoutAware)):
                authc.on_logout(principals)

        try:
            self.delete(subject)
        except Exception as ex:
            # log here
            msg = "Unable to cleanly unbind Subject.  Ignoring (logging out)."
            print(msg) 
        finally:
            try:
                self.stop_session(subject)
            except Exception as ex2:
                # log here 
                msg2 = ("Unable to cleanly stop Session for Subject [" 
                        + subject.principal + "] " +
                        "Ignoring (logging out).", ex2)
                print(msg2)

    def stop_session(self, subject):
        session = subject.get_session(False)
        if (session):
            session.stop()

    # DG:  omitted get_remembered Methods


class DefaultSecurityManager(SessionsSecurityManager):

    def __init__(self, realms=None):
        """
        Inputs:
            realms = a List of one or more realm objects
        """
        super().__init__()
        if (realms):
            self.realms = realms
            self.remember_me_manager = RememberMeManager()

    @property
    def subject_factory(self):
        return self._subject_factory

    @subject_factory.setter
    def subject_factory(self, subjectfactory):
        self._subject_factory = subjectfactory

    @property
    def subject_dao(self):
        return self._subject_dao

    @subject_dao.setter
    def subject_dao(self, subjectdao):
        self._subject_dao = subjectdao

    @property
    def remember_me_manager(self):
        return self._remember_me_manager

    @remember_me_manager.setter
    def remember_me_manager(self, remembermemanager):
        self._remember_me_manager = remembermemanager

    def create_subject_context(self):
        return DefaultSubjectContext()

    def create_subject(self, **kwargs):
        """
        This method can be used in two ways:
            1) passing a single parameter: subject_context
            2) passing all acceptable parameters below EXCEPT subject_context
        """
        acceptable_args = ['subject_context', 'authc_token', 
                           'authc_info', 'existing_subject']
        try:
            for x in kwargs.keys():
                if x not in acceptable_args:
                    msg = ('Unrecognized attribute passed to create_subject: ',
                           x)
                    raise IncorrectAttributeException(msg)
        except IncorrectAttributeException as ex:
            print('DefaultSecurityManager.create_subject: ', ex)

        else: 
            if (kwargs.get('subject_context', None)):
                context = self.copy_subject_context(kwargs['subject_context'])
                context = self.ensure_security_manager(context)
                context = self.resolve_session(context)
                context = self.resolve_principals(context)
                subject = self.do_create_subject(context)

                self.save(subject)

                return subject

            else: 
                context = self.create_subject_context()
                context.authenticated = True
                context.authentication_token = kwargs.get('authc_token', None)
                context.authentication_info = kwargs.get('authc_info', None)

                if (kwargs.get('existing_subject', None)):
                    context.subject = kwargs.get('existing_subject', None)

                return self.create_subject(context)

    def remember_me_successful_login(self, authc_token, authc_info, subject):
        rmm = self._remember_me_manager
        if (rmm is not None):
            try:
                rmm.on_successful_login(subject, authc_token, authc_info)
            except Exception as ex:
                # log here using the msg below:
                msg = ("Delegate RememberMeManager instance of type [" +
                       rmm.__class__.__name__ + "] threw an exception during "
                       "onsuccessfullogin.  RememberMe services will not be " +
                       "performed for account [" + authc_info + "].")
                raise    
        else:
            # log here using the msg below:
            msg = ("This " + self.__class__.__name__ + 
                   " instance does not have a [" +
                   RememberMeManager.__name__ + "] instance configured."
                   "RememberMe services will not be performed for account "
                   "[" + authc_info + "].")
            print(msg)

    def remember_me_failed_login(self, authc_token, authc_exc, subject):
        """
        authc_exc = the authentication exception 
        """
        rmm = self._remember_me_manager
        if (rmm is not None): 
            try:
                rmm.on_failed_login(subject, authc_token, authc_exc)
            except Exception as ex:
                # log here, using msg below:
                msg = ("Delegate RememberMeManager instance of type [" + 
                       rmm.__class__.__name__ + "] threw an exception during "
                       "on_failed_login for AuthenticationToken [" + 
                       authc_token + "].", ex)
                print(msg)

    def remember_me_logout(self, subject): 
        rmm = self._remember_me_manager
        if (rmm is not None): 
            try:
                rmm.on_logout(subject)
            except Exception as ex:
                # log here using msg below:
                prin = "[{prin}]".format(prin=subject.principals 
                                         if (subject) else '')
                msg = ("Delegate RememberMeManager instance of type [" + 
                       rmm.__class__.__name__ + "] threw an exception during "
                       "on_logout for subject with principals " + prin, ex)
                print(msg)
    
    def login(self, subject, authc_token):
        try:
            authc_info = self.authenticate(authc_token)
        except AuthenticationException as ex:
            try:
                self.on_failed_login(authc_token, ex, subject)
            except Exception as ex:
                # log here using msg:
                msg = ("onFailedLogin method threw an exception.  Logging "
                       "and propagating original AuthenticationException.", ex)
                print(msg)
                raise 
        else:
            logged_in = self.create_subject(authc_token, authc_info, subject)
            self.on_successful_login(authc_token, authc_info, logged_in)

            return logged_in
    
    def on_successful_login(self, authc_token, authc_info, subject):
        self.remember_me_successful_login(authc_token, authc_info, subject)

    def on_failed_login(self, authc_token, authc_exc, subject):
        self.remember_me_failed_login(authc_token, authc_exc, subject)

    def before_logout(self, subject):
        self.remember_me_logout(subject)

    def copy_subject_context(self, subject_context):  # DG:  renamed copy(
        return DefaultSubjectContext(subject_context)

    def do_create_subject(self, subject_context):
        return self.get_subject_factory().create_subject(subject_context)

    def save_subject(self, subject):  # DG:  renamed save(
        self.subject_DAO.save(subject)
    
    def delete_subject(self, subject):  # DG:  renamed delete(
        self.subject_DAO.delete_subject(subject)
    
    def ensure_security_manager(self, subject_context):
        if (subject_context.resolve_security_manager() is not None):
            # log here, using msg:
            msg = ("Context already contains a SecurityManager instance. " 
                   "Returning.")
            print(msg)
            return subject_context
        
        else:
            # log here, using msg:
            msg = ("No SecurityManager found in context.  Adding self "
                   "reference.")
            print(msg)

            subject_context.security_manager = self
            return subject_context

    def resolve_session(self, subject_context):
        if (subject_context.resolve_session() is not None):
            # log here, using msg:
            msg = "SubjectContext already contains a session.  Returning."
            print(msg)
            return subject_context
        
        try: 
            # Context couldn't resolve it directly, let's see if we can 
            # since we have direct access to the session manager
            session = self.resolve_context_session(subject_context)
            if (session is not None):
                subject_context.session = session
        except InvalidSessionException as ex:
            msg = ("Resolved SubjectContext context session is invalid.  "
                   "Ignoring and creating an anonymous (session-less) Subject "
                   "instance.", ex)
            print(msg)
        else:
            return subject_context

    def resolve_context_session(self, subject_context):
        try:
            key = self.get_session_key(subject_context)
            if (key is not None): 
                return self.get_session(key)
            else:
                return None 
    
        except:
            raise

    def get_session_key(self, subject_context):
        session_id = subject_context.session_id
        if (session_id is not None):
            return DefaultSessionKey(session_id)
        else:
            return None

    def resolve_principals(self, subject_context):

        principals = subject_context.resolve_principals()

        if (principals is None):
            # log here
            msg = ("No identity (PrincipalCollection) found in the context. "
                   "So, will look for a remembered identity.")

            principals = self.get_remembered_identity(subject_context)

            if (principals):
                # log here
                msg = ("Found remembered PrincipalCollection.  Adding to the "
                       "context to be used for subject construction by the "
                       "SubjectFactory.")
                print(msg)
                subject_context.principals = principals

            else:
                # log here
                msg = ("No remembered identity found.  Returning original "
                       "context.")
                print(msg)

        return subject_context
    
    def create_session_context(self, subject_context):
        session_context = DefaultSessionContext()
        if (subject_context):
            session_context.put_all(subject_context)

        session_id = subject_context.session_id
        if (session_id is not None):
            session_context.session_id = session_id

        host = subject_context.resolve_host()
        if (host is not None):
            session_context.host = host
        
        return session_context

    def logout(self, subject):

        try:
            if (subject is None):
                msg = "Subject method argument cannot be null."
                raise IllegalArgumentException(msg)
        except IllegalArgumentException as ex:
            print('DefaultSecurityManager.logout: ', ex)

        else:
            self.before_logout(subject)

            principals = subject.principals
            if (principals):
                # log here using msg:
                msg = ("Logging out subject with primary principal {0}".
                       format(principals.primary_principal))
                print(msg) 
                authc = self.authenticator
                # DG:  must add logout_away boolean to authenticator class!
                if (getattr(authc, 'logout_aware', None)):
                    authc.on_logout(principals)

            try:
                self.delete_subject(subject)
            except Exception as ex:
                # log here
                msg = ("Unable to cleanly unbind Subject.  Ignoring "
                       "(logging out).")
                print(msg) 
            finally:
                try:
                    self.stop_session(subject)
                except Exception as ex:
                    # log here 
                    msg = ("Unable to cleanly stop Session for Subject [" +
                           str(subject.principal) + 
                           "] Ignoring (logging out).", ex)
                    print(msg)

    def stop_session(self, subject):
        s = subject.get_session(False)
        if (s is not None): 
            s.stop()
    
    def get_remembered_identity(self, subject_context):
        rmm = self.remember_me_manager
        if (rmm is not None): 
            try:
                return rmm.get_remembered_principals(subject_context)
            except Exception as ex:
                # log here
                msg = ("Delegate RememberMeManager instance of type [" +
                       rmm.__class__.__name__ + "] threw an exception during "
                       "get_remembered_principals.", ex)
                print(msg)
                raise
        else:
            return None 
