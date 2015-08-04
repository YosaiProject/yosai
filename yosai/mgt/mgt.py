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
import copy

from yosai import(
    AuthenticationException,
    DefaultAuthenticator,
    DisabledCacheManager,
    DefaultSessionManager,
    DefaultSessionContext,
    DefaultSessionKey,
    DefaultSubjectContext,
    DefaultEventBus,
    IllegalArgumentException,
    InvalidSessionException,
    LogManager,
    ModularRealmAuthorizer,
    UnavailableSecurityManagerException,
    UnrecognizedAttributeException,
    mgt_abcs,
    authc_abcs,
    event_abcs,
    cache_abcs,
)


class AbstractRememberMeManager(mgt_abcs.RememberMeManager):
    """
    Abstract implementation of the RememberMeManager interface that handles
    serialization and encryption of the remembered user identity.

    The remembered identity storage location and details are left to 
    subclasses.

    Default encryption key
    -----------------------
    This implementation uses an {@link AesCipherService AesCipherService} for 
    strong encryption by default.  It also uses a default generated symmetric 
    key to both encrypt and decrypt data.  As AES is a symmetric cipher, the
    same key is used to both encrypt and decrypt data, BUT NOTE:

    Because Shiro is an open-source project, if anyone knew that you were 
    using Shiro's default key, they could download/view the source, and with 
    enough effort, reconstruct the key and decode encrypted data at will.

    Of course, this key is only really used to encrypt the remembered
    PrincipalCollection, which is typically a user id or username.  So if you
    do not consider that sensitive information, and you think the default key
    still makes things 'sufficiently difficult', then you can ignore this 
    issue.

    However, if you do feel this constitutes sensitive information, it is
    recommended that you provide your own key and set it via the cipher_key 
    property attribute to a key known only to your application,
    guaranteeing that no third party can decrypt your data.  
    
    You can generate your own key by calling the CipherService's 
    generate_new_key method and using that result as the 
    cipher_key configuration attribute.  
    """
    pass  # requires refactoring, TBD

# also known as ApplicationSecurityManager in Shiro 2.0 alpha:
class DefaultSecurityManager(mgt_abcs.SecurityManager, 
                             event_abcs.EventBusAware, 
                             cache_abcs.CacheManagerAware):

    def __init__(self):
        self.realms = None
        self._event_bus = DefaultEventBus()
        self._cache_manager = DisabledCacheManager()  # cannot be set to None
        
        # new to Yosai is the injection of the eventbus:
        self.authenticator = DefaultAuthenticator(self._event_bus)
        self.authorizer = ModularRealmAuthorizer()
        self.session_manager = None 
        self.remember_me_manager = None
        self.subject_DAO = None 
        self.subject_factory = None 

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
        if authenticator:
            self._authenticator = authenticator

            if (isinstance(self.authenticator, DefaultAuthenticator)):
                self.authenticator.realms = self.realms
            
            self.apply_event_bus(self.authenticator)
            self.apply_cache_manager(self.authenticator)
        
        else:
            msg = "authenticator parameter must have a value" 
            raise IllegalArgumentException(msg)

    @property
    def authorizer(self):
        return self._authorizer

    @authorizer.setter
    def authorizer(self, authorizer):
        if authorizer:
            self._authorizer = authorizer
            self.apply_event_bus(self.authorizer)
            self.apply_cache_manager(self.authorizer)
        else: 
            msg = "authorizer parameter must have a value" 
            raise IllegalArgumentException(msg)
        
    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        if (cachemanager):
            self._cache_manager = cachemanager
            self.apply_cache_manager(
                self.get_dependencies_for_injection(self._cache_manager))

        else: 
            msg = ('Incorrect parameter.  If you want to disable caching, '
                   'configure a disabled cachemanager instance')
            raise IllegalArgumentException(msg)
        
    #  property required by EventBusAware interface:
    @property
    def event_bus(self):
        return self._event_bus

    @event_bus.setter
    def event_bus(self, eventbus):
        if eventbus:
            self._event_bus = eventbus
            self.apply_event_bus(
                self.get_dependencies_for_injection(self._event_bus))

        else:
            msg = 'eventbus parameter must have a value'
            raise IllegalArgumentException(msg)

    def set_realms(self, realm_s):
        """
        :realm_s: an immutable collection of one or more realms
        :type realm_s: tuple
        """
        if realm_s: 
            self.apply_event_bus(realm_s)
            self.apply_cache_manager(realm_s)

            authc = self.authenticator
            if (isinstance(authc, DefaultAuthenticator)):
                authc.realms = realm_s 

            authz = self.authorizer
            if (isinstance(authz, ModularRealmAuthorizer)):
                authz.realms = realm_s 

        else: 
            msg = 'Cannot pass None as a parameter value for realms'
            raise IllegalArgumentException(msg)
   
    # new to yosai, helper method:
    def apply_target_s(self, validate_apply, target_s):
        try:
            for target in target_s:
                validate_apply(target)
        except TypeError: 
            validate_apply(target_s)

    def apply_cache_manager(self, target_s):
        """
        :param target: the object or objects that, if eligible, are to have
                       the cache manager set 
        :type target: an individual object instance or iterable
        """
        # yosai refactored, deferring iteration to the methods that call it
        def validate_apply(target):
            if isinstance(target, cache_abcs.CacheManagerAware):
                target.cache_manager = self.cache_manager

        self.apply_target_s(validate_apply, target_s)

    def apply_event_bus(self, target_s):
        """
        :param target: the object or objects that, if eligible, are to have
                       the eventbus set 
        :type target: an individual object instance or iterable
        """
        # yosai refactored, deferring iteration to the methods that call it

        def validate_apply(target):
            if isinstance(target, event_abcs.EventBusAware):
                target.event_bus = self.event_bus
        
        self.apply_target_s(validate_apply, target_s)

    def get_dependencies_for_injection(self, ignore):
        deps = {self._event_bus, self._cache_manager, self.realms, 
                self.authenticator, self.authorizer,
                self.session_manager, self.subject_DAO,
                self.subject_factory}
        try:
            deps.remove(ignore)
        except KeyError:
            msg = ("Could not remove " + str(ignore) + 
                   " from dependencies_for_injection: ")
            print(msg)
            # log warning here
        
        return deps
    
    """
    * ===================================================================== *
    * Authenticator Methods                                                 *
    * ===================================================================== *
    """
    
    def authenticate_account(self, authc_token):
        return self.authenticator.authenticate_account(authc_token)

    """
    * ===================================================================== *
    * Authorizer Methods                                                    *
    *
    * Note: Yosai refactored authz functionality in order to eliminate 
    *       method overloading
    * ===================================================================== *
    """
    def is_permitted(self, principals, permission_s):
        """
        :param principals: a collection of principals
        :type principals: Set

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission object(s) or String(s)

        :returns: a List of tuple(s), containing the Permission and a Boolean 
                  indicating whether the permission is granted
        """
        return self.authorizer.is_permitted(principals, permission_s)
    
    def is_permitted_all(self, principals, permission_s):
        """
        :param principals: a Set of Principal objects
        :param permission_s:  a List of Permission objects

        :returns: a Boolean
        """
        return self.authorizer.is_permitted_all(principals, permission_s)

    def check_permission(self, principals, permission_s):
        """
        :param principals: a collection of principals
        :type principals: Set

        :param permission_s: a collection of 1..N permissions
        :type permission_s: List of Permission objects or Strings

        :returns: a List of Booleans corresponding to the permission elements
        """
        return self.authorizer.check_permission(principals, permission_s)
   
    def has_role(self, principals, roleid_s):
        """
        :param principals: a collection of principals
        :type principals: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings 

        :returns: a tuple containing the roleid and a boolean indicating 
                  whether the role is assigned (this is different than Shiro)
        """
        return self.authorizer.has_role(principals, roleid_s)

    def has_all_roles(self, principals, roleid_s):
        """
        :param principals: a collection of principals
        :type principals: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings 

        :returns: a Boolean
        """
        return self.authorizer.has_all_roles(principals, roleid_s)

    def check_role(self, principals, roleid_s):
        """
        :param principals: a collection of principals
        :type principals: Set

        :param roleid_s: 1..N role identifiers
        :type roleid_s:  a String or List of Strings 

        :raises UnauthorizedException: if Subject not assigned to all roles
        """
        return self.authorizer.check_role(principals, roleid_s)

    """
    * ===================================================================== *
    * SessionManager Methods                                                *
    * ===================================================================== *
    """
    def start(self, session_context):
        return self.session_manager.start(session_context)

    def get_session(self, session_key):
        return self.session_manager.get_session(session_key)
    
    """
    * ===================================================================== *
    * SecurityManager Methods                                               *
    * ===================================================================== *
    """

    def create_subject_context(self):
        return DefaultSubjectContext()

    def create_subject(self, 
                       authc_token=None, 
                       account=None, 
                       existing_subject=None,
                       subject_context=None): 

        if not subject_context: 
            context = self.create_subject_context()
            context.authenticated = True
            context.authentication_token = authc_token
            context.account = account
            if (existing_subject):
                context.subject = existing_subject 

        else:
            context = copy.copy(subject_context)

        # ensure that the context has a security_manager instance, and if
        # not, add one: 
        context = self.ensure_security_manager(context)

        # Resolve an associated Session (usually based on a referenced
        # session ID), and place it in the context before sending to the
        # subject_factory.  The subject_factory should not need to know how
        # to acquire sessions as the process is often environment specific -
        # better to shield the SF from these details: 
        context = self.resolve_session(context)

        # Similarly, the subject_factory should not require any concept of
        # remember_me -- translate that here first if possible before handing
        # off to the subject_factory:
        context = self.resolve_principals(context)
        subject = self.do_create_subject(context)

        # save this subject for future reference if necessary:
        # (this is needed here in case remember_me principals were resolved
        # and they need to be stored in the session, so we don't constantly
        # re-hydrate the remember_me principal_collection on every operation).
        self.save(subject)
        return subject

    def remember_me_successful_login(self, authc_token, account, subject):
        rmm = self.remember_me_manager 
        if (rmm is not None):
            try:
                rmm.on_successful_login(subject, authc_token, account)
            except Exception as ex: 
                msg = ("Delegate RememberMeManager instance of type [" + 
                       rmm.__class__.__name__ + "] threw an exception "
                       + "during on_successful_login.  RememberMe services "
                       + "will not be performed for account [" + account + 
                       "].")
                print(msg)
                # log warn , including exc_info=ex

        else:
            msg = ("This " + rmm.__class__.__name__ + 
                   " instance does not have a [RememberMeManager] instance " +
                   "configured.  RememberMe services will not be performed " +
                   "for account [" + account + "].")
            print(msg)
            # log trace here 

    def remember_me_failed_login(self, authc_token, authc_exc, subject):
        rmm = self.remember_me_manager
        if (rmm is not None): 
            try:
                rmm.on_failed_login(subject, authc_token, ex)

            except Exception as ex:
                msg = ("Delegate RememberMeManager instance of type " 
                       "[" + rmm.__class__.__name__ + "] threw an exception "
                       "during on_failed_login for AuthenticationToken [" +
                       authc_token + "].")
                print(msg)
                # log warning here , including exc_info = ex

    def remember_me_logout(self, subject):
        rmm = self.remember_me_manager
        if (rmm is not None): 
            try:
                rmm.on_logout(subject)
            except Exception as ex:
                msg = ("Delegate RememberMeManager instance of type [" + 
                       rmm.__class__.__name__ + "] threw an exception during "
                       "on_logout for subject with principals [{principals}]".\
                       format(principals=subject.principals if subject else None))
                print(msg)
                # log warn, including exc_info = ex
        
    def login(self, subject, authc_token): 
        try:
            account = self.authenticate_account(authc_token)
        except AuthenticationException as authc_ex: 
            try:
                self.on_failed_login(authc_token, authc_ex, subject) 
            except Exception as ex:
                msg = ("on_failed_login method threw an exception.  Logging "
                       "and propagating original AuthenticationException.", ex)
                print(msg)
                # log info here, including exc_info=ex 
            raise

        logged_in = self.create_subject(authc_token, account, subject)
        self.on_successful_login(authc_token, account, logged_in)
        return logged_in

    def on_successful_login(self, authc_token, account, subject):
        self.remember_me_successful_login(authc_token, account, subject)
    
    def onfailed_login(self, authc_token, authc_exc, subject):
        self.remember_me_failed_login(authc_token, authc_exc, subject)

    def before_logout(self, subject):
        self.remember_me_logout(subject)

    def copy(self, subject_context):
        return DefaultSubjectContext(subject_context)

    def do_create_subject(self, subject_context):
        return self.subject_factory.create_subject(subject_context)

    def save(self, subject):
        self.subject_DAO.save(subject)

    def delete(self, subject):
        self.subject_DAO.delete(subject)

    def ensure_security_manager(self, subject_context):
        if (subject_context.resolve_security_manager() is not None):
            msg = ("Subject Context already contains a security_manager "
                   "instance. Returning.")
            print(msg)
            # log trace here
            return subject_context

        msg = ("No security_manager found in context.  Adding self "
               "reference.")
        print(msg)
        # log trace here
        subject_context.security_manager = self
        return subject_context

    def resolve_session(self, subject_context):
        if (subject_context.resolve_session() is not None): 
            msg = ("Context already contains a session.  Returning.")
            print(msg)
            # log debug here
            return subject_context
        
        try:
            # Context couldn't resolve it directly, let's see if we can 
            # since we  have direct access to the session manager:
            session = self.resolve_context_session(subject_context)
            if (session is not None): 
                subject_context.session = session
            
        except InvalidSessionException as ex:
            msg = ("Resolved subject_subject_context context session is "
                   "invalid.  Ignoring and creating an anonymous "
                   "(session-less) Subject instance.")
            print(msg)
            # log debug here, including exc_info=ex
        
        return subject_context
    
    def resolve_context_session(self, subject_context):
        session_key = self.get_session_key(subject_context)
      
        if (session_key is not None):
            return self.get_session(session_key)

        return None

    def get_session_key(self, subject_context):
        session_id = subject_context.session_id
        if (session_id is not None):
            return DefaultSessionKey(session_id)
        return None

    # yosai omits is_empty method

    def resolve_principals(self, subject_context):
        principals = subject_context.resolve_principals()
        if (not principals):
            msg = ("No identity (principal_collection) found in the "
                   "subject_context.  Looking for a remembered identity.")
            print(msg)
            # log trace here

            principals = self.get_remembered_identity(subject_context)
            
            if principals:
                msg = ("Found remembered PrincipalCollection.  Adding to the "
                       "context to be used for subject construction by the "
                       "SubjectFactory.")
                print(msg)
                # log debug here
                subject_context.principals = principals

            else:
                msg = ("No remembered identity found.  Returning original "
                       "context.")
                print(msg)
                # log trace here

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
        if (subject is None):
            msg = "Subject method argument cannot be None."
            raise IllegalArgumentException(msg)

        self.before_logout(subject)

        principals = subject.principals
        if (principals):
            msg = ("Logging out subject with primary principal {0}".format(
                   principals.primary_principal))
            print(msg)
            # log debug here
            authc = self.authenticator
            if (isinstance(authc, authc_abcs.LogoutAware)):
                authc.on_logout(principals)

        try:
            self.delete(subject)
        except Exception as ex:
            msg = "Unable to cleanly unbind Subject.  Ignoring (logging out)."
            print(msg) 
            # log debug here, including exc_info = ex
        finally:
            try:
                self.stop_session(subject)
            except Exception as ex2:
                msg2 = ("Unable to cleanly stop Session for Subject [" 
                        + subject.principal + "] " +
                        "Ignoring (logging out).", ex2)
                print(msg2)
                # log debug here, including exc_info = ex 

    def stop_session(self, subject):
        session = subject.get_session(False)
        if (session):
            session.stop()

    def get_remembered_identity(self, subject_context):
        rmm = self.remember_me_manager
        if rmm is not None:
            try:
                return rmm.get_remembered_principals(subject_context)
            except Exception as ex:
                msg = ("Delegate RememberMeManager instance of type [" + 
                       rmm.__class__.__name__ + "] raised an exception during "
                       "get_remembered_principals().")
                print(msg)
                # log warn here , including exc_info = ex
        return None 
