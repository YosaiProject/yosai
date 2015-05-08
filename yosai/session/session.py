from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from os import urandom
from hashlib import sha256
import time
import uuid

from yosai import (
    AbstractMethodException,
    Context,
    ExpiredSessionException,
    LogManager,
    MissingMethodException,
    UnknownSessionException,
)


class AbstractSessionDAO(object):

    def __init__(self):
        self._session_id_generator = UUIDSessionIdGenerator()
        
    @property
    def session_id_generator(self):
        return self._session_id_generator
    
    @session_id_generator.setter
    def session_id_generator(self, sid_generator):
        self._session_id_generator = sid_generator

    def generate_session_id(self, session):
        try:
            if (self.session_id_generator is None):
                msg = "sessionIdGenerator attribute has not been configured."
                raise IllegalStateException(msg)
        except IllegalStateException as ex:
            print('generate_session_id: ', msg)

        else:
            return self.session_id_generator.generate_id(session)
    
    def create_session_id(self, session):  # DG renamed
        session_id = self.do_create(session)
        self.verify_session_id(session_id)
        return session_id

    def verify_session_id(self, session_id):
        try:
            if (session_id is None):
                msg = ("sessionId returned from doCreate implementation "
                       "is null. Please verify the implementation.")
                raise IllegalStateException(msg)
        except IllegalStateException as ex:
            print('verify_session_id: ', ex)
    
    def assign_session_id(self, session, session_id):
        session = SimpleSession(session)  # DG:  shiro casts instead
        session.set_id(session_id)
    
    # abstract method, to be implemented by subclass
    def do_create(self, session):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'do_create')

    def read_session(self, session_id):
        try:
            session = self.do_read_session(session_id)
            if (session is None):
                msg = "There is no session with id [" + session_id + "]"
                raise UnknownSessionException(msg)
            return session
        except UnknownSessionException as ex:
            print('read_session: ', ex)

    # abstract method, to be implemented by subclass
    def do_read_session(self, session_id):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'do_read_session')


class AbstractNativeSessionManager(AbstractSessionManager):
    """ DG:  includes  AbstractSessionManager """

    MILLIS_PER_SECOND = 1000
    MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND
    MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE
    DEFAULT_GLOBAL_SESSION_TIMEOUT = 30 * MILLIS_PER_MINUTE

    def __init__(self): 
        self._listeners = []  # session listeners
        self._global_session_timeout = DEFAULT_GLOBAL_SESSION_TIMEOUT
    
    @property
    def global_session_timeout(self):
        return self._global_session_timeout

    @global_session_timeout.setter
    def global_session_timeout(self, timeout):
        self._global_session_timeout = timeout 

    @property
    def session_listeners(self):
        return self._listeners

    @session_listeners.setter
    def session_listeners(self, listeners=None):
        if (listeners is not None):
            self._listeners = listeners

    def start(self, session_context):
        session = self.create_session(session_context)
        self.apply_global_session_timeout(session_context)
        self.on_start(session, session_context)
        self.notify_start(session)
        
        # Don't expose the EIS-tier Session object to the client-tier:
        return self.create_exposed_session(session, session_context)

    def apply_global_session_timeout(self, session):
        session.set_timeout(self.global_session_timeout)
        self.on_change(session)
    
    def on_start(self, session, session_context):  # template for sub-classes
        pass

    def get_session(self, key):
        try:
            session = self.lookup_session(key)
        except:
            raise
        
        if (session):
            return self.create_exposed_session(session, key)
        else:
            return None

    def lookup_session(self, key):
        try:
            if (key is None): 
                msg = "session_key argument cannot be null."
                raise NullPointerException(msg)
            return self.do_get_session(key)
        except NullPointerException as ex:
            print('lookup_session : ', ex)

    def lookup_required_session(self, key):
        try:
            session = self.lookup_session(key)
            if (session is None):
                msg = ("Unable to locate required Session instance based "
                       "on session_key [" + key + "].")
                raise UnknownSessionException(msg)
            return session
        except UnknownSessionException as ex:
            print('lookup_required_session: ', ex)

    def create_exposed_session(self, **kwargs):
        acceptable_args = ['key', 'session', 'session_context']
        try:
            for key in kwargs.keys():
                if key not in acceptable_args:
                    raise UnrecognizedAttributeException(key)
        except UnrecognizedAttributeException as ex:
            print('create_exposed_session passed unrecognized attribute:', ex)

        return DelegatingSession(self, Defaultsession_key(session.id))

    def before_invalid_notification(self, session):
        return ImmutableProxiedSession(session)

    def notify_start(self, session):
        for listener in self.listeners:
            listener.on_start(session)

    def notify_stop(self, session):
        for_notification = self.before_invalid_notification(session)
        for listener in self.listeners: 
            listener.on_stop(for_notification)

    def notify_expiration(self, session):
        for_notification = self.before_invalid_notification(session)
        for listener in self.listeners: 
            listener.on_expiration(for_notification)

    def get_start_timestamp(self, session_key):
        return self.lookup_required_session(session_key).start_timestamp

    def get_last_access_time(self, session_key):
        return self.lookup_required_session(session_key).last_access_time

    def get_timeout(self, session_key):
        return self.lookup_required_session(session_key).timeout

    def set_timeout(self, session_key, max_idle_time_in_millis):
        try:
            session = self.lookup_required_session(session_key)
            session.timeout = max_idle_time_in_millis
            self.on_change(session)
        except:
            raise

    def touch(self, session_key):
        session = self.lookup_required_session(session_key)
        session.touch()
        self.on_change(s)

    def get_host(self, session_key):
        return self.lookup_required_session(session_key).host

    def get_attribute_keys(self, session_key):
        collection = self.lookup_required_session(session_key).\
            get_attribute_keys()
        if (collection):
            return tuple(collection) 
        else:
            return tuple() 

    def get_attribute(self, session_key, attribute_key):
        return self.lookup_required_session(sessionKey).\
            getAttribute(attributeKey)

    def set_attribute(self, session_key, attribute_key, value):
        if (value is None):
            self.remove_attribute(session_key, attribute_key)
        else: 
            session = self.lookup_required_session(session_key)
            session.set_attribute(attribute_key, value)
            self.on_change(session)

    def remove_attribute(self, session_key, attribute_key):
        session = self.lookup_required_session(session_key)
        removed = session.remove_attribute(attribute_key)
        if (removed is not None): 
            self.on_change(session)
        return removed

    def is_valid(self, session_key):
        try:
            self.check_valid(session_key)
            return True
        except:
            print('is_valid Exception!')
            raise
        return False 

    def stop(self, session_key):
        session = self.lookup_required_session(session_key)
        try:
            msg = ("Stopping session with id [" + session._id + "]")
            print(msg)            
            session.stop()
            self.on_stop(session, session_key)
            self.notify_stop(session)
        except:
            raise
        finally:
            self.after_stopped(session)

    def on_stop(self, session, session_key=None): 
        if (session_key is None):
            self.on_stop(session)
        else:
            self.on_change(session)

    def after_stopped(self, session):
        pass

    def check_valid(self, session_key):
        # just try to acquire it.  If there's a problem, an exception is thrown
        try:
            self.lookup_required_session(session_key)
        except:
            raise

    def on_change(self, session):
        pass


class AbstractValidatingSessionManager(AbstractNativeSessionManager):
    
    DEFAULT_SESSION_VALIDATION_INTERVAL = MILLIS_PER_HOUR

    def __init__(self):
        self._session_validation_scheduler = None 
        self._session_validation_scheduler_enabled = True  # isEnabled
        self._session_validation_interval = DEFAULT_SESSION_VALIDATION_INTERVAL

    @property
    def session_validation_scheduler_enabled(self):
        return self._session_validation_scheduler_enabled

    @session_validation_scheduler_enabled.setter
    def session_validation_scheduler_enabled(self, enabled):
        self._session_validation_scheduler_enabled = enabled

    @property
    def session_validation_scheduler(self):
        return self._session_validation_scheduler

    @session_validation_scheduler.setter
    def session_validation_scheduler(self, scheduler):
        self._session_validation_scheduler = scheduler

    def enable_session_validation_if_necessary(self):
        scheduler = self.session_validation_scheduler
        if (self.session_validation_scheduler_enabled and
           (scheduler is None or (not scheduler.enabled))):
            enableSessionValidation()

    @property
    def session_validation_interval(self):
        return self._session_validation_interval

    @session_validation_interval.setter
    def session_validation_interval(self, interval):
        self._session_validation_interval = interval 

    def do_get_session(self, session_key):
        try:
            self.enable_session_validation_if_necessary()
            # log here
            msg = "Attempting to retrieve session with key " + key
            print(msg)

            session = self.retrieve_session(session_key)
            if (session is not None):
                self.validate(session, key)
            
            return session
        except:
            print('do_get_session Exception!')
            raise

    def create_session(self, session_context):
        self.enable_session_validation_if_necessary()
        return self.do_create_session(session_context)

    # abstract method, to be implemented by subclass
    def retrieve_session(self, session_key):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'retrieve_session')

    # abstract method, to be implemented by subclass
    def do_create_session(self, session_context):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'do_create_session')
        
    def validate(self, session, session_key):
        try:
            self.do_validate(session)
        
        except ExpiredSessionException as ese:
            self.on_expiration(session, ese, session_key)
       
        except InvalidSessionException as ise:
            self.on_invalidation(session, ise, session_key)
      
    def on_expiration(self, **kwargs):
        """
        self.method can be used either with a single session parameter or
        with session, ese, and session_key passed altogether
        """

        acceptable_args = ['session', 'ese', 'session_key']
        try:
            for key in kwargs.keys():
                if key not in acceptable_args:
                    raise InvalidArgumentException
        except InvalidArgumentException:
            print('Invalid argument passed to on_expiration')

        if (kwargs.get('session_key', None) is not None):
            # log here
            msg = "Session with id [{0}] has expired.".format(session.get_id())
            try:
                self.on_expiration(session)
                self.notify_expiration(session)
            except:
                raise
            finally:
                self.after_expired(session)

        else:  # assuming just session is passed as a parameter
            self.on_change(session)

    # DG:  shiro defined self.as an empty method, for subclass implementation
    def after_expired(self, session):
        msg = 'Failed to Implement Method: '
        raise MissingMethodException(msg + 'after_expired')

    def on_invalidation(self, session, ise, session_key):
        if (isinstance(ise, InvalidSessionException)):
            self.on_expiration(session, ExpiredSessionException, session_key)
            return
        
        # log here
        msg = "Session with id [{0}] is invalid.".format(session.get_id())
        try:
            self.on_stop(session)
            self.notify_stop(session)
        except:
            raise
        finally:
            self.after_stopped(session)

    def do_validate(self, session):
        try:
            if (isinstance(session, ValidatingSession)):
                session.validate()
            else:
                msg = ("The {0} implementation only supports validating " 
                       "Session implementations of the {1} interface.  " 
                       "Please either implement self.interface in your "
                       "session implementation or override the {2}" 
                       ".do_validate(Session) method to validate.").\
                    format(self.__class__.__name__, 
                           ValidatingSession.__name__, 
                           AbstractValidatingSessionManager.__name__)
                raise IllegalStateException(msg)

        except IllegalStateException as ex:
            print('do_validate IllegalStateException: ', ex)

    def get_timeout(self, session):
        return session.timeout
    
    def create_session_validation_scheduler(self):
        # log here
        msg = ("No sessionValidationScheduler set.  Attempting to "
               "create default instance.")
        print(msg)

        scheduler = ExecutorServiceSessionValidationScheduler(self)
        scheduler.set_interval(self.session_validation_interval)

        # log here:
        msg2 = ("Created default SessionValidationScheduler instance of "
                "type [" + scheduler.__class__.__name__ + "].")
        print(msg2)
        
        return scheduler

    def enable_session_validation(self):
        scheduler = self.session_validation_scheduler
        if (scheduler is None):
            scheduler = self.create_session_validation_scheduler()
            self.session_validation_scheduler = scheduler
        
        # log here
        msg = "Enabling session validation scheduler..."
        print(msg)
       
        scheduler.enable_session_validation()
        self.after_session_validation_enabled()

    # DG:  shiro defined self.as an empty method, for subclass implementation
    def after_session_validation_enabled(self):
        msg = 'Failed to Implement Method: '
        raise MissingMethodException(msg + 'after_session_validation_enabled')

    def disable_session_validation(self):
        self.before_session_validation_disabled()
        scheduler = self.session_validation_scheduler
        if (scheduler is not None): 
            try:
                scheduler.disableSessionValidation()
                # log here
                msg = "Disabled session validation scheduler."
                print(msg)
               
            except:
                # log here 
                msg2 = ("Unable to disable SessionValidationScheduler. "
                        "Ignoring (shutting down)...")
                print(msg2) 
                raise 
            self.session_validation_scheduler = None

    # DG:  shiro defined self.as an empty method, for subclass implementation
    def before_session_validation_disabled(self):
        msg = 'Failed to Implement Method: '
        raise MissingMethodException(msg+'before_session_validation_disabled')
    
    def validate_sessions(self):
        # log here
        msg = "Validating all active sessions..."
        print(msg)        

        invalid_count = 0

        active_sessions = self.get_active_sessions()

        if (active_sessions):
            for session in active_sessions:
                try:
                    # simulate a lookup key to satisfy the method signature.
                    # self.could probably be cleaned up in future versions:
                    session_key = DefaultSessionKey(session.get_id())
                    validate(session, session_key)
                except InvalidSessionException as ex:
                    # log here 
                    expired = isinstance(ex, ExpiredSessionException)
                    msg3 = "Invalidated session with id [{s_id}] ({exp})".\
                           format(s_id=session.get_id(),
                                  exp="expired" if (expired) else "stopped")
                    print(msg3) 
                    invalidCount += 1

        # log here 
        msg3 = "Finished session validation."
        print(msg3)

        if (invalid_count > 0):
            msg4 += "  [" + invalid_count + "] sessions were stopped."
        else: 
            msg4 += "  No sessions were stopped."
        print(msg4) 

    # abstract method, to be implemented by subclass
    def get_active_sessions(self):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'get_active_sessions')


class DefaultSessionContext(object):  
    """
    DG:  shiro extends from MapContext but I just use composition instead,
         just as with SubjectContext
    """
    def __init__(self, context_map=None):
        dsc_name = self.__class__.__name__
        self.host_name = dsc_name + ".HOST"
        self.sessionid_name = dsc_name + ".SESSION_ID"
        if (context_map):
            self._session_context = Context(context_type='SESSION',
                                            **contextmap)
        else:
            self._session_context = Context(context_type='SESSION')

    @property
    def host(self):
        return self._session_context.get_and_validate(
            self.host_name, str)

    @host.setter
    def host(self, hostname):
        setattr(self._session_context, self.host_name, hostname)

    @property
    def session_id(self):
        return self._session_context.get_and_validate(self.sessionid_name, str)

    @session_id.setter
    def session_id(self, sessionid):
        setattr(self._session_context, self.sessionid_name, sessionid)


class DefaultSessionKey(object):

    def __init__(self, sessionid):
        self._session_id = sessionid

    def __eq__(self, other):
        # DG:  pythonic instance assumption..
        return self.session_id == other.session_id
    
    @property
    def session_id(self):
        return self._session_id

    @session_id.setter
    def session_id(self, sessionid):
        self._session_id = sessionid


class DefaultSessionManager(AbstractValidatingSessionManager):

    def __init__(self): 
        self._cache_manager = CacheManager()
        self._delete_invalid_sessions = True
        self._session_factory = SimpleSessionFactory()
        self._session_DAO = MemorySessionDAO()

    @property
    def session_DAO(self):
        return self._session_DAO

    @session_DAO.setter
    def session_DAO(self, sessiondao):
        self._session_DAO = sessiondao
        self.apply_cache_manager_to_session_DAO()

    @property
    def session_factory(self):
        return self._session_factory

    @session_factory.setter
    def session_factory(self, sessionfactory):
        self._session_factory = sessionfactory

    @property 
    def delete_invalid_sessions(self):
        return self._delete_invalid_sessions

    @delete_invalid_sessions.setter
    def delete_invalid_sessions(self, dis):
        # Expecting a bool
        self.delete_invalid_sessions = dis

    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        self._cache_manager = cachemanager
        self.apply_cache_manager_to_session_DAO()

    def apply_cache_manager_to_session_DAO(self):
        if (bool(self.cache_manager) and bool(self.sessionDAO) and 
                (getattr(self.session_DAO, 'set_cache_manager', None))):
            self.session_DAO.set_cache_manager(self.cache_manager)

    def do_create_session(self, session_context):
        session = self.new_session_instance(session_context)
        # log here
        msg = "Creating session for host " + session.host
        print(msg)
        self.create_session(session)
        return session

    def new_session_instance(self, session_context):
        return self.get_session_factory().create_session(session_context)

    def create(self, session):
        # log here
        msg = ("Creating new EIS record for new session instance [{0}]".
               format(session)) 
        self.session_DAO.create_session(session)

    def on_stop(self, session):
        if (isinstance(session, SimpleSession)):
            simple_session = SimpleSession(session)  # DG:  TBD!!  shiro casts 
            stop_timestamp = simple_session.stop_timestamp
            simple_session.last_access_time = stop_timestamp

        self.on_change(session)

    def after_stopped(self, session):
        if (self.delete_invalid_sessions):
            self.delete(session)

    def on_expiration(self, session):
        if (isinstance(session, SimpleSession)):
            session = SimpleSession(session)  # DG:  TBD.  shiro casts instead
            session.expired = True
        
        self.on_change(session)

    def after_expired(self, session):
        if (self.delete_invalid_sessions):
            self.delete(session)

    def on_change(self, session):
        self._session_DAO.update_session(session)

    def retrieve_session(self, session_key):
        try:
            session_id = self.get_session_id(session_key)
            if (session_id is None):
                # log here
                msg = ("Unable to resolve session ID from SessionKey [{0}]."
                       "Returning null to indicate a session could not be "
                       "found.".format(session_key))
                print(msg)
                return None 
            
            session = self.retrieve_session_from_data_source(session_id)
            if (session is None): 
                # session ID was provided, meaning one is expected to be found,
                # but we couldn't find one:
                msg2 = "Could not find session with ID [" + session_id + "]"
                raise UnknownSessionException(msg)
            
        except UnknownSessionException as ex:
            print(ex)
        except:
            raise

        else:
            return session

    def get_session_id(self, session_key):
        return session_key.session_id
    
    def retrieve_session_from_data_source(self, session_id):
        return self.session_DAO.read_session(session_id)

    def delete(self, session):
        self.session_DAO.delete_session(session)

    def get_active_sessions(self):
        active_sessions = self.session_DAO.get_active_sessions()
        if (active_sessions is not None):
            return active_sessions
        else:
            return set()  # DG: shiro returns an emptySet... TBD


class EnterpriseCacheSessionDAO(CachingSessionDAO):

    def __init__(self): 
        
        """
        DG:  not sure how to refactor this:
        public EnterpriseCacheSessionDAO() {
        setCacheManager(new AbstractCacheManager() {
            @Override
            protected Cache<Serializable, Session> createCache(String name) throws CacheException {
                return new MapCache<Serializable, Session>(name, new ConcurrentHashMap<Serializable, Session>());
            }
        });
        """

    def do_create(self, session):
        sessionid = self.generate_session_id(session)
        self.assign_session_id(session, sessionid)
        return sessionid
    

class MemorySessionDAO(AbstractSessionDAO):

    def __init__(self):
        self.sessions = {} 
    
    def do_create(self, session):
        sessionid = self.generate_session_id(session)
        self.assign_session_id(session, sessionid)
        self.store_session(sessionid, session)
        return sessionid

    def store_Session(self, sessionid, session):
        try:
            if (sessionid is None):
                raise IllegalArgumentException("id argument cannot be null.")
        except IllegalArgumentException as ex:
            print('MemorySessionDAO.store_session Null param passed', ex)
        else:
            self.sessions[sessionid] = session
            return self.sessions.get(session_id, None)

    def do_read_session(self, sessionid):
        return self.sessions.get(sessionid, None)
    
    def update(self, session):
        try:
            self.store_session(session.id, session)
        except:
            raise

    def delete(self, session):
        try:
            if (session is None):
                msg = "session argument cannot be null."
                raise IllegalArgumentException(msg)
        except IllegalArgumentException as ex:
            print('MemorySessionDAO.delete Null param passed', ex)
        else:
            sessionid = session.id
            if (sessionid is not None):
                self.sessions.pop(id)

    def get_active_sessions(self):
        values = self.sessions.values()
        if (not values()):
            return set() 
        else:
            return tuple(values)


class ProxiedSession(object):
   
    def __init__(self, target_session):
        self._delegate = self.check_delegate(target_session)

    def check_delegate(self, target_session):
        try:
            if (target_session is None):
                msg = "Target session to proxy cannot be null."
                raise IllegalArgumentException(msg)
        except IllegalArgumentException as ex:
            print(ex)
        else: 
            return target_session
    
    @property
    def id(self):
        return self._delegate.session_id

    @property
    def start_timestamp(self):
        return self._delegate.start_timestamp

    @property
    def last_access_time(self):
        return self._delegate.last_access_time

    @property
    def timeout(self):
        return self._delegate.timeout

    @timeout.setter
    def timeout(self, max_idle_time):
        """ max_idle_time should be expressed in milliseconds """
        self._delegate.timeout = max_idle_time

    @property
    def host(self):
        return self._delegate.host

    def touch(self):
        self._delegate.touch()

    def stop(self):
        self._delegate.stop()

    def get_attribute_keys(self):
        return self._delegate.get_attribute_keys()

    def get_attribute(self, key):
        return self._delegate.get_attribute(key)

    def set_attribute(self, key, value):
        self._delegate.set_attribute(key, value)

    def remove_attribute(self, key):
        self._delegate.remove_attribute(key)


class SessionTokenGenerator(object):
    pass


class SessionManager(object):
    """
    A SessionManager manages the creation, maintenance, and clean-up of all 
    application Sessions.  A SessionManager will only return a VALID Session
    object to serve a request.

    Sessions are 'the time-based data contexts in which a Subject interacts 
    with an application'.
    """

    def __init__(self, cache_manager):
        self._cache_manager = cache_manager
        self._scheduler = BackgroundScheduler()

    def get_session(self, token):
        if (token is None):
            return create_session()
        elif (token is not None):
            session = self._cache_manager.get_deserialized('session:'+token)
            if (session.is_valid()):
                return session
            else:
                return create_session()

    def create_session(self, kwargs):
        session = self._session_factory.create_session(self._scheduler, kwargs)
        if (session.is_valid()):
            return session
        else:
            raise Exception('SessionManager Could Not Create Valid Session!')
            return None

    def delete_session(self, token):
        pass

    def session_factory(self):
        pass


class Session(object):
    
    def __init__(self, scheduler, session_cfg, origin_ip): 
        self._abs_timeout = session_cfg.abs_timeout_threshold_minutes
        self._abs_timeout_job = self.schedule_timeout('ABSOLUTE', 
                                                      self._abs_timeout)
        self._created_dt = datetime.utcnow()
        self._idle_timeout = session_cfg.idle_timeout_minutes
        self._idle_timeout_job = self.schedule_timeout('IDLE',
                                                       self._idle_timeout)
        self._last_access_dt = datetime.utcnow()
        self._origin_ip = origin_ip
        self._scheduler = scheduler
        self._status = 'VALID'
        self._status_reason = None 
        self._session_id = self.generate_token()

    def __repr__(self):
        return "<Session(session_id={0})>".format(self._session_id)

    @property
    def session_id(self):
        return self._session_id

    def is_valid(self):
        return (self._status == 'VALID')

    def get_authz_constraints(self):
        if (self.is_valid()):
            return self._authz_constraints
        else:
            return None
    
    def get_authz_privileges(self):
        if (self.is_valid()):
            return self._authz_privs
        else:
            return None
    
    def generate_token(self):
        rand = urandom(20)
        return sha256(sha256(rand).digest()).hexdigest()

    def get_abs_timeout(self):
        return self._abs_timeout_job

    def get_token(self):
        return self._session_id
    
    def reset_idle_timeout(self):
        self._idle_timeout_job.modify(minutes=self._idle_timeout)
    
    def set_invalid(self, timeout_type):
        if (self._status != 'INVALID'):
            self._status = 'INVALID'
            self._status_reason = timeout_type + ' TIMEOUT'
            self._status_chg_dt = datetime.utcnow()
            self._abs_timeout_job.remove()
            self._idle_timeout_job.remove()
    
    def schedule_timeout(self, timeout_type, duration):
        """ Uses the Advanced Python Scheduler (APScheduler) to schedule
            one-off delayed executions of commit_timeout for
            idle and absolute time thresholds.  Idle timeouts reset
            as a session is re-engaged/used.
        
        timeout_type = a String of either 'IDLE' or 'ABSOLUTE'
        """
        return self._scheduler.add_job(self.set_invalid(timeout_type), 
                                       'interval', minutes=duration)

    def touch(self):
        self.reset_idle_timeout()
        self._last_access_dt = datetime.utcnow()


class CachingSessionDAO(AbstractSessionDAO):

    def __init__(self):
        self._active_sessions_cache_name = "shiro-activeSessionCache"

    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        self._cache_manager = cachemanager

    @property
    def active_sessions_cache_name(self):
        return self._active_sessions_cache_name

    @active_sessions_cache_name.setter
    def active_sessions_cache_name(self, name):
        self._active_sessions_cache_name = name

    @property
    def active_sessions_cache(self):
        return self._active_sessions_cache

    @active_sessions_cache.setter
    def active_sessions_cache(self, cache):
        self._active_sessions_cache = cache

    def get_active_sessions_cache_lazy(self):
        if (not self.active_sessions):
            self.active_sessions = self.create_active_sessions_cache()
        
        return active_sessions
    
    def create_active_sessions_cache(self):
        mgr = self.cache_manager
        if (mgr):
            name = self.active_sessions_cache_name
            cache = mgr.getCache(name)
        
        return cache
    
    def create(self, session):
        sessionid = super().create(session)
        self.cache(session, sessionid)
        return sessionid
    
    def get_cached_session(self, sessionid):
        if (sessionid):
            cache = get_active_sessions_cache_lazy()
            if (cache):
                cached = self.get_cached_session(sessionid, cache)
   
        return cached
    
    def get_cached_session(self, sessionid, cache): 
        return cache.get(sessionid)
    
    def cache(self, session=None, sessionid=None, cache=None):
        if (not session or not sessionid):
            return
    
        if (not cache):
            cache = self.get_active_sessions_cache_lazy()
            if (not cache):
                return
    
        cache.put(sessionid, session)

    def read_session(self, sessionid):
        try:
            session = self.get_cached_session(sessionid)
            if (not session):
                session = super().read_session(sessionid)
            
            return session
        except:
            raise
    
    def update(self, session):
        try:
            self.do_update(session)
            if (isinstance(session, ValidatingSession)):
                if (session.is_valid):
                    self.cache(session, session.id)
                else: 
                    self.uncache(session)
                
            else:
                self.cache(session, session.id)
            
        except:
            raise
    
    # abstract method, to be implemented by subclass
    def do_update(self, session):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'do_update')

    def delete(self, session):
        self.uncache(session)
        self.do_delete(session)

    # abstract method, to be implemented by subclass
    def do_delete(self, session):
        msg = 'Failed to Implement Abstract Method: '
        raise AbstractMethodException(msg + 'do_update')
    
    def uncache(self, session): 
        if (not session):
            return
        
        sessionid = session.id
        if (not session):
            return
        
        cache = self.get_active_sessions_cache_lazy()
        if (cache):
            cache.remove(sessionid)
        
    def get_active_sessions(self):
        cache = self.get_active_sessions_cache_lazy()
        if (cache):
            return cache.values()
        else: 
            return set()


class DelegatingSession(object):

    def __init__(self, session_manager, session_key):
        """
        session_manager = a NativeSessionManager instance
        """
        try:
            if (not session_manager):
                msg1 = "session_manager argument cannot be null."
                raise IllegalArgumentException(msg1)
            
            if (not key):
                msg2 = "sessionKey argument cannot be null."
                raise IllegalArgumentException(msg2)
            
            if (not key.session_id):
                msg3 = ("The " + self.__class__.__name__ + 
                        "implementation requires that the SessionKey argument "
                        "returns a non-null sessionId to support the " 
                        "Session.getId() invocations.")
                raise IllegalArgumentException(msg3)
        except IllegalArgumentException as ex:
            print('DelegatingSession __init__ Exception: ', ex)

        self._session_manager = session_manager
        self._key = key

    @property
    def id(self):
        return self.key.session_id

    @property
    def key(self):
        return self._key

    @property
    def session_manager(self):
        return self._session_manager
   
    @property
    def start_timestamp(self):
        if (not self._start_timestamp):
            self._start_timestamp = self.session_manager.get_start_timestamp(
                self.key)
        return self._start_timestamp

    @property
    def last_access_time(self):
        return self.session_manager.get_last_access_time(self.key)

    @property
    def timeout(self):
        return self.session_manager.get_timeout(self.key)

    @timeout.setter
    def timeout(self, max_idle_time_in_millis):
        try:
            self.session_manager.set_timeout(self.key, 
                                             self.max_idle_time_in_millis)
        except:
            raise

    @property
    def host(self):
        if (not self.host):
            self._host = self.session_manager.get_host(self.key)
        
        return self._host

    def touch(self): 
        self.session_manager.touch(self.key)
    
    def stop(self):
        try:
            self.session_manager.stop(self.key)
        except:
            raise

    def get_attribute_keys(self):
        try:
            result = self.session_manager.get_attribute_keys(self.key)
        except:
            raise
        return result

    def get_attribute(self, attribute_key):
        try:
            result = sessionManager.getAttribute(self.key, attribute_key)
        except:
            raise
        return result
    
    def set_attribute(self, attribute_key, value):
        try:
            if (not value):
                self.remove_attribute(attribute_key)
            else:
                self.session_manager.set_attribute(self.key, attribute_key,
                                                   value)
        except:
            raise

    def remove_attribute(self, attribute_key):
        try:
            result = self.session_manager.remove_attribute(self.key,
                                                           attribute_key)
        except:
            raise
        return result


class DefaultSessionStorageEvaluator(object):

    """ 
     * Global policy determining if Subject sessions may be used to persist
     * Subject state if the Subject's Session does not yet exist.
    """
    def __init__(self):
        self._session_storage_enabled = True

    def is_session_storage_enabled(self, subject=None):
        if (not subject):
            return self.session_storage_enabled
        else:
            return ((subject and subject.get_session(False)) or 
                    bool(self.session_storage_enabled))
   
    @property
    def session_storage_enabled(self):
        return self._session_storage_enabled
    
    @session_storage_enabled.setter
    def session_storage_enabled(self, sse):
        self._session_storage_enabled = sse


class ExecutorServiceSessionValidationScheduler(object):

    def __init__(self, sessionmanager):
        self._session_manager = sessionmanager
        self._interval = DefaultSessionManager.\
            DEFAULT_SESSION_VALIDATION_INTERVAL
        self._enabled = False

        self._service = ScheduledExecutorService()  # DG: is this needed?

    @property
    def session_manager(self):
        return self._session_manager

    @session_manager.setter
    def session_manager(self, sessionmanager):
        self._session_manager = sessionmanager

    @property
    def interval(self):
        return self._interval

    @interval.setter
    def interval(self, interval):
        self._interval = interval

    @property
    def enabled(self):
        return self._enabled
    
    # DG: URGENT todo -- requires analysis:
    """
     Creates a ScheduledExecutorService to validate sessions at fixed intervals 
     and enables this scheduler. The executor is created as a daemon thread to allow JVM to shut down

    """
    # TODO Implement an integration test to test for jvm exit as part of the standalone example
    # (so we don't have to change the unit test execution model for the core module)
    public void enableSessionValidation() {
        if (this.interval > 0l) {
            this.service = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {  
	        public Thread newThread(Runnable r) {  
	            Thread thread = new Thread(r);  
	            thread.setDaemon(true);  
	            return thread;  
                }  
            });                  
            this.service.scheduleAtFixedRate(this, interval, interval, TimeUnit.MILLISECONDS);
            this.enabled = true;
        }
    }

    def run(self):
        # log here
        msg = "Executing session validation..."
        print(msg)
        start_time = int(round(time.time() * 1000)) 
        self.session_manager.validate_sessions()
        stop_time = int(round(time.time() * 1000)) 
        # log here
        msg2 = ("Session validation completed successfully in "
                (stop_time - start_time) + " milliseconds.")
        print(msg2) 

    def disable_session_validation(self):
        self.service.shutdown_now()
        self.enabled = False


class RandomSessionIDGenerator(object):

    public RandomSessionIdGenerator(self):
        # DG:  simplified this for v1 release by defaulting to sha256
        rand = urandom(20)
        self._random = self.generate_id('foobar') 

    @property
    def random(self):
        return self._random

    @random.setter(self, random):
        self._random = random

    def generate_id(self, session):
        # DG:  again, shiro ignores the argument..
        return sha256(sha256(rand).digest()).hexdigest()
    

class SimpleSession(object):

    def __init__(self, host=None):
        self._millis_per_second = 1000
        self._millis_per_minute = 60 * self.millis_per_second
        self._millis_per_hour = 60 * self.millis_per_minute
        # DG:  removed serialization bitmask fields and transient attributes
        #      until it's clear whether self issue carries over to python and 
        #      jsonpickle 

        # DG: todo - remove concrete reference to DefaultSessionManager:
        self._timeout = DefaultSessionManager.DEFAULTGLOBALSESSIONTIMEOUT
        self._start_timestamp = datetime.now() 
        self._last_access_time = self._start_timestamp
        self._host = host
    
    def __eq__(self, other):
        if (self == other): 
            return True
        
        if (isinstance(other, SimpleSession)):
            self_id = self.session_id
            other_id = other.session_id
            if (self_id and other_id):
                return (self_id == other_id)
            else:
                # fall back to an attribute based comparison:
                return self.on_equals(other)
        return False 

    # DG:  renamed id to session_id because of reserved word conflict
    @property
    def session_id(self):
        return self._session_id
    
    @session_id.setter
    def session_id(self, identity):
        self._session_id = identity

    @property
    def start_timestamp(self):
        return self._start_timestamp

    @start_timestamp.setter
    def start_timestamp(self, start_ts):
        self._start_timestamp = start_ts

    @property
    def stop_timestamp(self):
        return self._stop_timestamp

    @stop_timestamp.setter
    def stop_timestamp(self, stop_ts):
        self._stop_timestamp = stop_ts
    
    @property
    def last_access_time(self):
        return self._last_access_time
    
    @last_access_time.setter
    def last_access_time(self, last_access_time):
        self._last_access_time = last_access_time

    @property
    def expired(self):
        return self._expired

    @expired.setter
    def expired(self, expired):
        self.expired = expired

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, timeout):
        """ timeout = expressed in milliseconds """
        self._timeout = timeout

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        self._host = host

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, attrs):
        self._attributes = attrs

    def touch(self):
        self._last_access_time = datetime.now() 

    def stop(self):
        if (not self.stop_timestamp):
            self.stop_timestamp = datetime.now() 

    def stopped(self):
        return bool(self.stop_timestamp)

    def expire(self):
        self.stop()
        self.expired = True

    def is_valid(self):
        return (not self.stopped and not self.expired)

    def is_timed_out(self):
        if (self.expired):
            return True

        timeout = self.timeout

        if (timeout):
            try:
                last_access_time = self.last_access_time

                if (not last_access_time):
                    msg = ("session.lastAccessTime for session with id [" + 
                           self.session_id + "] is null. This value must be"
                           "set at least once, preferably at least upon "
                           "instantiation. Please check the " 
                           + self.__class__.__name__ +
                           " implementation and ensure self value will be set "
                           "(perhaps in the constructor?)")
                    raise IllegalStateException(msg)
            except IllegalStateException as ex:
                print('is_time_out IllegalStateException:', ex)
            """
             Calculate at what time a session would have been last accessed
             for it to be expired at self point.  In other words, subtract
             from the current time the amount of time that a session can
             be inactive before expiring.  If the session was last accessed
             before self time, it is expired.
            """
            current_millis = int(round(time.time() * 1000)) 
            expiretimemillis = current_millis - timeout
            return last_access_time < expiretimemillis 
        else:
            # log here
            msg2 = ("No timeout for session with id [" + self.session_id + 
                    "]. Session is not considered expired.")
            print(msg2) 
        
        return False

    def validate(self):
        try:
            # check for stopped:
            if (self.stopped):
                # timestamp is set, so the session is considered stopped:
                msg = ("Session with id [" + self.session_id + "] has been "
                       "explicitly stopped.  No further interaction under "
                       "this session is allowed.")
                raise StoppedSessionException(msg)
            
            # check for expiration
            if (self.is_timed_out()):
                self.expire()

                # throw an exception explaining details of why it expired:
                lastaccesstime = str(datetime.fromtimestamp(
                    self.last_access_time))
                timeout_sec = str(datetime.fromtimestamp(
                    self.timeout//self.millis_per_second))
                timeout_min = str(datetime.fromtimestamp(
                    self.timeout//self.millis_per_minute))

                currenttime = str(datetime.now()) 
                session_id = self.session_id 

                msg2 = ("Session with id [" + session_id + "] has expired. " 
                        "Last access time: " + lastaccesstime + 
                        ".  Current time: " + currenttime +
                        ".  Session timeout is set to " + timeout_sec + 
                        " seconds (" + timeout_min + " minutes)")
                # log here
                print(msg2)
                raise ExpiredSessionException(msg2)
            
        except StoppedSessionException as ex:
            print('SimpleSession.validate StoppedSessionException:', ex)
            raise

        except ExpiredSessionException as ex:
            print('SimpleSession.validate ExpiredSessionException:', ex)
            raise

    def get_attributes_lazy(self):
        attributes = self.attributes
        if (not attributes):
            attributes = {}
            self.attributes = attributes
        return self.attributes

    def get_attribute_keys(self):
        try:
            attributes = self.attributes
            if (not attributes):
                return set() 
            return {attributes}  # keys is default
        except:
            raise

    def get_attribute(self, key):
        attributes = self.attributes  # should be a Dict
        if (not attributes):
            return None 
        
        return attributes.get(key, None)

    def set_attribute(self, key, value):
        if (not value):
            self.remove_attribute(key)
        else:
            self.get_attributes_lazy()[key] = value
        
    def remove_attribute(self, key):
        attributes = self.attributes
        if (not attributes):
            return None 
        else:
            return attributes.pop(key)

    def on_equals(self, ss):
        return (((self.start_timestamp == ss.start_timestamp) if (self.start_timestamp) else (not ss.start_timestamp)) and 
                ((self.stop_timestamp == ss.stop_timestamp) if (self.stop_timestamp) else (not ss.stop_timestamp)) and
                ((self.last_access_time == ss.last_access_time) if (self.last_access_time) else (not ss.last_accessTime)) and
                (self.timeout == ss.timeout) and
                (self.expired == ss.expired) and
                ((self.host == ss.host) if (self.host) else (not ss.host)) and
                ((self.attributes == ss.attributes) if (self.attributes) else (not ss.attributes)))
    
    # DG:  deleted hashcode, string builder, writeobject, readObject, 
    #      getalteredfieldsbitmask, isFieldPresent


class SimpleSessionFactory(object):
   
    def __init__(self):
        pass

    @classmethod
    def create_session(self, session_context=None):
        if (session_context):
            host = session_context.host
            if (host):
                return SimpleSession(host)
            
        return SimpleSession()


class UUIDSessionGenerator(object):
    
    def __init__(self):
        pass

    def generate_id(self, session):
        # DG: ignores session argument.. as to why, who knows?
        return str(uuid.uuid4())

