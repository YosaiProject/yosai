
"""
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
        self.method can be used either with a single session parameter or
        with session, ese, and session_key passed altogether

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

class DefaultSessionContext():  
    DG:  shiro extends from MapContext but I just use composition instead,
         just as with SubjectContext
    
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


class DefaultSessionKey:

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


class SessionTokenGenerator:
    pass


class SessionManager:
    A SessionManager manages the creation, maintenance, and clean-up of all 
    application Sessions.  A SessionManager will only return a VALID Session
    object to serve a request.

    Sessions are 'the time-based data contexts in which a Subject interacts 
    with an application'.

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


class Session:
    
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
        Uses the Advanced Python Scheduler (APScheduler) to schedule
            one-off delayed executions of commit_timeout for
            idle and absolute time thresholds.  Idle timeouts reset
            as a session is re-engaged/used.
        
        timeout_type = a String of either 'IDLE' or 'ABSOLUTE'
        return self._scheduler.add_job(self.set_invalid(timeout_type), 
                                       'interval', minutes=duration)

    def touch(self):
        self.reset_idle_timeout()
        self._last_access_dt = datetime.utcnow()


class DefaultSessionStorageEvaluator:

     # Global policy determining if Subject sessions may be used to persist
     # Subject state if the Subject's Session does not yet exist.
    
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


class ExecutorServiceSessionValidationScheduler:

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
    """    
    # DG: URGENT todo -- requires analysis:
    # Creates a ScheduledExecutorService to validate sessions at fixed intervals 
    # and enables this scheduler. The executor is created as a daemon thread to allow JVM to shut down

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
"""
"""
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

"""
