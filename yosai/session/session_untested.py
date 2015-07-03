
"""
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


"""
