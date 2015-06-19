class AbstractSessionDAO:

    def __init__(self):
        self._session_id_generator = RandomSessionIDGenerator()
        
    @property
    def session_id_generator(self):
        return self._session_id_generator
    
    @session_id_generator.setter
    def session_id_generator(self, sid_generator):
        self._session_id_generator = sid_generator

    def generate_session_id(self, session):
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


