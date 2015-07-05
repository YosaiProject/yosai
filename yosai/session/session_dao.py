from . import (
    RandomSessionIDGenerator,
    SimpleSession,
)

from yosai import (
    AbstractMethodException,
    IllegalArgumentException,
    IllegalStateException,
    SessionDeleteException,
    UnknownSessionException,
)

from yosai.session import abcs as session_abcs
from abc import abstractmethod


class AbstractSessionDAO(session_abcs.SessionDAO):
    """
    An abstract SessionDAO implementation that performs some sanity checks on
    session creation and reading and allows for pluggable Session ID generation
    strategies if desired.  The SessionDAO SessionDAO.update and
    SessionDAO.delete methods are left to subclasses.

    Session ID Generation
    ---------------------
    This class also allows for plugging in a {@link SessionIdGenerator} for
    custom ID generation strategies.  This is optional, as the default
    generator is probably sufficient for most cases.  Subclass implementations
    that do use a generator (default or custom) will want to call the
    generate_session_id(Session) method from within their do_create
    implementations.

    Subclass implementations that rely on the EIS data store to generate the ID
    automatically (e.g. when the session ID is also an auto-generated primary
    key), they can simply ignore the SessionIdGenerator concept
    entirely and just return the data store's ID from the do_create
    implementation.
    """

    def __init__(self):
        # shiro defaults to UUID, yosai uses random:
        self._session_id_generator = RandomSessionIDGenerator()
        
    def generate_session_id(self, session):
        try:
            return self.session_id_generator.generate_id(session)
        except AttributeError:
            msg = "session_id_generator attribute has not been configured"
            raise IllegalStateException(msg)
    
    def create(self, session):
        session_id = self.do_create(session)
        self.verify_session_id(session_id)
        return session_id

    def verify_session_id(self, session_id):
        if (session_id is None):
            msg = ("session_id returned from do_create implementation "
                   "is None. Please verify the implementation.")
            raise IllegalStateException(msg)
    
    def assign_session_id(self, session, session_id):
        session.session_id = session_id
    
    @abstractmethod
    def do_create(self, session):
        pass

    def read_session(self, session_id):
        try:
            return self.do_read_session(session_id)
        except AttributeError:
            msg = "There is no session with id [" + str(session_id) + "]"
            raise UnknownSessionException(msg)

    @abstractmethod
    def do_read_session(self, session_id):
        pass


class MemorySessionDAO(AbstractSessionDAO):

    def __init__(self):
        self.sessions = {} 
    
    def do_create(self, session):
        sessionid = self.generate_session_id(session)
        self.assign_session_id(session, sessionid)
        self.store_session(sessionid, session)
        return sessionid

    def store_session(self, session_id, session):
        try:
            self.sessions[session_id] = session
            return self.sessions.get(session_id, None)
        except (AttributeError, KeyError):
            msg = 'MemorySessionDAO.store_session invalid param passed'
            raise IllegalArgumentException(msg)

    def do_read_session(self, sessionid):
        return self.sessions.get(sessionid, None)
    
    def update(self, session):
        self.store_session(session.session_id, session)

    def delete(self, session):
        try:
            sessionid = session.session_id
            self.sessions.pop(sessionid)
        except AttributeError: 
            msg = 'MemorySessionDAO.delete None param passed'
            raise IllegalArgumentException(msg)
        except KeyError:
            msg = 'MemorySessionDAO could not delete: ', str(session)
            raise SessionDeleteException(msg)

    def get_active_sessions(self):
        try:
            return tuple(self.sessions.values())
        except TypeError:
            return tuple()

"""
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
            if (isinstance(session, abcs.ValidatingSession)):
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
"""

"""
class EnterpriseCacheSessionDAO(CachingSessionDAO):

    def __init__(self): 
        
        DG:  not sure how to refactor this:
        public EnterpriseCacheSessionDAO() {
        setCacheManager(new AbstractCacheManager() {
            @Override
            protected Cache<Serializable, Session> createCache(String name) throws CacheException {
                return new MapCache<Serializable, Session>(name, new ConcurrentHashMap<Serializable, Session>());
            }
        });

    def do_create(self, session):
        sessionid = self.generate_session_id(session)
        self.assign_session_id(session, sessionid)
        return sessionid

"""

