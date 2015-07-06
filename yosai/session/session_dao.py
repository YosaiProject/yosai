from . import (
    RandomSessionIDGenerator,
    SimpleSession,
)

from yosai import (
    AbstractMethodException,
    IllegalArgumentException,
    IllegalStateException,
    SessionDeleteException,
    SessionCacheException,
    UncacheSessionException,
    UnknownSessionException,
)

from yosai.session import abcs as session_abcs
from yosai.cache import abcs as cache_abcs

from abc import abstractmethod


class AbstractSessionDAO(session_abcs.SessionDAO):
    """
    An abstract SessionDAO implementation that performs some sanity checks on
    session creation and reading and allows for pluggable Session ID generation
    strategies if desired.  The SessionDAO.update and SessionDAO.delete method
    implementations are left to subclasses.

    Session ID Generation
    ---------------------
    This class also allows for plugging in a SessionIdGenerator for
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
        self.session_id_generator = RandomSessionIDGenerator
        
    def generate_session_id(self, session):
        """
        :param session: the new session instance for which an ID will be 
                        generated and then assigned
        """
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
        if session is None or session_id is None:
            msg = ("session and sessionid parameters must be passed in "
                   "order to assign session_id")
            raise IllegalArgumentException(msg)
        session.session_id = session_id
    
    @abstractmethod
    def do_create(self, session):
        pass

    def read_session(self, session_id):
        session = self.do_read_session(session_id)
        if session is None:
            msg = "There is no session with id [" + str(session_id) + "]"
            raise UnknownSessionException(msg)
        return session

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


class CachingSessionDAO(AbstractSessionDAO, cache_abcs.CacheManagerAware):
    """
    An CachingSessionDAO is a SessionDAO that provides a transparent caching
    layer between the components that use it and the underlying EIS
    (Enterprise Information System) session backing store (for example,
    filesystem, database, enterprise grid/cloud, etc).

    This implementation caches all active sessions in a configured
    active_sessions_cache.  This property is None by default and if one is
    not explicitly set, a cache manager is expected to be configured that will 
    in turn be used to acquire the Cache instance used for the 
    active_sessions_cache.

    All SessionDAO methods are implemented by this class to employ
    caching behavior and delegates the actual EIS operations to respective 
    'do' methods to be implemented by subclasses (do_create, do_read, etc).
    """
    def __init__(self):
        self.active_sessions_cache_name = "yosai_active_session_cache"
        self.cache_manager = None
        self.active_sessions = None
    
    # cache_manager property is required by interface
    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        self._cache_manager = cachemanager

    @property
    def active_sessions_cache(self):
        return self.active_sessions

    @active_sessions_cache.setter
    def active_sessions_cache(self, cache):
        self.active_sessions = cache

    def get_active_sessions_cache_lazy(self):
        if (self.active_sessions is None):
            self.active_sessions = self.create_active_sessions_cache()
        
        return self.active_sessions
    
    def create_active_sessions_cache(self):
        cache = None
        mgr = self.cache_manager
        if (mgr):
            name = self.active_sessions_cache_name
            cache = mgr.get_cache(name)
        return cache
    
    def create(self, session):
        sessionid = super().create(session)
        self.cache(session=session, session_id=sessionid)
        return sessionid
    
    def get_cached_session(self, sessionid, cache=None):
            try:
                if not cache: 
                    cache = self.get_active_sessions_cache_lazy()
                    return self.get_cached_session(sessionid, cache)
                else:
                    return cache.get(sessionid)
            except AttributeError:
                msg = "Cannot get cached session"
                raise SessionCacheException(msg)

    def cache(self, session, sessionid, cache=None):
        # don't try to cache garbage:
        if session is None or sessionid is None:
            return
        try:
            if (not cache):
                cache = self.get_active_sessions_cache_lazy()
        
            cache.put(sessionid, session)
        except AttributeError:
            return

    def read_session(self, sessionid):
        session = self.get_cached_session(sessionid)
        if (session is None):
            session = super().read_session(sessionid)
        
        return session
    
    def update(self, session):
        self.do_update(session)
        if (isinstance(session, session_abcs.ValidatingSession)):
            if (session.is_valid):
                self.cache(session=session, session_id=session.session_id)
            else: 
                self.uncache(session)
            
        else:
            self.cache(session=session, session_id=session.session_id)
    
    @abstractmethod
    def do_update(self, session):
        pass

    def delete(self, session):
        self.uncache(session)
        self.do_delete(session)

    @abstractmethod
    def do_delete(self, session):
        pass

    def uncache(self, session): 
        try:
            sessionid = session.session_id
            cache = self.get_active_sessions_cache_lazy()
            cache.remove(sessionid)
        except AttributeError:
            msg = "Tried to uncache a session with incomplete parameters"
            print(msg)
            # log here
            return
        except KeyError:
            msg = "Tried to uncache a session that wasn't cached."
            raise UncacheSessionException(msg)
            
    def get_active_sessions(self):
        try:
            cache = self.get_active_sessions_cache_lazy()
            return tuple(cache.values())

        except AttributeError: 
            return tuple()

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

