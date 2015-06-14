from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from os import urandom
from hashlib import sha256
import time
import uuid

from yosai import (
    AbstractMethodException,
    # Context,
    ExpiredSessionException,
    LogManager,
    MissingMethodException,
    UnknownSessionException,
    settings,
)
import yosai.serialize.abcs as serialize_abcs
import abcs


class DefaultSessionSettings:
    """
    DefaultSessionSettings is a settings proxy.  It is new for Yosai.
    It obtains the session configuration from Yosai's global settings
    and default values if there aren't any.
    """
    def __init__(self):
        self.millis_per_second = 1000
        self.millis_per_minute = 60 * self.millis_per_second
        self.millis_per_hour = 60 * self.millis_per_minute

        session_config = settings.SESSION_CONFIG
        timeout_config = session_config.get('session_timeout', None)
        validation_config = session_config.get('session_validation', None)

        self.absolute_timeout = timeout_config.get('absolute_timeout',
                                                   45 * self.millis_per_minute)
        self.idle_timeout = timeout_config.get('idle_timeout',
                                               15 * self.millis_per_minute)
        self.validation_scheduler_enable =\
            validation_config.get('scheduler_enabled', True)

        self.validation_time_interval = validation_config.get('time_interval',
                                                              self.millis_per_hour)
    
    def __repr__(self):
        return ("SessionSettings(absolute_timeout={0}, idle_timeout={1}, "
                "validation_scheduler_enable={2}, "
                "validation_time_interval={3})".
                format(
                    self.absolute_timeout, 
                    self.idle_timeout,
                    self.validation_scheduler_enable,
                    self.validation_time_interval))


# Yosai omits the SessionListenerAdapter class as a valid use case is unclear

class ProxiedSession(abcs.Session):
   
    def __init__(self, target_session):
        # the proxied instance:
        self._delegate = target_session

    @property
    def session_id(self):
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
        """ 
        max_idle_time should be expressed in milliseconds 
        """
        self._delegate.timeout = max_idle_time

    @property
    def host(self):
        return self._delegate.host

    def touch(self):
        self._delegate.touch()

    def stop(self):
        self._delegate.stop()

    @property
    def attribute_keys(self):
        return self._delegate.attribute_keys

    def get_attribute(self, key):
        return self._delegate.get_attribute(key)

    def set_attribute(self, key, value):
        self._delegate.set_attribute(key, value)

    def remove_attribute(self, key):
        self._delegate.remove_attribute(key)


class SimpleSession(abcs.ValidatingSession, serialize_abcs.Serializable):
    
    # Serialization reminder:
    # ------------------------------------------------------------------
    # Messagepack is schemaless, and so to trace possible version 
    # compatability issues between deserialized objects and this class, 
    # a version UUID is used 
    #
    # You _MUST_ change the following UUID if you introduce a change to this 
    # class that is NOT serialization backwards compatible.  
    # Serialization-compatible  changes do not require a change to this 
    # number.  If you need to generate a new ID in this case, use the 
    # stdlib uuid module:  
    #    >>> import uuid
    #    >>> uuid.uuid4()
    #       UUID('1677d236-b814-406b-94dc-28a879791cfc')
    # 
    # this is essentially a serialVersionUID without any autovalidation
    VERSION_UUID = "1677d236-b814-406b-94dc-28a879791cfc"

    def __init__(self, session_config, host=None):
        # Yosai includes a session_config parameter to enable dynamic settings
        self._timeout = session_config.absolute_timeout
        self._start_timestamp = self.unix_epoch_time 
        self._last_access_time = self._start_timestamp
        self._host = host
        self.millis_per_second = session_config.millis_per_second
        self.millis_per_minute = session_config.millis_per_minute
        self.serialization_method = session_config.serialization_method
    
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
    
    @property
    def unix_epoch_time(self): 
        # expressed in milliseconds:
        return int(time.mktime(datetime.datetime.now().timetuple())) * 1000

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
        """
        :param  : expressed as unix epoch timestamp in milliseconds
        """
        self._start_timestamp = start_ts

    @property
    def stop_timestamp(self):
        return self._stop_timestamp

    @stop_timestamp.setter
    def stop_timestamp(self, stop_ts):
        """
        :param  : expressed as unix epoch timestamp in milliseconds
        """
        self._stop_timestamp = stop_ts
    
    @property
    def last_access_time(self):
        return self._last_access_time
    
    @last_access_time.setter
    def last_access_time(self, last_access_time):
        """
        :param  : expressed as unix epoch timestamp in milliseconds
        """
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
        """ timeout = expressed in milliseconds in milliseconds """
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
        self._last_access_time = self.unix_epoch_time 

    def stop(self):
        if (not self.stop_timestamp):
            self.stop_timestamp = self.unix_epoch_time 

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
            current_millis = self.unix_epoch_time 
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
                lastaccesstime = datetime.fromtimestamp(
                    self.last_access_time).strftime('%Y-%m-%d %H:%M:%S')

                timeout_sec = datetime.fromtimestamp(
                    self.timeout//self.millis_per_second)
                timeout_min = str(datetime.fromtimestamp(
                    self.timeout//self.millis_per_minute))

                currenttime = str(datetime.now()) 
                session_id = str(self.session_id)

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

    def __serialize__(self):
        """ follows similar role as __json__ does """
        return {key: value for key, value in 
                {'class': self.__class__.__name__,
                 'version': self.__class___.VERSION_UUID,
                 'session_id': self.session_id,
                 'start_timestamp': self.start_timestamp,
                 'stop_timestamp': self.stop_timestamp,
                 'last_access_time': self.last_access_time,
                 'timeout': self.timeout,
                 'expired': self.expired,
                 'host': self.host,
                 'attributes': self.attributes}.items() if value}


class SimpleSessionFactory:
   
    def __init__(self):
        pass

    @classmethod
    def create_session(self, session_context=None):
        if (session_context):
            host = session_context.host
            if (host):
                return SimpleSession(host)
            
        return SimpleSession()

"""
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
"""
