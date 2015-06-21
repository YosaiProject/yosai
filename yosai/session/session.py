import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from os import urandom
from hashlib import sha256, sha512
import time
import uuid
import traceback as tb
from abc import ABCMeta, abstractmethod
from yosai.event import abcs as event_abcs

from yosai import (
    AbstractMethodException,
    # Context,
    ExpiredSessionException,
    IllegalArgumentException,
    IllegalStateException,
    InvalidSessionException,
    LogManager,
    MissingMethodException,
    SessionEventException,
    StoppedSessionException,
    UnknownSessionException,
    UnrecognizedAttributeException,
    settings,
)
from yosai.serialize import abcs as serialize_abcs
from yosai.session import abcs

class DefaultSessionSettings:
    """
    DefaultSessionSettings is a settings proxy.  It is new for Yosai.
    It obtains the session configuration from Yosai's global settings
    and default values if there aren't any.
    """
    def __init__(self):

        # omitted millisecond conversions

        session_config = settings.SESSION_CONFIG
        timeout_config = session_config.get('session_timeout', None)
        validation_config = session_config.get('session_validation', None)

        abstimeout = timeout_config.get('absolute_timeout', 1800)  # def:30min
        self.absolute_timeout = datetime.timedelta(seconds=abstimeout) 

        idletimeout = timeout_config.get('idle_timeout', 450) # def:15min
        self.idle_timeout = datetime.timedelta(seconds=idletimeout)

        self.validation_scheduler_enable =\
            validation_config.get('scheduler_enabled', True)

        interval = validation_config.get('time_interval', 3600) # def:1hr 
        self.validation_time_interval = interval

    def __repr__(self):
        return ("SessionSettings(absolute_timeout={0}, idle_timeout={1}, "
                "validation_scheduler_enable={2}, "
                "validation_time_interval={3})".
                format(
                    self.absolute_timeout, 
                    self.idle_timeout,
                    self.validation_scheduler_enable,
                    self.validation_time_interval))

# initalize module-level settings:
session_settings = DefaultSessionSettings()


# Yosai omits the SessionListenerAdapter class

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
    def idle_timeout(self):
        return self._delegate.idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, max_idle_time):
        self._delegate.idle_timeout = max_idle_time
    
    @property
    def absolute_timeout(self):
        return self._delegate.absolute_timeout

    @absolute_timeout.setter
    def absolute_timeout(self, abs_time):
        self._delegate.absolute_timeout = abs_time

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

    def __repr__(self):
        return "ProxiedSession(session_id={0})".format(self.session_id)


class ImmutableProxiedSession(ProxiedSession):
    """
    Implementation of the Session interface that proxies another 
    Session, but does not allow any 'write' operations to the underlying 
    session. It allows 'read' operations only.

    The Session write operations are defined as follows.  A call to any of 
    these methods/setters on this proxy will immediately raise an 
    InvalidSessionException:
        * idle_timeout.setter, absolute_timeout.setter 
        * touch()
        * stop()
        * set_attribute(key,value)
        * remove_attribute(key)

    Any other method invocation not listed above will result in a 
    corresponding call to the underlying Session.
    """
    def __init__(self, target_session):
        super().__init__(target_session)
        self.exc_message = ("This session is immutable and read-only - it "
                            "cannot be altered.  This is usually because "
                            "the session has been stopped or expired.")
    
    @property
    def set_idle_timeout(self, idle_timeout):
        raise InvalidSessionException(self.exc_message)

    @property
    def set_absolute_timeout(self, absolute_timeout):
        raise InvalidSessionException(self.exc_message)

    def touch(self):
        raise InvalidSessionException(self.exc_message)

    def stop(self):
        raise InvalidSessionException(self.exc_message)

    def set_attribute(self, key, value):
        raise InvalidSessionException(self.exc_message)

    def remove_attribute(self, key):
        raise InvalidSessionException(self.exc_message)
        raise Exception('this exception should never have raised, ALERT!')


class SimpleSession(abcs.ValidatingSession, serialize_abcs.Serializable):
    
    # Yosai omits:
    #    - the manual class version control process (too policy-reliant)
    #    - the bit-flagging technique (will cross this bridge later, if needed)

    def __init__(self, host=None):
        self._attributes = None
        self._is_expired = None
        self._session_id = None

        self._stop_timestamp = None
        self._start_timestamp = datetime.datetime.utcnow() 
        self._last_access_time = self._start_timestamp
        
        # yosai renames global_session_timeout to idle_timeout and added
        # the absolute_timeout feature
        self._absolute_timeout = session_settings.absolute_timeout  # timedelta 
        self._idle_timeout = session_settings.idle_timeout  # timedelta

        self._host = host

    # the properties are required to enforce the Session abc-interface.. 
    @property
    def absolute_timeout(self):
        return self._absolute_timeout

    @absolute_timeout.setter
    def absolute_timeout(self, abs_timeout):
        """
        :type abs_timeout: timedelta
        """
        self._absolute_timeout = abs_timeout

    @property
    def attributes(self):
        return self._attributes

    @attributes.setter
    def attributes(self, attrs):
        self._attributes = attrs

    @property
    def attribute_keys(self):
        if (self.attributes is None):
            return None 
        return set(self.attributes)  # a set of keys 

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, host):
        """
        :type host:  string 
        """
        self._host = host

    @property
    def idle_timeout(self):
        return self._idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, idle_timeout):
        """
        :type idle_timeout: timedelta
        """
        self._idle_timeout = idle_timeout
    
    @property
    def is_expired(self):
        return self._is_expired

    @is_expired.setter
    def is_expired(self, expired):
        self._is_expired = expired

    @property
    def is_stopped(self):
        return bool(self.stop_timestamp)

    @property
    def last_access_time(self):
        return self._last_access_time
    
    @last_access_time.setter
    def last_access_time(self, last_access_time):
        """
        :param  last_access_time: time that the Session was last used, in utc 
        :type last_access_time: datetime
        """
        self._last_access_time = last_access_time

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
        :param  start_ts: the time that the Session is started, in utc 
        :type start_ts: datetime
        """
        self._start_timestamp = start_ts

    @property
    def stop_timestamp(self):
        return self._stop_timestamp

    @stop_timestamp.setter
    def stop_timestamp(self, stop_ts):
        """
        :param  stop_ts: the time that the Session is stopped, in utc 
        :type stop_ts: datetime
        """
        self._stop_timestamp = stop_ts

    @property
    def absolute_expiration(self):
        if self.absolute_timeout:
            return self.start_timestamp + self.absolute_timeout
        return None

    @property
    def idle_expiration(self):
        if self.idle_timeout:
            return self.last_access_time + self.idle_timeout
        return None

    def touch(self):
        self.last_access_time = datetime.datetime.utcnow() 

    def stop(self):
        if (not self.stop_timestamp):
            self.stop_timestamp = datetime.datetime.utcnow()  

    def expire(self):
        self.stop()
        self.is_expired = True

    def is_valid(self):
        return (not self.is_stopped and not self.is_expired)

    def is_timed_out(self):
        """
        determines whether a Session has been inactive/idle for too long a time
        OR exceeds the absolute time that a Session may exist
        """
        if (self.is_expired):
            return True

        if (self.absolute_timeout or self.idle_timeout):
            if (not self.last_access_time):
                msg = ("session.last_access_time for session with id [" + 
                       str(self.session_id) + "] is null. This value must be"
                       "set at least once, preferably at least upon "
                       "instantiation. Please check the " + 
                       self.__class__.__name__ +
                       " implementation and ensure self value will be set "
                       "(perhaps in the constructor?)")
                raise IllegalStateException(msg)

            """
             Calculate at what time a session would have been last accessed
             for it to be expired at this point.  In other words, subtract
             from the current time the amount of time that a session can
             be inactive before expiring.  If the session was last accessed
             before this time, it is expired.
            """
            current_time = datetime.datetime.utcnow() 

            # Check 1:  Absolute Timeout
            if self.absolute_expiration:
                if (current_time > self.absolute_expiration):
                    return True

            # Check 2:  Inactivity Timeout
            if self.idle_expiration:
                if (current_time > self.idle_expiration): 
                    return True

        else:
            msg2 = ("Timeouts not set for session with id [" + 
                    str(self.session_id) + "]. Session is not considered "
                    "expired.")
            print(msg2) 
            # log here
        
        return False

    def validate(self):
        # check for stopped:
        if (self.is_stopped):
            # timestamp is set, so the session is considered stopped:
            msg = ("Session with id [" + str(self.session_id) + "] has been "
                   "explicitly stopped.  No further interaction under "
                   "this session is allowed.")
            raise StoppedSessionException(msg)
        
        # check for expiration
        if (self.is_timed_out()):
            self.expire()

            # throw an exception explaining details of why it expired:
            lastaccesstime = self.last_access_time.isoformat()

            idle_timeout = self.idle_timeout.seconds
            idle_timeout_min = str(idle_timeout // 60)

            absolute_timeout = self.absolute_timeout.seconds
            absolute_timeout_min = str(absolute_timeout // 60)

            currenttime = datetime.datetime.utcnow().isoformat() 
            session_id = str(self.session_id)

            msg2 = ("Session with id [" + session_id + "] has expired. " 
                    "Last access time: " + lastaccesstime + 
                    ".  Current time: " + currenttime +
                    ".  Session idle timeout is set to " + str(idle_timeout) + 
                    " seconds (" + idle_timeout_min + " minutes) and "
                    " absolute timeout is set to " + str(absolute_timeout) +
                    " seconds (" + absolute_timeout_min + "minutes)")
            print(msg2)
            # log here
            raise ExpiredSessionException(msg2)
            
    def get_attributes_lazy(self):
        if (self.attributes is None):
            self.attributes = {}
        return self.attributes 

    def get_attribute(self, key):
        if (not self.attributes):
            return None 
        
        return self.attributes.get(key, None)

    def set_attribute(self, key, value=None):
        if (not value):
            self.remove_attribute(key)
        else:
            self.get_attributes_lazy()[key] = value
        
    def remove_attribute(self, key):
        if (not self.attributes):
            return None 
        else:
            return self.attributes.pop(key, None)

    # deleted on_equals as it is unecessary in python
    # deleted hashcode method as python's __hash__ is fine

    # omitting the bit-flagging methods:
    #       writeobject, readObject, getalteredfieldsbitmask, isFieldPresent
    
    def __eq__(self, other):
        try:
            result = (self.session_id == other.session_id)
        except AttributeError:
            return (self.__dict__ == other.__dict__)
        return result 

    def __repr__(self):
        return "SimpleSession(start_timestamp={0}, last_access_time={1})".\
            format(self.start_timestamp, self.last_access_time)
       
    def __serialize__(self):
        return {'session_id': self.session_id,
                'start_timestamp': self.start_timestamp,
                'stop_timestamp': self.stop_timestamp,
                'last_access_time': self.last_access_time,
                'timeout': self.timeout,
                'is_expired': self.is_expired,
                'host': self.host,
                'attributes': self.attributes}


class SimpleSessionFactory(abcs.SessionFactory):
   
    @classmethod
    def create_session(cls, session_context=None):
        return SimpleSession(host=getattr(session_context, 'host', None))


class UUIDSessionIDGenerator(abcs.SessionIDGenerator):

    @classmethod
    def generate_id(self, session):
        # session argument is ignored
        return str(uuid.uuid4())


class RandomSessionIDGenerator(abcs.SessionIDGenerator):

    # saving self.random is unecessary, so omitting

    @classmethod
    def generate_id(self, session):
        # session argument is ignored
        return sha256(sha512(urandom(20)).digest()).hexdigest()


class DelegatingSession(abcs.Session):
    """
    A DelegatingSession is a client-tier representation of a server side 
    Session.  This implementation is basically a proxy to a server-side 
    NativeSessionManager, which will return the proper results for each 
    method call.

    A DelegatingSession will cache data when appropriate to avoid a remote 
    method invocation, only communicating with the server when necessary.

    Of course, if used in-process with a NativeSessionManager business object,
    as might be the case in a web-based application where the web classes 
    and server-side business objects exist in the same namespace, a remote 
    method call will not be incurred.
    """

    def __init__(self, session_manager, key):
        # omitting None-type checking
        self.key = key
        self.session_manager = session_manager
        self._start_timestamp = None
        self._host = None

    @property
    def session_id(self):
        return self.key.session_id

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
    def idle_timeout(self):
        return self.session_manager.get_idle_timeout(self.key)

    @idle_timeout.setter
    def idle_timeout(self, timeout):
        self.session_manager.set_idle_timeout(self.key, timeout)

    @property
    def absolute_timeout(self):
        return self.session_manager.get_absolute_timeout(self.key)

    @absolute_timeout.setter
    def absolute_timeout(self, timeout):
        self.session_manager.set_absolute_timeout(self.key, timeout)

    @property
    def host(self):
        if (not self._host):
            self._host = self.session_manager.get_host(self.key)
        
        return self._host

    def touch(self): 
        self.session_manager.touch(self.key)
    
    def stop(self):
        self.session_manager.stop(self.key)
    
    @property
    def attribute_keys(self):
        return self.session_manager.get_attribute_keys(self.key)

    def get_attribute(self, attribute_key):
        return self.session_manager.get_attribute(self.key, attribute_key)
    
    def set_attribute(self, attribute_key, value=None):
        if (value is None):
            self.remove_attribute(attribute_key)
        else:
            self.session_manager.set_attribute(self.key, attribute_key, value)

    def remove_attribute(self, attribute_key):
        return self.session_manager.remove_attribute(self.key, attribute_key)


class DefaultSessionKey(abcs.SessionKey):
    
    def __init__(self, session_id):
        self._session_id = session_id

    @property
    def session_id(self):
        return self._session_id

    @session_id.setter
    def session_id(self, session_id):
        self._session_id = session_id

    def __eq__(self, other):
        try:
            return self.session_id == other.session_id
        except AttributeError:
            return False


class AbstractNativeSessionManager(event_abcs.EventBusAware, 
                                   abcs.NativeSessionManager,
                                   metaclass=ABCMeta): 
    """
    AbstractNativeSessionManager is a mix-in, consisting largely of a 
    concrete implementation but also the specification of abstract methods
    to be implemented by its subclasses.  This is consistent with Shiro's
    abstract design.
    """

    def __init__(self, event_bus): 
        # new to yosai is the injection of the event_bus, as done with any
        # other EventBusAware subclasses
        
        self._listeners = []
        self._event_bus = event_bus
    
    @property
    def session_listeners(self):
        return self._listeners

    @session_listeners.setter
    def session_listeners(self, listeners):
        self._listeners = listeners

    @property
    def event_bus(self):
        return self._event_bus
    
    @event_bus.setter
    def event_bus(self, event_bus):
        self._event_bus = event_bus

    def publish_event(self, event):
        try:
            self.event_bus.publish(event)
        except AttributeError:
            msg = 'Could not publish event to eventbus.'
            raise SessionEventException(msg)

    def start(self, session_context):
        session = self.create_session(session_context)
        # new approach for yosai is to apply *two* timeouts:
        self.apply_session_timeouts(session_context)
        self.on_start(session, session_context)
        self.notify_start(session)
        
        # Don't expose the EIS-tier Session object to the client-tier:
        return self.create_exposed_session(session, session_context)

    @abstractmethod
    def create_session(self, session_context):
        """
        Creates a new {@code Session Session} instance based on the specified
        (possibly {@code null}) * initialization data.  Implementing classes
        must manage the persistent state of the returned session such that it
        could later be acquired via the {@link #getSession(SessionKey)} method.
     
        :param session_context: the initialization data that can be used by the
                                implementation or underlying SessionFactory
                                when instantiating the internal Session 
                                instance

        :returns: the new Session instance
     
        :raises HostUnauthorizedException:  if the system access control policy 
                                            restricts access based on client 
                                            location/IP and the specified 
                                            host address hasn't been enabled

        :raises AuthorizationException:  if the system access control policy 
                                         does not allow the currently executing
                                         caller to start sessions
        """
        pass

    # yosai renames applyGlobalSessionTimeout:
    def apply_session_timeouts(self, session):
        # new to yosai is the use of the absolute timeout:
        session.absolute_timeout = self.absolute_timeout
        session.idle_timeout = self.idle_timeout
        self.on_change(session)
    
    # yosai makes the following an abstractmethod, unlike shiro, so that 
    # any subclass will state its use or pass, but state it nonetheless
    @abstractmethod
    def on_start(self, session, session_context):  
        """
        Template method that allows subclasses to react to a new session being
        created.  This method is invoked *before* any session listeners are 
        notified.
     
        :param session: the session that was just created
        :param context: the SessionContext that was used to start the session
        """
        pass

    def get_session(self, key):
        session = self.lookup_session(key)
        if (session):
            return self.create_exposed_session(session, key)
        else:
            return None

    def lookup_session(self, key):
        return self.do_get_session(key)

    def lookup_required_session(self, key):
        session = self.lookup_session(key)
        if (session is None):
            msg = ("Unable to locate required Session instance based "
                   "on session_key [" + str(key) + "].")
            raise UnknownSessionException(msg)
        return session

    @abstractmethod
    def do_get_session(self, session_key):
        pass

    # yosai introduces the keyword parameterization
    def create_exposed_session(self, session, key=None, context=None): 
        # shiro ignores key and context parameters
        return DelegatingSession(self, DefaultSessionKey(session.session_id))

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

    @property
    def absolute_timeout(self):
        pass

    @absolute_timeout.setter
    def absolute_timeout(self, abs_timeout):
        """
        :type abs_timeout: timedelta
        """
        pass

    @property
    def idle_timeout(self):
        pass

    @idle_timeout.setter
    def idle_timeout(self, idle_timeout):
        """
        :type idle_timeout: timedelta
        """
        pass

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
