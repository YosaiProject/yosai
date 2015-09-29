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

import datetime
import threading
import time
from abc import ABCMeta, abstractmethod
from marshmallow import Schema, fields, post_load

from yosai import (
    AbstractMethodException,
    MapContext,
    ExpiredSessionException,
    IllegalArgumentException,
    IllegalStateException,
    InvalidSessionException,
    LogManager,
    MissingMethodException,
    RandomSessionIDGenerator,
    SessionDeleteException,
    SessionEventException,
    StoppableScheduledExecutor,
    StoppedSessionException,
    UncacheSessionException,
    UnknownSessionException,
    UnrecognizedAttributeException,
    settings,
    session_settings,
    cache_abcs,
    event_abcs,
    serialize_abcs,
    session_abcs,
)

from abc import abstractmethod


class AbstractSessionStore(session_abcs.SessionStore):
    """
    An abstract SessionStore implementation performs some sanity checks on
    session creation and reading and allows for pluggable Session ID generation
    strategies if desired.  The SessionStore.update and SessionStore.delete method
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


class MemorySessionStore(AbstractSessionStore):
    """
    Simple memory-based implementation of the SessionStore that stores all of its
    sessions in an in-memory dict.  This implementation does not page
    to disk and is therefore unsuitable for applications that could experience
    a large amount of sessions and would therefore result in MemoryError
    exceptions as the interpreter runs out of memory.  This class is *not*
    recommended for production use in most environments.

    Memory Restrictions
    -------------------
    If your application is expected to host many sessions beyond what can be
    stored in the memory available to the Python interpreter, it is highly
    recommended that you use a different SessionStore implementation using a
    more expansive or permanent backing data store.

    Instead, use a custom CachingSessionStore implementation that communicates
    with a higher-capacity data store of your choice (Redis, Memcached,
    file system, rdbms, etc).
    """

    def __init__(self):
        self.sessions = {}

    def do_create(self, session):
        sessionid = self.generate_session_id(session)
        self.assign_session_id(session, sessionid)
        self.store_session(sessionid, session)
        return sessionid

    def store_session(self, session_id, session):
        # stores only if session doesn't already exist, returning the existing
        # session (as default) otherwise
        if session_id is None or session is None:
            msg = 'MemorySessionStore.store_session invalid param passed'
            raise IllegalArgumentException(msg)

        return self.sessions.setdefault(session_id, session)

    def do_read_session(self, sessionid):
        return self.sessions.get(sessionid)

    def update(self, session):
        return self.store_session(session.session_id, session)

    def delete(self, session):
        try:
            sessionid = session.session_id
            self.sessions.pop(sessionid)
        except AttributeError:
            msg = 'MemorySessionStore.delete None param passed'
            raise IllegalArgumentException(msg)
        except KeyError:
            msg = ('MemorySessionStore could not delete ', str(sessionid),
                   'because it does not exist in memory!')
            print(msg)
            # log here

    def get_active_sessions(self):
        return tuple(self.sessions.values())


class CachingSessionStore(AbstractSessionStore, cache_abcs.CacheManagerAware):
    """
    An CachingSessionStore is a SessionStore that provides a transparent caching
    layer between the components that use it and the underlying EIS
    (Enterprise Information System) session backing store (e.g.
    Redis, Memcached, filesystem, database, enterprise grid/cloud, etc).

    This implementation caches all active sessions in a configured
    active_sessions_cache.  This property is None by default. If one is
    not explicitly set, a cache manager is expected to be configured
    to acquire the Cache instance used for the active_sessions_cache.

    All SessionStore methods are implemented by this class to employ
    caching behavior, delegating the actual EIS operations to respective
    'do' methods implemented by subclasses (do_create, do_read, etc).
    """

    def __init__(self):
        self.active_sessions_cache_name = settings.active_sessions_cache_name
        self.cache_manager = None
        self.active_sessions = None

    # cache_manager property is required for CacheManagerAware interface
    @property
    def cache_manager(self):
        return self._cache_manager

    # cache_manager property is required for CacheManagerAware interface
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
        try:
            mgr = self.cache_manager
            name = self.active_sessions_cache_name
            return mgr.get_cache(name)
        except:
            return None

    def create(self, session):
        sessionid = super().create(session)
        self.cache(session=session, session_id=sessionid)
        return sessionid

    # java overloaded methods combined:
    def get_cached_session(self, sessionid, cache=None):
        if cache is None:
            cache = self.get_active_sessions_cache_lazy()
        try:
            # assume that sessionid isn't None
            return cache.get(sessionid)
        except AttributeError:
            msg = "no cache parameter nor lazy-defined cache"
            print(msg)
            # log here
        return None

    def cache(self, session, sessionid, cache=None):

        if (cache is None):
            cache = self.get_active_sessions_cache_lazy()

        try:
            cache.put(sessionid, session)
        except AttributeError:
            msg = "no cache parameter nor lazy-defined cache"
            print(msg)
        return

    def read_session(self, sessionid):
        session = self.get_cached_session(sessionid)
        if (session is None):
            session = super().read_session(sessionid)

        return session

    def update(self, session):
        self.do_update(session)

        # if (isinstance(session, session_abcs.ValidatingSession)):
        try:
            if (session.is_valid):
                self.cache(session=session, session_id=session.session_id)
            else:
                self.uncache(session)

        except AttributeError:
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

    def get_active_sessions(self):
        try:
            cache = self.get_active_sessions_cache_lazy()
            return tuple(cache.values)  # s/b a property attribute

        except AttributeError:
            return tuple()


# Yosai omits the SessionListenerAdapter class

class ProxiedSession(session_abcs.Session):

    def __init__(self, target_session):
        # the proxied instance:
        self._delegate = target_session
        self._session_id = None

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

    def set_idle_timeout(self, idle_timeout):
        raise InvalidSessionException(self.exc_message)

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


class SimpleSession(session_abcs.ValidatingSession, serialize_abcs.Serializable):

    # Yosai omits:
    #    - the manually-managed class version control process (too policy-reliant)
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
        if not hasattr(self, '_stop_timestamp'):
            self._stop_timestamp = None
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

    @property
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

        return self.attributes.get(key)

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
    # deleted hashcode method as python's __hash__ may be fine -- TBD!

    # omitting the bit-flagging methods:
    #       writeobject, readObject, getalteredfieldsbitmask, isFieldPresent

    def __eq__(self, other):
        try:
            result = (self.session_id == other.session_id)
        except AttributeError:
            return (self.__dict__ == other.__dict__)
        return result

    def __repr__(self):
        return ("SimpleSession(session_id: {0}, start_timestamp: {1}, "
                "stop_timestamp: {2}, last_access_time: {3},"
                "idle_timeout: {4}, absolute_timeout: {5}, is_expired: {6},"
                "host: {7})".format(self.session_id, self.start_timestamp,
                                    self.stop_timestamp, self.last_access_time,
                                    self.idle_timeout, self.absolute_timeout,
                                    self.is_expired, self.host))

    class SimpleSessionAttributesSchema(Schema):
        # Define key/value here for the attributes dictionary
        # e.g.:
        #  attribute1 = fields.Str()
        pass

        @post_load
        def make_ss_attributes(self, data):
            return dict(data)

    @classmethod
    def serialization_schema(cls):
        class SerializationSchema(Schema):
            _session_id = fields.Str()
            _start_timestamp = fields.DateTime()  # iso is default
            _stop_timestamp = fields.DateTime()  # iso is default
            _last_access_time = fields.DateTime()  # iso is default
            _idle_timeout = fields.TimeDelta()
            _absolute_timeout = fields.TimeDelta()
            _is_expired = fields.Boolean()
            _host = fields.Str()

            # NOTE:  After you've defined your SimpleSessionAttributesSchema,
            #        the Raw() fields assignment below should be replaced by
            #        the Schema line that follows it
            attributes = fields.Raw()
            # attributes = fields.Nested(cls.SimpleSessionAttributesSchema)

            @post_load
            def make_simple_session(self, data):
                mycls = SimpleSession
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema


class SimpleSessionFactory(session_abcs.SessionFactory):

    @classmethod
    def create_session(cls, session_context=None):
        return SimpleSession(host=getattr(session_context, 'host', None))


class DelegatingSession(session_abcs.Session):
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

    Note:  Shiro makes DelegatingSession Serializable where as Yosai doesn't
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

    def __repr__(self):
        return ("DelegatingSubject(session_id: {0}, start_timestamp: {1}, "
                "stop_timestamp: {2}, last_access_time: {3},"
                "idle_timeout: {4}, absolute_timeout: {5}, host: {6}, "
                "key: {7})".format(self.session_id, self.start_timestamp,
                                   self.stop_timestamp, self.last_access_time,
                                   self.idle_timeout, self.absolute_timeout,
                                   self.host, self.key))


class DefaultSessionKey(session_abcs.SessionKey):

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
                                   session_abcs.NativeSessionManager,
                                   metaclass=ABCMeta):
    """
    AbstractNativeSessionManager is an abc , consisting largely of a
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

        # new to yosai is the use of the absolute timeout and module-level
        # session_settings
        session.absolute_timeout = session_settings.absolute_timeout
        session.idle_timeout = session_settings.idle_timeout
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
        if (not session):
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
        """
         Returns the session instance that should be passed to registered
         SessionListener(s) for notification that the session has been
         invalidated (stopped or expired).

         The default implementation returns an ImmutableProxiedSession instance
         to ensure that the specified {@code session} argument is not modified
         by any listeners.

         :param session: the Session object to be invalidated
         :returns: the Session instance that is passed to registered
                   SessionListener(s) as part of the notification process
        """
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

    def get_absolute_timeout(self, session_key):
        return self.lookup_required_session(session_key).absolute_timeout

    def get_idle_timeout(self, session_key):
        return self.lookup_required_session(session_key).idle_timeout

    def set_idle_timeout(self, session_key, idle_time):
        session = self.lookup_required_session(session_key)
        session.idle_timeout = idle_time
        self.on_change(session)

    def set_absolute_timeout(self, session_key, absolute_time):
        session = self.lookup_required_session(session_key)
        session.absolute_timeout = absolute_time
        self.on_change(session)

    def touch(self, session_key):
        session = self.lookup_required_session(session_key)
        session.touch()
        self.on_change(session)

    def get_host(self, session_key):
        return self.lookup_required_session(session_key).host

    def get_attribute_keys(self, session_key):
        collection = self.lookup_required_session(session_key).attribute_keys
        try:
            return tuple(collection)
        except TypeError:  # collection is None
            return tuple()

    def get_attribute(self, session_key, attribute_key):
        return self.lookup_required_session(session_key).\
            get_attribute(attribute_key)

    def set_attribute(self, session_key, attribute_key, value=None):
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
        except InvalidSessionException:
            return False

    def stop(self, session_key):
        session = self.lookup_required_session(session_key)
        try:
            msg = ("Stopping session with id [" + str(session.session_id) + "]")
            print(msg)
            # log here
            session.stop()
            self.on_stop(session, session_key)
            self.notify_stop(session)
        except InvalidSessionException:
            raise
        finally:
            self.after_stopped(session)

    def on_stop(self, session, session_key=None):
        self.on_change(session)

    @abstractmethod
    def after_stopped(self, session):
        pass

    def check_valid(self, session_key):
        # just try to acquire it.  If there's a problem, an exception is raised
        self.lookup_required_session(session_key)

    @abstractmethod
    def on_change(self, session):
        pass


class ExecutorServiceSessionValidationScheduler(session_abcs.SessionValidationScheduler):
    """
    Note:  Many data stores support TTL (time to live) as a feature.  It
           is unecessary to run a session-validation/Executor service if
           you can use the TTL timeout feature.

           yosai vs shiro:
           Shiro uses a daemon thread for scheduled validation, signaling
           it when to shutdown.  Python terminates daemon threads much more
           abruptly than Java, so Yosai will not use them.  Instead, Yosai uses
           regular threads and an event notification process to gracefully terminate.
           See:  https://docs.python.org/3/library/threading.html#thread-objects

    """
    def __init__(self, session_manager, interval):
        """
        :param sessionmanager: a ValidatingSessionManager
        :param interval:  a time interval, in seconds
        """
        self.session_manager = session_manager
        self.interval = interval  # in seconds
        self._enabled = False
        self.service = StoppableScheduledExecutor(self.run,
                                                  interval=self.interval)

    @property
    def is_enabled(self):
        return self._enabled

    # StoppableScheduledExecutor validates sessions at fixed intervals
    def enable_session_validation(self):
        if (self.interval):
            self.service.start()
            self._enabled = True

    def run(self):
        msg = "Executing session validation..."
        print(msg)
        # log here

        start_time = int(round(time.time() * 1000, 2))
        self.session_manager.validate_sessions()
        stop_time = int(round(time.time() * 1000, 2))

        msg2 = ("Session validation completed successfully in " +
                str(stop_time - start_time) + " milliseconds.")
        print(msg2)
        # log here

    def disable_session_validation(self):
        self.service.stop()
        self.enabled = False


class AbstractValidatingSessionManager(session_abcs.ValidatingSessionManager,
                                       AbstractNativeSessionManager):

    def __init__(self, event_bus):
        # event_bus injection is new to Yosai
        super().__init__(event_bus)
        self.session_validation_scheduler = None
        self.session_validation_scheduler_enabled =\
            session_settings.validation_scheduler_enable
        self.session_validation_interval =\
            session_settings.validation_time_interval

    def enable_session_validation_if_necessary(self):
        scheduler = self.session_validation_scheduler
        if (self.session_validation_scheduler_enabled and
           (scheduler is None or (not scheduler.is_enabled))):
            self.enable_session_validation()

    def do_get_session(self, session_key):
        self.enable_session_validation_if_necessary()
        msg = "Attempting to retrieve session with key " + str(session_key)
        print(msg)
        # log here

        session = self.retrieve_session(session_key)
        if (session is not None):
            self.validate(session, session_key)

        return session

    @abstractmethod
    def retrieve_session(self, session_key):
        pass

    @abstractmethod
    def do_create_session(self, session_context):
        pass

    def create_session(self, session_context):
        self.enable_session_validation_if_necessary()
        return self.do_create_session(session_context)

    def validate(self, session, session_key):
        # session exception hierarchy:  invalid -> stopped -> expired
        try:
            self.do_validate(session)

        except ExpiredSessionException as ese:
            self.on_expiration(session, ese, session_key)
            raise

        # should be a stopped exception if this is reached, but a more
        # generalized invalid exception is checked
        except InvalidSessionException as ise:  # a more generalized exception
            self.on_invalidation(session, ise, session_key)
            raise

    def on_expiration(self, session, expired_session_exception=None,
                      session_key=None):
        """
        Two possible scenarios supported:
            1) All three arguments passed = session + ese + session_key
            2) Only session passed as an argument
        """
        if (expired_session_exception and session_key):
            try:
                self.on_change(session)
                msg = "Session with id [{0}] has expired.".\
                    format(session.session_id)
                print(msg)
                # log here
                self.notify_expiration(session)
            except:
                raise
            finally:
                self.after_expired(session)
        elif not expired_session_exception and not session_key:
            self.on_change(session)

        # Yosai adds this exception handling
        else:
            msg = "on_exception takes either 1 argument or 3 arguments"
            raise IllegalArgumentException(msg)

    @abstractmethod
    def after_expired(self, session):
        pass

    def on_invalidation(self, session, ise, session_key):

        # session exception hierarchy:  invalid -> stopped -> expired
        if (isinstance(ise, ExpiredSessionException)):
            self.on_expiration(session, ise, session_key)
            return

        msg = "Session with id [{0}] is invalid.".format(session.session_id)
        print(msg)
        # log here

        try:
            self.on_stop(session)
            self.notify_stop(session)
        except:
            raise
        finally:
            self.after_stopped(session)

    def do_validate(self, session):
        # session.validate will raise exceptions handled further up the stack
        try:
            session.validate()  # can raise Stopped or Expired exceptions
        except AttributeError:  # means it's not a validating session
            msg = ("The {0} implementation only supports Validating "
                   "Session implementations of the {1} interface.  "
                   "Please either implement this interface in your "
                   "session implementation or override the {0}"
                   ".do_validate(Session) method to validate.").\
                format('AbstractValidatingSessionManager',
                       'ValidatingSession')

            raise IllegalStateException(msg)

    def get_idle_timeout(self, session):
        return session.idle_timeout

    def get_absolute_timeout(self, session):
        return session.absolute_timeout

    def create_session_validation_scheduler(self):
        msg = ("No SessionValidationScheduler set.  Attempting to "
               "create default instance.")
        # log here
        print(msg)

        scheduler =\
            ExecutorServiceSessionValidationScheduler(
                session_manager=self, interval=self.session_validation_interval)

        msg2 = ("Created default SessionValidationScheduler instance of "
                "type [" + scheduler.__class__.__name__ + "].")
        print(msg2)
        # log here:

        return scheduler

    def enable_session_validation(self):
        scheduler = self.session_validation_scheduler
        if (scheduler is None):
            print("Creating session validation scheduler")
            scheduler = self.create_session_validation_scheduler()
            self.session_validation_scheduler = scheduler

        msg = "Enabling session validation scheduler..."
        # log here
        print(msg)

        scheduler.enable_session_validation()
        self.after_session_validation_enabled()

    @abstractmethod
    def after_session_validation_enabled(self):
        pass

    def disable_session_validation(self):
        self.before_session_validation_disabled()
        scheduler = self.session_validation_scheduler
        if (scheduler is not None):
            try:
                scheduler.disable_session_validation()
                msg = "Disabled session validation scheduler."
                # log here
                print(msg)

            except:
                msg2 = ("Unable to disable SessionValidationScheduler. "
                        "Ignoring (shutting down)...")
                # log here
                print(msg2)

            self.session_validation_scheduler = None

    @abstractmethod
    def before_session_validation_disabled(self):
        pass

    def validate_sessions(self):
        msg1 = "Validating all active sessions..."
        print(msg1)
        # log here

        invalid_count = 0
        active_sessions = self.get_active_sessions()
        print('\n\nactive sessions: ', active_sessions, '\n\n')
        if (active_sessions):
            for session in active_sessions:
                try:
                    # simulate a lookup key to satisfy the method signature.
                    # self.could probably be cleaned up in future versions:
                    session_key = DefaultSessionKey(session.session_id)
                    self.validate(session, session_key)
                except InvalidSessionException as ex:
                    expired = isinstance(ex, ExpiredSessionException)
                    msg2 = "Invalidated session with id [{s_id}] ({exp})".\
                           format(s_id=session.get_id(),
                                  exp="expired" if (expired) else "stopped")
                    print(msg2)
                    # log here
                    invalid_count += 1

        msg3 = "Finished session validation.  "
        print(msg3)
        # log here

        if (invalid_count > 0):
            msg3 += "[" + str(invalid_count) + "] sessions were stopped."
        else:
            msg3 += "No sessions were stopped."
        print(msg3)
        # log here

        return msg3

    @abstractmethod
    def get_active_sessions(self):
        pass


class DefaultSessionContext(MapContext, session_abcs.SessionContext):
    """
    This implementation refactors shiro's version quite a bit:
        - Accessor/mutator methods are omitted
            - getTypedValue isn't pythonic
            - attribute access is much more straightforward in python
        - key names aren't following the CLASSNAME.KEY convention
    """
    def __init__(self, context_map={}):
        """
        :type context_map: dict
        """
        super().__init__(context_map)

    # properties are used to enforce the interface:

    @property
    def host(self):
        return self.get('host')

    @host.setter
    def host(self, host):
        self.put('host', host)

    @property
    def session_id(self):
        return self.get('session_id')

    @session_id.setter
    def session_id(self, sessionid):
        # cannot set a session_id == None
        self.none_safe_put('session_id', sessionid)


class DefaultSessionManager(AbstractValidatingSessionManager,
                            cache_abcs.CacheManagerAware):
    """
    Default business-tier implementation of a ValidatingSessionManager.
    All session CRUD operations are delegated to an internal SessionStore.
    """

    def __init__(self):
        self.delete_invalid_sessions = True
        self.session_factory = SimpleSessionFactory()
        self._cache_manager = None
        self._session_Store = MemorySessionStore()  # advised change to CachingSessionStore

    @property
    def session_Store(self):
        return self._session_Store

    @session_Store.setter
    def session_Store(self, sessionstore):
        self._session_Store = sessionstore
        self.apply_cache_manager_to_session_Store()

    @property
    def cache_manager(self):
        return self._cache_manager

    @cache_manager.setter
    def cache_manager(self, cachemanager):
        self._cache_manager = cachemanager
        self.apply_cache_manager_to_session_Store()

    def apply_cache_manager_to_session_Store(self):
        try:
            if isinstance(self.session_Store, cache_abcs.CacheManagerAware):
                self.session_Store.cache_manager = self._cache_manager
        except AttributeError:
            msg = ("tried to set a cache manager in a SessionStore that isn\'t"
                   "defined or configured in the DefaultSessionManager")
            print(msg)
            # log warning here
            return

    def do_create_session(self, session_context):
        session = self.new_session_instance(session_context)

        msg = "Creating session for host " + session.host
        print(msg)
        # log trace here

        self.create(session)
        return session

    def new_session_instance(self, session_context):
        return self.session_factory.create_session(session_context)

    def create(self, session):
        msg = ("Creating new EIS record for new session instance [{0}]".
               format(session))
        print(msg)
        # log debug here
        self.session_Store.create(session)

    def on_stop(self, session):
        try:
            session.last_access_time = session.stop_timestamp
        except AttributeError:
            msg = "not working with a SimpleSession instance"
            print(msg)
            # log warning here

        self.on_change(session)

    def after_stopped(self, session):
        if (self.delete_invalid_sessions):
            self.delete(session)

    def on_expiration(self, session):
        try:
            session.is_expired = True
        except AttributeError:
            msg = ("tried to expire a session but couldn\'t, unlikely "
                   "working with a SimpleSession instance")
            print(msg)
            # log warning here

        self.on_change(session)

    def after_expired(self, session):
        if (self.delete_invalid_sessions):
            self.delete(session)

    def on_change(self, session):
        self.session_Store.update(session)

    def retrieve_session(self, session_key):
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
            raise UnknownSessionException(msg2)

        return session

    def get_session_id(self, session_key):
        return session_key.session_id

    def retrieve_session_from_data_source(self, session_id):
        return self.session_Store.read_session(session_id)

    def delete(self, session):
        self.session_Store.delete(session)

    def get_active_sessions(self):
        active_sessions = self.session_Store.get_active_sessions()
        if (active_sessions is not None):
            return active_sessions
        else:
            return tuple()


class DefaultSessionStorageEvaluator(session_abcs.SessionStorageEvaluator):

    # Global policy determining whether Subject sessions may be used to persist
    # Subject state if the Subject's Session does not yet exist.

    def __init__(self):
        self._session_storage_enabled = True

    def is_session_storage_enabled(self, subject=None):
        if (not subject):
            return self._session_storage_enabled
        else:
            return ((subject is not None and
                     subject.get_session(False) is not None) or
                    bool(self._session_storage_enabled))

    @property
    def session_storage_enabled(self):
        return self._session_storage_enabled

    @session_storage_enabled.setter
    def session_storage_enabled(self, sse):
        self._session_storage_enabled = sse
