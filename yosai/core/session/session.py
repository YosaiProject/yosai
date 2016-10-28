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
import time
import collections
import logging
import pytz
import datetime
from os import urandom
from hashlib import sha256, sha512
from abc import abstractmethod

from yosai.core import (
    AbsoluteExpiredSessionException,
    SessionSettings,
    ExpiredSessionException,
    IdleExpiredSessionException,
    InvalidSessionException,
    StoppedSessionException,
    serialize_abcs,
    session_abcs,
)

logger = logging.getLogger(__name__)

SessionKey = collections.namedtuple('SessionKey', 'session_id')

session_tuple = collections.namedtuple(
    'session_tuple', ['identifiers', 'session_id'])


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

    def generate_session_id(self):
        """
        :param session: the new session instance for which an ID will be
                        generated and then assigned
        """
        return sha256(sha512(urandom(20)).digest()).hexdigest()

    def create(self, session):
        session_id = self._do_create(session)
        self.verify_session_id(session_id)
        return session_id

    def verify_session_id(self, session_id):
        if (session_id is None):
            msg = ("session_id returned from do_create implementation "
                   "is None. Please verify the implementation.")
            raise ValueError(msg)

    def read(self, session_id):
        session = self._do_read(session_id)
        if session is None:
            msg = "There is no session with id [" + str(session_id) + "]"
            raise ValueError(msg)
        return session

    @abstractmethod
    def _do_read(self, session_id):
        pass

    @abstractmethod
    def _do_create(self, session):
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

    def update(self, session):
        return self.store_session(session.session_id, session)

    def delete(self, session):
        try:
            sessionid = session.session_id
            self.sessions.pop(sessionid)
        except AttributeError:
            msg = 'MemorySessionStore.delete None param passed'
            raise AttributeError(msg)
        except KeyError:
            msg = ('MemorySessionStore could not delete ', str(sessionid),
                   'because it does not exist in memory!')
            logger.warning(msg)

    def store_session(self, session_id, session):
        # stores only if session doesn't already exist, returning the existing
        # session (as default) otherwise
        if session_id is None or session is None:
            msg = 'MemorySessionStore.store_session invalid param passed'
            raise ValueError(msg)

        return self.sessions.setdefault(session_id, session)

    def _do_create(self, session):
        sessionid = self.generate_session_id()
        session.session_id = sessionid
        self.store_session(sessionid, session)
        return sessionid

    def _do_read(self, sessionid):
        return self.sessions.get(sessionid)


class CachingSessionStore(AbstractSessionStore):
    """
    An CachingSessionStore is a SessionStore that provides a transparent caching
    layer between the components that use it and the underlying EIS
    (Enterprise Information System) session backing store (e.g.
    Redis, Memcached, filesystem, database, enterprise grid/cloud, etc).

    Yosai omits 'active sessions' related functionality, which is used in Shiro
    as a means to bulk-invalidate timed out sessions.  Rather than manually sift
    through a collection containing every active session just to find
    timeouts, Yosai lazy-invalidates idle-timeout sessions and relies on
    automatic expiration of absolute timeout within cache. Absolute timeout is
    set as the cache entry's expiration time.

    Unlike Shiro:
    - Yosai implements the CRUD operations within CachingSessionStore
    rather than defer implementation further to subclasses
    - Yosai comments out support for a write-through caching strategy
    - Yosai uses an IdentifierCollection with session caching as part of its
      caching strategy


    Write-Through Caching
    -----------------------
    Write-through caching is a caching pattern where writes to the cache cause
    writes to an underlying database (EIS). The cache acts as a facade to the
    underlying resource.

    All methods within CachingSessionStore are implemented to employ caching
    behavior while delegating cache write-through related operations
    to respective 'do' CRUD methods, which are to be implemented by subclasses:
    do_create, do_read, do_update and do_delete.

    Potential write-through caching strategies:
    ------------------------------------
    As of Postgresql 9.5, you can UPSERT session records

    Databases such as Postgresql offer what is known as foreign data wrappers
    (FDWs) that pipe data from cache to the database.

    Ref: https://en.wikipedia.org/wiki/Cache_%28computing%29#Writing_policies
    """
    def __init__(self):
        super().__init__()  # obtains a session id generator
        self.cache_handler = None

    def _do_create(self, session):
        sessionid = self.generate_session_id()
        session.session_id = sessionid
        return sessionid

    def create(self, session):
        """
        caches the session and caches an entry to associate the cached session
        with the subject
        """
        sessionid = super().create(session)  # calls _do_create and verify
        self._cache(session, sessionid)
        return sessionid

    def read(self, sessionid):
        session = self._get_cached_session(sessionid)

        # for write-through caching:
        # if (session is None):
        #    session = super().read(sessionid)

        return session

    def update(self, session):

        # for write-through caching:
        # self._do_update(session)

        if (session.is_valid):
            self._cache(session, session.session_id)

        else:
            self._uncache(session)

    def delete(self, session):
        self._uncache(session)
        # for write-through caching:
        # self._do_delete(session)

    # java overloaded methods combined:
    def _get_cached_session(self, sessionid):
        try:
            # assume that sessionid isn't None

            return self.cache_handler.get(domain='session',
                                          identifier=sessionid)
        except AttributeError:
            msg = "no cache parameter nor lazy-defined cache"
            logger.warning(msg)

        return None

    def _cache(self, session, session_id):
        self.cache_handler.set(domain='session',
                               identifier=session_id,
                               value=session)

    def _uncache(self, session):
        sessionid = session.session_id
        self.cache_handler.delete(domain='session',
                                  identifier=sessionid)

    # intended for write-through caching:
    def _do_read(self, session_id):
        pass

    # intended for write-through caching:
    def _do_delete(self, session):
        pass

    # intended for write-through caching:
    def _do_update(self, session):
        pass


class SimpleSession(session_abcs.ValidatingSession,
                    serialize_abcs.Serializable):

    def __init__(self, absolute_timeout, idle_timeout, host=None):
        self.attributes = {}
        self.internal_attributes = {'run_as_identifiers_session_key': None,
                                    'authenticated_session_key': None,
                                    'identifiers_session_key': None}
        self.is_expired = None
        self.session_id = None

        self.stop_timestamp = None
        self.start_timestamp = round(time.time() * 1000)  # milliseconds

        self.last_access_time = self.start_timestamp

        # yosai.core.renames global_session_timeout to idle_timeout and added
        # the absolute_timeout feature
        self.absolute_timeout = absolute_timeout
        self.idle_timeout = idle_timeout

        self.host = host

    # the properties are required to enforce the Session abc-interface..

    @property
    def attribute_keys(self):
        return self.attributes.keys()

    @property
    def internal_attribute_keys(self):
        if (self.internal_attributes is None):
            return None
        return set(self.internal_attributes)  # a set of keys

    @property
    def is_stopped(self):
        return bool(self.stop_timestamp)

    def touch(self):
        self.last_access_time = round(time.time() * 1000)  # milliseconds

    def stop(self):
        self.stop_timestamp = round(time.time() * 1000)  # milliseconds

    def expire(self):
        self.stop()
        self.is_expired = True

    @property
    def is_valid(self):
        return (not self.is_stopped and not self.is_expired)

    @property
    def is_absolute_timed_out(self):
        current_time = round(time.time() * 1000)  # milliseconds
        abs_expir = self.start_timestamp + self.absolute_timeout

        if current_time > abs_expir:
            return True

        return False

    @property
    def is_idle_timed_out(self):
        current_time = round(time.time() * 1000)  # milliseconds

        idle_expir = self.last_access_time + self.idle_timeout
        if current_time > idle_expir:
            return True

        return False

    def is_timed_out(self):
        """
        determines whether a Session has been inactive/idle for too long a time
        OR exceeds the absolute time that a Session may exist
        """
        if (self.is_expired):
            return True

        try:
            if (not self.last_access_time):
                msg = ("session.last_access_time for session with id [" +
                       str(self.session_id) + "] is null. This value must be"
                       "set at least once, preferably at least upon "
                       "instantiation. Please check the " +
                       self.__class__.__name__ +
                       " implementation and ensure self value will be set "
                       "(perhaps in the constructor?)")
                raise ValueError(msg)

            """
             Calculate at what time a session would have been last accessed
             for it to be expired at this point.  In other words, subtract
             from the current time the amount of time that a session can
             be inactive before expiring.  If the session was last accessed
             before this time, it is expired.
            """
            if self.is_absolute_timed_out:
                return True

            if self.is_idle_timed_out:
                return True

        except AttributeError:
            msg2 = ("Timeouts not set for session with id [" +
                    str(self.session_id) + "]. Session is not considered "
                    "expired.")
            logger.debug(msg2)

        return False

    def validate(self):
        # check for stopped:
        if (self.is_stopped):
            # timestamp is set, so the session is considered stopped:
            msg = ("Session with id [" + str(self.session_id) + "] has been "
                   "explicitly stopped.  No further interaction under "
                   "this session is allowed.")
            raise StoppedSessionException(msg)  # subclass of InvalidSessionException

        # check for expiration
        if (self.is_timed_out()):
            self.expire()

            # throw an exception explaining details of why it expired:
            idle_timeout_min = self.idle_timeout / 1000 // 60
            absolute_timeout_min = self.absolute_timeout / 1000 // 60

            currenttime = datetime.datetime.now(pytz.utc).isoformat()
            session_id = str(self.session_id)

            msg2 = ("Session with id [" + session_id + "] has expired. "
                    "Last access time: " + str(self.last_access_time) +
                    ".  Current time: " + currenttime +
                    ".  Session idle timeout is set to " + str(self.idle_timeout/1000) +
                    " seconds (" + str(idle_timeout_min) + " minutes) and "
                    " absolute timeout is set to " + str(self.absolute_timeout/1000) +
                    " seconds (" + str(absolute_timeout_min) + "minutes)")

            logger.debug(msg2)

            if self.is_absolute_timed_out:
                raise AbsoluteExpiredSessionException(msg2)

            raise IdleExpiredSessionException(msg2)

    def get_internal_attribute(self, key):
        if (not self.internal_attributes):
            return None

        return self.internal_attributes.get(key)

    def set_internal_attribute(self, key, value=None):
        self.internal_attributes[key] = value

    def set_internal_attributes(self, key_values):
        self.internal_attributes.update(key_values)

    def remove_internal_attribute(self, key):
        if (not self.internal_attributes):
            return None
        else:
            return self.internal_attributes.pop(key, None)

    def remove_internal_attributes(self, to_remove):
        return [self.remove_internal_attribute(key) for key in to_remove]

    def get_attribute(self, key):
        return self.attributes.get(key)

    # new to yosai
    def get_attributes(self, keys):
        """
        :param attributes: the keys of attributes to get from the session
        :type attributes: list of strings

        :returns: a dict containing the attributes requested, if they exist
        """
        return self.attributes.keys()

    def set_attribute(self, key, value):
        self.attributes[key] = value

    # new to yosai is the bulk setting/getting/removing
    def set_attributes(self, attributes):
        """
        :param attributes: the attributes to add to the session
        :type attributes: dict
        """
        self.attributes.update(attributes)

    def remove_attribute(self, key):
        return self.attributes.pop(key, None)

    # new to yosai
    def remove_attributes(self, keys):
        """
        :param attributes: the keys of attributes to remove from the session
        :type attributes: list of strings

        :returns: a list of popped attribute values
        """
        return [self.attributes.pop(key, None) for key in keys]

    def __eq__(self, other):
        if self is other:
            return True
        if isinstance(other, session_abcs.ValidatingSession):
            return (self.session_id == other.session_id and
                    self.idle_timeout == other.idle_timeout and
                    self.absolute_timeout == other.absolute_timeout and
                    self.start_timestamp == other.start_timestamp and
                    self.attributes == other.attributes and
                    self.internal_attributes == other.internal_attributes)
        return False

    def __repr__(self):
        return (self.__class__.__name__ + "(session_id: {0}, start_timestamp: {1}, "
                "stop_timestamp: {2}, last_access_time: {3},"
                "idle_timeout: {4}, absolute_timeout: {5}, is_expired: {6},"
                "host: {7}, attributes:{8}, internal_attributes: {9})".
                format(self.session_id, self.start_timestamp,
                       self.stop_timestamp, self.last_access_time,
                       self.idle_timeout, self.absolute_timeout,
                       self.is_expired, self.host, self.attributes,
                       self.internal_attributes))

    def __getstate__(self):
        return {
            'session_id': self.session_id,
            'start_timestamp': self.start_timestamp,
            'stop_timestamp': self.stop_timestamp,
            'last_access_time': self.last_access_time,
            'idle_timeout': self.idle_timeout,
            'absolute_timeout': self.absolute_timeout,
            'is_expired': self.is_expired,
            'host': self.host,
            'internal_attributes': self.internal_attributes,
            'attributes': self.attributes
        }

    def __setstate__(self, state):
        self.session_id = state['session_id']
        self.start_timestamp = state['start_timestamp']
        self.stop_timestamp = state['stop_timestamp']
        self.last_access_time = state['last_access_time']
        self.idle_timeout = state['idle_timeout']
        self.absolute_timeout = state['absolute_timeout']
        self.is_expired = state['is_expired']
        self.host = state['host']
        self.internal_attributes = state['internal_attributes']
        self.attributes = state['attributes']


class DelegatingSession(session_abcs.Session):
    """
    A DelegatingSession is a client-tier representation of a server side
    Session.  This implementation is basically a proxy to a server-side
    NativeSessionManager, which will return the proper results for each
    method call.

    A DelegatingSession will cache data when appropriate to avoid a remote
    method invocation, only communicating with the server when necessary and
    if write-through session caching is implemented.

    Of course, if used in-process with a NativeSessionManager business object,
    as might be the case in a web-based application where the web classes
    and server-side business objects exist in the same namespace, a remote
    method call will not be incurred.
    """

    def __init__(self, session_manager, sessionkey):
        # omitting None-type checking
        self.session_key = sessionkey
        self.session_manager = session_manager
        self._start_timestamp = None
        self._host = None
        self.stop_session_callback = None  # is set by Subject owner

    @property
    def session_id(self):
        return self.session_key.session_id

    @property
    def start_timestamp(self):
        if (not self._start_timestamp):
            self._start_timestamp = self.session_manager.get_start_timestamp(
                self.session_key)
        return self._start_timestamp

    @property
    def last_access_time(self):
        return self.session_manager.get_last_access_time(self.session_key)

    @property
    def idle_timeout(self):
        return self.session_manager.get_idle_timeout(self.session_key)

    @idle_timeout.setter
    def idle_timeout(self, timeout):
        self.session_manager.set_idle_timeout(self.session_key, timeout)

    @property
    def absolute_timeout(self):
        return self.session_manager.get_absolute_timeout(self.session_key)

    @absolute_timeout.setter
    def absolute_timeout(self, timeout):
        self.session_manager.set_absolute_timeout(self.session_key, timeout)

    @property
    def host(self):
        if (not self._host):
            self._host = self.session_manager.get_host(self.session_key)

        return self._host

    def touch(self):
        self.session_manager.touch(self.session_key)

    def stop(self, identifiers):
        self.session_manager.stop(self.session_key, identifiers)
        try:
            self.stop_session_callback()
        except TypeError:
            msg = "DelegatingSession has no stop_session_callback set."
            logger.debug(msg)

    @property
    def internal_attribute_keys(self):
        return self.session_manager.get_internal_attribute_keys(self.session_key)

    def get_internal_attribute(self, attribute_key):
        return self.session_manager.get_internal_attribute(self.session_key,
                                                           attribute_key)

    def get_internal_attributes(self):
        return self.session_manager.get_internal_attributes(self.session_key)

    def set_internal_attribute(self, attribute_key, value=None):
        # unlike shiro, yosai doesn't support removing keys when value is None
        self.session_manager.set_internal_attribute(self.session_key,
                                                    attribute_key,
                                                    value)

    def set_internal_attributes(self, key_values):
        # unlike shiro, yosai doesn't support removing keys when value is None
        self.session_manager.set_internal_attributes(self.session_key, key_values)

    def remove_internal_attribute(self, attribute_key):
        return self.session_manager.remove_internal_attribute(self.session_key,
                                                              attribute_key)

    def remove_internal_attributes(self, to_remove):
        return self.session_manager.remove_internal_attributes(self.session_key,
                                                               to_remove)

    @property
    def attribute_keys(self):
        return self.session_manager.get_attribute_keys(self.session_key)

    def get_attribute(self, attribute_key):
        if attribute_key:
            return self.session_manager.get_attribute(self.session_key,
                                                      attribute_key)
        return None

    def get_attributes(self, attribute_keys):
        if attribute_keys:
            return self.session_manager.get_attributes(self.session_key,
                                                       attribute_keys)
        return None

    def set_attribute(self, attribute_key, value):
        if all([attribute_key, value]):
            self.session_manager.set_attribute(self.session_key,
                                               attribute_key,
                                               value)

    def set_attributes(self, attributes):
        if attributes:
            self.session_manager.set_attributes(self.session_key, attributes)

    def remove_attribute(self, attribute_key):
        if attribute_key:
            return self.session_manager.remove_attribute(self.session_key,
                                                         attribute_key)

    def remove_attributes(self, attribute_keys):
        if attribute_keys:
            return self.session_manager.remove_attributes(self.session_key,
                                                          attribute_keys)

    def __repr__(self):
        return "{0}(session_id: {1})".format(self.__class__.__name__,
                                             self.session_id)


class NativeSessionHandler(session_abcs.SessionHandler):

    def __init__(self,
                 session_store=CachingSessionStore(),
                 delete_invalid_sessions=True):
        self.delete_invalid_sessions = delete_invalid_sessions
        self.session_store = session_store
        self.event_bus = None

    # -------------------------------------------------------------------------
    # Session Creation Methods
    # -------------------------------------------------------------------------

    def create_session(self, session):
        """
        :returns: a session_id string
        """
        return self.session_store.create(session)

    # -------------------------------------------------------------------------
    # Session Teardown Methods
    # -------------------------------------------------------------------------

    def delete(self, session):
        self.session_store.delete(session)

    # -------------------------------------------------------------------------
    # Session Lookup Methods
    # -------------------------------------------------------------------------

    def _retrieve_session(self, session_key):
        """
        :type session_key: SessionKey
        :returns: SimpleSession
        """
        session_id = session_key.session_id
        if (session_id is None):
            msg = ("Unable to resolve session ID from SessionKey [{0}]."
                   "Returning null to indicate a session could not be "
                   "found.".format(session_key))
            logger.debug(msg)
            return None

        session = self.session_store.read(session_id)

        if (session is None):
            # session ID was provided, meaning one is expected to be found,
            # but we couldn't find one:
            msg2 = "Could not find session with ID [{0}]".format(session_id)
            raise ValueError(msg2)

        return session

    def do_get_session(self, session_key):
        """
        :type session_key: SessionKey
        :returns: SimpleSession
        """
        session_id = session_key.session_id
        msg = ("do_get_session: Attempting to retrieve session with key " +
               str(session_id))
        logger.debug(msg)

        session = self._retrieve_session(session_key)

        if (session is not None):
            self.validate(session, session_key)

        return session

    # -------------------------------------------------------------------------
    # Validation Methods
    # -------------------------------------------------------------------------

    def validate(self, session, session_key):
        # session exception hierarchy:  invalid -> stopped -> expired
        try:
            session.validate()  # can raise Stopped or Expired exceptions
        except AttributeError:  # means it's not a validating session
            msg = ("The {0} implementation only supports Validating "
                   "Session implementations of the {1} interface.  "
                   "Please either implement this interface in your "
                   "session implementation or override the {0}"
                   ".do_validate(Session) method to validate.").\
                format(self.__class__.__name__, 'ValidatingSession')

            raise AttributeError(msg)

        except ExpiredSessionException as ese:
            self.on_expiration(session, ese, session_key)
            raise ese

        # should be a stopped exception if this is reached, but a more
        # generalized invalid exception is checked
        except InvalidSessionException as ise:
            self.on_invalidation(session, ise, session_key)
            raise ise

    # -------------------------------------------------------------------------
    # Event-driven Methods
    # -------------------------------------------------------------------------

    # used by WebSessionManager:
    def on_start(self, session, session_context):
        """
        placeholder for subclasses to react to a new session being created
        """
        pass

    def on_stop(self, session, session_key):
        # session_key is used by the child class
        try:
            session.last_access_time = session.stop_timestamp
        except AttributeError:
            msg = "not working with a SimpleSession instance"
            logger.warning(msg)

        self.on_change(session)

    def after_stopped(self, session):
        # this appears to be redundant
        if (self.delete_invalid_sessions):
            self.delete(session)

    def on_expiration(self, session, expired_session_exception=None,
                      session_key=None):
        """
        This method overloaded for now (java port).  TBD
        Two possible scenarios supported:
            1) All three arguments passed = session + ese + session_key
            2) Only session passed as an argument
        """
        if (expired_session_exception and session_key):
            try:
                self.on_change(session)
                msg = "Session with id [{0}] has expired.".\
                    format(session.session_id)
                logger.debug(msg)

                identifiers = session.get_internal_attribute('identifiers_session_key')

                mysession = session_tuple(identifiers, session_key.session_id)

                self.notify_event(mysession, 'SESSION.EXPIRE')
            except:
                raise
            finally:
                self.after_expired(session)
        elif not expired_session_exception and not session_key:
            self.on_change(session)

        # Yosai adds this exception handling
        else:
            msg = "on_exception takes either 1 argument or 3 arguments"
            raise ValueError(msg)

    def after_expired(self, session):
        if (self.delete_invalid_sessions):
            self.delete(session)

    def on_invalidation(self, session, ise, session_key):
        # session exception hierarchy:  invalid -> stopped -> expired
        if (isinstance(ise, ExpiredSessionException)):
            self.on_expiration(session, ise, session_key)
            return

        msg = "Session with id [{0}] is invalid.".format(session.session_id)
        logger.debug(msg)

        try:
            self.on_stop(session, session_key)
            identifiers = session.get_internal_attribute('identifiers_session_key')

            mysession = session_tuple(identifiers, session_key.session_id)

            self.notify_event(mysession, 'SESSION.STOP')
        except:
            raise
        # DG:  this results in a redundant delete operation (from shiro):
        finally:
            self.after_stopped(session)

    def on_change(self, session):
        self.session_store.update(session)

    def notify_event(self, session_info, topic):
        """
        :type identifiers:  SimpleIdentifierCollection
        """
        try:
            self.event_bus.sendMessage(topic, items=session_info)
        except AttributeError:
            msg = "Could not publish {} event".format(topic)
            raise AttributeError(msg)


class NativeSessionManager(session_abcs.NativeSessionManager):
    """
    Yosai's NativeSessionManager represents a massive refactoring of Shiro's
    SessionManager object model.  The refactoring is an ongoing effort to
    replace a confusing inheritance-based mixin object graph with a compositional
    design.  This compositional design continues to evolve.  Event handling can be
    better designed as it currently is done by the manager AND session handler.
    Pull Requests are welcome.

    Touching Sessions
    ------------------
    A session's last_access_time must be updated on every request.  Updating
    the last access timestamp is required for session validation to work
    correctly as the timestamp is used to determine whether a session has timed
    out due to inactivity.

    In web applications, the [Shiro Filter] updates the session automatically
    via the session.touch() method.  For non-web environments (e.g. for RMI),
    something else must call the touch() method to ensure the session
    validation logic functions correctly.
    """
    def __init__(self, settings, session_handler=NativeSessionHandler()):

        # timeouts are use during session construction:
        session_settings = SessionSettings(settings)
        self.absolute_timeout = session_settings.absolute_timeout
        self.idle_timeout = session_settings.idle_timeout

        self.session_handler = session_handler

    def apply_cache_handler(self, cachehandler):
        # no need for a local instance, just pass through
        self.session_handler.session_store.cache_handler = cachehandler

    def apply_event_bus(self, event_bus):
        self.session_handler.event_bus = event_bus
        self.event_bus = event_bus

    # -------------------------------------------------------------------------
    # Session Lifecycle Methods
    # -------------------------------------------------------------------------

    def start(self, session_context):
        """
        unlike shiro, yosai does not apply session timeouts from within the
        start method of the SessionManager but rather defers timeout settings
        responsibilities to the SimpleSession, which uses session_settings
        """
        # is a SimpleSesson:
        session = self._create_session(session_context)

        self.session_handler.on_start(session, session_context)

        mysession = session_tuple(None, session.session_id)
        self.notify_event(mysession, 'SESSION.START')

        # Don't expose the EIS-tier Session object to the client-tier, but
        # rather a DelegatingSession:
        return self.create_exposed_session(session=session, context=session_context)

    def stop(self, session_key, identifiers):
        session = self._lookup_required_session(session_key)
        try:
            msg = ("Stopping session with id [{0}]").format(session.session_id)
            logger.debug(msg)

            session.stop()

            self.session_handler.on_stop(session, session_key)

            idents = session.get_internal_attribute('identifiers_session_key')

            if not idents:
                idents = identifiers

            mysession = session_tuple(idents, session_key.session_id)

            self.notify_event(mysession, 'SESSION.STOP')

        except InvalidSessionException:
            raise

        finally:
            # DG: this results in a redundant delete operation (from shiro).
            self.session_handler.after_stopped(session)

    # -------------------------------------------------------------------------
    # Session Creation Methods
    # -------------------------------------------------------------------------

    # consolidated with do_create_session:
    def _create_session(self, session_context):
        session = SimpleSession(self.absolute_timeout,
                                self.idle_timeout,
                                host=session_context.get('host'))
        msg = "Creating session. "
        logger.debug(msg)

        msg = ("Creating new EIS record for new session instance [{0}]".
               format(session))
        logger.debug(msg)

        sessionid = self.session_handler.create_session(session)
        if not sessionid:  # new to yosai
            msg = 'Failed to obtain a sessionid while creating session.'
            raise ValueError(msg)

        return session

    # yosai.core.introduces the keyword parameterization
    def create_exposed_session(self, session, key=None, context=None):
        """
        :type session:  SimpleSession
        """
        # shiro ignores key and context parameters
        return DelegatingSession(self, SessionKey(session.session_id))

    # -------------------------------------------------------------------------
    # Session Lookup Methods
    # -------------------------------------------------------------------------

    # called by mgt.ApplicationSecurityManager:
    def get_session(self, key):
        """
        :returns: DelegatingSession
        """
        # a SimpleSession:
        session = self.session_handler.do_get_session(key)
        if (session):
            return self.create_exposed_session(session, key)
        else:
            return None

    # called internally:
    def _lookup_required_session(self, key):
        """
        :returns: SimpleSession
        """
        session = self.session_handler.do_get_session(key)
        if (not session):
            msg = ("Unable to locate required Session instance based "
                   "on session_key [" + str(key) + "].")
            raise ValueError(msg)
        return session

    # -------------------------------------------------------------------------
    # Session Attribute Methods
    # -------------------------------------------------------------------------

    # consolidated with check_valid
    def is_valid(self, session_key):
        """
        if the session doesn't exist, _lookup_required_session raises
        """
        try:
            self.check_valid(session_key)
            return True
        except InvalidSessionException:
            return False

    def check_valid(self, session_key):
        return self._lookup_required_session(session_key)

    def get_start_timestamp(self, session_key):
        return self._lookup_required_session(session_key).start_timestamp

    def get_last_access_time(self, session_key):
        return self._lookup_required_session(session_key).last_access_time

    def get_absolute_timeout(self, session_key):
        return self._lookup_required_session(session_key).absolute_timeout

    def get_idle_timeout(self, session_key):
        return self._lookup_required_session(session_key).idle_timeout

    def set_idle_timeout(self, session_key, idle_time):
        session = self._lookup_required_session(session_key)
        session.idle_timeout = idle_time
        self.session_handler.on_change(session)

    def set_absolute_timeout(self, session_key, absolute_time):
        session = self._lookup_required_session(session_key)
        session.absolute_timeout = absolute_time
        self.session_handler.on_change(session)

    def touch(self, session_key):
        session = self._lookup_required_session(session_key)
        session.touch()
        self.session_handler.on_change(session)

    def get_host(self, session_key):
        return self._lookup_required_session(session_key).host

    def get_internal_attribute_keys(self, session_key):
        session = self._lookup_required_session(session_key)
        collection = session.internal_attribute_keys
        try:
            return tuple(collection)
        except TypeError:  # collection is None
            return tuple()

    def get_internal_attribute(self, session_key, attribute_key):
        return self._lookup_required_session(session_key).\
            get_internal_attribute(attribute_key)

    def get_internal_attributes(self, session_key):
        return self._lookup_required_session(session_key).internal_attributes

    def set_internal_attribute(self, session_key, attribute_key, value=None):
        session = self._lookup_required_session(session_key)
        session.set_internal_attribute(attribute_key, value)
        self.session_handler.on_change(session)

    def set_internal_attributes(self, session_key, key_values):
        session = self._lookup_required_session(session_key)
        session.set_internal_attributes(key_values)
        self.session_handler.on_change(session)

    def remove_internal_attribute(self, session_key, attribute_key):
        session = self._lookup_required_session(session_key)
        removed = session.remove_internal_attribute(attribute_key)

        if removed:
            self.session_handler.on_change(session)
        return removed

    def remove_internal_attributes(self, session_key, to_remove):
        session = self._lookup_required_session(session_key)
        removed = session.remove_internal_attributes(to_remove)

        if removed:
            self.session_handler.on_change(session)
        return removed

    def get_attribute_keys(self, session_key):
        collection = self._lookup_required_session(session_key).attribute_keys
        try:
            return tuple(collection)
        except TypeError:  # collection is None
            return tuple()

    def get_attribute(self, session_key, attribute_key):
        return self._lookup_required_session(session_key).\
            get_attribute(attribute_key)

    def get_attributes(self, session_key, attribute_keys):
        """
        :type attribute_keys: a list of strings
        """
        return self._lookup_required_session(session_key).\
            get_attributes(attribute_keys)

    def set_attribute(self, session_key, attribute_key, value=None):
        if (value is None):
            self.remove_attribute(session_key, attribute_key)
        else:
            session = self._lookup_required_session(session_key)
            session.set_attribute(attribute_key, value)
            self.session_handler.on_change(session)

    # new to yosai
    def set_attributes(self, session_key, attributes):
        """
        :type attributes: dict
        """
        session = self._lookup_required_session(session_key)
        session.set_attributes(attributes)
        self.session_handler.on_change(session)

    def remove_attribute(self, session_key, attribute_key):
        session = self._lookup_required_session(session_key)
        removed = session.remove_attribute(attribute_key)
        if (removed is not None):
            self.session_handler.on_change(session)
        return removed

    def remove_attributes(self, session_key, attribute_keys):
        """
        :type attribute_keys: a list of strings
        """
        session = self._lookup_required_session(session_key)
        removed = session.remove_attributes(attribute_keys)
        if removed:
            self.session_handler.on_change(session)
        return removed

    def notify_event(self, session_tuple, topic):
        """
        :type identifiers:  SimpleIdentifierCollection
        """
        try:
            self.event_bus.sendMessage(topic, items=session_tuple)
        except AttributeError:
            msg = "Could not publish {} event".format(topic)
            raise AttributeError(msg)


class SessionStorageEvaluator:
    """
    Global policy determining whether Subject sessions may be used to persist
    Subject state if the Subject's Session does not yet exist.
    """
    def __init__(self):
        self.session_storage_enabled = True

    def is_session_storage_enabled(self, subject=None):
        try:
            return bool(subject.get_session(False)) or self.session_storage_enabled
        except AttributeError:
            return self.session_storage_enabled
