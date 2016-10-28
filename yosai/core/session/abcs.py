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

from abc import ABCMeta, abstractmethod


class Session(metaclass=ABCMeta):
    """
    A Session is a stateful data context associated with a single
    Subject's (user, daemon process, etc) interaction with a software system
    over a period of time.

    A Session is intended to be managed by the business tier and accessible via
    other tiers without being tied to any given client technology.  This is a
    great benefit to Python systems as most viable session mechanisms are
    those highly-coupled and deeply embedded in web application
    frameworks.

    The following attributes are required of a Session:
        session_id: The unique identifier assigned by the system upon session creation.
        start_timestamp: The time that the session started (the time that the system created
                         the instance
        last_access_time: Returns the last time the application received a request or method
                          invocation from THE USER associated with this session.  Application
                          calls to this method do not affect this access time.

        absolute_timeout: Returns the time, in milliseconds, that the session may
                          exist before it expires
        idle_timeout:  Returns the time, in milliseconds, that the session may
                       remain idle before it expires

        host: Returns the host name or IP string of the host that originated this
              session, or None if the host is unknown.

        attributes

        internal_attributes
    """

    @abstractmethod
    def touch(self):
        """
        Explicitly updates the last_access_time of this session to the
        current time when this method is invoked.  This method can be used to
        ensure a session does not time out.
        """
        pass

    @abstractmethod
    def stop(self):
        """
        Explicitly stops (invalidates) this session and releases all associated
        resources.
        """
        pass

    @property
    @abstractmethod
    def attribute_keys(self):
        """
        Returns the keys of all the attributes stored under this session.  If
        there are no attributes, this returns an empty collection.
        """
        pass

    @abstractmethod
    def get_attribute(self, key):
        """
        Returns the object bound to this session identified by the specified
        key.  If there is no object bound under the key, None is returned.
        """
        pass

    @abstractmethod
    def set_attribute(self, key, value):
        """
        Binds the specified value to this session, uniquely identified by the
        specifed key name.  If there is already an object bound under
        the key name, that existing object will be replaced by the new
        value.
        """
        pass

    @abstractmethod
    def remove_attribute(self, key):
        """
        Removes (unbinds) the object bound to this session under the specified
        key name.
        """
        pass

    def __eq__(self, other):
        if self is other:
            return True

        return (isinstance(other, self.__class__) and
                self.__dict__ == other.__dict__)


class SessionListener(metaclass=ABCMeta):
    """
    Interface to be implemented by components that wish to be notified of
    events that occur during a Session's life cycle.
    """

    @abstractmethod
    def on_start(self, session):
        """
        Notification callback that occurs when the corresponding Session has
        started.

        :param session: the session that has started
        """
        pass

    @abstractmethod
    def on_stop(self, session):
        """
        Notification callback that occurs when the corresponding Session has
        stopped, either programmatically via {@link Session#stop} or
        automatically upon a subject logging out.

        :param session: the session that has stopped
        """
        pass

    @abstractmethod
    def on_expiration(self, session):
        """
        Notification callback that occurs when the corresponding Session has
        expired.

        Note: this method is almost never called at the exact instant that the
        Session expires.  Almost all session management systems, including
        Yosai's implementations, lazily validate sessions - either when they
        are accessed or during a regular validation interval.  It would be too
        resource intensive to monitor every single session instance to know the
        exact instant it expires.

        If you need to perform time-based logic when a session expires, it
        is best to write it based on the session's last_access_time and
        NOT the time when this method is called.

        :param session: the session that has expired
        """
        pass


# moved from /mgt:
class SessionStorageEvaluator(metaclass=ABCMeta):
    """
    Evaluates whether Yosai may use a Subject's Session to persist that
    Subject's internal state.

    It is a common Yosai implementation strategy to use a Subject's session to
    persist the Subject's identity and authentication state (e.g. after login)
    so that information does not need to be passed around for any further
    requests/invocations.  This effectively allows a session id to be used for
    any request or invocation as the only 'pointer' that Shiro needs, and from
    that, Shiro can re-create the Subject instance based on the referenced
    Session.

    However, in purely stateless applications, such as some REST applications
    or those where every request is authenticated, it is usually not needed or
    desirable to use Sessions to store this state (since it is in fact
    re-created on every request).  In these applications, sessions would never
    be used.

    This interface allows implementations to determine exactly when a Session
    might be used or not to store Subject state on a *per-Subject* basis.

    If you simply wish to enable or disable session usage at a global level for
    all Subject(s), the SessionStorageEvaluator should be sufficient.
    Per-subject behavior should be performed in custom implementations of this
    interface.
    """

    @abstractmethod
    def is_session_storage_enabled(self, subject):
        pass


class ValidatingSession(Session):

    @property
    @abstractmethod
    def is_valid(self):
        pass

    @abstractmethod
    def validate(self):
        pass


class SessionFactory(metaclass=ABCMeta):
    """
    A simple factory class that instantiates concrete Session instances.  This
    is mainly a mechanism to allow instances to be created at runtime if they
    need to be different than the defaults.  It is not used by end-users of the
    framework, but rather those configuring Yosai to work in an application,
    and is typically injected into a SecurityManager or SessionManager.
    """

    @abstractmethod
    def create_session(self, init_data):
        """
        Creates a new Session instance based on the specified contextual
        initialization data.

        :param init_data: the initialization data to be used during
                          Session creation.
        :type init_data: dict
        :returns: a new Session instance
        """
        pass


class SessionIDGenerator(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def generate_id(self, session):
        pass


# new to yosai:
class SessionHandler(metaclass=ABCMeta):

    @abstractmethod
    def create_session(self, session):
        pass

    @abstractmethod
    def delete(self, session):
        pass

    @abstractmethod
    def _retrieve_session(self, session_key):
        pass

    @abstractmethod
    def do_get_session(self, session_key):
        pass

    @abstractmethod
    def validate(self, session, session_key):
        pass

    @abstractmethod
    def on_start(self, session, session_context):
        """
        placeholder for subclasses to react to a new session being created
        """
        pass

    @abstractmethod
    def on_stop(self, session):
        pass

    @abstractmethod
    def after_stopped(self, session):
        pass

    @abstractmethod
    def on_expiration(self, session, expired_session_exception=None,
                      session_key=None):
        pass

    @abstractmethod
    def after_expired(self, session):
        pass

    @abstractmethod
    def on_invalidation(self, session, ise, session_key):
        pass

    @abstractmethod
    def on_change(self, session):
        pass


class SessionManager(metaclass=ABCMeta):
    """
    A SessionManager manages the creation, maintenance, and clean-up of all
    application Sessions
    """

    @abstractmethod
    def start(self, session_context):
        pass
        """
        Starts a new session based on the specified contextual initialization
        data, which can be used by the underlying implementation to determine
        how exactly to create the internal Session instance.
        """

    @abstractmethod
    def get_session(self, session_key):
        """
        Retrieves the session corresponding to the specified contextual
        data (such as a session ID if applicable), or None if no
        Session could be found.  If a session is found but invalid (stopped
        or expired), an exception will raise
        """
        pass


class NativeSessionManager(SessionManager):
    """
    A Native session manager is one that manages sessions natively - that is,
    it is directly responsible for the creation, persistence and removal of
    Session instances and their lifecycles.
    """

    @abstractmethod
    def get_start_timestamp(self, session_key):
        """
        Returns the time the associated Session started (was created).
        """
        pass

    @abstractmethod
    def get_last_access_time(self, session_key):
        """
        Returns the time the associated {@code Session} last interacted with
        the system.
        """
        pass

    @abstractmethod
    def is_valid(self, session_key):
        """
        Returns True if the associated session is valid (it exists and is
        not stopped nor expired), False otherwise.
        """
        pass

    @abstractmethod
    def check_valid(self, session_key):
        """
        Returns quietly if the associated session is valid (it exists and is
        not stopped or expired) or raises an InvalidSessionException
        indicating that the session_id is invalid.  This might be preferred
        to be used instead of is_valid since any exception thrown will
        definitively explain the reason for invalidation.
        """
        pass

    @abstractmethod
    def get_idle_timeout(self, session_key):
        """
        Returns the time that the associated session may remain idle before
        expiring.

        - A negative return value means the session will never expire.
        - A non-negative return value (0 or greater) means the session
          expiration will occur if idle for that length of time.

        raises InvalidSessionException if the session has been stopped or
        expired prior to calling this method
        """
        pass

    @abstractmethod
    def get_absolute_timeout(self, session_key):
        """
        Returns the time that the associated session may remain idle before
        expiring.
        """
        pass

    @abstractmethod
    def set_idle_timeout(self, session_key, idle_timeout):
        """
        Sets the time, as a datetime.timedelta, that the associated session may
        remain idle before expiring.

        - A negative return value means the session will never expire.
        - A non-negative return value (0 or greater) means the session
          expiration will occur if idle for that * length of time.

        raises InvalidSessionException if the session has been stopped or
        expired prior to calling this method
        """
        pass

    @abstractmethod
    def set_absolute_timeout(self, session_key, absolute_timeout):
        """
        Sets the time, as a datetime.timedelta, that the associated session may
        exist before expiring.

        raises InvalidSessionException if the session has been stopped or
        expired prior to calling this method
        """
        pass

    @abstractmethod
    def touch(self, session_key):
        """
        Updates the last accessed time of the session identified by
        session_id.  This can be used to explicitly ensure that a
        session does not time out.

        raises InvalidSessionException if the session has been stopped or
        expired prior to calling this method
        """
        pass

    @abstractmethod
    def get_host(self, session_key):
        """
        Returns the host name or IP string of the host where the session was
        started, if known.  If no host name or IP was specified when starting
        the session, this method returns None
        """
        pass

    @abstractmethod
    def stop(self, session_key):
        """
        Explicitly stops the associated session, thereby releasing all of its
        resources.
        """
        pass

    @abstractmethod
    def get_attribute_keys(self, session_key):
        """
        Returns all attribute keys maintained by the target session or an empty
        collection if there are no attributes.

        raises InvalidSessionException if the associated session has stopped or
        expired prior to calling this method
        """
        pass

    @abstractmethod
    def get_attribute(self, session_key, attribute_key):
        """
        Returns the object bound to the associated session identified by the
        specified attribute key.  If there is no object bound under the
        attribute key for the given session, None is returned.

        raises InvalidSessionException if the specified session has stopped
        or expired prior to calling this method
        """
        pass

    @abstractmethod
    def set_attribute(self, session_key, attribute_key, value):
        """
        Binds the specified value to the associated session uniquely identified
        by the attribute_key.  If there is already a session attribute
        bound under the attribute_key, that existing object will be
        replaced by the new value.

        If the value parameter is None, it has the same effect as if the
        remove_attribute(session_key, attribute_key) method was called.

        raises InvalidSessionException if the specified session has stopped or
        expired prior to calling this method
        """
        pass

    @abstractmethod
    def remove_attribute(self, session_key, attribute_key):
        """
        Removes (unbinds) the object bound to associated Session under
        the given attribute_key

        raises InvalidSessionException if the specified session has stopped
        or expired prior to calling this method
        """
        pass


class SessionKey(metaclass=ABCMeta):

    @property
    @abstractmethod
    def session_id(self):
        pass

    @session_id.setter
    @abstractmethod
    def session_id(self, session_id):
        pass


class ValidatingSessionManager(SessionManager):
    """
    A ValidatingSessionManager is a SessionManager that can proactively
    validate any or all sessions that may be expired.
    """

    @abstractmethod
    def validate_sessions(self):
        """
        Performs session validation for all open/active sessions in the system
        (those that have not been stopped or expired), and validates each one.
        If a session is found to be invalid (e.g. it has expired), it is
        updated and saved to the EIS.

        This method is necessary in order to handle orphaned sessions and is
        expected to be run at a regular interval, such as once an hour, once a
        day or once a week, etc.  The &quot;best&quot; frequency to run this
        method is entirely dependent upon the application and would be based on
        factors such as performance, average number of active users, hours of
        least activity, and other things.

        Most enterprise applications use a request/response programming model.
        This is obvious in the case of web applications due to the HTTP
        protocol, but it is equally true of remote client applications making
        remote method invocations.  The server essentially sits idle and only
        *works* when responding to client requests and/or method invocations.
        This type of model is particularly efficent since it means the security
        system only has to validate a session during those cases.  Such
        *lazy* behavior enables the system to lie stateless and/or idle and
        only incur overhead for session validation when necessary.

        However, if a client forgets to log-out, or in the event of a server
        failure, it is possible for sessions to be orphaned since no further
        requests would utilize that session.  Because of these
        lower-probability cases, it might be required to regularly clean-up the
        sessions maintained by the system, especially if sessions are backed by
        a persistent data store.

        Even in applications that aren't primarily based on a request/response
        model, such as those that use enterprise asynchronous messaging (where
        data is pushed to a client without first receiving a client request),
        it is almost always acceptable to utilize this lazy approach and run
        this method at defined interval.

        Systems that want to proactively validate individual sessions may
        simply call the get_session(session_key) method on any
        ValidatingSessionManager instance as that method is expected to
        validate the session before retrieving it.  Note that even with
        proactive calls to get_session, this validate_sessions
        method should be invoked regularly anyway to *guarantee* no
        orphans exist.

        Note:
        Yosai supports automatic execution of this method at a regular interval
        by using SessionValidationScheduler(s).  The Yosai default
        SecurityManager implementations needing session validation will
        create and use one by default if one is not provided by the
        application configuration.
        """
        pass

class SessionValidationScheduler(metaclass=ABCMeta):

    """
    Returns True if this Scheduler is enabled and ready to begin validation at
    the appropriate time, False otherwise.

    It does *not* indicate if the validation is actually executing at that
    instant - only that it is prepared to do so at the appropriate time.
    """
    @property
    @abstractmethod
    def is_enabled(self):
        pass

    @abstractmethod
    def enable_session_validation(self):
        pass

    @abstractmethod
    def disable_session_validation(self):
        pass


class SessionStore(metaclass=ABCMeta):
    """
    Data Access Object design pattern specification to enable Session
    access to an EIS (Enterprise Information System).  It provides your four
    typical CRUD methods:
        - create(session)
        - read(session_id)
        - update(Session)
        - delete(Session)

    The remaining get_active_sessions() method exists as a support
    mechanism to pre-emptively orphaned sessions, typically by
    ValidatingSessionManager(s), and should be as efficient as possible,
    especially if there are thousands of active sessions.  Large scale/high
    performance implementations will often return a subset of the total active
    sessions and perform validation a little more frequently, rather than
    return a massive set and infrequently validate.
    """

    @abstractmethod
    def create(self, session):
        """
        Inserts a new Session record into the underling EIS (e.g. Relational
        database, file system, persistent cache, etc, depending on the Store
        implementation).  After this method is invoked, the Session.session_id
        property obtained from the argument must return a valid session
        identifier.  That is, the following should always be true:

            session_id = create(session)
            session_id.equals(session.session_id) == True

        Implementations are free to throw any exceptions that might occur due
        to integrity violation constraints or other EIS related errors.

        :param session: the Session object to create in the EIS
        :returns: the EIS id (e.g. primary key) of the created
                  Session object
        """
        pass

    # yosai.core.renamed read_session:
    @abstractmethod
    def read(self, session_id):
        """
        Retrieves the session from the EIS uniquely identified by the specified
        session_id

        :param session_id: the system-wide unique identifier of the Session
                           object to retrieve from the EIS
        :returns: the persisted session in the EIS identified by session_id
        """
        pass

    @abstractmethod
    def update(self, session):
        """
        Updates (persists) data from a previously created Session instance in
        the EIS identified by session.session_id.  This effectively propagates
        the data in the argument to the EIS record previously saved.

        :param session: the Session to update
        :raises ValueError: if no existing EIS session record
                             exists with the identifier of session.session_id
        """
        pass

    @abstractmethod
    def delete(self, session):
        """
        Deletes the associated EIS record of the specified session.  If there
        never existed a session EIS record with the identifier of
        session.session_id, then this method does nothing.

        :param session: the session to delete
        """
        pass

    def get_active_sessions(self):
        """
        Returns all sessions in the EIS that are considered active, meaning all
        sessions that haven't been stopped/expired.  This is primarily used to
        validate potential orphans.

        If there are no active sessions in the EIS, this method may return an
        empty collection or None.

        Performance
        -----------
        This method should be as efficient as possible, especially in larger
        systems where there might be thousands of active sessions.  Large
        scale/high performance implementations will often return a subset of
        the total active sessions and perform validation a little more
        frequently, rather than return a massive set and validate infrequently.
        If efficient and possible, it would make sense to return the oldest
        unstopped sessions available, ordered by last_access_time.

        Smart Results
        -------------
        *Ideally*, this method would only return active sessions that the EIS
        was certain should be invalided.  Typically that is any session that is
        not stopped and where its last_access_timestamp is older than either
        session timeout (idle or absolute).

        For example, if sessions were backed by a relational database or SQL-92
        'query-able' enterprise cache, you might return something similar to
        the results returned by this query (assuming SimpleSession(s) were
        being stored):

            SELECT *
            FROM sessions s
            WHERE s.lastAccessTimestamp < {idle_timeout} and
                  s.lastAccessTimestamp < {absolute_timeout} and
                  s.stopTimestamp is null

        :returns: a Collection of session(s) that are considered active, or an
                  empty collection or None if there are no active sessions
        """
        pass
