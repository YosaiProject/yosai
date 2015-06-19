from abc import ABCMeta, abstractmethod
from yosai import (
    IllegalStateException,
    UnknownSessionException,
)
import uuid

class Session(metaclass=ABCMeta):
    """
    A Session is a stateful data context associated with a single 
    Subject's (user, daemon process, etc) interaction with a software system 
    over a period of time.

    A Session is intended to be managed by the business tier and accessible via
    other tiers without being tied to any given client technology.  This is a
    great benefit to Python systems, since until now the only viable session 
    mechanisms were those highly-coupled and deeply embedded in web application 
    frameworks.
    """

    @property
    @abstractmethod
    def session_id(self):
        """
        The unique identifier assigned by the system upon session creation.
        """
        pass
    
    @property
    @abstractmethod
    def start_timestamp(self):
        """ 
        The time that the session started (the time that the system created 
        the instance )
        """
        pass

    @property
    @abstractmethod
    def last_access_time(self):
        """ 
        Returns the last time the application received a request or method 
        invocation from THE USER associated with this session.  Application 
        calls to this method do not affect this access time.
        """
        pass

    @property
    @abstractmethod
    def absolute_timeout(self):
        """ 
        Returns the time, in milliseconds, that the session may 
        exist before it expires
        """    
        pass

    @absolute_timeout.setter
    @abstractmethod
    def absolute_timeout(self, abs_timeout): 
        """ 
        Sets the time in milliseconds that the session may exist 
        before expiring.

        - A negative value means the session will never expire
        - A non-negative value (0 or greater) means the session expiration will
          occur if idle for that length of time.
        """
        pass

    @property
    @abstractmethod
    def idle_timeout(self):
        """ 
        Returns the time, in milliseconds, that the session may 
        remain idle before it expires
        """    
        pass

    @idle_timeout.setter
    @abstractmethod
    def idle_timeout(self, idle_timeout): 
        """ 
        Sets the time in milliseconds that the session may remain idle 
        before expiring.

        - A negative value means the session will never expire
        - A non-negative value (0 or greater) means the session expiration will
          occur if idle for that length of time.
        """
        pass

    @property
    @abstractmethod
    def host(self):
        """
        Returns the host name or IP string of the host that originated this
        session, or None if the host is unknown.
        """
        pass

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
        Shiro's implementations, lazily validate sessions - either when they
        are accessed or during a regular validation interval.  It would be too
        resource intensive to monitor every single session instance to know the
        exact instant it expires.

        If you need to perform time-based logic when a session expires, it
        is best to write it based on the session's last_access_time and
        NOT the time when this method is called.
     
        :param session: the session that has expired
        """
        pass


class SessionStorageEvaluator(metaclass=ABCMeta):

    @abstractmethod
    def is_session_storage_enabled(self, subject):
        pass


class ValidatingSession(Session):

    @abstractmethod
    def is_valid(self):
        pass

    @abstractmethod
    def validate(self):
        pass


class SessionIDGenerator(metaclass=ABCMeta):

    @classmethod
    @abstractmethod
    def generate_id(self, session):
        pass

