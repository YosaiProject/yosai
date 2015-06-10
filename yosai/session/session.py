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
)

from . import (
    ISession,
)

class ProxiedSession(ISession, object):
   
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
