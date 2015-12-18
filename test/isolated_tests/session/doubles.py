import datetime
from yosai.core import (
    DefaultNativeSessionManager,
    AbstractSessionStore,
    CachingSessionStore,
    event_bus,
    session_abcs,
)


class MockSessionManager:

    def get_start_timestamp():
        return datetime.datetime(2015, 1, 2, 12, 34, 56, 123456)

    def get_last_access_time(self, key):
        return datetime.datetime(2015, 1, 2, 12, 34, 59, 111111)

    def get_idle_timeout(self, key):
        return datetime.timedelta(minutes=15)

    def set_idle_timeout(self, key, timeout):
        pass

    def get_absolute_timeout(self, key):
        return datetime.timedelta(minutes=60)

    def set_absolute_timeout(self, key, timeout):
        pass

    def get_host(self, key):
        pass

    def touch(self, key):
        pass

    def stop(self, key):
        pass

    def get_attribute_keys(self, key):
        pass

    def get_attribute(self, key, attr_key):
        pass

    def set_attribute(self, key, attr_key, value):
        pass

    def remove_attribute(self, key, attr_key):
        pass


class MockDefaultNativeSessionManager(DefaultNativeSessionManager):

    def __init__(self):
        super().__init__()
        self._event_bus = event_bus
        self.listeners = []

    def create_session(self, session_context):
        pass

    def on_start(self, session, session_context):
        pass

    def do_get_session(self, session_key):
        pass

    def after_stopped(self, session):
        pass

    def on_change(self, session):
        pass

    def validate_sessions(self):
        pass


class MockAbstractSessionStore(AbstractSessionStore):

    def __init__(self):
        super().__init__()

    def do_create(self, session):
        pass

    def do_read_session(self, session_id):
        pass

    def delete(self, session):
        pass

    def update(self, session):
        pass


class MockCachingSessionStore(CachingSessionStore):

    def do_create(self, session):
        pass

    def do_delete(self, session):
        pass

    def do_read_session(self, session_id):
        pass

    def do_update(self, session):
        pass

