import datetime
from yosai.core import (
    NativeSessionManager,
    AbstractSessionStore,
    session_abcs,
)
from unittest import mock


class MockSessionManager:

    def get_start_timestamp():
        return 1472291665000

    def get_last_access_time(self, key):
        return 1472291665100

    def get_idle_timeout(self, key):
        return (10 * 60 * 1000)

    def set_idle_timeout(self, key, timeout):
        pass

    def get_absolute_timeout(self, key):
        return (60 * 60 * 1000)

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

    def get_internal_attribute_keys(self, key):
        pass

    def get_internal_attribute(self, key, attr_key):
        pass

    def set_internal_attribute(self, key, attr_key, value):
        pass

    def remove_internal_attribute(self, key, attr_key):
        pass


class MockNativeSessionManager(NativeSessionManager):

    def __init__(self, settings):
        super().__init__(settings)
        self._event_bus = mock.MagicMock()
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

    def _do_create(self, session):
        pass

    def _do_read(self, session_id):
        pass
