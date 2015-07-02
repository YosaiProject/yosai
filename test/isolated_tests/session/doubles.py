import yosai.session.abcs as session_abcs
import datetime
from yosai import (
    AbstractNativeSessionManager,
    AbstractValidatingSessionManager,
)

class MockSession(session_abcs.Session, object):

    def __init__(self):
        self.session = {'attr1': 1, 'attr2': 2, 'attr3': 3}
        self._idle_timeout = datetime.timedelta(minutes=15)
        self._absolute_timeout = datetime.timedelta(minutes=60) 

    @property
    def attribute_keys(self):
        return self.session.keys() 
    
    @property
    def host(self):
        return '127.0.0.1' 

    @property
    def session_id(self):
        return 'MockSession12345'
    
    @property
    def last_access_time(self):
        return datetime.datetime(2015, 6, 17, 19, 45, 51, 818810) 

    @property
    def start_timestamp(self):
        return datetime.datetime(2015, 6, 17, 19, 43, 51, 818810) 

    @property
    def idle_timeout(self):
        return self._idle_timeout 
 
    @idle_timeout.setter
    def idle_timeout(self, idle_timeout):
        self._idle_timeout = idle_timeout 
   
    @property
    def absolute_timeout(self):
        return self._absolute_timeout 

    @absolute_timeout.setter
    def absolute_timeout(self, absolute_timeout):
        self._absolute_timeout = absolute_timeout

    def get_attribute(self, key):
        return 'attrX' 
    
    def remove_attribute(self, key):
        return self.session.pop(key, None) 
    
    def set_attribute(self, key, value):
        self.session[key] = value 

    def stop(self):
        pass

    def touch(self):
        pass 

    def validate(self):
        pass


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


class MockAbstractNativeSessionManager(AbstractNativeSessionManager):

    def __init__(self, event_bus):
        super().__init__(event_bus)
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


class MockAbstractValidatingSessionManager(AbstractValidatingSessionManager):

    def __init__(self, event_bus):
        super().__init__(event_bus)
        self.listeners = []
    
    def on_start(self, session, session_context):
        pass

    def after_stopped(self, session):
        pass

    def on_change(self, session):
        pass
    
    def retrieve_session(self, session_key):
        pass
    
    def do_create_session(self, session_context):
        pass

    def after_expired(self, session):
        pass

    def after_session_validation_enabled(self):
        pass

    def before_session_validation_disabled(self):
        pass

    def get_active_sessions(self):
        pass
