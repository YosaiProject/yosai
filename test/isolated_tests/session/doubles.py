import yosai.session.abcs as session_abcs
import datetime

class MockSession(session_abcs.Session, object):

    def __init__(self):
        self.session = {'attr1': 1, 'attr2': 2, 'attr3': 3}

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
        return datetime.timedelta(minutes=15)
 
    @idle_timeout.setter
    def idle_timeout(self, idle_timeout):
        pass
   
    @property
    def absolute_timeout(self):
        return datetime.timedelta(minutes=60) 

    @absolute_timeout.setter
    def absolute_timeout(self, absolute_timeout):
        pass

    def get_attribute(self, key):
        pass
    
    def remove_attribute(self, key):
        pass
    
    def set_attribute(self, key, value):
        pass

    def stop(self):
        pass

    def touch(self):
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

