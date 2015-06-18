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

