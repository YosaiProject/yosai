import yosai.session.abcs as session_abcs

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
        return 1433961196

    @property
    def start_timestamp(self):
        return 1433961176  # guess when I created this mock? 

    @property
    def timeout(self):
        return 1433962096  # 15 minutes from last_access_time 

    @timeout.setter
    def timeout(self, max_idle_time_in_millis):
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

