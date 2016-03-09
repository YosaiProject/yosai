from yosai.web import web_abcs


class MockWebRegistry(web_abcs.WebRegistry):

    def __init__(self, request=None, response=None):
        # both request and response are ignored for the Mock
        self.request = {'remember_me': None,
                        'session_id': None,
                        'remote_host': '127.0.0.1',
                        'session_creation_enabled': True}

        self.response = self.request  # same until cookies are changed

    @property
    def remember_me(self):
        return self.request.get('remember_me')

    @remember_me.setter
    def remember_me(self, rememberme):
        self.response['remember_me'] = rememberme

    @remember_me.deleter
    def remember_me(self):
        self.response['remember_me'] = None

    @property
    def session_id(self):
        return self.request.get('session_id')

    @session_id.setter
    def session_id(self, session_id):
        self.response['session_id'] = session_id

    @session_id.deleter
    def session_id(self):
        self.response['session_id'] = None

    @property
    def remote_host(self):
        return self.request.get('remote_host')

    @remote_host.setter
    def remote_host(self, remote_host):
        self.response['remote_host'] = remote_host

    @remote_host.deleter
    def remote_host(self):
        self.response['remote_host'] = None

    @property
    def session_creation_enabled(self):
        return self.request.get('session_creation_enabled')

    @session_creation_enabled.setter
    def session_creation_enabled(self, session_creation_enabled):
        self.response['session_creation_enabled'] = session_creation_enabled

    @session_creation_enabled.deleter
    def session_creation_enabled(self):
        self.response['session_creation_enabled'] = None
