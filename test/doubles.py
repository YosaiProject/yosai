
class MockException(Exception):
    pass


class MockWebRegistry:

    def __init__(self):
        self.current_session_id = None
        self.current_remember_me = None
        self._remote_host = '123.45.6789'

        self.session_id_history = []
        self.remember_me_history = []
        self.mock_exception = MockException
        self.resource_params = {}

    @property
    def remember_me(self):
        return self.current_remember_me

    @remember_me.setter
    def remember_me(self, rememberme):
        self.current_remember_me = rememberme
        self.remember_me_history.append(('SET', self.current_remember_me))

    @remember_me.deleter
    def remember_me(self):
        self.remember_me_history.append(('DELETE', self.current_remember_me))
        self.current_remember_me = None

    @property
    def session_id(self):
        return self.current_session_id

    @session_id.setter
    def session_id(self, session_id):
        self.current_session_id = session_id
        self.session_id_history.append(('SET', session_id))

    @session_id.deleter
    def session_id(self):
        self.session_id_history.append(('DELETE', self.current_session_id))
        self.current_session_id = None

    @property
    def remote_host(self):
        return self._remote_host

    @remote_host.setter
    def remote_host(self, remote_host):
        self._remote_host = remote_host

    @remote_host.deleter
    def remote_host(self):
        self._remote_host = None

    @property
    def session_creation_enabled(self):
        return True

    @session_creation_enabled.setter
    def session_creation_enabled(self, session_creation_enabled):
        pass

    @session_creation_enabled.deleter
    def session_creation_enabled(self):
        pass

    def raise_unauthorized(self, msg):
        raise MockException(msg)

    def raise_forbidden(self, msg):
        raise MockException(msg)

    def __repr__(self):
        return ("MockWebRegistry(current_session_id={0}, session_id_history={1},"
                "current_remember_me={2}, remember_me_history={3})".
                format(self.current_session_id, self.session_id_history,
                       self.current_remember_me, self.remember_me_history))
