

# new to yosai:
class CookieRegistry:

    def __init__(self, session_policy=None, remember_me_policy=None):
        self._session_policy = session_policy
        self._remember_me_policy = remember_me_policy

    @property
    def session(self):
        return self._session_policy.cookie

    @session.setter
    def session(self, session):
        self._session_policy.cookie = session

    @session.deleter
    def session(self):
        del self._session_policy.cookie

    @property
    def remember_me(self):
        return self._remember_me_policy.cookie

    @remember_me.setter
    def remember_me(self, remember_me):
        self._remember_me_policy.cookie = remember_me

    @remember_me.deleter
    def remember_me(self):
        del self._remember_me_policy.cookie
