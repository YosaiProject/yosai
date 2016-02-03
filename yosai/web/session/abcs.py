
from yosai.core import (
    session_abcs,
)

from abc import abstractmethod


class WebSessionManager(session_abcs.SessionManager):

    @abstractmethod
    def is_wsgi_container_sessions(self):
        """
        Returns ``True`` if session management and storage is managed by the
        underlying WSGI container or ``False`` if managed by Yosai directly
        (called 'native' sessions).

        If sessions are enabled, Yosai can make use of Sessions to retain
        security information from request to request.  This method indicates
        whether Yosai would use the WSGI container sessions to fulfill its
        needs, or if it would use its own native session management instead (which
        can support enterprise features such as distributed caching - in a
        container-independent manner).

        :returns: True if session management and storage is managed by the
                  underlying WSGI container or False if managed by Yosai directly
                  (called 'native' sessions)

        """
        pass
