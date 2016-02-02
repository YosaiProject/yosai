from yosai.core import (
    mgt_abcs,
)

from abc import abstractmethod


class WebSecurityManager(mgt_abcs.SecurityManager):
    """
    This interface represents a ``SecurityManager`` implementation that can used
    in web-enabled applications
    """

    @abstractmethod
    def is_http_session_mode(self):
        """
        Security information needs to be retained from request to request, so
        Yosai makes use of a session for this. Typically, a security manager will
        use the wsgi container's HTTP session but custom session implementations
        may also be used. This method indicates whether the security manager is
        using the HTTP session.

        :returns:  True if the security manager is using the HTTP session, else False
        """
        pass
