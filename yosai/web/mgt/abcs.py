"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""


from yosai.core import (
    mgt_abcs,
    session_abcs,
)
from yosai.web import (
    web_util_abcs,
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


class WebSessionContext(session_abcs.SessionContext,
                        web_util_abcs.RequestPairSource):
    """
     A ```WebSubjectContext`` is a ``SessionContext`` that additionally
     provides methods to set and retrieve a ``WSGIRequest`` and ``WSGIResponse``,
    as the request/response pair will often need to be referenced during
    construction of web-initiated {@code Session} instances.
    """

    @abstractmethod
    @property
    def wsgi_request(self):
        """
        Returns the ``WSGIRequest`` received by the wsgi container triggering
        the creation of the ``Session`` instance.
        """
        pass

    @abstractmethod
    @wsgi_request.setter
    def wsgi_request(self, request):
        """
        Sets the ``WSGIRequest`` received by the wsgi container triggering the
        creation of the ``Session`` instance.

        :param request: the ``WSGIRequest`` received by the wsgi container
                        triggering the creation of the ``Session`` instance
        """
        pass

    @abstractmethod
    @property
    def wsgi_response(self):
        """
        The paired ``WSGIResponse`` corresponding to the associated
        ``wsgiRequest``.

        :returns: the paired ``WSGIResponse`` corresponding to the associated
                  ``wsgi_request``
        """
        pass

    @abstractmethod
    @wsgi_response.setter
    def wsgi_response(self, response):
        """
        Sets the paired ``WSGIResponse`` corresponding to the associated
        ``wsgiRequest``.

        :param response: The paired ``WSGIResponse`` corresponding to the
                         associated ``wsgiRequest``.
        """
        pass
