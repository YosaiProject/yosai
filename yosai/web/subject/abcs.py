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

from abcs import abstractmethod, ABCMeta

from yosai.core import (
    subject_abcs,
)

from yosai.web import (
    web_utils_abcs,
)


class WebSubject(subject_abcs.Subject,
                 web_utils_abcs.RequestPairSource):
    """
    A ``WebSubject`` represents a Subject instance that was acquired as a result
    of an incoming ``WSGIRequest``.
    """

    @abstractmethod
    def get_wsgi_Request(self):
        """
        Returns the ``WSGIRequest`` accessible when the Subject instance was
        created.

        :returns: the ``WSGIRequest`` accessible when the Subject instance was created
        """
        pass

    @abstractmethod
    def get_wsgi_response(self):
        """
        Returns the ``WSGIResponse`` accessible when the Subject instance was
        created.

        :returns: the ``WSGIResponse`` accessible when the Subject instance was created
        """
        pass


class WebSubjectContext(subject_abcs.SubjectContext,
                        web_utils_abcs.RequestPairSource):
    """
    A ``WebSubjectContext`` is a ``SubjectContext`` that additionally provides
    for type-safe methods to set and retrieve a ``WSGIRequest`` and
    ``WSGIResponse``.
    """

    @abstractmethod
    @property
    def wsgi_request(self):
        """
        Returns the ``WSGIRequest`` received by the wsgi container triggering
        the creation of the ``Subject`` instance.

        :returns: the ``WSGIRequest`` received by the wsgi container triggering
                  the creation of the ``Subject`` instance
        """
        pass

    @abstractmethod
    @wsgi_request.setter
    def wsgi_request(self, request):
        """
        Sets the ``WSGIRequest`` received by the wsgi container triggering
        the creation of the ``Subject`` instance

        :param request: the ``WSGIRequest`` received by the wsgi container
                        triggering the creation of the ``Subject`` instance
        """
        pass

    @abstractmethod
    def resolveWSGIRequest(self):
        """
         * The paired {@code WSGIResponse} corresponding to the associated {@link #getWSGIRequest wsgiRequest}.
         *
         * @return the paired {@code WSGIResponse} corresponding to the associated
         *         {@link #getWSGIRequest wsgiRequest}.
         */
        """

    @abstractmethod
    def get_wsgi_response(self):
        pass

    @abstractmethod
    def set_wsgi_response(self, response):
        """
        Sets the paired ``WSGIResponse`` corresponding to the associated
        ``WSGIRequest``

        :param response: the paired ``WSGIResponse`` corresponding to the associated
                         ``WSGIRequest``.
        """
        pass

    @abstractmethod
    def resolve_wsgi_response(self):
        pass
