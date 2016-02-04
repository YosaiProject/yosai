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
import logging

from yosai.core import (
    DefaultSubjectContext,
    DelegatingSubject,
    IllegalStateException,
    SubjectBuilder,
)

from yosai.web import (
    web_subject_abcs,
)

logger = logging.getLogger(__name__)


class DefaultWebSubjectContext(DefaultSubjectContext,
                               web_subject_abcs.WebSubjectContext):
    """
    Default ``WebSubjectContext`` implementation that provides for additional
    storage and retrieval of ``WSGIRequest`` and ``WSGIResponse``
    """

    WSGI_REQUEST = "DefaultWebSubjectContext.WSGI_REQUEST"
    WSGI_RESPONSE = "DefaultWebSubjectContext.WSGI_RESPONSE"

    def __init__(self, subject_context):
        """
        :subject_context:  WebSubjectContext
        """
        super().__init__(subject_context)

    # overridden:
    def resolve_host(self):
        host = super().resolve_host()
        if not host:
            try:
                request = self.resolve_wsgi_request()
                host = request.remote_host
            except:
                pass

        return host

    @property
    def wsgi_request(self):
        return self.get(self.__class__.WSGI_REQUEST)

    @wsgi_request.setter
    def wsgi_request(self, request):
        self.put(self.__class__.WSGI_REQUEST, request)

    def resolve_wsgi_request(self):
        request = self.get_wsgi_request()

        # fall back on existing subject instance, if it exists:
        if not request:
            existing = self.subject
            try:
                request = existing.wsgi_request
            except AttributeError:
                pass # means it's not a WebSubject

        return request

    @property
    def wsgi_response(self):
        return self.get(self.__class__.WSGI_RESPONSE)

    @wsgi_response.setter
    def wsgi_response(self, response):
        """
        :type response:  WSGIResponse
        """
        self.put(self.__class__.WSGI_RESPONSE, response)

    def resolve_wsgi_response(self):
        response = self.get_wsgi_response()

        # fall back on existing subject instance if it exists:
        if not response:
            existing = self.subject
            try:
                response = existing.wsgi_response
            except AttributeError:
                pass  # means it's not a WebSubject

        return response


# yosai renamed:
class WebSubjectBuilder(SubjectBuilder):
    """
    A ``WebSubjectBuilder`` performs the same function as a ``SubjectBuilder``,
    but additionally ensures that the WSGI request/response pair that is
    triggering the Subject instance's creation is retained for use by internal
    Yosai components as necessary.
    """

    def __init__(self,
                 security_manager=None,
                 subject_context=None,
                 host=None,
                 session_id=None,
                 session=None,
                 identifiers=None,
                 session_creation_enabled=True,
                 authenticated=False,
                 request=None,
                 response=None,
                 **context_attributes):
        """
        Constructs a new ``WebSubjectBuilder`` instance using the ``SecurityManager``
        obtained by calling ``SecurityUtils.get_security_manager()``.  If you want
        to specify your own SecurityManager instance, pass it as an argument.

        :param request:  the incoming WSGIRequest that will be associated with the
                         built ``WebSubject`` instance
        :param response: the outgoing WSGIRequest paired with the WSGIRequest that
                         will be associated with the built ``WebSubject`` instance

        :type request:  WSGIRequest
        :type response:  WSGIReponse
        """
        super().__init__(security_manager=None,
                         subject_context=None,
                         host=None,
                         session_id=None,
                         session=None,
                         identifiers=None,
                         session_creation_enabled=True,
                         authenticated=False,
                         **context_attributes)

        self.subject_context.wsgi_request = request
        self.subject_context.wsgi_response = response

        # overridden:
        def new_subject_context_instance(self):
            """
            Overrides the parent implementation to return a new instance of a
            ``DefaultWebSubjectContext`` to account for the additional request/response
            pair.

            :returns: a new instance of a ``DefaultWebSubjectContext``
            """
            return DefaultWebSubjectContext()

        def build_web_subject(self):
            """
            Returns ``super().build_subject()``, but additionally ensures that
            the returned instance is an instance of ``WebSubject``.

            :returns: a new ``WebSubject`` instance
            """
            subject = super().build_subject()

            if not isinstance(subject, web_subject_abcs.WebSubject):
                msg = ("Subject implementation returned from the SecurityManager"
                       "was not a WebSubject implementation.  Please ensure a "
                       "Web-enabled SecurityManager has been configured and made"
                       "available to this builder.")
                raise IllegalStateException(msg)

            return subject


class WebDelegatingSubject(DelegatingSubject,
                           web_subject_abcs.WebSubject):
    """
    Default ``WebSubject`` implementation that additional ensures the ability to
    retain a wsgi request/response pair to be used by internal shiro components
    as necessary during the request execution.
    """
    def __init__(self, identifiers, authenticated,
                 host, session, session_enabled=True,
                 request, response, security_manager):

        super().__init__(identifiers, authenticated, host, session,
                         session_enabled, securityManager)
        self._wsgi_request = request
        self._wsgi_response = response

    # property is required for interface enforcement:
    @property
    def wsgi_request(self):
        return self._wsgi_request

    @property
    def wsgi_response(self):
        return self._wsgi_response

    # overridden
    @property
    def session_creation_enabled(self):
        """
        Returns True if session creation is allowed  (as determined by the super
        class's is_session_creation_enabled value and no request-specific override
        has disabled sessions for this subject, False otherwise.

        This means session creation is disabled if the super is_session_creation_enabled
        property is False or if a request attribute is discovered that turns off
        sessions for the current request.

         :returns: True if session creation is allowed  (as determined by the
                   super class's session_creation_enabled value and no
                   request-specific override has disabled sessions for this
                   subject, False otherwise
        """
        enabled = super().session_creation_enabled()
        return enabled and WebUtils._is_session_creation_enabled(self)

    # overridden
    def create_session_context(self):
        wsc = DefaultWebSessionContext()

        host = self.host
        if host:
            wsc.host = host

        wsc.wsgi_request = self.wsgi_request
        wsc.wsgi_response = self.wsgi_response
        return wsc
