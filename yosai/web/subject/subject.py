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
    Default ``WebSubjectContext`` implementation that supports a web registry,
    facilitating cookie and remote-host management
    """

    WEB_REGISTRY = "DefaultWebSubjectContext.WEB_REGISTRY"

    def __init__(self, subject_context):
        """
        :subject_context:  WebSubjectContext
        """
        super().__init__(subject_context)

    # overridden:
    def resolve_host(self):
        host = super().resolve_host()

        if not host:
            return self.resolve_web_registry().remote_host

    @property
    def web_registry(self):
        return self.get(self.__class__.WEB_REGISTRY)

    @web_registry.setter
    def web_registry(self, webregistry):
        self.put(self.__class__.WEB_REGISTRY, webregistry)

    def resolve_web_registry(self):
        registry = self.web_registry

        # fall back on existing subject instance, if it exists:
        if not registry:
            try:
                return self.subject.web_registry
            except AttributeError:  # implies that it's not a WebSubject
                return None


# yosai renamed:
class WebSubjectBuilder(SubjectBuilder):
    """
    A ``WebSubjectBuilder`` performs the same function as a ``SubjectBuilder``,
    but additionally ensures that the web request, coordinating with the 
    request/response objects,  is retained for use by internal Yosai components.
    """

    def __init__(self,
                 security_utils,
                 security_manager=None,
                 subject_context=None,
                 host=None,
                 session_id=None,
                 session=None,
                 identifiers=None,
                 session_creation_enabled=True,
                 authenticated=False,
                 web_registry=None,
                 **context_attributes):
        """
        Constructs a new ``WebSubjectBuilder`` instance using the ``SecurityManager``
        obtained by calling ``SecurityUtils.security_manager``.  If you want
        to specify your own SecurityManager instance, pass it as an argument.

        :param web_registry:  facilitates interaction with request and response
                              objects used by the web application
        :type web_registry:  WebRegistry
        """
        super().__init__(security_utils=security_utils,
                         security_manager=None,
                         subject_context=None,
                         host=None,
                         session_id=None,
                         session=None,
                         identifiers=None,
                         session_creation_enabled=True,
                         authenticated=False,
                         **context_attributes)

        self.subject_context.web_registry = web_registry

        # overridden:
        def new_subject_context_instance(self):
            """
            Overrides the parent implementation to return a new instance of a
            ``DefaultWebSubjectContext`` to account for the additional
            web_registry attribute

            :returns: a new instance of a ``DefaultWebSubjectContext``
            """
            return DefaultWebSubjectContext(self.security_utils)

        def build_web_subject(self):
            """
            Returns ``super().build_subject()``, but additionally ensures that
            the returned instance is an instance of ``WebSubject``.

            :returns: a new ``WebSubject`` instance
            """
            subject = super().build_subject()  # in turn calls the WebSecurityManager

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
    Default ``WebSubject`` implementation that additionally ensures the ability to
    retain a web registry
    """
    def __init__(self, identifiers, authenticated,
                 host, session, session_enabled=True,
                 web_registry, security_manager):

        super().__init__(identifiers, authenticated, host, session,
                         session_enabled, security_manager)
        self._web_registry = web_registry

    # property is required for interface enforcement:
    @property
    def web_registry(self):
        return self._web_registry

    @property
    def web_registry(self):
        return self._web_registry

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
        return (self.session_creation_enabled and
                self.web_registry.session_creation_enabled)

    # overridden
    def create_session_context(self):
        wsc = DefaultWebSessionContext()

        host = self.host
        if host:
            wsc.host = host

        wsc.web_registry = self.web_registry

        return wsc
