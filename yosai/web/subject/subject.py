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
    SecurityUtils,
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

    def __init__(self, web_registry, security_utils, context={}):
        """
        :subject_context:  WebSubjectContext
        """
        super().__init__(security_utils=security_utils, context=context)
        self.web_registry = web_registry

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
                 web_registry=None,
                 subject_context=None,
                 host=None,
                 session_id=None,
                 session=None,
                 identifiers=None,
                 session_creation_enabled=True,
                 authenticated=False,
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
        self.web_registry = web_registry

        # using properties, for consistency:
        @property
        def web_registry(self):
            return self._web_registry

        @web_registry.setter
        def web_registry(self, web_registry):
            self._web_registry = web_registry

        # overridden:
        def new_subject_context_instance(self):
            """
            Overrides the parent implementation to return a new instance of a
            ``DefaultWebSubjectContext`` to account for the additional
            web_registry attribute

            :returns: a new instance of a ``DefaultWebSubjectContext``
            """
            return DefaultWebSubjectContext(web_registry=self.web_registry,
                                            security_utils=self.security_utils)

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
        self.web_registry = web_registry

    # property is required for interface enforcement:
    @property
    def web_registry(self):
        return self._web_registry

    @web_registry.setter
    def web_registry(self, web_registry):
        self._web_registry = web_registry

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
        wsc = DefaultWebSessionContext(web_registry=self.web_registry)

        host = self.host
        if host:
            wsc.host = host  # parent class puts it into the context map

        return wsc


class WebSecurityUtils(SecurityUtils):
    """
    This is a web-enabled SecurityUtils.  It is initialized using a
    WebSecurityManager.  Unlike ``SecurityUtils``, ``WebSecurityUtils`` is
    callable, passing it a ``WebRegistry`` instance that contains web request and
    response objects and functionality to manage cookies.
    """

    def __init__(self, security_manager=None):
        super().__init__(security_manager)

    @property
    def web_registry(self):
        return self._web_registry

    @web_registry.setter
    def web_registry(self, web_registry):
        self._web_registry = web_registry
        self.security_manager.web_registry = web_registry

    # overridden:
    def load_subject(self):
        # there should always be a web_registry at this moment, so propagate
        # an exception if that is not the case:
        try:
            subject_builder = WebSubjectBuilder(security_utils=self,
                                                security_manager=self.security_manager,
                                                web_registry=self.web_registry)
        except AttributeError:
            msg = "WebSecurityUtils cannot create a  "
            raise MissingWebRegistryException(msg)
        self._subject = subject_builder.build_subject()

    def __call__(self, web_registry):
        self.web_registry = web_registry

    def __exit__(self, exc_type=None, exc_value=None, exc_trace=None):
        super().__exit__()
        self.web_registry = None
