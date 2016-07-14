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
    Yosai,
    SubjectBuilder,
    memoized_property,
)

from yosai.web import (
    DefaultWebSessionContext,
    WebProxiedSession,
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

    def __init__(self, security_utils, security_manager, web_registry, context={}):
        """
        :subject_context:  WebSubjectContext
        """
        super().__init__(security_utils, security_manager, context=context)

        self.web_registry = web_registry

    # overridden:
    def resolve_host(self, session=None):
        host = super().resolve_host(session)

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
                msg = "WebSubjectContext could not find a WebRegistry."
                logger.warn(msg)
                return None

        return registry


# yosai renamed:
class WebSubjectBuilder(SubjectBuilder):
    """
    A ``WebSubjectBuilder`` performs the same function as a ``SubjectBuilder``,
    but additionally ensures that the web request, coordinating with the
    request/response objects,  is retained for use by internal Yosai components.
    """

    def __init__(self, security_utils, security_manager=None):
        """
        Constructs a new ``WebSubjectBuilder`` instance using the ``SecurityManager``
        obtained by calling ``Yosai.security_manager``.  If you want
        to specify your own SecurityManager instance, pass it as an argument.

        """
        self.security_utils = security_utils
        self.security_manager = security_manager

    # overridden
    def create_subject_context(self, web_registry):
        subject_context = DefaultWebSubjectContext(security_utils=self.security_utils,
                                                   security_manager=self.security_manager,
                                                   web_registry=web_registry)
        return subject_context

    def build_subject(self, web_registry):
        """
        :param web_registry:  facilitates interaction with request and response
                              objects used by the web application
        :type web_registry:  WebRegistry

        :returns: a new ``WebSubject`` instance
        """
        subject_context = self.create_subject_context(web_registry)
        subject = self.security_manager.create_subject(subject_context=subject_context)

        if not isinstance(subject, web_subject_abcs.WebSubject):
            msg = ("Subject implementation returned from the SecurityManager"
                   "was not a WebSubject implementation.  Please ensure a "
                   "Web-enabled SecurityManager has been configured and made"
                   "available to this builder.")
            raise IllegalStateException(msg)

        # The Subject was just created, but before returning it a Session needs
        # to be initialized for it: Web Subjects must have a session ready to manage
        # CSRF tokens and flash messages.  This is new to Yosai.
        subject.get_session(True)

        return subject


class WebDelegatingSubject(DelegatingSubject,
                           web_subject_abcs.WebSubject):
    """
    A ``WebDelegatingSubject`` delegates method calls to an underlying ``WebSecurityManager``
    instance for security checks.  It is essentially a ``WebSecurityManager`` proxy,
    just as ``DelegatingSession`` is to ``DefaultNativeSessionManager``.

    This implementation does not maintain security-related state such as roles and
    permissions. Instead, it asks the underlying ``WebSecurityManager`` to check
    authorization. However, Subject-specific state, such as username, and
    the WebRegistry object is saved so to facilitate subject-specific processing
    in the context of a web request.
    """
    def __init__(self, identifiers, authenticated,
                 host, session, web_registry, security_manager,
                 session_creation_enabled=True):

        super().__init__(identifiers=identifiers,
                         authenticated=authenticated,
                         host=host,
                         session=session,
                         session_creation_enabled=session_creation_enabled,
                         security_manager=security_manager)

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
        return (self._session_creation_enabled and
                self.web_registry.session_creation_enabled)

    # overridden
    def create_session_context(self):
        wsc = DefaultWebSessionContext(web_registry=self.web_registry)

        host = self.host
        if host:
            wsc.host = host  # parent class puts it into the context map

        return wsc

    # this override is new to yosai, to support CSRF token synchronization:
    def get_session(self, create=True):
        """
        :type create:  bool

        A CSRF Token is generated for each new session (and at successful login).
        """
        super().get_session(create)

        return self.session

    # inner class:
    class StoppingAwareProxiedSession(WebProxiedSession):

        def __init__(self, target_session, owning_subject):
            """
            :type target_session:  session_abcs.Session
            :type owning_subject:  subject_abcs.Subject
            """
            super().__init__(target_session)
            self.owner = owning_subject

        def stop(self, identifiers):
            """
            :type identifiers:  subject_abcs.IdentifierCollection
            :raises InvalidSessionException:
            """
            super().stop(identifiers)
            self.owner.session_stopped()

        def __repr__(self):
            return "Web - StoppingAwareProxiedSession()"


class WebYosai(Yosai):
    """
    This is a web-enabled Yosai.  It is initialized using a
    WebSecurityManager.  Unlike ``Yosai``, ``WebYosai`` is
    callable, passing it a ``WebRegistry`` instance that contains web request and
    response objects and functionality to manage cookies.
    """

    def __init__(self, security_manager):
        super().__init__(security_manager)

    @memoized_property
    def subject_builder(self):
        self._subject_builder = WebSubjectBuilder(security_utils=self,
                                                  security_manager=self.security_manager)
        return self._subject_builder

    # overridden:
    def get_subject(self, web_registry):
        """
        Returns the currently accessible Subject available to the calling code
        depending on runtime environment.

        :param web_registry:  The WebRegistry instance that knows how to interact
                              with the web application's request and response APIs

        :returns: the Subject currently accessible to the calling code
        :raises IllegalStateException: if no Subject instance or SecurityManager
                                       instance is available to obtain a Subject
                                       (such an setup is considered an invalid
                                        application configuration because a Subject
                                        should *always* be available to the caller)
        """
        return self.subject_builder.build_subject(web_registry=web_registry)
