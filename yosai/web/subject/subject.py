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
import functools
import logging
from contextlib import contextmanager

from yosai.core import (
    AuthorizationException,
    DefaultSubjectContext,
    DelegatingSubject,
    IdentifiersNotSetException,
    IllegalStateException,
    Yosai,
    SubjectBuilder,
    ThreadStateManager,
    WebRegistrySettings,
    YosaiContextException,
    global_yosai_context,
    global_subject_context,
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

    def __init__(self, security_utils, security_manager, web_registry):
        """
        :subject_context:  WebSubjectContext
        """
        super().__init__(security_utils, security_manager)

        self.web_registry = web_registry

    # overridden:
    def resolve_host(self, session=None):
        host = super().resolve_host(session)

        if not host:
            return self.resolve_web_registry().remote_host

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
    def __init__(self, identifiers=None, authenticated=None,
                 host=None, session=None, session_creation_enabled=True,
                 security_manager=None, web_registry=None):

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
        wsc.host = self.host
        return wsc

    # this override is new to yosai, to support CSRF token synchronization:
    def get_session(self, create=True):
        """
        :type create:  bool

        A CSRF Token is generated for each new session (and at successful login).
        """
        super().get_session(create)
        if self.session and not create:  # touching a new session is redundant
            self.session.touch()  # this is used to reset the idle timer (new to yosai)
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
            return "WebStoppingAwareProxiedSession()"


class WebYosai(Yosai):
    """
    This is a web-enabled Yosai.  It is initialized using a
    WebSecurityManager.  Unlike ``Yosai``, ``WebYosai`` is
    callable, passing it a ``WebRegistry`` instance that contains web request and
    response objects and functionality to manage cookies.
    """

    def __init__(self, env_var=None, file_path=None):
        super().__init__(env_var=env_var, file_path=file_path)

        # web_registry objects are injected with secret as context is set:
        registry_settings = WebRegistrySettings(self.settings)
        self.signed_cookie_secret = registry_settings.signed_cookie_secret

    @memoized_property
    def subject_builder(self):
        self._subject_builder = WebSubjectBuilder(security_utils=self,
                                                  security_manager=self.security_manager)
        return self._subject_builder

    # overridden:
    def _get_subject(self):
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
        web_registry = WebYosai.get_current_webregistry()
        return self.subject_builder.build_subject(web_registry=web_registry)

    @staticmethod
    @contextmanager
    def context(yosai, webregistry):
        global_yosai_context.stack.append(yosai)  # how to weakref? TBD
        webregistry.secret = yosai.signed_cookie_secret  # inject the secret
        global_webregistry_context.stack.append(webregistry)  # how to weakref? TBD
        yield

        try:
            global_subject_context.stack.pop()
        except IndexError:
            logger.debug('Could not pop a subject from the context stack.')
        global_yosai_context.stack.pop()
        global_webregistry_context.stack.pop()

    @staticmethod
    def get_current_webregistry():
        try:
            return global_webregistry_context.stack[-1]
        except IndexError:
            msg = 'A yosai instance does not exist in the global context.'
            raise YosaiContextException(msg)

    @staticmethod
    def requires_authentication(fn):
        """
        Requires that the calling Subject be authenticated before allowing access.
        """

        @functools.wraps(fn)
        def wrap(*args, **kwargs):
            subject = WebYosai.get_current_subject()

            if not subject.authenticated:
                msg = "The current Subject is not authenticated.  ACCESS DENIED."
                raise WebYosai.get_current_webregistry().raise_unauthorized(msg)

            return fn(*args, **kwargs)
        return wrap

    @staticmethod
    def requires_user(fn):
        """
        Requires that the calling Subject be *either* authenticated *or* remembered
        via RememberMe services before allowing access.

        This method essentially ensures that subject.identifiers IS NOT None
        """
        @functools.wraps(fn)
        def wrap(*args, **kwargs):

            subject = WebYosai.get_current_subject()

            if subject.identifiers is None:
                msg = ("Attempting to perform a user-only operation.  The "
                       "current Subject is NOT a user (they haven't been "
                       "authenticated or remembered from a previous login). "
                       "ACCESS DENIED.")
                raise WebYosai.get_current_webregistry().raise_unauthorized(msg)
            return fn(*args, **kwargs)
        return wrap

    @staticmethod
    def requires_guest(fn):
        """
        Requires that the calling Subject be NOT (yet) recognized in the system as
        a user -- the Subject is not yet authenticated nor remembered through
        RememberMe services.

        This method essentially ensures that subject.identifiers IS None
        """
        @functools.wraps(fn)
        def wrap(*args, **kwargs):

            subject = WebYosai.get_current_subject()

            if subject.identifiers is not None:
                msg = ("Attempting to perform a guest-only operation.  The "
                       "current Subject is NOT a guest (they have either been "
                       "authenticated or remembered from a previous login). "
                       "ACCESS DENIED.")
                raise WebYosai.get_current_webregistry().raise_unauthorized(msg)

            return fn(*args, **kwargs)
        return wrap

    @staticmethod
    def requires_permission(permission_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the permission_s specified and the logical operation
        upon them.

        :param permission_s:   the permission(s) required
        :type permission_s:  a List of Strings or List of Permission instances

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        Elaborate Example:
            requires_permission(
                permission_s=['domain1:action1,action2', 'domain2:action1'],
                logical_operator=any)

        Basic Example:
            requires_permission(['domain1:action1,action2'])
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):

                subject = WebYosai.get_current_subject()
                try:
                    subject.check_permission(permission_s, logical_operator)

                except IdentifiersNotSetException:
                    msg = ("Attempting to perform a user-only operation.  The "
                           "current Subject is NOT a user (they haven't been "
                           "authenticated or remembered from a previous login). "
                           "ACCESS DENIED.")
                    raise WebYosai.get_current_webregistry().raise_unauthorized(msg)

                except AuthorizationException:
                    msg = "Access Denied.  Insufficient Permissions."
                    raise WebYosai.get_current_webregistry().raise_forbidden(msg)

                return fn(*args, **kwargs)
            return inner_wrap
        return outer_wrap

    @staticmethod
    def requires_dynamic_permission(permission_s, logical_operator=all):
        """
        This method requires that the calling Subject be authorized to the extent
        that is required to satisfy the dynamic permission_s specified and the logical
        operation upon them.  Unlike ``requires_permission``, which uses statically
        defined permissions, this function derives a permission from arguments
        specified at declaration.

        Dynamic permissioning requires that the dynamic arguments be keyword
        arguments of the decorated method.

        :param permission_s:   the permission(s) required
        :type permission_s:  a List of Strings or List of Permission instances

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        Elaborate Example:
            requires_permission(
                permission_s=['{kwarg1.domainid}:action1,action2',
                               '{kwarg2.domainid}:action1'],
                logical_operator=any)

        Basic Example:
            requires_permission(['{kwarg.domainid}:action1,action2'])
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):

                params = WebYosai.get_current_webregistry().resource_params
                newperms = [perm.format(**params) for perm in permission_s]

                subject = WebYosai.get_current_subject()

                try:
                    subject.check_permission(newperms, logical_operator)

                except IdentifiersNotSetException:
                    msg = ("Attempting to perform a user-only operation.  The "
                           "current Subject is NOT a user (they haven't been "
                           "authenticated or remembered from a previous login). "
                           "ACCESS DENIED.")
                    raise WebYosai.get_current_webregistry().raise_unauthorized(msg)

                except AuthorizationException:
                    msg = "Access Denied.  Insufficient Permissions."
                    raise WebYosai.get_current_webregistry().raise_forbidden(msg)

                return fn(*args, **kwargs)
            return inner_wrap
        return outer_wrap

    @staticmethod
    def requires_role(roleid_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the roleid_s specified and the logical operation
        upon them.

        :param roleid_s:   a collection of the role(s) required, specified by
                           identifiers (such as a role name)
        :type roleid_s:  a List of Strings

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        Elaborate Example:
            requires_role(roleid_s=['sysadmin', 'developer'], logical_operator=any)

        Basic Example:
            requires_role('physician')
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):

                subject = WebYosai.get_current_subject()

                try:
                    subject.check_role(roleid_s, logical_operator)

                except IdentifiersNotSetException:
                    msg = ("Attempting to perform a user-only operation.  The "
                           "current Subject is NOT a user (they haven't been "
                           "authenticated or remembered from a previous login). "
                           "ACCESS DENIED.")
                    raise WebYosai.get_current_webregistry().raise_unauthorized(msg)

                except AuthorizationException:
                    msg = "Access Denied.  Insufficient Role Membership."
                    raise WebYosai.get_current_webregistry().raise_forbidden(msg)

                return fn(*args, **kwargs)
            return inner_wrap
        return outer_wrap


global_webregistry_context = ThreadStateManager()
