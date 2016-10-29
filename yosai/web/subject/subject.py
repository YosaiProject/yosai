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
    SubjectContext,
    DelegatingSubject,
    ExpiredSessionException,
    Yosai,
    ThreadStateManager,
    global_yosai_context,
    global_subject_context,
    memoized_property,
)

from yosai.web import (
    WebRegistrySettings,
    web_subject_abcs,
)

logger = logging.getLogger(__name__)


class WebSubjectContext(SubjectContext,
                               web_subject_abcs.WebSubjectContext):
    """
    Default ``WebSubjectContext`` implementation that supports a web registry,
    facilitating cookie and remote-host management
    """

    def __init__(self, yosai, security_manager, web_registry):
        """
        :subject_context:  WebSubjectContext
        """
        super().__init__(yosai, security_manager)

        self.web_registry = web_registry

    # overridden:
    def resolve_host(self, session=None):
        host = super().resolve_host(session)

        if not host:
            return self.resolve_web_registry().remote_host
        return host

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


class WebDelegatingSubject(DelegatingSubject):
    """
    A ``WebDelegatingSubject`` delegates method calls to an underlying ``WebSecurityManager``
    instance for security checks.  It is essentially a ``WebSecurityManager`` proxy,
    just as ``DelegatingSession`` is to ``NativeSessionManager``.

    This implementation does not maintain security-related state such as roles and
    permissions. Instead, it asks the underlying ``WebSecurityManager`` to check
    authorization. However, Subject-specific state, such as username, and
    the WebRegistry object is saved so to facilitate subject-specific processing
    in the context of a web request.

    Unlike DelegatingSubject, WebDelegatingSubject requires a web_registry attribute
    """
    def __init__(self, identifiers=None, remembered=False, authenticated=False,
                 host=None, session=None, session_creation_enabled=True,
                 security_manager=None, web_registry=None):

        super().__init__(identifiers=identifiers,
                         remembered=False,
                         authenticated=authenticated,
                         host=host,
                         session=session,
                         session_creation_enabled=session_creation_enabled,
                         security_manager=security_manager)

        self.web_registry = web_registry

    def is_session_creation_enabled(self):
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
        wsc = {'web_registry': self.web_registry, 'host': self.host}
        return wsc


class WebYosai(Yosai):
    """
    This is a web-enabled Yosai.  It is initialized using a
    WebSecurityManager.  Unlike ``Yosai``, ``WebYosai`` is
    callable, passing it a ``WebRegistry`` instance that contains web request and
    response objects and functionality to manage cookies.
    """

    def __init__(self, env_var=None, file_path=None, session_attributes=None):
        super().__init__(env_var=env_var,
                         file_path=file_path,
                         session_attributes=session_attributes)

        # web_registry objects are injected with secret as context is set:
        registry_settings = WebRegistrySettings(self.settings)
        self.signed_cookie_secret = registry_settings.signed_cookie_secret

    # overridden:
    def _get_subject(self):
        """
        Returns the currently accessible Subject available to the calling code
        depending on runtime environment.

        :param web_registry:  The WebRegistry instance that knows how to interact
                              with the web application's request and response APIs

        :returns: the Subject currently accessible to the calling code
        """
        web_registry = WebYosai.get_current_webregistry()
        subject_context = WebSubjectContext(yosai=self,
                                            security_manager=self.security_manager,
                                            web_registry=web_registry)
        subject = self.security_manager.create_subject(subject_context=subject_context)

        if not hasattr(subject, 'web_registry'):
            msg = ("Subject implementation returned from the SecurityManager"
                   "was not a WebSubject implementation.  Please ensure a "
                   "Web-enabled SecurityManager has been configured and made"
                   "available to this builder.")
            raise AttributeError(msg)

        return subject

    @staticmethod
    @contextmanager
    def context(yosai, webregistry):
        global_yosai_context.stack.append(yosai)  # how to weakref? TBD
        webregistry.secret = yosai.signed_cookie_secret  # configuration
        global_webregistry_context.stack.append(webregistry)  # how to weakref? TBD
        try:
            yield
        except:
            raise
        finally:
            global_yosai_context.stack = []
            global_webregistry_context.stack = []
            global_subject_context.stack = []

    @staticmethod
    def get_current_webregistry():
        try:
            return global_webregistry_context.stack[-1]
        except IndexError:
            msg = 'A yosai instance does not exist in the global context.'
            raise IndexError(msg)

    @staticmethod
    def get_current_subject():
        try:
            subject = global_subject_context.stack[-1]
            msg = ('A subject instance DOES exist in the global context. '
                   'Touching and then returning it.')
            logger.debug(msg)
            subject.get_session().touch()
            return subject

        except IndexError:
            msg = 'A subject instance _DOES NOT_ exist in the global context.  Creating one.'
            logger.debug(msg)

            subject = Yosai.get_current_yosai()._get_subject()
            global_subject_context.stack.append(subject)
            return subject

        except ExpiredSessionException as exc:
            # absolute timeout of remember_me cookies is TBD (idle expired rolls)
            if WebYosai.get_current_webregistry().remember_me:
                msg = ('A remembered subject from the global context has an '
                       'idle-expired session.  Re-creating a new subject '
                       'instance/session for it.')
                logger.debug(msg)
                global_subject_context.stack.pop()
                subject = Yosai.get_current_yosai()._get_subject()
                global_subject_context.stack.append(subject)
                return subject

            raise WebYosai.get_current_webregistry().raise_unauthorized(exc)

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

                except ValueError:
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

                except ValueError:
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
    def requires_role(role_s, logical_operator=all):
        """
        Requires that the calling Subject be authorized to the extent that is
        required to satisfy the role_s specified and the logical operation
        upon them.

        :param role_s:   a collection of the role(s) required, specified by
                           identifiers (such as a role name)
        :type role_s:  a List of Strings

        :param logical_operator:  indicates whether all or at least one permission
                                  is true (and, any)
        :type: and OR all (from python standard library)

        Elaborate Example:
            requires_role(role_s=['sysadmin', 'developer'], logical_operator=any)

        Basic Example:
            requires_role('physician')
        """
        def outer_wrap(fn):
            @functools.wraps(fn)
            def inner_wrap(*args, **kwargs):

                subject = WebYosai.get_current_subject()

                try:
                    subject.check_role(role_s, logical_operator)

                except ValueError:
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
