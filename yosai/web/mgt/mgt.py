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
import base64
import logging

from yosai.core import (
    AbstractRememberMeManager,
    DefaultSubjectFactory,
    DefaultSubjectStore,
    NativeSecurityManager,
)

from yosai.web import (
    CookieRememberMeManager,
    DefaultWebSessionContext,
    DefaultWebSessionStorageEvaluator,
    DefaultWebSessionManager,
    DefaultWebSubjectContext,
    SimpleCookie,
    WebDelegatingSubject,
    WebSessionKey,
    WebSubject,
    WebUtils,
    WSGIContainerSessionManager,
    YosaiHttpWSGIRequest,
    web_mgt_abcs,
    web_session_abcs,
    web_subject_abcs,
    web_wsgi_abcs,
)

logger = logging.getLogger(__name__)


class DefaultWebSubjectFactory(DefaultSubjectFactory):
    """
    ``SubjectFactory`` implementation that creates ``WebDelegatingSubject``
    instances.
    """

    def __init__(self):
        super().__init__()

    def create_subject(self, subject_context):
        """
        :type subject_context:  subject_abcs.SubjectContext
        """

        if not isinstance(subject_context, web_mgt_abcs.WebSubjectContext):
            return super().create_subject(subject_context)

        security_manager = subject_context.resolve_security_manager()
        session = subject_context.resolve_session()
        session_enabled = subject_context.session_creation_enabled
        identifiers = subject_context.resolve_identifiers()
        authenticated = subject_context.resolve_authenticated()
        host = subject_context.resolve_host()

        web_registry = subject_context.web_registry

        return WebDelegatingSubject(identifiers=identifiers,
                                    authenticated=authenticated,
                                    host=host,
                                    session=session,
                                    session_enabled=session_enabled,
                                    web_registry=web_registry,
                                    security_manager=security_manager)


class DefaultWebSecurityManager(NativeSecurityManager,
                                web_mgt_abcs.WebSecurityManager):
    """
    This is the default ``WebSecurityManager`` implementation used in web-based
    applications or any application that requires HTTP connectivity.
    """

    def __init__(self, realms=None, session_attributes_schema=None):
        """
        :type realms: tuple
        :type session_attributes_schema: marshmallow.Schema
        """
        super().__init__(realms=realms,
                         session_attributes_schema=session_attributes_schema)

        self.subject_store.session_storage_evaluator = DefaultWebSessionStorageEvaluator()
        self.session_mode = 'http'
        self.subject_factory = DefaultWebSubjectFactory()
        self.remember_me_manager = CookieRememberMeManager()

        # yosai uses the native web session manager as default, unlike Shiro,
        # which uses the middleware version instead
        self.session_manager = DefaultWebSessionManager()

    # override base method
    def create_subject_context(self):
        return DefaultWebSubjectContext()

    @property
    def subject_store(self):
        return self._subject_store

    @subject_store.setter
    def subject_store(self, subject_store):
        self._subject_store = subject_store
        self.apply_session_manager_to_sse_if_possible()

    @property
    def session_manager(self):
        return self.session_manager  # inherited

    # extends the property of the parent:
    @session_manager.setter
    def session_manager(self, sessionmanager):

        if (sessionmanager is not None and
            not isinstance(sessionmanager, web_session_abcs.WebSessionManager)):

            if logger.getEffectiveLevel() <= logging.WARNING:
                msg = ("The {0} implementation expects SessionManager instances "
                       "to implement the WebSessionManager interface.  The " +
                       "configured instance of the sessionmanager argument is of"
                       "type [{1}] which does not implement this interface.."
                       "This may cause unexpected behavior.".format(
                       self.__class__.__name__, sessionmanager.__class__.__name__))
                logger.warning(msg)

        # this is the syntax used to call the property setter of the parent:
        super_dwsm = super(DefaultWebSecurityManager, DefaultWebSecurityManager)
        super_dwsm.session_manager.__set__(self, sessionmanager)

        self.apply_session_manager_to_sse_if_possible()

    def apply_session_manager_to_sse_if_possible(self):
        if isinstance(self.subject_store, DefaultSubjectStore):
            evaluator = self.subject_store.session_storage_evaluator
            if isinstance(evaluator, DefaultWebSessionStorageEvaluator):
                evaluator.session_manager = self.session_manager

    # overidden parent method
    def copy(self, subject_context):
        if isinstance(subject_context, web_subject_abcs.WebSubjectContext):
            return DefaultWebSubjectContext(subject_context)

        return super().copy(subject_context)

    @property
    def is_http_session_mode(self):
        sm = self.session_manager
        return (isinstance(sm, web_session_abcs.WebSessionManager) and
                sm.is_wsgi_container_sessions)

    def create_session_manager(self, session_mode):
        if (session_mode is None) or (not session_mode.lower() == 'native'):
            msg = "http mode - enabling WSGIContainerSessionManager (HTTP-only Sessions)"
            logger.info(msg)
            return WSGIContainerSessionManager()
        else:
            msg = "native mode - enabling DefaultWebSessionManager (non-HTTP and HTTP Sessions)"
            logger.info(msg)
            return DefaultWebSessionManager()

    # overridden:
    def create_session_context(self, subject_context):
        session_context = super().create_session_context(subject_context)
        try:  # will only succeed with WebSubjectContext instances
            web_session_context = DefaultWebSessionContext(session_context)

            web_registry = subject_context.resolve_web_registry()
            web_session_context.web_registry = web_registry

            session_context = web_session_context
        except AttributeError:
            pass

        return session_context

    # overridden
    def get_session_key(self, subject_context):
        try:
            session_id = subject_context.session_id
            web_registry = subject_context.resolve_web_registry()
            return WebSessionKey(session_id, web_registry)
        except AttributeError:  # not dealing with a WebSubjectContext
            return super().get_session_key(subject_context)

    # overridden
    def before_logout(self, subject):
        super().before_logout(subject)
        self.remove_identity(subject)

    def remove_identity(self, subject):
        try:
            subject.web_registry.remove_identity()
        except AttributeError:  # then it's not a WebSubject
            pass


class CookieRememberMeManager(AbstractRememberMeManager):
    """
    Remembers a Subject's identity by saving the Subject's identifiers to a Cookie
    for later retrieval.  The Cookie is accessed through the WebRegistry api.

    Note that since this class subclasses the AbstractRememberMeManager, which
    already provides serialization and encryption logic, this class utilizes
    both features for added security before setting the cookie value.
    """

    def __init__(self, web_registry):
        self._web_registry = web_registry

    @property
    def web_registry(self):
        return self._web_registry

    @web_registry.setter
    def web_registry(self, web_registry):
        self._web_registry = web_registry

    def remember_serialized_identity(self, subject, serialized):
        """
        Base64-encodes the specified serialized byte array and sets that
        base64-encoded String as the cookie value.

        The ``subject`` instance is expected to be a ``WebSubject`` instance
        with a web_registry handle so that an HTTP cookie may be set on an
        outgoing response.  If it is not a ``WebSubject`` or that ``WebSubject``
        does not have a web_registry handle, this implementation does
        nothing.

        :param subject: the Subject for which the identity is being serialized

        :param serialized: the serialized bytes to be persisted
        :type serialized: bytearray
        """
        if not WebUtils.is_http(subject):
            if logger.getEffectiveLevel() <= logging.DEBUG:
                msg = ("Subject argument is not an HTTP-aware instance.  This "
                       "is required to obtain a wsgi request and response in "
                       "order to set the rememberMe cookie. Returning immediately "
                       "and ignoring rememberMe operation.")
                log.debug(msg)
            return

        # base 64 encode it and store as a cookie:
        self.web_registry.remember_me = base64.b64encode(serialized)

    def is_identity_removed(self, subject_context):
        request = subject_context.resolve_wsgi_request()
        if request:
            removed = request.get_attribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY)
            return removed is not None and bool(removed)

        return False

    def get_remembered_serialized_identity(self, subject_context):
        """
        Returns a previously serialized identity byte array or None if the byte
        array could not be acquired.

        This implementation retrieves an HTTP cookie, Base64-decodes the cookie
        value, and returns the resulting byte array.

        The ``subject_context`` instance is expected to be a ``WebSubjectContext``
        instance with an HTTP Request/Response pair so that an HTTP cookie may be
        retrieved from an incoming request.  If it is not a ``WebSubjectContext``
        or is one yet does not have an HTTP Request/Response pair, this
        implementation returns None.

        :param subject_context: the contextual data, usually provided by a
                                ``SubjectBuilder`` implementation, that is being
                                used to construct a ``Subject`` instance

        :returns: a previously serialized identity bytearray or None if the byte
                  array could not be acquired
        """

        if not WebUtils.is_http(subject_context):
            if logger.getEffectiveLevel() <= logging.DEBUG:
                msg = ("SubjectContext argument is not an HTTP-aware instance. "
                       "This is required to obtain a wsgi request and response "
                       "in order to retrieve the rememberMe cookie. Returning "
                       "immediately and ignoring rememberMe operation.")
                logger.debug(msg)

            return None

        wsc = subject_context
        if (self.is_identity_removed(wsc)):
            return None

        request = WebUtils.get_http_request(wsc)
        response = WebUtils.get_http_response(wsc)

        base64 = self.cookie.read_value(request, response)

        # Browsers do not always remove cookies immediately
        # ignore cookies that are scheduled for removal
        if (web_wsgi_abcs.Cookie.DELETED_COOKIE_VALUE.equals(base64)):
            return None

        if base64:
            base64 = self.ensure_padding(base64)

            if logger.getEffectiveLevel() <= logging.DEBUG:
                logger.debug("Acquired Base64 encoded identity [" + base64 + "]")

            decoded = base64.b64decode(base64)

            if logger.getEffectiveLevel() <= logging.DEBUG:
                logger.debug("Base64 decoded byte array length: {0} bytes".format(
                             len(decoded) if decoded else 0))

            return decoded

        else:
            # no cookie set - new site visitor?
            return None

    # DG:  this should be refactored (TBD):
    def forget_identity(self, subject=None, subject_context=None,
                        request=None, response=None):
        """
        Removes the 'rememberMe' cookie from the associated ``WebSubject``'s,
        ``WebSubjectContext``'s request/response pair, or from the actual pair.

        The ``subject`` instance is expected to be a ``WebSubject`` instance with
        an HTTP Request/Response pair. If it is not a ``WebSubject`` or that
        ``WebSubject`` does not have an HTTP Request/Response pair, this
        implementation does nothing.

        The ``subject_context`` instance is expected to be a ``WebSubjectContext``
        instance with an HTTP Request/Response pair.  If it is not a ``WebSubjectContext``
        or that ``WebSubjectContext`` does not have an HTTP Request/Response pair,
        this implementation does nothing.

        :param subject: the subject instance for which identity data should be
                        forgotten from the underlying persistence

        :param subject_context: the contextual data, usually provided by a
                                ``SubjectBuilder`` implementation

        :param request:  the incoming HTTP wsgi request
        :param response: the outgoing HTTP wsgi response
        """
        if subject:
            if WebUtils.is_http(subject):
                request = WebUtils.get_http_request(subject)
                response = WebUtils.get_http_response(subject)
                self.forget_identity(request, response)
            return

        if subject_context:
            if WebUtils.is_http(subject_context):
                request = WebUtils.get_http_request(subject_context)
                response = WebUtils.get_http_response(subject_context)
                self.forget_identity(request, response)
            return

        # otherwise, assume the args are request/response:
        self.cookie.remove_from(request, response)
