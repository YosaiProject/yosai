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
    MisconfiguredException,
    NativeSecurityManager,
    global_subject_context,
)

from yosai.web import (
    DefaultWebSessionContext,
    DefaultWebSessionStorageEvaluator,
    DefaultWebSessionManager,
    DefaultWebSubjectContext,
    WebDelegatingSubject,
    WebSessionKey,
    web_subject_abcs,
)

logger = logging.getLogger(__name__)


class DefaultWebSubjectFactory(DefaultSubjectFactory):
    """
    ``SubjectFactory`` implementation that creates ``WebDelegatingSubject``
    instances.
    """

    def __init__(self):
        super().__init__()

    def create_subject(self, subject_context=None):

        if not isinstance(subject_context, web_subject_abcs.WebSubjectContext):
            return super().create_subject(subject_context=subject_context)

        security_manager = subject_context.resolve_security_manager()
        session = subject_context.resolve_session()
        session_creation_enabled = subject_context.session_creation_enabled

        # passing the session arg is new to yosai, eliminating redunant
        # get_session calls:
        identifiers = subject_context.resolve_identifiers(session)
        authenticated = subject_context.resolve_authenticated(session)
        host = subject_context.resolve_host(session)

        web_registry = subject_context.web_registry

        return WebDelegatingSubject(identifiers=identifiers,
                                    authenticated=authenticated,
                                    host=host,
                                    session=session,
                                    session_creation_enabled=session_creation_enabled,
                                    security_manager=security_manager,
                                    web_registry=web_registry)



class WebSecurityManager(NativeSecurityManager):
    """
    This is the default ``WebSecurityManager`` implementation used in web-based
    applications or any application that requires HTTP connectivity.

    - yosai omits any session_mode logic since no wsgi middleware exists (yet)

    - yosai uses the native web session manager as default, unlike Shiro,
      which uses the middleware version instead

    - the security_utils attribute is set by WebYosai when the
      SecurityManager is passed to the WebYosai

    """

    def __init__(self,
                 settings,
                 default_cipher_key,
                 realms=None,
                 cache_handler=None,
                 session_attributes_schema=None):
        """
        :type realms: tuple
        :type session_attributes_schema: marshmallow.Schema
        """
        super().__init__(settings=settings,
                         realms=realms,
                         cache_handler=cache_handler,
                         session_attributes_schema=session_attributes_schema,
                         session_manager=DefaultWebSessionManager(settings),
                         subject_factory=DefaultWebSubjectFactory(),
                         remember_me_manager=CookieRememberMeManager(default_cipher_key))

        self.subject_store.session_storage_evaluator = DefaultWebSessionStorageEvaluator()

    def create_subject_context(self, subject):
        if not hasattr(self, 'security_utils'):
            msg = "WebSecurityManager has no security_utils attribute set."
            raise MisconfiguredException(msg)

        web_registry = subject.web_registry
        return DefaultWebSubjectContext(self.security_utils, self, web_registry)

    @property
    def session_manager(self):
        return self._session_manager  # inherited

    # extends the property of the parent:
    @session_manager.setter
    def session_manager(self, sessionmanager):

        # this is the syntax used to call the property setter of the parent:
        super_dwsm = super(WebSecurityManager, WebSecurityManager)
        super_dwsm.session_manager.__set__(self, sessionmanager)

        evaluator = self.subject_store.session_storage_evaluator
        evaluator.session_manager = sessionmanager

    # overridden:
    def create_session_context(self, subject_context):
        web_registry = subject_context.resolve_web_registry()
        session_context = DefaultWebSessionContext(web_registry)
        session_context.host = self.host

        return session_context

    # overridden
    def get_session_key(self, subject_context):
        try:
            web_registry = subject_context.resolve_web_registry()
            session_id = subject_context.session_id

            return WebSessionKey(session_id=session_id,
                                 web_registry=web_registry)
        except AttributeError:  # not dealing with a WebSubjectContext
            return super().get_session_key(subject_context)

    # overridden
    def before_logout(self, subject):
        super().before_logout(subject)
        self.remove_identity(subject)

    def remove_identity(self, subject):
        try:
            del subject.web_registry.remember_me  # descriptor sets to None
        except AttributeError:  # then it's not a WebSubject
            pass

    # new to yosai, overriding to support CSRF token synchronization
    def on_successful_login(self, authc_token, account, subject):
        subject.session.new_csrf_token()
        super().remember_me_successful_login(authc_token, account, subject)


class CookieRememberMeManager(AbstractRememberMeManager):
    """
    Remembers a Subject's identity by saving the Subject's identifiers to a Cookie
    for later retrieval.  The Cookie is accessed through the WebRegistry api.
    """

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
        try:
            # base 64 encode it and store as a cookie:
            subject.web_registry.remember_me = base64.b64encode(serialized)
        except AttributeError:
            msg = ("Subject argument is not an HTTP-aware instance.  This "
                   "is required to obtain a web registry in order to"
                   "set the RememberMe cookie. Returning immediately "
                   "and ignoring RememberMe operation.")
            logger.debug(msg)
            return

    def is_identity_removed(self, subject_context):
        try:
            registry = subject_context.resolve_web_registry()
            return registry.remember_me is None
        except AttributeError:
            return False

    def ensure_padding(self, base64):
        """
        Sometimes a user agent will send the rememberMe cookie value without
        padding, most likely because `=` is a separator in the cookie header.

        :param base64: the base64 encoded String that may need to be padded
        :returns: the base64 String, padded if necessary
        """

        pad = b'=' * (((~len(base64)) + 1) & 3)
        base64 = base64 + pad
        return base64

    def get_remembered_serialized_identity(self, subject_context):
        """
        Returns a previously serialized identity byte array or None if the byte
        array could not be acquired.

        This implementation retrieves an HTTP cookie, Base64-decodes the cookie
        value, and returns the resulting byte array.

        The ``subject_context`` instance is expected to be a ``WebSubjectContext``
        instance with a web_registry so that an HTTP cookie may be
        retrieved from an incoming request.  If it is not a ``WebSubjectContext``
        or is one yet does not have a web_registry, this implementation returns
        None.

        :param subject_context: the contextual data, usually provided by a
                                ``SubjectBuilder`` implementation, that is being
                                used to construct a ``Subject`` instance

        :returns: a previously serialized identity bytearray or None if the byte
                  array could not be acquired
        """
        if (self.is_identity_removed(subject_context)):
            if not isinstance(subject_context, web_subject_abcs.WebSubjectContext):
                msg = ("SubjectContext argument is not an HTTP-aware instance. "
                       "This is required to obtain a web registry "
                       "in order to retrieve the RememberMe cookie. Returning "
                       "immediately and ignoring rememberMe operation.")
                logger.debug(msg)

            return None

        base64_rememberme = self.subject_context.web_registry.remember_me

        # TBD:
        # Browsers do not always remove cookies immediately
        # ignore cookies that are scheduled for removal
        # if (web_wsgi_abcs.Cookie.DELETED_COOKIE_VALUE.equals(base64)):
        #     return None

        if base64_rememberme:
            base64 = self.ensure_padding(base64_rememberme)

            logger.debug("Acquired Base64 encoded identity [" + base64 + "]")

            decoded = base64.b64decode(base64)

            logger.debug("Base64 decoded byte array length: {0} bytes".format(
                         len(decoded) if decoded else 0))

            return decoded

        else:
            # no cookie set - new site visitor?
            return None

    #    Currently, both subject and subject_context serving any function
    #    after porting to Python (TBD):
    def forget_identity(self, subject=None, subject_context=None):
        """
        Removes the 'rememberMe' cookie from the WebRegistry.

        :param subject: the subject instance for which identity data should be
                        forgotten from the underlying persistence

        :param subject_context: the contextual data, usually provided by a
                                ``SubjectBuilder`` implementation
        """

        del subject.web_registry.remember_me  # no use of subject data (TBD)
