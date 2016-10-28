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
    SubjectStore,
    NativeSecurityManager,
)

from yosai.web import (
    WebSessionStorageEvaluator,
    WebSessionManager,
    WebSubjectContext,
    WebDelegatingSubject,
    WebSessionKey,
    web_subject_abcs,
)

logger = logging.getLogger(__name__)


class WebSecurityManager(NativeSecurityManager):
    """
    This is the default ``WebSecurityManager`` implementation used in web-based
    applications or any application that requires HTTP connectivity.

    - yosai omits any session_mode logic since no wsgi middleware exists (yet)

    - yosai uses the native web session manager as default, unlike Shiro,
      which uses the middleware version instead

    - the yosai attribute is set by WebYosai when the
      SecurityManager is passed to the WebYosai

    """

    def __init__(self,
                 yosai,
                 settings,
                 realms=None,
                 cache_handler=None,
                 serialization_manager=None):
        """
        :type realms: tuple
        """

        super().__init__(yosai,
                         settings,
                         realms=realms,
                         cache_handler=cache_handler,
                         serialization_manager=serialization_manager,
                         session_manager=WebSessionManager(settings),
                         subject_store=SubjectStore(WebSessionStorageEvaluator()),
                         remember_me_manager=CookieRememberMeManager(settings))

    def create_subject_context(self, subject):
        web_registry = subject.web_registry
        return WebSubjectContext(self.yosai, self, web_registry)

    # overridden:
    def create_session_context(self, subject_context):
        web_registry = subject_context.resolve_web_registry()
        session_context = {'web_registry': web_registry,
                           'host': getattr(self, 'host', None)}
        return session_context

    # overridden
    def get_session_key(self, subject_context):
        try:
            web_registry = subject_context.resolve_web_registry()
            session_id = subject_context.session_id
            return WebSessionKey(session_id, web_registry=web_registry)
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
    def on_successful_login(self, authc_token, account_id, subject):
        # Generating a new session_id at successful login is a recommended
        # countermeasure to a session fixation
        subject.session = subject.session.recreate_session()
        super().remember_me_successful_login(authc_token, account_id, subject)

    # overridden
    def do_create_subject(self, subject_context):
        """
        By the time this method is invoked, all possible
        ``SubjectContext`` data (session, identifiers, et. al.) has been made
        accessible using all known heuristics.

        :returns: a Subject instance reflecting the data in the specified
                  SubjectContext data map
        """
        if not isinstance(subject_context, web_subject_abcs.WebSubjectContext):
            return super().do_create_subject(subject_context=subject_context)

        security_manager = subject_context.resolve_security_manager()
        session = subject_context.resolve_session()
        session_creation_enabled = subject_context.session_creation_enabled

        # passing the session arg is new to yosai, eliminating redunant
        # get_session calls:
        identifiers = subject_context.resolve_identifiers(session)
        authenticated = subject_context.resolve_authenticated(session)
        host = subject_context.resolve_host(session)

        # must run after resolve_identifiers:
        remembered = getattr(subject_context, 'remembered', None)

        return WebDelegatingSubject(identifiers=identifiers,
                                    remembered=remembered,
                                    authenticated=authenticated,
                                    host=host,
                                    session=session,
                                    session_creation_enabled=session_creation_enabled,
                                    security_manager=security_manager,
                                    web_registry=subject_context.web_registry)


class CookieRememberMeManager(AbstractRememberMeManager):
    """
    Remembers a Subject's identity by saving the Subject's identifiers to a Cookie
    for later retrieval.  The Cookie is accessed through the WebRegistry api.
    """
    def __init__(self, settings):
        super().__init__(settings)

    def remember_encrypted_identity(self, subject, encrypted):
        """
        Base64-encodes the specified serialized byte array and sets that
        base64-encoded String as the cookie value.

        The ``subject`` instance is expected to be a ``WebSubject`` instance
        with a web_registry handle so that an HTTP cookie may be set on an
        outgoing response.  If it is not a ``WebSubject`` or that ``WebSubject``
        does not have a web_registry handle, this implementation does
        nothing.

        :param subject: the Subject for which the identity is being serialized

        :param serialized: the serialized bytes to persist
        :type serialized: bytearray
        """
        try:
            # base 64 encode it and store as a cookie:
            encoded = base64.b64encode(encrypted).decode('utf-8')
            subject.web_registry.remember_me = encoded
        except AttributeError:
            msg = ("Subject argument is not an HTTP-aware instance.  This "
                   "is required to obtain a web registry in order to"
                   "set the RememberMe cookie. Returning immediately "
                   "and ignoring RememberMe operation.")
            logger.debug(msg)

    def is_identity_removed(self, subject_context):
        try:
            registry = subject_context.resolve_web_registry()
            return not registry.remember_me
        except AttributeError:
            return False

    def get_remembered_encrypted_identity(self, subject_context):
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

        :param subject_context: the contextual data used to construct a ``Subject`` instance

        :returns: an encrypted, serialized identifier collection
        """
        if (self.is_identity_removed(subject_context)):
            if not isinstance(subject_context, web_subject_abcs.WebSubjectContext):
                msg = ("SubjectContext argument is not an HTTP-aware instance. "
                       "This is required to obtain a web registry "
                       "in order to retrieve the RememberMe cookie. Returning "
                       "immediately and ignoring rememberMe operation.")
                logger.debug(msg)

            return None

        remember_me = subject_context.web_registry.remember_me

        # TBD:
        # Browsers do not always remove cookies immediately
        # ignore cookies that are scheduled for removal
        # if (web_wsgi_abcs.Cookie.DELETED_COOKIE_VALUE.equals(base64)):
        #     return None

        if remember_me:

            logger.debug("Acquired encoded identity [" + str(remember_me) + "]")

            encrypted = base64.b64decode(remember_me)

            return encrypted
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

        :param subject_context: the contextual data
        """
        del subject.web_registry.remember_me  # no use of subject data (TBD)
