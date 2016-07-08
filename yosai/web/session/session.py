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
import binascii
import os
import collections

from marshmallow import Schema, fields, post_load

from yosai.core import (
    CachingSessionStore,
    DefaultNativeSessionHandler,
    DefaultNativeSessionManager,
    DefaultSessionContext,
    DefaultSessionKey,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    SimpleIdentifierCollection,
    SimpleSession,
    session_abcs,
)

from yosai.web import (
    CSRFTokenException,
    web_session_abcs,
    web_subject_abcs,
)

logger = logging.getLogger(__name__)


# new to yosai:
class WebDelegatingSession(DelegatingSession):

    def __init__(self, session_manager, session_key):
        super().__init__(session_manager, session_key)

    # new to yosai
    def new_csrf_token(self):
        """
        :rtype: str
        :returns: a CSRF token
        """

        try:
            csrf_token = binascii.hexlify(os.urandom(20)).decode('utf-8')
            self.set_internal_attribute('csrf_token', csrf_token)
        except AttributeError:
            raise CSRFTokenException('Could not save CSRF_TOKEN to session.')

        return csrf_token

    # new to yosai
    def get_csrf_token(self):
        token = self.get_internal_attribute('csrf_token')
        if token is None:
            return self.new_csrf_token()


class WebSimpleSession(SimpleSession):

    @classmethod
    def serialization_schema(cls):

        class InternalSessionAttributesSchema(Schema):
            identifiers_session_key = fields.Nested(
                SimpleIdentifierCollection.serialization_schema(),
                attribute='identifiers_session_key',
                allow_none=False)

            authenticated_session_key = fields.Boolean(
                attribute='authenticated_session_key',
                allow_none=False)

            run_as_identifiers_session_key = fields.Nested(
                SimpleIdentifierCollection.serialization_schema(),
                attribute='run_as_identifiers_session_key',
                many=True,
                allow_none=False)

            csrf_token = fields.Str(attribute='csrf_token', allow_none=False)

            @post_load
            def make_internal_attributes(self, data):
                try:
                    raisk = 'run_as_identifiers_session_key'
                    runas = data.get(raisk)
                    if runas:
                        que = collections.deque(runas)
                        data[raisk] = que
                except TypeError:
                    msg = ("Session de-serialization note: "
                           "run_as_identifiers_session_key attribute N/A.")
                    logger.warning(msg)

                return data

class DefaultWebSessionContext(DefaultSessionContext,
                               web_session_abcs.WebSessionContext):

    WEB_REGISTRY = "DefaultWebSessionContext.WEB_REGISTRY"

    def __init__(self, web_registry, context_map={}):
        super().__init__(context_map=context_map)
        self.web_registry = web_registry

    @property
    def web_registry(self):
        return self.get(self.__class__.WEB_REGISTRY)

    @web_registry.setter
    def web_registry(self, webregistry):
        self.put(self.__class__.WEB_REGISTRY, webregistry)


class WebCachingSessionStore(CachingSessionStore):

    def __init__(self):
        super().__init__()

    def _cache_identifiers_to_key_map(self, session, session_id):
        """
        creates a cache entry within a user's cache space that is used to
        identify the active session associated with the user

        when a session is associated with a user, it will have an identifiers
        attribute

        including a primary identifier is new to yosai
        """
        isk = 'identifiers_session_key'
        identifiers = session.get_internal_attribute(isk)

        try:
            self.cache_handler.set(domain='session',
                                   identifier=identifiers.primary_identifier,
                                   value=WebSessionKey(session_id=session_id))
        except AttributeError:
            msg = "Could not cache identifiers_session_key."
            if not identifiers:
                msg += '  \'identifiers\' internal attribute not set.'
            logger.debug(msg)


class DefaultWebSessionStorageEvaluator(DefaultSessionStorageEvaluator):
    """
    A web-specific ``SessionStorageEvaluator`` that performs the same logic as
    the parent class ``DefaultSessionStorageEvaluator`` but additionally checks
    for a request-specific flag that may enable or disable session access.

    This implementation usually works in conjunction with the
    ``NoSessionCreationFilter``:  If the ``NoSessionCreationFilter``
    is configured in a filter chain, that filter will set a specific
    ``WSGIRequest`` attribute indicating that session creation should be
    disabled.

    This ``DefaultWebSessionStorageEvaluator`` will then inspect this attribute,
    and if it has been set, will return ``False`` from the
    ``is_session_storage_enabled(subject)`` method, thereby preventing
    Yosai from creating a session for the purpose of storing subject state.

    If the request attribute has not been set (i.e. the ``NoSessionCreationFilter``
    is not configured or has been disabled), this class does nothing and
    delegates to the parent class for existing behavior.
    """

    def __init__(self):
        super().__init__()  # new to yosai
        self.session_manager = None

    # overridden:
    def is_session_storage_enabled(self, subject=None):
        """
        Returns ``True`` if session storage is generally available (as determined
        by the super class's global configuration property is_session_storage_enabled
        and no request-specific override has turned off session storage, False
        otherwise.

        This means session storage is disabled if the is_session_storage_enabled
        property is False or if a request attribute is discovered that turns off
        session storage for the current request.

        :param subject: the ``Subject`` for which session state persistence may
                        be enabled

        :returns: ``True`` if session storage is generally available (as
                  determined by the super class's global configuration property
                  is_session_storage_enabled and no request-specific override has
                  turned off session storage, False otherwise.
        """
        if subject.get_session(False):
            # then use what already exists
            return True

        if not self.session_storage_enabled:
            # honor global setting:
            return False

        # non-web subject instances can't be saved to web-only session managers:
        if (not isinstance(subject, web_subject_abcs.WebSubject) and
            self.session_manager and
                not isinstance(self.session_manager, session_abcs.NativeSessionManager)):
            return False

        web_registry = subject.web_registry

        return web_registry.session_creation_enabled


class WebSessionHandler(DefaultNativeSessionHandler):

    def __init__(self, session_event_handler, auto_touch=False,
                 delete_invalid_sessions=True):

        super().__init__(session_event_handler=session_event_handler,
                         auto_touch=auto_touch,
                         session_store=WebCachingSessionStore(),
                         delete_invalid_sessions=delete_invalid_sessions)

        self.is_session_id_cookie_enabled = True

    # overridden
    def on_start(self, session, session_context):
        """
        Stores the Session's ID, usually as a Cookie, to associate with future
        requests.

        :param session: the session that was just ``createSession`` created
        """
        session_id = session.session_id
        web_registry = session_context.web_registry

        if self.is_session_id_cookie_enabled:
            web_registry.session_id = session_id
            logger.debug("Set SessionID cookie using id: " + str(session_id))

        else:
            msg = ("Session ID cookie is disabled.  No cookie has been set for "
                   "new session with id: " + str(session_id))
            logger.debug(msg)

    # overridden
    def on_stop(self, session, session_key):
        super().on_stop(session, session_key)
        msg = ("Session has been stopped (subject logout or explicit stop)."
               "  Removing session ID cookie.")
        logger.debug(msg)

        web_registry = session_key.web_registry

        del web_registry.session_id

    # overridden
    def on_expiration(self, session, ese=None, session_key=None):
        """
        :type session: session_abcs.Session
        :type ese: ExpiredSessionException
        :type session_key:  session_abcs.SessionKey
        """
        super().on_expiration(session, ese, session_key)
        self.on_invalidation(session_key)

    # overridden
    def on_invalidation(self, session_key, session=None, ise=None):
        """
        :type session_key:  session_abcs.SessionKey
        :type session: session_abcs.Session
        :type ese: InvalidSessionException
        """
        if session:
            super().on_invalidation(session, ise, session_key)

        web_registry = session_key.web_registry

        del web_registry.session_id


class WebSessionFactory(session_abcs.SessionFactory):

    @staticmethod
    def create_session(session_context=None):
        return WebSimpleSession(host=getattr(session_context, 'host', None))


class DefaultWebSessionManager(DefaultNativeSessionManager):
    """
    Web-application capable SessionManager implementation
    """
    def __init__(self):
        super().__init__(session_factory=WebSessionFactory())
        self.session_handler = \
            WebSessionHandler(session_event_handler=self.session_event_handler,
                              auto_touch=False)

    # yosai omits get_referenced_session_id method

    # overidden
    def create_exposed_session(self, session, key=None, context=None):
        """
        This was an overloaded method ported from java that should be refactored. (TBD)
        Until it is refactored, it is called in one of two ways:
            1) passing it session and session_context
            2) passing it session and session_key
        """
        try:
            web_registry = context.web_registry
        except AttributeError:
            return super().create_exposed_session(session, context=context)
        except SyntaxError:  # implies session_context is None
            try:
                web_registry = key.web_registry
            except AttributeError:
                return super().create_exposed_session(session, key=key)

        # otherwise, assume we are dealing with a Web-enabled request
        session_key = WebSessionKey(session_id=session.session_id,
                                    web_registry=web_registry)
        return WebDelegatingSession(self, session_key)


class WebSessionKey(DefaultSessionKey):
    """
    A ``SessionKey`` implementation that also retains the ``WebRegistry``
    associated with the web request that is performing the session lookup
    """
    def __init__(self, session_id=None, web_registry=None):
        super().__init__(session_id)
        self.web_registry = web_registry
        self.resolve_session_id()

    @property
    def session_id(self):
        if not self._session_id:
            self.resolve_session_id()
            return self._session_id
        return self._session_id

    def resolve_session_id(self):
        session_id = self._session_id

        if not session_id:
            session_id = self.web_registry.session_id

        self._session_id = session_id

    def __repr__(self):
        return "WebSessionKey(session_id={0}, web_registry={1})".\
            format(self._session_id, self.web_registry)

    @classmethod
    def serialization_schema(cls):
        class SerializationSchema(Schema):
            _session_id = fields.Str(allow_none=True)

            @post_load
            def make_default_session_key(self, data):
                mycls = WebSessionKey
                instance = mycls.__new__(mycls)
                instance.__dict__.update(data)
                return instance

        return SerializationSchema
