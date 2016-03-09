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
    DefaultNativeSessionManager,
    DefaultSessionContext,
    DefaultSessionKey,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    IllegalArgumentException,
    InvalidSessionException,
    session_abcs,
)

from yosai.web import (
    web_session_abcs,
)

logger = logging.getLogger(__name__)


class DefaultWebSessionContext(DefaultSessionContext,
                               web_session_abcs.WebSessionContext):

    WEB_REGISTRY = "DefaultWebSessionContext.WEB_REGISTRY"

    def __init__(self, web_registry, context_map=None):
        super().__init__(context_map=context_map)
        self.web_registry = web_registry

    @property
    def web_registry(self):
        return self.get(self.__class__.WEB_REGISTRY)

    @web_registry.setter
    def web_registry(self, webregistry):
        self.put(self.__class__.WEB_REGISTRY, webregistry)


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
        if (not isinstance(subject, WebSubject) and self.session_manager and
                not isinstance(self.session_manager, session_abcs.NativeSessionManager)):
            return False

        web_registry = subject.web_registry

        return web_registry.session_creation_enabled


class DefaultWebSessionManager(DefaultNativeSessionManager):
    """
    Web-application capable SessionManager implementation.  Initialize it
    with a ``WebRegistry`` so that it may create/remove/update/read a session_id
    cookie.
    """

    def __init__(self):
        super().__init__()
        self._web_registry = None

    @property
    def session_id(self):
        if not self.is_session_id_cookie_enabled:
            msg = ("Session ID cookie is disabled - session id will not be "
                   "acquired from a request cookie.")
            logger.debug(msg)
            return None

        return self.web_registry.session_id

    @property
    def web_registry(self):
        return self._web_registry

    @web_registry.setter
    def web_registry(self, webregistry):
        self._web_registry = webregistry

    # yosai omits get_referenced_session_id method

    def create_exposed_session(self, session, session_context=None, session_key=None):

        if not self.web_registry:  # presumably not dealing with a web request
            return super().create_exposed_session(session=session,
                                                  session_key=session_key)

        if session_context:
            try:
                return super().create_exposed_session(session=session,
                                                      session_context=session_context)
            except AttributeError:
                pass

        # otherwise, assume we are dealing with a Web-enabled request
        session_key = WebSessionKey(self.web_registry, session.session_id)
        return DelegatingSession(self, session_key)

    # overridden
    def on_start(self, session, session_context):
        """
        Stores the Session's ID, usually as a Cookie, to associate with future
        requests.

        :param session: the session that was just ``createSession`` created
        """
        super().on_start(session, session_context)
        session_id = session.session_id

        if self.is_session_id_cookie_enabled:
            self.web_registry.session_id = session_id
            logger.debug("Set SessionID cookie using id: " + str(session_id))

        else:
            msg = ("Session ID cookie is disabled.  No cookie has been set for "
                   "new session with id: " + str(session_id))
            logger.debug(msg)

    # overridden
    def get_session_id(self, session_key=None):
        session_id = None
        if session_key:
            session_id = super().get_session_id(session_key)
        if not session_id:
            try:
                session_id = self.web_registry.session_id
            except AttributeError:
                pass
        return session_id

    # overridden
    def on_expiration(self, session, ese, session_key):
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

        del self.web_registry.session_id

    # overridden
    def on_stop(self, session, session_key):
        super().on_stop(session, session_key)
        msg = ("Session has been stopped (subject logout or explicit stop)."
               "  Removing session ID cookie.")
        logger.debug(msg)

        del self.web_registry.session_id


class WebSessionKey(DefaultSessionKey):
    """
    A ``SessionKey`` implementation that also retains the ``WebRegistry``
    associated with the web request that is performing the session lookup
    """
    def __init__(self, web_registry, session_id=None):
        self.web_registry = web_registry
        self.session_id = session_id
