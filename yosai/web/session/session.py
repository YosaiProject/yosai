import pdb
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
import copy

from yosai.core import (
    CachingSessionStore,
    DefaultNativeSessionHandler,
    DefaultNativeSessionManager,
    DefaultSessionContext,
    DefaultSessionKey,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    ProxiedSession,
    SessionCreationException,
    SessionEventHandler,
    SimpleSession,
    SimpleSessionFactory,
    session_abcs,
)

from yosai.web import (
    CSRFTokenException,
    web_subject_abcs,
)

logger = logging.getLogger(__name__)


class WebProxiedSession(ProxiedSession):
    def __init__(self, target_session):
        super().__init__(target_session)

    def new_csrf_token(self):
        """
        :rtype: str
        :returns: a CSRF token
        """
        return self._delegate.new_csrf_token()

    def get_csrf_token(self):
        return self._delegate.get_csrf_token()

    def flash(self, msg, queue='default', allow_duplicate=False):
        return self._delegate.flash(msg, queue, allow_duplicate)

    # new to yosai
    def peek_flash(self, queue='default'):
        return self._delegate.peek_flash(queue)

    # new to yosai
    def pop_flash(self, queue='default'):
        return self._delegate.pop_flash(queue)

    # new to yosai
    def recreate_session(self):
        return self._delegate.recreate_session()


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
        return self.session_manager.new_csrf_token(self.session_key)  # BUG TBD

    # new to yosai
    def get_csrf_token(self):
        token = self.get_internal_attribute('csrf_token')
        if token is None:
            return self.new_csrf_token()
        return token

    # new to yosai
    # flash_messages is a dict of lists
    def flash(self, msg, queue='default', allow_duplicate=False):
        flash_messages = self.get_internal_attribute('flash_messages')

        if allow_duplicate or (msg not in flash_messages[queue]):
            flash_messages[queue].append(msg)
            self.set_internal_attribute('flash_messages', flash_messages)

    # new to yosai
    def peek_flash(self, queue='default'):
        return self.get_internal_attribute('flash_messages')[queue]

    # new to yosai
    def pop_flash(self, queue='default'):
        """
        :rtype: list
        """
        flash_messages = self.get_internal_attribute('flash_messages')
        message = flash_messages.pop(queue, None)
        self.set_internal_attribute('flash_messages', flash_messages)
        return message

    def recreate_session(self):
        return self.session_manager.recreate_session(self.session_key)


class WebSimpleSession(SimpleSession):

    def __init__(self, csrf_token, absolute_timeout, idle_timeout,
                 attributes_schema, host=None):
        super().__init__(absolute_timeout, idle_timeout, attributes_schema, host=host)
        self.set_internal_attribute('flash_messages',
                                    collections.defaultdict(list))
        self.set_internal_attribute('csrf_token', csrf_token)

    def __getstate__(self):
        return {
            '_session_id': self._session_id,
            '_start_timestamp': self._start_timestamp,
            '_stop_timestamp': self._stop_timestamp,
            '_last_access_time': self._last_access_time,
            '_idle_timeout': self._idle_timeout,
            '_absolute_timeout': self._absolute_timeout,
            '_is_expired': self._is_expired,
            '_host': self._host,
            '_internal_attributes': dict(self._internal_attributes),
            '_attributes': self._attributes
        }

    def __setstate__(self, state):
        self._session_id = state['_session_id']
        self._start_timestamp = state['_start_timestamp']
        self._stop_timestamp = state['_stop_timestamp']
        self._last_access_time = state['_last_access_time']
        self._idle_timeout = state['_idle_timeout']
        self._absolute_timeout = state['_absolute_timeout']
        self._is_expired = state['_is_expired']
        self._host = state['_host']
        self._attributes = state['_attributes']
        self._internal_attributes = state['_internal_attributes']

        flash_messages = collections.defaultdict(list)
        flash_messages.update(state['_internal_attributes']['flash_messages'])
        self._internal_attributes['flash_messages'] = flash_messages


class DefaultWebSessionContext(DefaultSessionContext):

    def __init__(self, web_registry):
        self.web_registry = web_registry


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

    def __init__(self, session_event_handler, delete_invalid_sessions=True):

        super().__init__(session_event_handler=session_event_handler,
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

    # new to yosai:
    def on_recreate_session(self, new_session_id, session_key):
        web_registry = session_key.web_registry

        if self.is_session_id_cookie_enabled:
            web_registry.session_id = new_session_id

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


class WebSessionFactory(SimpleSessionFactory):

    def __init__(self, attributes_schema, settings):
        super().__init__(attributes_schema, settings)

    def create_session(self, csrf_token, session_context):
        return WebSimpleSession(csrf_token,
                                self.absolute_timeout,
                                self.idle_timeout,
                                self.attributes_schema,
                                host=getattr(session_context, 'host', None))


class DefaultWebSessionManager(DefaultNativeSessionManager):
    """
    Web-application capable SessionManager implementation
    """
    def __init__(self, attributes_schema, settings):

        self.session_factory = WebSessionFactory(attributes_schema, settings)
        self._session_event_handler = SessionEventHandler()
        self.session_handler = \
            WebSessionHandler(session_event_handler=self.session_event_handler)
        self._event_bus = None

    # yosai omits get_referenced_session_id method

    # new to yosai (fixation countermeasure)
    def recreate_session(self, session_key):
        old_session = self.session_handler.do_get_session(session_key)
        new_session = copy.copy(old_session)
        self.session_handler.delete(old_session)

        new_session_id = self.session_handler.create_session(new_session)

        if not new_session_id:
            msg = 'Failed to re-create a sessionid for:' + str(session_key)
            raise SessionCreationException(msg)

        self.session_handler.on_recreate_session(new_session_id, session_key)

        logger.debug('Re-created SessionID. [old: {0}, new: {1}]'.
                     format(session_key.session_id, new_session_id))

        new_session_key = WebSessionKey(session_id=new_session_id,
                                        web_registry=session_key.web_registry)
        return self.create_exposed_session(new_session, key=new_session_key)

    # overidden
    def create_exposed_session(self, session, key=None, context=None):
        """
        This was an overloaded method ported from java that should be refactored. (TBD)
        Until it is refactored, it is called in one of two ways:
            1) passing it session and session_context
            2) passing it session and session_key
        """
        if key:
            return WebDelegatingSession(self, key)

        web_registry = context.web_registry
        session_key = WebSessionKey(session_id=session.session_id,
                                    web_registry=web_registry)

        return WebDelegatingSession(self, session_key)

    def new_csrf_token(self, session_key):
        """
        :rtype: str
        :returns: a CSRF token
        """
        try:
            csrf_token = self._generate_csrf_token()

            session = self._lookup_required_session(session_key)
            session.set_internal_attribute('csrf_token', csrf_token)
            self.session_handler.on_change(session)

        except AttributeError:
            raise CSRFTokenException('Could not save CSRF_TOKEN to session.')

        return csrf_token

    def _generate_csrf_token(self):
        return binascii.hexlify(os.urandom(20)).decode('utf-8')

    # overridden to support csrf_token
    def _create_session(self, session_context):
        csrf_token = self._generate_csrf_token()

        session = self.session_factory.create_session(csrf_token, session_context)

        msg = "Creating session. "
        logger.debug(msg)

        msg = ("Creating new EIS record for new session instance [{0}]".
               format(session))
        logger.debug(msg)

        sessionid = self.session_handler.create_session(session)
        if not sessionid:  # new to yosai
            msg = 'Failed to obtain a sessionid while creating session.'
            raise SessionCreationException(msg)

        return session

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

    def __getstate__(self):
        return {'_session_id': self._session_id}

    def __setstate__(self, state):
        self._session_id = state['_session_id']
