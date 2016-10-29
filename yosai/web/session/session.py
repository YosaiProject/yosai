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
    NativeSessionHandler,
    NativeSessionManager,
    SessionStorageEvaluator,
    DelegatingSession,
    SimpleSession,
    session_abcs,
)

from yosai.web import (
    CSRFTokenException,
)

logger = logging.getLogger(__name__)


class WebSessionKey(collections.namedtuple('WebSessionKey', 'session_id, web_registry')):
    __slots__ = ()

    def __new__(cls, session_id, web_registry=None):
        return super(WebSessionKey, cls).__new__(cls, session_id, web_registry)


class WebSimpleSession(SimpleSession):

    def __init__(self, csrf_token, absolute_timeout, idle_timeout, host=None):
        super().__init__(absolute_timeout, idle_timeout, host=host)
        self.set_internal_attribute('flash_messages',
                                    collections.defaultdict(list))
        self.set_internal_attribute('csrf_token', csrf_token)

    def __getstate__(self):
        return {
            'session_id': self.session_id,
            'start_timestamp': self.start_timestamp,
            'stop_timestamp': self.stop_timestamp,
            'last_access_time': self.last_access_time,
            'idle_timeout': self.idle_timeout,
            'absolute_timeout': self.absolute_timeout,
            'is_expired': self.is_expired,
            'host': self.host,
            'internal_attributes': dict(self.internal_attributes),
            'attributes': self.attributes
        }

    def __setstate__(self, state):
        self.session_id = state['session_id']
        self.start_timestamp = state['start_timestamp']
        self.stop_timestamp = state['stop_timestamp']
        self.last_access_time = state['last_access_time']
        self.idle_timeout = state['idle_timeout']
        self.absolute_timeout = state['absolute_timeout']
        self.is_expired = state['is_expired']
        self.host = state['host']
        self.attributes = state['attributes']
        self.internal_attributes = state['internal_attributes']

        flash_messages = collections.defaultdict(list)
        flash_messages.update(state['internal_attributes']['flash_messages'])
        self.internal_attributes['flash_messages'] = flash_messages


class WebSessionHandler(NativeSessionHandler):

    def __init__(self, delete_invalid_sessions=True):
        super().__init__(delete_invalid_sessions=delete_invalid_sessions)

        self.is_session_id_cookie_enabled = True

    # overridden
    def on_start(self, session, session_context):
        """
        Stores the Session's ID, usually as a Cookie, to associate with future
        requests.

        :param session: the session that was just ``createSession`` created
        """
        session_id = session.session_id
        web_registry = session_context['web_registry']

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


class WebSessionManager(NativeSessionManager):
    """
    Web-application capable SessionManager implementation
    """
    def __init__(self, settings):
        super().__init__(settings,
                         session_handler=WebSessionHandler())

    # new to yosai (fixation countermeasure)
    def recreate_session(self, session_key):
        old_session = self.session_handler.do_get_session(session_key)
        new_session = copy.copy(old_session)
        self.session_handler.delete(old_session)

        new_session_id = self.session_handler.create_session(new_session)

        if not new_session_id:
            msg = 'Failed to re-create a sessionid for:' + str(session_key)
            raise ValueError(msg)

        self.session_handler.on_recreate_session(new_session_id, session_key)

        logger.debug('Re-created SessionID. [old: {0}, new: {1}]'.
                     format(session_key.session_id, new_session_id))

        new_session_key = WebSessionKey(new_session_id,
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

        web_registry = context['web_registry']
        session_key = WebSessionKey(session.session_id,
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

        session = WebSimpleSession(csrf_token,
                                   self.absolute_timeout,
                                   self.idle_timeout,
                                   host=session_context.get('host'))

        msg = "Creating session. "
        logger.debug(msg)

        msg = ("Creating new EIS record for new session instance [{0}]".
               format(session))
        logger.debug(msg)

        sessionid = self.session_handler.create_session(session)
        if not sessionid:  # new to yosai
            msg = 'Failed to obtain a sessionid while creating session.'
            raise ValueError(msg)

        return session


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
        messages = flash_messages.pop(queue, None)
        self.set_internal_attribute('flash_messages', flash_messages)
        return messages

    def recreate_session(self):
        return self.session_manager.recreate_session(self.session_key)


class WebSessionStorageEvaluator(SessionStorageEvaluator):
    """
    A web-specific ``SessionStorageEvaluator`` that performs the same logic as
    the parent class ``SessionStorageEvaluator`` but additionally checks
    for a request-specific flag that may enable or disable session access.

    This ``WebSessionStorageEvaluator`` will then inspect this attribute,
    and if it has been set, will return ``False`` from the
    ``is_session_storage_enabled(subject)`` method, thereby preventing
    Yosai from creating a session for the purpose of storing subject state.
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
        if (not hasattr(subject, 'web_registry') and self.session_manager and
                not isinstance(self.session_manager, session_abcs.NativeSessionManager)):
            return False

        return subject.web_registry.session_creation_enabled
