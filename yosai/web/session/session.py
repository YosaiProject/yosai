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
    IllegalArgumentException,
    InvalidSessionException,
    session_abcs,
)

from yosai.web import (
    WebUtils,
    web_utils_abcs,
)

logger = logging.getLogger(__name__)


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

        return WebUtils._is_session_creation_enabled(subject)  # DG:  TBD, refactor?


class HttpWSGISession(session_abcs.Session):
    """
    ``Session`` implementation that is backed entirely by a standard wsgi container
    ``HttpSession`` instance.  It does not interact with any of Yosai's
    session-related components: ``SessionManager``, ``SecurityManager``, etc,
    and instead satisfies all method implementations by interacting
    with a wsgi container provided ``HttpSession`` instance.
    """

    HOST_SESSION_KEY = "HttpWSGISession.HOST_SESSION_KEY"
    TOUCH_OBJECT_SESSION_KEY = "HttpWSGISession.TOUCH_OBJECT_SESSION_KEY"

    def __init__(self, http_session, host=None):

        # if not http_session:
        #     msg = "HttpSession constructor argument cannot be None."
        #     raise IllegalArgumentException(msg)

        # if isinstance(httpSession, YosaiHttpSession):
        #    msg = ("HttpSession constructor argument cannot be an instance of "
        #           "YosaiHttpSession.  This is enforced to prevent circular "
        #           "dependencies and infinite loops.")
        #    raise IllegalArgumentException(msg)

        self.http_session = http_session

        if host:
            self.host = host

    @property
    def session_id(self):
        return self.http_session.session_id

    @property
    def start_timestamp(self):
        # shiro uses getCreationTime():
        return self.http_session.start_timestamp

    @property
    def last_access_time(self):
        return self.http_session.last_access_time

    @property
    def absolute_timeout(self):
        return self.http_session.absolute_timeout

    @absolute_timeout.setter
    def absolute_timeout(self, timeout):
        self.http_session.absolute_timeout = timeout

    @property
    def idle_timeout(self):
        # note:  shiro uses millisecond conversion (TBD):
        return self.http_session.idle_timeout

    @idle_timeout.setter
    def idle_timeout(self, timeout):
        self.http_session.idle_timeout = timeout

    @property
    def host(self):
        return self.get_internal_attribute(self.__class__.HOST_SESSION_KEY)

    @host.setter
    def host(self, host):
        # unlike shiro, yosai uses internal_attributes:
        self.set_internal_attribute(self.__class__.HOST_SESSION_KEY, host)

    def touch(self):
        # just manipulate the session to update the access time:
        try:
            self.http_session.set_internal_attribute(self.__class__.TOUCH_OBJECT_SESSION_KEY,
                                                     self.__class__.TOUCH_OBJECT_SESSION_KEY)
            self.http_session.remove_internal_attribute(self.__class__.TOUCH_OBJECT_SESSION_KEY)

        except Exception as exc:
            raise InvalidSessionException(exc)

    def stop(self):
        try:
            self.http_session.invalidate()
        except Exception as exc:
            raise InvalidSessionException(exc)

    @property
    def internal_attribute_keys(self):
        try:
            return self.http_session.internal_attribute_keys
        except Exception as exc:
            raise InvalidSessionException(exc)

    def get_internal_attribute(self, key):
        """
        :type key: String
        """
        try:
            return self.http_session.get_internal_attribute(key)
        except Exception as exc:
            raise InvalidSessionException(exc)

    def set_internal_attribute(self, key, value):
        """
        :type key: String
        """
        try:
            self.http_session.set_internal_attribute(key, value)
        except Exception as exc:
            raise InvalidSessionException(exc)

    def remove_internal_attribute(self, key):
        """
        :type key: String
        """
        try:
            removed = self.http_session.get_internal_attribute(key)
            self.http_session.remove_internal_attribute(key)
            return removed
        except Exception as exc:
            raise InvalidSessionException(exc)


class DefaultWebSessionManager(DefaultNativeSessionManager,
                               web_session_abcs.WebSessionManager):

    """
    Web-application capable SessionManager implementation
    """

    def __init__(self):

        sessionidname = web_session_abcs.YosaiHttpSession.DEFAULT_SESSION_ID_NAME
        cookie = SimpleCookie(sessionidname)
        cookie.http_only = True # more secure, protects against XSS attacks
        self.session_id_cookie = cookie
        self.session_id_cookie_enabled = True

    @property
    def session_id_name(self):
        try:
            name = self.session_id_cookie.name
        except AttributeError:
            name = None

        if not name:
            return web_session_abcs.YosaiHttpSession.DEFAULT_SESSION_ID_NAME

        return name


    @property
    def is_session_id_cookie_enabled(self):
        return sessionIdCookieEnabled

    def store_session_id(self, current_id, request, response):
        """
        :type currentId: String
        :type request: HttpWSGIRequest
        :type response: HttpWSGIResponse
        """
        template = self.session_id_cookie
        cookie = SimpleCookie(template)

        cookie.set_value(current_id)
        cookie.save_to(request, response)

        logger.debug("Set session ID cookie for session with id " + str(current_id))

    def remove_session_id_cookie(self, request, response):
        self.session_id_cookie.remove_from(request, response)

    def get_session_id_cookie_value(self, request, response):
        if not self.is_session_id_cookie_enabled:
            msg = ("Session ID cookie is disabled - session id will not be "
                   "acquired from a request cookie.")
            logger.debug(msg)
            return None

        if not isinstance(request, HttpWSGIRequest):
            msg = ("Current request is not an HttpWSGIRequest - cannot get "
                   "session ID cookie.  Returning None.")
            logger.debug(msg)
            return None

        response = WebUtils.to_http(response)
        return self.session_id_cookie.read_value(request, response)

    def get_referenced_session_id(self, request, response):

        session_id = self.get_session_id_cookie_value(request, response)
        if session_id:
            request.set_attribute(web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_ID_SOURCE,
                                  web_session_abcs.YosaiHttpWSGIRequest.COOKIE_SESSION_ID_SOURCE)
        else:
            # not in a cookie, or cookie is disabled - try the request URI as a
            # fallback (i.e. due to URL rewriting):

            # try the URI path segment parameters first:
            session_name = web_session_abcs.YosaiHttpSession.DEFAULT_SESSION_ID_NAME
            session_id = self.get_uri_path_segment_param_value(request,
                                                               session_name)

            if not session_id:
                # not a URI path segment parameter, try the query parameters:
                name = self.session_id_name
                session_id = request.get_parameter(name)
                if not session_id:
                    # try lowercase:
                    session_id = request.get_parameter(name.lower())

            if session_id:
                ref_src = web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_ID_SOURCE
                url_src = web_session_abcs.YosaiHttpWSGIRequest.URL_SESSION_ID_SOURCE
                request.set_attribute(ref_src, url_src)

        if session_id:
            ref_id = web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_ID
            request.set_attribute(ref_id, session_id)

            # Automatically mark it valid here.  If it is invalid, the
            # on_unknown_session method below will be invoked and we'll remove
            # the attribute at that time.
            ref_isvalid = web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_ID_IS_VALID
            request.set_attribute(ref_isvalid, True)

        return session_id

    # DG:  this will require refactoring (TBD)
    def get_uri_path_segment_param_value(self, request, param_name):
        """
        :type request: WSGIRequest
        :type param_name: String
        """

        if not isinstance(wsgi_request, HttpWSGIRequest):
            return None

        uri = request.request_uri

        if uri is None:
            return None

        try:
            # try to get rid of the query string
            uri = uri[:uri.index('?')]
        except ValueError:
            pass

        try:
            index = uri.index(';')
        except ValueError:
            # no path segment params - return
            return None

        # there are path segment params, so let's get the last one that
        # may exist:

        # uri now contains only the path segment params
        uri = uri[(index + 1):]

        token = param_name + "="
        # we only care about the last param (SESSIONID):
        index = uri.rfind(token)
        if (index < 0):
            # no segment param:
            return None

        uri = uri[index + len(token):]

        try:
            # strip off any remaining segment params:
            index = uri.index(';')
            uri = uri[0:index]
        except:
            pass

        # what remains is the value:
        return uri

    def create_exposed_session(self, session, session_context=None, session_key=None):
        if session_context:
            if not WebUtils.is_web(session_context=session_context):
                return super().create_exposed_session(session=session,
                                                      session_context=session_context)

            request = WebUtils.get_request(session_context)
            response = WebUtils.get_response(session_context)
            session_key = WebSessionKey(session.session_id, request, response)
            return DelegatingSession(self, session_key)

        if not WebUtils.is_web(session_key=session_key):
            return super().create_exposed_session(session=session,
                                                  session_key=session_key)

        request = WebUtils.get_request(session_key)
        response = WebUtils.get_response(session_key)
        session_key = WebSessionKey(session.session_id, request, response)
        return DelegatingSession(self, session_key)


    # overridden
    def on_start(self, session, session_context):
        """
        Stores the Session's ID, usually as a Cookie, to associate with future
        requests.

        :param session: the session that was just ``createSession`` created
        """
        super().on_start(session, session_context)

        if not WebUtils.is_http(session_context):
            msg = ("SessionContext argument is not HTTP compatible or does not "
                   "have an HTTP request/response pair. No session ID cookie"
                   "will be set.")
            logger.debug(msg)
            return

        request = WebUtils.get_http_request(session_context)
        response = WebUtils.get_http_response(session_context)

        if self.is_session_id_cookie_enabled:
            session_dd = session.session_id
            self.store_session_id(session_id, request, response)
        else:
            msg = ("Session ID cookie is disabled.  No cookie has been set for "
                   "new session with id " + str(session.session_id))
            log.debug(msg)

        sid_src = web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_ID_SOURCE
        request.remove_attribute(sid_src)

        rs_is_new = web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_IS_NEW
        request.setAttribute(rs_is_new, True)

    # overridden
    def get_session_id(self, session_key=None, request=None, response=None):
        if session_key:
            session_id = super().get_session_id(session_key)
            if (not session_id and WebUtils.is_web(session_key)):
                request = WebUtils.get_request(session_key)
                response = WebUtils.get_response(session_key)
            else:
                return session_id
        return get_referenced_session_id(request, response)

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

        request = WebUtils.get_request(session_key)

        if request:
            rsid_is_valid = web_session_abcs.YosaiHttpWSGIRequest.REFERENCED_SESSION_ID_IS_VALID
            request.remove_attribute(rsid_is_valid)

        if WebUtils.is_http(session_key)
            msg = "Referenced session was invalid.  Removing session ID cookie."
            logger.debug(msg)
            self.remove_session_id_cookie(WebUtils.get_http_request(session_key),
                                          WebUtils.get_http_response(sessionkey))
        else:
            msg = ("SessionKey argument is not HTTP compatible or does not have"
                   "an HTTP request/response pair. Session ID cookie will not "
                   "be removed due to invalidated session.")
            logger.debug(msg)

    # overridden
    def on_stop(self, session, session_key):
        super().on_stop(session, session_key)
        if WebUtils.is_http(session_key):
            request = WebUtils.get_http_request(session_key)
            response = WebUtils.get_http_response(session_key)
            msg = ("Session has been stopped (subject logout or explicit stop)."
                   "  Removing session ID cookie.")
            logger.debug(msg)
            self.remove_session_id_cookie(request, response)
        else:
            msg = ("SessionKey argument is not HTTP compatible or does not have "
                   "an HTTP request/response pair. Session ID cookie will not be"
                   " removed due to stopped session.")
            logger.debug(msg)

    def is_wsgi_container_sessions(self):
        """
        This is a native session manager implementation, so this method returns
        ``False`` always.
        """
        return False


class DefaultWebSessionContext(DefaultSessionContext,
                               web_session_abcs.WebSessionContext):

    WSGI_REQUEST = "DefaultWebSessionContext.WSGI_REQUEST"
    WSGI_RESPONSE = "DefaultWebSessionContext.WSGI_RESPONSE"

    def __init__(self, context_map={}):
        super().__init__(context_map)

    @property
    def wsgi_request(self):
        return self.get(self.__class__.WSGI_REQUEST)

    @wsgi_request.setter
    def wsgi_request(self, request):
        """
        :type request: WSGIRequest
        """
        self.put(self.__class__.WSGI_REQUEST, request)

    @property
    def wsgi_response(self):
        return self.get(self.__class__.WSGI_RESPONSE)

    @wsgi_response.setter
    def wsgi_response(self, response):
        """
        :type request: WSGIResponse
        """
        self.put(self.__class__.WSGI_RESPONSE, response)


class WSGIContainerSessionManager(web_session_abcs.WebSessionManager):
    """
    SessionManager implementation providing ``Session`` implementations that
    are merely wrappers for the WSGI container's ``HttpSession``.

    Despite its name, this implementation *does not* itself manage Sessions since
    the WSGI container provides the actual management support.  This class mainly
    exists to 'impersonate' a regular Yosai ``SessionManager`` so that it can plug
    into a normal Yosai configuration in a pure web application.

    Note that because this implementation relies on the ``HttpSession``, it is
    only functional in a wsgi container - it is not capable of supporting
    Sessions for any clients other than those using the HTTP protocol.

    Therefore, if you need ``Session`` support for heterogeneous clients (e.g. web browsers,
    RMI clients, etc), use the ``DefaultWebSessionManager`` instead.  The
    ``DefaultWebSessionManager`` supports both traditional web-based access as
    well as non web-based clients.
    """

    def __init__(self):
        pass

    def start(self, session_context):
        return self.create_session(session_context)

    def get_session(self, session_key):
        if not WebUtils.is_http(session_key):
            msg = "SessionKey must be an HTTP compatible implementation."
            raise IllegalArgumentException(msg)

        request = WebUtils.get_http_request(session_key)

        session = None

        http_session = request.get_session(False)
        if http_session:
            session = self.create_session(http_session,
                                          request.remote_host)

        return session

    def get_host(self, session_context):
        host = session_context.host
        if not host:
            request = WebUtils.get_request(session_context)
            if request:
                host = request.remote_host

        return host

    def create_session(self, session_context):
        if not WebUtils.is_http(session_context):
            msg = "SessionContext must be an HTTP compatible implementation."
            raise IllegalArgumentException(msg)

        request = WebUtils.get_http_request(session_context)

        http_session = request.session

        host = self.get_host(session_context)

        return self.create_session(http_session, host)

    def create_session(self, http_session, host):
        return HttpWSGISession(http_session, host)

    def is_wsgi_container_sessions(self):
        """
        This implementation always delegates to the wsgi container for sessions,
        so this method always returns ``True``.
        """
        return True


class WebSessionKey(DefaultSessionKey,
                    web_utils_abcs.RequestPairSource):
    """
    A ``SessionKey`` implementation that also retains the ``WSGIRequest`` and
    ``WSGIResponse`` associated with the web request that is performing the
    session lookup
    """
    def __init__(self, request, response, session_id=None):

        self.wsgi_request = request
        self.wsgi_response = response
        self.session_id = session_id

    def get_wsgi_request(self):
        return self.wsgi_request

    def get_wsgi_response(self):
        return self.wsgi_response
