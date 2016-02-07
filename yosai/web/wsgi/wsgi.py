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
from abc import abstractmethod
import unicodedata
import logging

from yosai.core import (
    SecurityUtils,
)

from yosai.web import (
    WSGIException,
    web_wsgi_abcs,
    WebUtils,
)

logger = logging.getLogger(__name__)

# no Filter abc exists (unlike shiro, which implements one from wsgi):
class AbstractFilter(web_wsgi_abcs.WSGIContextSupport):
    """
    Base abstract Filter simplifying Filter initialization and get_init_param(String)
    access to init parameters.  Subclass initialization logic should be performed
    by overriding the on_filter_config_set() template method.

    FilterChain execution logic (do_filter(wsgi_request, wsgi_response,
                                 filter_chain) is left to subclasses.
    """

    @property
    def filter_config(self):
        return self._filter_config

    @filter_config.setter
    def filter_config(self, filter_config):
        self.filter_config = filter_config
        self.wsgi_context = filter_config.wsgi_context

    def init_param(self, param_name):
        try:
            param = self.filter_config.get_init_parameter(param_name)

            # removes control characters:
            cleaned = "".join(ch for ch in param if
                              unicodedata.category(ch)[0] != "C")
            return cleaned

        except AttributeError:
            return None

    def init(self, filter_config):
        """
        Sets the filter's ``filter_config`` and then immediately calls
        ``on_filter_config_set()`` to trigger any processing a subclass might
        wish to perform

        :param filter_config: the wsgi container supplied FilterConfig instance
        :raises WSGIException:  if ``on_filter_config_set`` raises an Exception.
        """
        self.filter_config = filter_config

        try:
            self.on_filter_config_set()
        except Exception as exc:
            if isinstance(exc, WSGIException):
                raise exc
            else:
                if logger.getEffectiveLevel() <= logging.ERROR:
                    logger.error("Unable to start Filter: [" + str(exc) + "].", exc)

                raise WSGIException(exc)

    @abstractmethod
    def on_filter_config_set(self):
        """
        Template method to be overridden by subclasses to perform initialization
        logic at start-up.  The ``WSGIContext`` and ``FilterConfig`` will be
        accessible  (and non-None) at the time this method is invoked via the
        wsgi_context and filter_config attributes

        ``init-param`` values may be conveniently obtained via the
        get_init_param(String) method
        """
        pass

    @abstractmethod
    def destroy(self):
        """
        Default no-op implementation that can be overridden by subclasses for
        custom cleanup behavior.
        """
        pass

    def __repr__(self):
        return str(self.filter_config)  # TBD


# seems like boilerplate, may refactor (TBD):
class NameableFilter(AbstractFilter):

    def __init__(self):
        self._name = None

    @property
    def name(self):
        if not self._name:
            try:
                self._name = self.filter_config.filter_name
            except AttributeError:
                pass

        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    def __repr__(self):
        return str(super()) + ', name:' + self.name  # TBD


# TBD:  this class extends HttpWSGIRequestWrapper , so need to consider this further
class YosaiHttpWSGIRequest:

    COOKIE_SESSION_ID_SOURCE = "cookie"
    URL_SESSION_ID_SOURCE = "url"
    REFERENCED_SESSION_ID = "YosaiHttpWSGIRequest_REQUESTED_SESSION_ID"
    REFERENCED_SESSION_ID_IS_VALID = "YosaiHttpWSGIRequest_REQUESTED_SESSION_ID_VALID"
    REFERENCED_SESSION_IS_NEW = "YosaiHttpWSGIRequest_REFERENCED_SESSION_IS_NEW"
    REFERENCED_SESSION_ID_SOURCE = "YosaiHttpWSGIRequest_REFERENCED_SESSION_ID_SOURCE"
    IDENTITY_REMOVED_KEY = "YosaiHttpWSGIRequest_IDENTITY_REMOVED_KEY"

    def __init__(self, wrapped, wsgi_context, http_sessions):
        super().__(wrapped)__  # TBD:  no parent yet
        self.wsgi_context = wsgi_context
        self.httpSessions = httpSessions

    def is_http_sessions(self):
        return self.httpSessions

    @property
    def remote_user(self):
        remoteUser = None
        scIdentifier = self.subject_identifiers
        if scIdentifier:
            try:
                remoteUser = scIdentifier.name
            except AttributeError:
                remoteUser = str(scIdentifier)
        else:
            remoteUser = super().getRemoteUser()  # TBD, this won't work

        return remoteUser

    @property
    def subject(self):
        return SecurityUtils.get_subject()

    @property
    def subject_identifier(self):
        try:
            return self.subject.identifier
        except AttributeError:
            return None

    def is_user_in_role(self, role):
        subject = self.subject
        inRole = (subject and subject.has_role(role))
        if not inRole:
            inRole = super().isUserInRole(role)  # TBD this wont work

        return inRole

    @property
    def user_identifier(self):
        userIdentifier = None
        scIdentifier = self.subject_identifier
        if scIdentifier:
            if isinstance(scIdentifier, Identifier):
                userIdentifier = scIdentifier
            else:
                userIdentifier = ObjectIdentifier(scIdentifier)
            
        else:
            userIdentifier = super().UserIdentifier()  # TBD wont work
        }
    return userIdentifier

    @property
    def requested_session_id(self):
        requestedSessionId = None
        if self.is_http_sessions:
            requestedSessionId = super().requested_session_id  # TBD wont work
        else:
            sessionId = self.get_attribute(self.__class__.REFERENCED_SESSION_ID)
            if sessionId:
                requestedSessionId = str(sessionId)

        return requestedSessionId

    def get_session(self, create):

        HttpSession httpSession;

        if (isHttpSessions()) {
            httpSession = super.getSession(false);
            if (httpSession == null && create) {
                //Yosai 1.2: assert that creation is enabled (SHIRO-266):
                if (WebUtils._isSessionCreationEnabled(this)) {
                    httpSession = super.getSession(create);
                } else {
                    throw newNoSessionCreationException();
                }
            }
        } else {
            if (this.session == null) {

                boolean existing = getSubject().getSession(false) != null;

                Session shiroSession = getSubject().getSession(create);
                if (shiroSession != null) {
                    this.session = new YosaiHttpSession(shiroSession, this, this.wsgiContext);
                    if (!existing) {
                        setAttribute(REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
                    }
                }
            }
            httpSession = this.session;
        }

        return httpSession;
    }

    /**
     * Constructs and returns a {@link DisabledSessionException} with an appropriate message explaining why
     * session creation has been disabled.
     *
     * @return a new DisabledSessionException with appropriate no creation message
     * @since 1.2
     */
    private DisabledSessionException newNoSessionCreationException() {
        String msg = "Session creation has been disabled for the current request.  This exception indicates " +
                "that there is either a programming error (using a session when it should never be " +
                "used) or that Yosai's configuration needs to be adjusted to allow Sessions to be created " +
                "for the current request.  See the " + DisabledSessionException.class.getName() + " JavaDoc " +
                "for more.";
        return new DisabledSessionException(msg);
    }

    public HttpSession getSession() {
        return getSession(true);
    }

    public boolean isRequestedSessionIdValid() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdValid();
        } else {
            Boolean value = (Boolean) getAttribute(REFERENCED_SESSION_ID_IS_VALID);
            return (value != null && value.equals(Boolean.TRUE));
        }
    }

    public boolean isRequestedSessionIdFromCookie() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdFromCookie();
        } else {
            String value = (String) getAttribute(REFERENCED_SESSION_ID_SOURCE);
            return value != null && value.equals(COOKIE_SESSION_ID_SOURCE);
        }
    }

    public boolean isRequestedSessionIdFromURL() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdFromURL();
        } else {
            String value = (String) getAttribute(REFERENCED_SESSION_ID_SOURCE);
            return value != null && value.equals(URL_SESSION_ID_SOURCE);
        }
    }

    public boolean isRequestedSessionIdFromUrl() {
        return isRequestedSessionIdFromURL();
    }

    private class ObjectIdentifier implements java.security.Identifier {
        private Object object = null;

        public ObjectIdentifier(Object object) {
            this.object = object;
        }

        public Object getObject() {
            return object;
        }

        public String getName() {
            return getObject().toString();
        }

        public int hashCode() {
            return object.hashCode();
        }

        public boolean equals(Object o) {
            if (o instanceof ObjectIdentifier) {
                ObjectIdentifier op = (ObjectIdentifier) o;
                return getObject().equals(op.getObject());
            }
            return false;
        }

        public String toString() {
            return object.toString();
        }
    }
}


class ProxiedFilterChain:

    def __init__(self, orig, filters):
        self.orig = orig
        self.filters = filters
        self.index = 0

    # TBD
    # do_filter is an overwritten method from:
    # https://tomcat.apache.org/tomcat-5.5-doc/wsgiapi/javax/wsgi/FilterChain.html
    def do_filter(self, request, response):
        if (not self.filters or len(self.filters) == self.index):
            # we've reached the end of the wrapped chain, so invoke the original one:
            if logger.getEffectiveLevel() <= logging.DEBUG:
                logger.debug("Invoking original filter chain.")

            self.orig.do_filter(request, response)

        else:
            if logger.getEffectiveLevel() <= logging.DEBUG:
                logger.debug("Invoking wrapped filter at index [" + self.index + "]")

            self.filters.get(self.index).do_filter(request, response, self)
            self.index += 1


class OncePerRequestFilter(NameableFilter):

    ALREADY_FILTERED_SUFFIX = ".FILTERED"

    def __init__(self):
        self.enabled = True

    def is_enabled(self, request=None, response=None):
        # params are unused , TBD refactoring
        return self.enabled

    def do_filter(self, request, response, filter_chain):
        af_attribute_name = self.already_filtered_attribute_name
        if request.get_attribute(af_attribute_name):
            logger.debug("Filter '{}' already executed.  Proceeding without "
                         " invoking this filter.".format(self.name))
            filter_chain.do_filter(request, response)
        elif (self.is_enabled(request, reseponse) or self.should_not_filter(request)):
            logger.debug("Filter '{}' is not enabled for the current request. "
                         "Proceeding without invoking this filter.".format(self.name))
            filter_chain.do_filter(request, response)
        else:
            # Do invoke this filter...
            logger.debug("Filter '{}' not yet executed.  Executing now.".format(self.name))
            request.set_attribute(af_attribute_name, True)

            try:
                self.do_filter_internal(request, response, filter_chain)
            finally:
                # Once the request has finished, we're done and we don't
                # need to mark as 'already filtered' any more.
                request.remove_attribute(self.already_filtered_attribute_name)

    @property
    def already_filtered_attribute_name(self):
        name = ''
        if not self.name:
            name = self.__class__.__name__
        return name + self.__class__.ALREADY_FILTERED_SUFFIX

    @abstractmethod
    def do_filter_internal(self, request, response, chain):
        pass


class YosaiFilter(AbstractYosaiFilter):

    # yosai renamed Yosai's init method to initialize to avoid collision:
    def initialize(self):
        env = WebUtils.get_required_web_environment(self.wsgi_context)
        self.security_manager = env.web_security_manager
        resolver = env.filter_chain_resolver

        if resolver:
            self.filter_chain_resolver = resolver


class WSGIContextSupport:

    def __init__(self):
        self.wsgi_context = None

    def get_context_init_param(self, param_name):
        return self.wsgi_context.get_init_parameter(param_name)

    # yosai omits use of the required_wsgi_context method because Python's
    # AttributeError is sufficient in cases where wsgi_context isn't set

    def set_context_attribute(self, key, value):
        if not value:
            self.remove_context_attribute(key)
        else:
            self.wsgi_context.set_attribute(key, value)

    def get_context_attribute(self, key):
        return self.get_attribute(key)

    def remove_context_attribute(self, key):
        self.remove_attribute(key)

    def __repr__(self):
        return str(self.wsgi_context)


class AbstractYosaiFilter(OncePerRequestFilter):

    STATIC_INIT_PARAM_NAME = "staticSecurityManagerEnabled"

    def __init__(self):
        self.static_security_manager_enabled = False

    @property
    def security_manager(self):
        return self._security_manager

    @security_manager.setter
    def security_manager(self, securitymanager):
        self._security_manager = securitymanager

    @property
    def filter_chain_resolver(self):
        return self._filter_chain_resolver

    @filter_chain_resolver.setter
    def filter_chain_resolver(self, resolver):
        self._filter_chain_resolver = resolver

    def is_static_security_manager_enabled(self):
        return self.static_security_manager_enabled

    def on_filter_config_set(self):
        self.apply_static_security_manager_enabled_config()
        self.initialize()
        self.ensure_security_manager()

        if self.is_static_security_manager_enabled():
            SecurityUtils.set_security_manager(self.security_manager)

    def apply_static_security_manager_enabled_config(self):
        value = self.get_init_param(self.__class__.STATIC_INIT_PARAM_NAME)
        self.static_security_manager_enabled = bool(value)

    @abstractmethod
    def initialize(self):
        pass

    def ensure_security_manager(self):
        if not self.securityManager:
            logger.info("No SecurityManager configured.  Creating default.")
            security_manager = self.create_default_security_manager()
            self.security_manager = security_manager

    def create_default_security_manager(self):
        return DefaultWebSecurityManager()

    def is_http_sessions(self):
        return self.security_manager.is_http_session_mode

    def wrap_wsgi_request(self, orig_request):
        return YosaiHttpWSGIRequest(orig_request,
                                    self.wsgi_context,
                                    self.is_http_sessions)

    def prepare_wsgi_request(self, request, response, chain):
        to_use = None

        if isinstance(request, HttpWSGIRequest):
            to_use = self.wrap_wsgi_request(http)

        return to_use

    def wrap_wsgi_response(self, orig, request):
        return YosaiHttpWSGIResponse(orig, self.wsgi_context, request)

    def prepare_wsgi_response(self, request, response, chain):
        to_use = response

        if not (self.is_http_sessions and
                isinstance(request, YosaiHttpWSGIRequest) and
                isinstance(response, HttpWSGIResponse)):
            # the YosaiHttpWSGIResponse exists to support URL rewriting for session ids.
            # This is only needed if using Yosai sessions (i.e. not simple
            # HttpSession based sessions):
            to_use = self.wrap_wsgi_response(response, request)

        return to_use

    def create_subject(self, request, response):
        builder = WebSubjectBuilder(self.security_manager, request, response)
        return builder.build_web_subject()

    def update_session_last_access_time(self, request, response):
        if not self.is_http_sessions:  # 'native' sessions
            subject = SecurityUtils.get_subject()
            # Subject should never _ever_ be null, but just in case:
            if subject:
                session = subject.get_session(False)
                try:
                    session.touch()
                except Exception as exc:
                    logger.error("session.touch() method invocation has failed."
                                 "Unable to update the corresponding session's "
                                 "last access time based on the incoming request.", exc)

    def do_filter_internal(self, wsgi_request, wsgi_response, chain):
        try:
            request = self.prepare_wsgi_request(wsgi_request, wsgi_response, chain)
            response = self.prepare_wsgi_response(wsgi_request, wsgi_response, chain)

            subject = self.create_subject(request, response)

            # TBD TBD TBD:
            subject.execute(new Callable() {
                public Object call() throws Exception {
                    updateSessionLastAccessTime(request, response);
                    executeChain(request, response, chain);
                    return null;
                }
            })

        } catch (ExecutionException ex) {
            t = ex.getCause();
        } catch (Throwable throwable) {
            t = throwable;
        }

        if (t != null) {
            if (t instanceof WSGIException) {
                throw (WSGIException) t;
            }
            if (t instanceof IOException) {
                throw (IOException) t;
            }
            //otherwise it's not one of the two exceptions expected by the filter method signature - wrap it in one:
            String msg = "Filtered request failed.";
            throw new WSGIException(msg, t);
        }
    }

    def get_execution_chain(self, request, response, orig_chain):
        chain = orig_chain
        resolver = self.filter_chain_resolver
        if not resolver:
            logger.debug("No FilterChainResolver configured.  Returning "
                         "original FilterChain.")
            return orig_chain

        resolved = resolver.get_chain(request, response, orig_chain)

        if resolved:
            logger.trace("Resolved a configured FilterChain for the current request.")
            chain = resolved
        else:
            logger.trace("No FilterChain configured for the current request. "
                         " Using the default.")
        return chain

    def execute_chain(self, request, response, orig_chain):
        chain = self.get_execution_chain(request, response, orig_chain)
        chain.do_filter(request, response)
