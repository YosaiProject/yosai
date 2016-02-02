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
    web_mgt_abcs,
    web_session_abcs,
    web_subject_abcs,
    WebDelegatingSubject,
    WebSessionKey,
    WebSubject,
    WebUtils,
    WSGIContainerSessionManager,
    YosaiHttpWSGIRequest,
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

        request = subject_context.resolve_wsgi_request()
        response = subject_context.resolve_wsgi_response()

        return WebDelegatingSubject(identifiers=identifiers,
                                    authenticated=authenticated,
                                    host=host,
                                    session=session,
                                    session_enabled=session_enabled,
                                    request=request,
                                    response=response,
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
        self.session_manager = WSGIContainerSessionManager()

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
        return super().session_manager

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
            msg = "http mode - enabling ServletContainerSessionManager (HTTP-only Sessions)"
            logger.info(msg)
            return WSGIContainerSessionManager()
        else:
            msg = "native mode - enabling DefaultWebSessionManager (non-HTTP and HTTP Sessions)"
            logger.info(msg)
            return DefaultWebSessionManager()

    # overridden:
    def create_session_sontext(self, subject_context):
        session_context = super().create_session_context(subject_context)
        if isinstance(subject_context, web_subject_abcs.WebSubjectContext):
            wsc = subject_context
            request = wsc.resolve_wsgi_request()
            response = wsc.resolve_wsgi_response()
            web_session_context = DefaultWebSessionContext(session_context)

            if request:
                web_session_context.wsgi_request = request

            if response:
                web_session_context.wsgi_response = response

            session_context = web_session_context

        return session_context

    # overridden
    def get_session_key(self, subject_context):
        if (WebUtils.is_web(subject_context)):
            session_id = subject_context.session_id
            request = WebUtils.get_request(subject_context)
            response = WebUtils.get_response(subject_context)
            return WebSessionKey(session_id, request, response)
        else:
            return super().get_session_key(subject_context)

    # overridden
    def before_logout(self, subject):
        super().before_logout(subject)
        self.remove_request_identity(subject)

    def remove_request_identity(self, subject):
        if isinstance(subject, WebSubject):
            request = subject.wsgi_request
            if request:
                request.set_attribute(YosaiHttpWSGIRequest.IDENTITY_REMOVED_KEY, True)
