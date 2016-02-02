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

from yosai.core import (
    DefaultSessionStorageEvaluator,
)


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

    //since 1.2.1
    private SessionManager sessionManager;

    /**
     * Sets the session manager to use when checking to see if session storage is possible.
     * @param sessionManager the session manager instance for checking.
     * @since 1.2.1
     */
    //package protected on purpose to maintain point-version compatibility: (1.2.3 -> 1.2.1 should work always).
    void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    /**
     * Returns {@code true} if session storage is generally available (as determined by the super class's global
     * configuration property {@link #isSessionStorageEnabled()} and no request-specific override has turned off
     * session storage, {@code false} otherwise.
     * <p/>
     * This means session storage is disabled if the {@link #isSessionStorageEnabled()} property is {@code false} or if
     * a request attribute is discovered that turns off session storage for the current request.
     *
     * @param subject the {@code Subject} for which session state persistence may be enabled
     * @return {@code true} if session storage is generally available (as determined by the super class's global
     *         configuration property {@link #isSessionStorageEnabled()} and no request-specific override has turned off
     *         session storage, {@code false} otherwise.
     */
    @SuppressWarnings({"SimplifiableIfStatement"})
    @Override
    public boolean isSessionStorageEnabled(Subject subject) {
        if (subject.getSession(false) != null) {
            //use what already exists
            return true;
        }

        if (!isSessionStorageEnabled()) {
            //honor global setting:
            return false;
        }

        //SHIRO-350: non-web subject instances can't be saved to web-only session managers:
        //since 1.2.1:
        if (!(subject instanceof WebSubject) && (this.sessionManager != null && !(this.sessionManager instanceof NativeSessionManager))) {
            return false;
        }

        return WebUtils._isSessionCreationEnabled(subject);
    }


}
