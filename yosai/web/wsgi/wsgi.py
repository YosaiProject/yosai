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

from yosai.web import (
    WSGIException,
    web_wsgi_abcs,
)

logger = logging.getLogger(__name__)

# no Filter abc exists (unlike shiro, which implements one from servlet):
class AbstractFilter(web_wsgi_abcs.WSGIContextSupport):
    """
    Base abstract Filter simplifying Filter initialization and get_init_param(String)
    access to init parameters.  Subclass initialization logic should be performed
    by overriding the on_filter_config_set() template method.

    FilterChain execution logic (do_filter(servlet_request, servlet_response,
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
            param = filter_config.get_init_parameter(param_name)

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
    def onFilterConfigSet(self):
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

/**
 * Base implementation for any components that need to access the web application's {@link ServletContext ServletContext}.
 *
 * @since 0.2
 */
public class ServletContextSupport {

    //TODO - complete JavaDoc
    private ServletContext servletContext = null;

    public ServletContext getServletContext() {
        return servletContext;
    }

    public void setServletContext(ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected String getContextInitParam(String paramName) {
        return getServletContext().getInitParameter(paramName);
    }

    private ServletContext getRequiredServletContext() {
        ServletContext servletContext = getServletContext();
        if (servletContext == null) {
            String msg = "ServletContext property must be set via the setServletContext method.";
            throw new IllegalStateException(msg);
        }
        return servletContext;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected void setContextAttribute(String key, Object value) {
        if (value == null) {
            removeContextAttribute(key);
        } else {
            getRequiredServletContext().setAttribute(key, value);
        }
    }

    @SuppressWarnings({"UnusedDeclaration"})
    protected Object getContextAttribute(String key) {
        return getRequiredServletContext().getAttribute(key);
    }

    protected void removeContextAttribute(String key) {
        getRequiredServletContext().removeAttribute(key);
    }

    /**
     * It is highly recommended not to override this method directly, and instead override the
     * {@link #toStringBuilder() toStringBuilder()} method, a better-performing alternative.
     *
     * @return the String representation of this instance.
     */
    @Override
    public String toString() {
        return toStringBuilder().toString();
    }

    /**
     * Same concept as {@link #toString() toString()}, but returns a {@link StringBuilder} instance instead.
     *
     * @return a StringBuilder instance to use for appending String data that will eventually be returned from a
     *         {@code toString()} invocation.
     */
    protected StringBuilder toStringBuilder() {
        return new StringBuilder(super.toString());
    }
}
