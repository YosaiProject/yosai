
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

from abc import abstractmethod, ABCMeta


class Cookie(metaclass=ABCMeta):
    """
    Interface representing HTTP cookie operations, supporting plain old property
    based getters and setters for all attributes specified for
    <a href="http://www.owasp.org/index.php/HttpOnly">HttpOnly</a> support.
    """

    # The value of deleted cookie (with the maxAge 0)
    DELETED_COOKIE_VALUE = "deleteMe"


    # The number of seconds in one year (= 60 * 60 * 24 * 365)
    ONE_YEAR = 60 * 60 * 24 * 365


    # Root path to use when the path hasn't been set and request context root
    # is empty or None
    ROOT_PATH = "/"

    @abstractmethod
    @property
    def name(self):
        pass

    @abstractmethod
    @name.setter
    def name(self, name):
        pass

    @abstractmethod
    @property
    def value(self):
        pass

    @abstractmethod
    @value.setter
    def value(self, value):
        pass

    @abstractmethod
    @property
    def comment(self):
        pass

    @abstractmethod
    @comment.setter
    def comment(self, comment):
        pass

    @abstractmethod
    @property
    def domain(self):
        pass

    @abstractmethod
    @domain.setter
    def domain(self, domain):
        pass

    @abstractmethod
    @property
    def max_age(self):
        pass

    @abstractmethod
    @max_age.setter
    def max_age(self, max_age):
        pass

    @abstractmethod
    @property
    def path(self):
        pass

    @abstractmethod
    @path.setter
    def path(self, path):
        pass

    @abstractmethod
    @property
    def is_secure(self):
        pass

    @abstractmethod
    @is_secure.setter
    def is_secure(self, secure):
        pass

    @abstractmethod
    @property
    def version(self):
        pass

    @abstractmethod
    @version.setter
    def version(self, version):
        pass

    @abstractmethod
    @property
    def is_http_only(self):
        pass

    @abstractmethod
    @is_http_only.setter
    def is_http_only(self, httponly):
        pass

    @abstractmethod
    def save_to(self, request, response):
        """
        :type request:  HttpWSGIRequest
        :type response:  HttpWSGIResponse
        """
        pass

    @abstractmethod
    def remove_from(self, request, response):
        """
        :type request:  HttpWSGIRequest
        :type response:  HttpWSGIResponse
        """
        pass

    @abstractmethod
    def read_value(self, request, response):
        """
        :type request:  HttpWSGIRequest
        :type response:  HttpWSGIResponse
        """
        pass
