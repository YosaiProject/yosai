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


from abc import ABCMeta, abstractmethod


class WebRegistry(metaclass=ABCMeta):
    """
    Cookie attributes (path, domain, maxAge, etc) may be set on this class's
    default ``cookie`` attribute, which acts as a template to use to set all
    properties of outgoing cookies created by this implementation.

    The default cookie has the following attribute values set:

    |Attribute Name|    Value
    |--------------|----------------
    | name         | rememberMe
    | path         | /
    | max_age      | Cookie.ONE_YEAR

    http-only attribute support

    shiro marked cookies as deleted and ignored those because cookies weren't
    immediately removed by browsers (or through servlets?).. not sure how to
    address this in Yosai yet (TBD)

    removed cookies should return None values for their __get__'s

    set http-only to True

    Note:  when session is created, REFERENCED_SESSION_ID_SOURCE attribute is
    removed from the servlet and REFERENCED_SESSION_IS_NEW attribute gets set

    removing a cookie entails removing from request and response objects

    take a close look at the cookie arguments used in the SessionManager,
    including:
        REFERENCED_SESSION_ID
        REFERENCED_SESSION_ID_SOURCE
        REFERENCED_SESSION_IS_NEW
        REFERENCED_SESSION_ID_IS_VALID
    """

    @abstractmethod
    def __init__(self, request=None, response=None):
        pass

    @property
    @abstractmethod
    def remember_me(self):
        pass

    @remember_me.setter
    @abstractmethod
    def remember_me(self, rememberme):
        pass

    @remember_me.deleter
    @abstractmethod
    def remember_me(self):
        pass

    @property
    @abstractmethod
    def session_id(self):
        pass

    @session_id.setter
    @abstractmethod
    def session_id(self, session_id):
        pass

    @session_id.deleter
    @abstractmethod
    def session_id(self):
        pass

    @property
    @abstractmethod
    def remote_host(self):
        pass

    @remote_host.setter
    @abstractmethod
    def remote_host(self, remote_host):
        pass

    @remote_host.deleter
    @abstractmethod
    def remote_host(self):
        pass

    @property
    @abstractmethod
    def session_creation_enabled(self):
        pass

    @session_creation_enabled.setter
    @abstractmethod
    def session_creation_enabled(self, session_creation_enabled):
        pass

    @session_creation_enabled.deleter
    @abstractmethod
    def session_creation_enabled(self):
        pass
