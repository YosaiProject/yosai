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
    notes (TBD):
        shiro marked cookies as deleted and ignored those because cookies weren't
        immediately removed by browsers (or through servlets?).. not sure how to
        address this in Yosai yet

        - set http-only to True
    """

    @abstractmethod
    def __init__(self, request):
        self.request = request
        self.secret = None  # it is injected by the SecurityManager
        self.cookies = {'set_cookie': {}, 'delete_cookie': set()}
        self._session_creation_enabled = True
        self.set_cookie_attributes = {}  # cookie properties
        self.register_response_callback()

    @property
    def remember_me(self):
        return self._get_cookie('remember_me', self.secret)

    @remember_me.setter
    def remember_me(self, rememberme):
        cookie = {'value': rememberme}
        self.cookies['set_cookie']['remember_me'] = cookie

    @remember_me.deleter
    def remember_me(self):
        self.cookies['delete_cookie'].add('remember_me')

    @property
    def session_id(self):
        return self._get_cookie('session_id', self.secret)

    @session_id.setter
    def session_id(self, session_id):
        cookie = {'value': session_id}
        self.cookies['set_cookie']['session_id'] = cookie

    @session_id.deleter
    def session_id(self):
        self.cookies['delete_cookie'].add('session_id')

    @property
    def remote_host(self):
        return self.request.client_addr

    @property
    def session_creation_enabled(self):
        return self._session_creation_enabled

    @session_creation_enabled.setter
    def session_creation_enabled(self, session_creation_enabled):
        self._session_creation_enabled = session_creation_enabled

    @session_creation_enabled.deleter
    def session_creation_enabled(self):
        self._session_creation_enabled = None

    def webregistry_callback(self, request, response):
        while self.cookies['delete_cookie']:
            key = self.cookies['delete_cookie'].pop()
            self._delete_cookie(response, key)

        while self.cookies['set_cookie']:
            key, value = self.cookies['set_cookie'].popitem()
            self._set_cookie(response, key, value['value'])

    @property
    @abstractmethod
    def resource_params(self):
        """
        Obtains the resource-specific parameters of the HTTP request, returning
        a dict that will be used to bind parameter values to dynamic permissions.

        :rtype: dict
        """
        pass

    @abstractmethod
    def raise_forbidden(self, msg=None):
        """
        This method is called to raise HTTP Error Code 403 (Forbidden).
        """
        pass

    @abstractmethod
    def raise_unauthorized(self, msg=None):
        """
        This method is called to raise HTTP Error Code 401 (Unauthorized).
        """
        pass

    @abstractmethod
    def _get_cookie(self, cookie_name, secret):
        pass

    @abstractmethod
    def _set_cookie(self, response, cookie_name, cookie_val):
        pass

    @abstractmethod
    def _delete_cookie(self, response, cookie_name):
        pass

    @abstractmethod
    def register_response_callback(self):
        pass

    def __repr__(self):
        return "{0}(session_id={1}, remember_me={2})".format(
            self.__class__.__name__, self.session_id, self.remember_me)
