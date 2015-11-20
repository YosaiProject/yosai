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


class CacheHandler(metaclass=ABCMeta):

    @abstractmethod
    def get(self, key_source):
        """
        :param key_source:  a yosai object that contains the key identifer
        :type key_source:  Account, UsernamePasswordToken
        """
        pass

    @abstractmethod
    def get_or_create(self, key_source, creator_func):
        """
        :param key_source:  a yosai object that contains the key identifer
        :type key_source:  Account, UsernamePasswordToken

        :param creator_func: the function called to generate a new
                             Serializable object for cache
        :type creator_func:  function
        """
        pass

    @abstractmethod
    def cache(self, key_source, value):
        """
        Also known as the 'set' command, renamed to avoid collision.  This
        method is used to cache an object.

        :param key_source:  a yosai object that contains the key identifer
        :type key_source:  Account, UsernamePasswordToken

        :param value:  the Serializable object to cache
        """
        pass

    @abstractmethod
    def delete(self, key_source):
        """
        Removes an object from cache

        :param key_source:  a yosai object that contains the key identifer
        :type key_source:  Account, UsernamePasswordToken
        """
        pass

    # @abstractmethod
    # def set_ttl(self, key_source, ttl):
    #    """
    #    Resets the time to live attribute of a cache entry

    #    :param key_source:  a yosai object that contains the key identifer
    #    :type key_source:  Account, UsernamePasswordToken
    #    """

class CacheKeyResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_cache_key(self, authc_token=None, account=None, account_id=None):
        pass


class CacheResolver(metaclass=ABCMeta):

    @abstractmethod
    def get_cache(self, authc_token=None, account=None, account_id=None):
        pass
