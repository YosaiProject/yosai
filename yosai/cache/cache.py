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

from yosai import (
    CacheException,
    LogManager,
    cache_abcs,
    settings,
)


class CacheSettings():
    """
    This is a proxy to the global settings module
    - new to yosai
    """
    def __init__(self):
        self.cache_config = settings.CACHE_CONFIG

        self.region_init_config = self.cache_config.get('INIT_CONFIG')

        self.server_config = self.cache_config.get('SERVER_CONFIG')

        self.ttl_config = self.cache_config.get('TTL_CONFIG')
        self.absolute_ttl = self.ttl_config.get('ABSOLUTE_TTL')
        self.credentials_ttl = self.ttl_config.get('CREDENTIALS_TTL')
        self.authz_info_ttl = self.ttl_config.get('AUTHZ_INFO_TTL')
        self.session_abs_ttl = self.ttl_config.get('SESSION_ABSOLUTE_TTL')

        self.key_config = self.cache_config.get('KEY_CONFIG')
        self.credentials_key = self.key_config.get('CREDENTIALS_KEY')
        self.authz_info_key = self.key_config.get('AUTHZ_INFO_KEY')
        self.session_key = self.key_config.get('SESSION_KEY')


def create_cache_region(cache_settings, make_region):

    cache_region = make_region(**cache_settings.region_init_config)

    cache_region.configure(backend='yosai_dpcache.cache.redis',
                           expiration_time=cache_settings.absolute_ttl,
                           arguments=cache_settings.server_config,
                           wrap=SerializationProxy)

    return cache_region


class CacheHandler(cache_abcs.CacheHandler):

    def __init__(self, cache_region, ttl, cache_key):
        """
        :type cache_region: a [yosai_dpcache] CacheRegion object

        :param ttl: time to live, expressed in seconds
        :type ttl: integer

        :param cache_key:  the key formatted for String.Formatter variable
                     substitution
            ``example cache_key:
                "yosai:{0}:{1}:credentials"
            ``
        """
        self.cache_region = cache_region
        self.ttl = ttl
        self.cache_key = cache_key

    def generate_key(self, obj):
        identifier = obj.identifier  # this is a standard across classes
        return self.cache_key.format(identifier)

    def get(self, obj):
        """
        :param obj:  a yosai object that contains an identifer
        :type obj:  Account, UsernamePasswordToken
        """
        key = self.generate_key(obj)
        return self.cache_region.get(key)

    def get_or_create(self, obj, creator_func):
        """
        This method will try to obtain an object from cache.  If the object is
        not available from cache, the creator_func function is called to generate
        a new Serializable object and then the object is cached.  get_or_create
        uses dogpile locking to avoid race condition among competing get_or_create
        threads where by the first requesting thread obtains exclusive privilege
        to generate the new object while other requesting threads wait for the
        value and then return it.

        :param obj:  a yosai object that contains an identifer
        :type obj:  Account, UsernamePasswordToken

        :param creator_func: the function called to generate a new
                             Serializable object for cache
        :type creator_func:  function
        """
        key = self.generate_key(obj)
        return self.cache_region.get_or_create(key=key,
                                               creator=creator_func,
                                               expiration=self.ttl)

    def put(self, obj, value):
        """
        :param obj:  a yosai object that contains the key identifer
        :type obj:  Account, UsernamePasswordToken

        :param value:  the Serializable object to cache
        """
        key = self.generate_key(obj)
        self.cache_region.put(key, value, expiration=self.ttl)

    def delete(self, obj):
        """
        Removes an object from cache

        :param obj:  a yosai object that contains an identifer
        :type obj:  Account, UsernamePasswordToken
        """
        key = self.generate_key(obj)
        self.cache_region.delete(key)
