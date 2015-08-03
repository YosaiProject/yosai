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

from yosai import (
    CacheException, 
    LogManager,
    IllegalArgumentException,
    cache_abcs
)

class DisabledCache:
    pass

class DisabledCacheManager:
    pass

class CacheManager:
    # temporary mock class used to pass session testing.. replace later
    pass


class MapCache(cache_abcs.Cache):

    def __init__(self, name=None, backing_map=None):
        if (name is None):
            raise IllegalArgumentException("Cache name cannot be null.")
        
        if (backing_map is None):
            raise IllegalArgumentException("Backing map cannot be null.")
        
        self.name = name
        self.backing_map = backing_map
    
    def __str__(self): 
        return "MapCache '{0}' ({1} entries)".format(
               self.name, self.backing_map.size())

    def get(self, key):
        return self.backing_map.get(key, None)
    
    def put(self, key, value):
        return self.backing_map.put(key, value)

    def remove(self, key):
        return self.backing_map.remove(key)

    def clear(self):
        self.backing_map.clear()

    def size(self):
        return self.backing_map.size()

    def keys(self):
        keys = self.backing_map.key_set()
        if (not keys):
            return set(keys)
        
        return set()

    def values(self):
        values = self.backing_map.values()
        if (values):
            return set(values)  # immutability required , but no frozenset
        
        return set()


class MemoryConstrainedCacheManager(cache_abcs.AbstractCacheManager):

    def create_cache(self, name):
        return MapCache(name, {})  # DG:  was a SoftHashMap...
