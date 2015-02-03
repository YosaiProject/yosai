from exceptions import IllegalArgumentException
from interfaces import (ABCAbstractCacheManager, ICacheManager, ICache)


class DisabledCacheManager(ICacheManager):

    def __init__(self):
        self.instance = DisabledCacheManager()
        self.disabled_cache = self.DisabledCache()

    def get_cache(self, name):
        return self.disabled_cache

    class DisabledCache(ICache):

        def get(self, key):
            return None 

        def put(self, key, value):
            return None

        def remove(self, key):
            return None 

        def clear(self):
            return None 

        def size(self):
            return 0

        def keys(self):
            return set()

        def values(self):
            return set()


class MapCache(ICache):

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


class MemoryConstrainedCacheManager(ABCAbstractCacheManager):

    def create_cache(self, name):
        return MapCache(name, {})  # DG:  was a SoftHashMap...
