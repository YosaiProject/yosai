from abc import ABCMeta, abstractmethod


class ABCAbstractCacheManager(metaclass=ABCMeta, ICacheManager):

    def __init__(self):
        self.caches = {}

    def get_cache(self, name=None):
        if (not name):
            msg = "Cache name cannot be null or empty."
            raise IllegalArgumentException(msg)

        cache = self.caches.get(name, None)  # DG:  not sure whether to copy?
        if (cache is None):
            cache = self.create_cache(name)
            existing = self.caches.put_if_absent(name, cache)
            if (existing is not None):
                cache = existing

        # noinspection unchecked
        return cache

    @abstractmethod
    def create_cache(self, name):
        pass

    def destroy(self):
        while (not self.caches.is_empty()):
            for cache in self.caches.values():
                del cache  # DG:  not sure about this..
            
            self.caches.clear()

    def __str__(self): 
        sb = "{0} with {1} cache(s)): [".\
            format(self.__class__.__name__, " with ", len(self.caches))
        ", ".join([str(cache) for cache in self.caches.values])
        sb += "]"
        return sb


class ICache(metaclass=ABCMeta):

    @abstractmethod
    def get(self, key):
        pass

    @abstractmethod
    def put(self, key, value):
        pass

    @abstractmethod
    def remove(self, key):
        pass

    @property
    @abstractmethod
    def values(self):
        pass


class ICacheManagerAware (metaclass=ABCMeta):

    @property
    @abstractmethod
    def cache_manager(self):
        pass

    @cache_manager.setter
    @abstractmethod
    def cache_manager(self, cachemanger):
        pass


class ICacheManager(metaclass=ABCMeta):

    @abstractmethod
    def get_cache(self, name):
        pass
