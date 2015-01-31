/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.cache;

import org.apache.shiro.util.Destroyable;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.util.StringUtils;

import java.util.Collection;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Very simple abstract {@code CacheManager} implementation that retains all created {@link Cache Cache} instances in
 * an in-memory {@link ConcurrentMap ConcurrentMap}.  {@code Cache} instance creation is left to subclasses via
 * the {@link #createCache createCache} method implementation.
 *
 * @since 1.0
 */
public abstract class AbstractCacheManager implements CacheManager, Destroyable {

    /**
     * Retains all Cache objects maintained by this cache manager.
     */
    private final ConcurrentMap<String, Cache> caches;

    /**
     * Default no-arg constructor that instantiates an internal name-to-cache {@code ConcurrentMap}.
     */
    public AbstractCacheManager() {
        this.caches = new ConcurrentHashMap<String, Cache>();
    }

    /**
     * Returns the cache with the specified {@code name}.  If the cache instance does not yet exist, it will be lazily
     * created, retained for further access, and then returned.
     *
     * @param name the name of the cache to acquire.
     * @return the cache with the specified {@code name}.
     * @throws IllegalArgumentException if the {@code name} argument is {@code null} or does not contain text.
     * @throws CacheException           if there is a problem lazily creating a {@code Cache} instance.
     */
    public <K, V> Cache<K, V> getCache(String name) throws IllegalArgumentException, CacheException {
        if (!StringUtils.hasText(name)) {
            throw new IllegalArgumentException("Cache name cannot be null or empty.");
        }

        Cache cache;

        cache = caches.get(name);
        if (cache == null) {
            cache = createCache(name);
            Cache existing = caches.putIfAbsent(name, cache);
            if (existing != null) {
                cache = existing;
            }
        }

        //noinspection unchecked
        return cache;
    }

    /**
     * Creates a new {@code Cache} instance associated with the specified {@code name}.
     *
     * @param name the name of the cache to create
     * @return a new {@code Cache} instance associated with the specified {@code name}.
     * @throws CacheException if the {@code Cache} instance cannot be created.
     */
    protected abstract Cache createCache(String name) throws CacheException;

    /**
     * Cleanup method that first {@link LifecycleUtils#destroy destroys} all of it's managed caches and then
     * {@link java.util.Map#clear clears} out the internally referenced cache map.
     *
     * @throws Exception if any of the managed caches can't destroy properly.
     */
    public void destroy() throws Exception {
        while (!caches.isEmpty()) {
            for (Cache cache : caches.values()) {
                LifecycleUtils.destroy(cache);
            }
            caches.clear();
        }
    }

    public String toString() {
        Collection<Cache> values = caches.values();
        StringBuilder sb = new StringBuilder(getClass().getSimpleName())
                .append(" with ")
                .append(caches.size())
                .append(" cache(s)): [");
        int i = 0;
        for (Cache cache : values) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(cache.toString());
            i++;
        }
        sb.append("]");
        return sb.toString();
    }
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.cache;

import java.util.Collection;
import java.util.Set;

/**
 * A Cache efficiently stores temporary objects primarily to improve an application's performance.
 *
 * <p>Shiro doesn't implement a full Cache mechanism itself, since that is outside the core competency of a
 * Security framework.  Instead, this interface provides an abstraction (wrapper) API on top of an underlying
 * cache framework's cache instance (e.g. JCache, Ehcache, JCS, OSCache, JBossCache, TerraCotta, Coherence,
 * GigaSpaces, etc, etc), allowing a Shiro user to configure any cache mechanism they choose.
 *
 * @since 0.2
 */
public interface Cache<K, V> {

    /**
     * Returns the Cached value stored under the specified {@code key} or
     * {@code null} if there is no Cache entry for that {@code key}.
     *
     * @param key the key that the value was previous added with
     * @return the cached object or {@code null} if there is no entry for the specified {@code key}
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public V get(K key) throws CacheException;

    /**
     * Adds a Cache entry.
     *
     * @param key   the key used to identify the object being stored.
     * @param value the value to be stored in the cache.
     * @return the previous value associated with the given {@code key} or {@code null} if there was no previous value
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public V put(K key, V value) throws CacheException;

    /**
     * Remove the cache entry corresponding to the specified key.
     *
     * @param key the key of the entry to be removed.
     * @return the previous value associated with the given {@code key} or {@code null} if there was no previous value
     * @throws CacheException if there is a problem accessing the underlying cache system
     */
    public V remove(K key) throws CacheException;

    /**
     * Clear all entries from the cache.
     *
     * @throws CacheException if there is a problem accessing the underlying cache system
     * @deprecated since 2.0.  Shiro's implementations never called this method - it is extraneous and causes unnecessary implementation requirements on Cache implementors.
     */
    @Deprecated
    public void clear() throws CacheException;

    /**
     * Returns the number of entries in the cache.
     *
     * @return the number of entries in the cache.
     * @deprecated since 2.0.  Shiro's implementations never called this method - it is extraneous and causes unnecessary implementation requirements on Cache implementors.
     */
    @Deprecated
    public int size();

    /**
     * Returns a view of all the keys for entries contained in this cache.
     *
     * @return a view of all the keys for entries contained in this cache.
     * @deprecated since 2.0.  Shiro's implementations never called this method - it is extraneous and causes unnecessary implementation requirements on Cache implementors.
     */
    @Deprecated
    public Set<K> keys();

    /**
     * Returns a view of all of the values contained in this cache.
     *
     * @return a view of all of the values contained in this cache.
     */
    public Collection<V> values();
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.cache;

/**
 * Interface implemented by components that utilize a CacheManager and wish that CacheManager to be supplied if
 * one is available.
 *
 * <p>This is used so internal security components that use a CacheManager can be injected with it instead of having
 * to create one on their own.</p>
 *
 * @since 0.9
 */
public interface CacheManagerAware {

    /**
     * Sets the available CacheManager instance on this component.
     *
     * @param cacheManager the CacheManager instance to set on this component.
     */
    void setCacheManager(CacheManager cacheManager);
}
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.cache;

/**
 * A CacheManager provides and maintains the lifecycles of {@link Cache Cache} instances.
 *
 * <p>Shiro doesn't implement a full Cache mechanism itself, since that is outside the core competency of a
 * Security framework.  Instead, this interface provides an abstraction (wrapper) API on top of an underlying
 * cache framework's main Manager component (e.g. JCache, Ehcache, JCS, OSCache, JBossCache, TerraCotta, Coherence,
 * GigaSpaces, etc, etc), allowing a Shiro user to configure any cache mechanism they choose.
 *
 * @since 0.9
 */
public interface CacheManager {

    /**
     * Acquires the cache with the specified <code>name</code>.  If a cache does not yet exist with that name, a new one
     * will be created with that name and returned.
     *
     * @param name the name of the cache to acquire.
     * @return the Cache with the given name
     * @throws CacheException if there is an error acquiring the Cache instance.
     */
    public <K, V> Cache<K, V> getCache(String name) throws CacheException;
}
