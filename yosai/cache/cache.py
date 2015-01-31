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
import java.util.Collections;
import java.util.Set;

/**
 * A {@code CacheManager} implementation that does not perform any caching at all.  While at first glance this concept
 * might sound odd, it reflects the <a href="http://en.wikipedia.org/wiki/Null_Object_pattern">Null Object Design
 * Pattern</a>: other parts of Shiro or users' code do not need to perform null checks when interacting with Cache or
 * CacheManager instances, reducing code verbosity, enhancing readability, and reducing probability for certain bugs.
 *
 * @since 2.0
 */
public class DisabledCacheManager implements CacheManager {

    public static final DisabledCacheManager INSTANCE = new DisabledCacheManager();

    private static final Cache DISABLED_CACHE = new DisabledCache();

    @SuppressWarnings("unchecked")
    public <K, V> Cache<K, V> getCache(String name) throws CacheException {
        return DISABLED_CACHE;
    }

    private static final class DisabledCache<K,V> implements Cache<K,V> {

        public V get(K key) throws CacheException {
            return null;
        }

        public V put(K key, V value) throws CacheException {
            return null;
        }

        public V remove(K key) throws CacheException {
            return null;
        }

        public void clear() throws CacheException {
        }

        public int size() {
            return 0;
        }

        public Set<K> keys() {
            return Collections.emptySet();
        }

        public Collection<V> values() {
            return Collections.emptySet();
        }
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

import org.apache.shiro.util.CollectionUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * A <code>MapCache</code> is a {@link Cache Cache} implementation that uses a backing {@link Map} instance to store
 * and retrieve cached data.
 *
 * @since 1.0
 */
public class MapCache<K, V> implements Cache<K, V> {

    /**
     * Backing instance.
     */
    private final Map<K, V> map;

    /**
     * The name of this cache.
     */
    private final String name;

    public MapCache(String name, Map<K, V> backingMap) {
        if (name == null) {
            throw new IllegalArgumentException("Cache name cannot be null.");
        }
        if (backingMap == null) {
            throw new IllegalArgumentException("Backing map cannot be null.");
        }
        this.name = name;
        this.map = backingMap;
    }

    public V get(K key) throws CacheException {
        return map.get(key);
    }

    public V put(K key, V value) throws CacheException {
        return map.put(key, value);
    }

    public V remove(K key) throws CacheException {
        return map.remove(key);
    }

    public void clear() throws CacheException {
        map.clear();
    }

    public int size() {
        return map.size();
    }

    public Set<K> keys() {
        Set<K> keys = map.keySet();
        if (!keys.isEmpty()) {
            return Collections.unmodifiableSet(keys);
        }
        return Collections.emptySet();
    }

    public Collection<V> values() {
        Collection<V> values = map.values();
        if (!CollectionUtils.isEmpty(values)) {
            return Collections.unmodifiableCollection(values);
        }
        return Collections.emptySet();
    }

    public String toString() {
        return new StringBuilder("MapCache '")
                .append(name).append("' (")
                .append(map.size())
                .append(" entries)")
                .toString();
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

import org.apache.shiro.util.SoftHashMap;

/**
 * Simple memory-only based {@link CacheManager CacheManager} implementation usable in production
 * environments.  It will not cause memory leaks as it produces {@link Cache Cache}s backed by
 * {@link SoftHashMap SoftHashMap}s which auto-size themselves based on the runtime environment's memory
 * limitations and garbage collection behavior.
 * <p/>
 * While the {@code Cache} instances created are thread-safe, they do not offer any enterprise-level features such as
 * cache coherency, optimistic locking, failover or other similar features.  For more enterprise features, consider
 * using a different {@code CacheManager} implementation backed by an enterprise-grade caching product (Hazelcast,
 * EhCache, TerraCotta, Coherence, GigaSpaces, etc, etc).
 *
 * @since 1.0
 */
public class MemoryConstrainedCacheManager extends AbstractCacheManager {

    /**
     * Returns a new {@link MapCache MapCache} instance backed by a {@link SoftHashMap}.
     *
     * @param name the name of the cache
     * @return a new {@link MapCache MapCache} instance backed by a {@link SoftHashMap}.
     */
    @Override
    protected Cache createCache(String name) {
        return new MapCache<Object, Object>(name, new SoftHashMap<Object, Object>());
    }
}
