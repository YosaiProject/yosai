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


"""
class SessionTokenGenerator:
    pass
"""

"""
class DefaultSessionStorageEvaluator:

     # Global policy determining if Subject sessions may be used to persist
     # Subject state if the Subject's Session does not yet exist.
    
    def __init__(self):
        self._session_storage_enabled = True

    def is_session_storage_enabled(self, subject=None):
        if (not subject):
            return self.session_storage_enabled
        else:
            return ((subject and subject.get_session(False)) or 
                    bool(self.session_storage_enabled))
   
    @property
    def session_storage_enabled(self):
        return self._session_storage_enabled
    
    @session_storage_enabled.setter
    def session_storage_enabled(self, sse):
        self._session_storage_enabled = sse


"""

"""
class EnterpriseCacheSessionDAO(CachingSessionDAO):

    def __init__(self): 
        
        DG:  not sure how to refactor this:
        public EnterpriseCacheSessionDAO() {
        setCacheManager(new AbstractCacheManager() {
            @Override
            protected Cache<Serializable, Session> createCache(String name) throws CacheException {
                return new MapCache<Serializable, Session>(name, new ConcurrentHashMap<Serializable, Session>());
            }
        });

    def do_create(self, session):
        sessionid = self.generate_session_id(session)
        self.assign_session_id(session, sessionid)
        return sessionid

"""


