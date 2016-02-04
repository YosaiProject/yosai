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

from yosai.core import (
    session_abcs,
)

from abc import abstractmethod


class WebSessionManager(session_abcs.SessionManager):

    @abstractmethod
    def is_wsgi_container_sessions(self):
        """
        Returns ``True`` if session management and storage is managed by the
        underlying WSGI container or ``False`` if managed by Yosai directly
        (called 'native' sessions).

        If sessions are enabled, Yosai can make use of Sessions to retain
        security information from request to request.  This method indicates
        whether Yosai would use the WSGI container sessions to fulfill its
        needs, or if it would use its own native session management instead (which
        can support enterprise features such as distributed caching - in a
        container-independent manner).

        :returns: True if session management and storage is managed by the
                  underlying WSGI container or False if managed by Yosai directly
                  (called 'native' sessions)

        """
        pass
