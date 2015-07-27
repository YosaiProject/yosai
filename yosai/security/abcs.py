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
import yosai.authc.abcs as authc_abcs
import yosai.authz.abcs as authz_abcs
import yosai.session.abcs as session_abcs


class RememberMeManager(metaclass=ABCMeta):

    @abstractmethod
    def get_remembered_principals(self, subject_context):
        pass

    @abstractmethod
    def forget_identity(self, subject_context):
        pass

    @abstractmethod
    def on_successful_login(self, subject, authc_token, auth_info):
        pass

    @abstractmethod
    def on_failed_login(self, subject, token, auth_exc):
        pass

    @abstractmethod
    def on_logout(self, subject):
        pass


class SecurityManager(authc_abcs.Authenticator, authz_abcs.Authorizer, 
                      session_abcs.SessionManager):

    @abstractmethod
    def login(self, subject, authc_token): 
        pass

    @abstractmethod
    def logout(self, subject):
        pass

    @abstractmethod
    def create_subject(self, subject_context):
        pass

