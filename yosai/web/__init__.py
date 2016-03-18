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
__license__ = 'Apache 2.0'
__author__ = 'Darin Gordon'
__credits__ = ['Apache Shiro']
__maintainer__ = 'Darin Gordon'
__email__ = 'dkcdkg@gmail.com'
__status__ = 'Development'


from yosai.web.mgt import abcs as web_mgt_abcs
from yosai.web.session import abcs as web_session_abcs
from yosai.web.subject import abcs as web_subject_abcs
from yosai.web.utils import abcs as web_abcs  # since it is the primary api

from .exceptions import (
    YosaiWebException,
    MissingWebRegistryException,
)


from yosai.web.session.session import (
    DefaultWebSessionContext,
    DefaultWebSessionStorageEvaluator,
    DefaultWebSessionManager,
    WebSessionKey,
)


from yosai.web.subject.subject import (
    WebSubjectBuilder,
    DefaultWebSubjectContext,
    WebDelegatingSubject,
    WebSecurityUtils,
)

from yosai.web.mgt.mgt import (
    DefaultWebSubjectFactory,
    WebSecurityManager,
    CookieRememberMeManager,
)
