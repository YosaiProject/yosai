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


import threading

from .exceptions import (
    AbsoluteExpiredSessionException,
    AccountException,
    AccountStoreRealmAuthenticationException,
    AdditionalAuthenticationRequired,
    AuthenticationConfigException,
    AuthenticationSettingsContextException,
    AuthenticationException,
    AuthenticationEventException,
    AuthenticationStrategyMissingRealmException,
    AuthorizationException,
    AuthorizationEventException,
    AuthzInfoNotFoundException,
    CacheException,
    CacheInitializationException,
    CredentialsNotFoundException,
    CredentialsException,
    CryptContextException,
    DeleteSubjectException,
    DeserializationException,
    EventBusMessageDataException,
    EventBusSubscriptionException,
    EventBusTopicException,
    EventException,
    EventRegistrationException,
    ExpiredCredentialsException,
    ExpiredSessionException,
    HostUnauthorizedException,
    IdentifierMismatchException,
    IdleExpiredSessionException,
    IncorrectCredentialsException,
    IncorrectAttributeException,
    InsufficientAuthcInfoException,
    InvalidAuthcAttemptRealmsArgumentException,
    InvalidAuthenticationSequenceException,
    InvalidSessionException,
    InvalidAuthenticationTokenException,
    InvalidSerializationFormatException,
    InvalidTokenException,
    LockedAccountException,
    LogoutEventException,
    LoggingException,
    LoggingSetupException,
    MissingCredentialsException,
    MissingHashAlgorithmException,
    MissingPrivateSaltException,
    MultiRealmAuthenticationException,
    PasswordMatchException,
    PreparePasswordException,
    PermissionIndexingException,
    RealmAttributesException,
    SaveSubjectException,
    SecurityManagerException,
    SecurityManagerInitException,
    SerializationException,
    SessionCacheException,
    SessionDeleteException,
    SessionException,
    SessionEventException,
    StoppedSessionException,
    SubjectContextException,
    SubjectException,
    UnauthenticatedException,
    UnauthorizedException,
    UncacheSessionException,
    UnknownAccountException,
    UnrecognizedAttributeException,
    UnsupportedTokenException,
    YosaiException,
)

from yosai.core.serialize import abcs as serialize_abcs
from yosai.core.event import abcs as event_abcs
from yosai.core.account import abcs as account_abcs
from yosai.core.authc import abcs as authc_abcs
from yosai.core.realm import abcs as realm_abcs
from yosai.core.authz import abcs as authz_abcs
from yosai.core.session import abcs as session_abcs
from yosai.core.subject import abcs as subject_abcs
from yosai.core.mgt import abcs as mgt_abcs
from yosai.core.cache import abcs as cache_abcs

from yosai.core.utils.utils import (
    OrderedSet,
    ThreadStateManager,
    maybe_resolve,
    memoized_property,
    qualified_name,
    resolve_reference,
    unix_epoch_time,
)


from yosai.core.conf.yosaisettings import (
    LazySettings,
    Settings,
)


from yosai.core.mgt.mgt_settings import(
    RememberMeSettings,
    SecurityManagerSettings,
)


from yosai.core.session.session_settings import (
    DefaultSessionSettings,
)


from yosai.core.authc.authc_settings import (
    AuthenticationSettings,
)


from yosai.core.logging.slogging import (
    load_logconfig,
)


from yosai.core.account.account import (
    Account,
)


from yosai.core.event.event import (
    DefaultEventBus,
    EventLogger,
)


from yosai.core.concurrency.concurrency import (
    StoppableScheduledExecutor,
)


from yosai.core.subject.identifier import (
    SimpleIdentifierCollection,
)


from yosai.core.session.session import (
    AbstractSessionStore,
    SessionEventHandler,
    CachingSessionStore,
    DefaultSessionKey,
    DefaultNativeSessionManager,
    DefaultSessionStorageEvaluator,
    DelegatingSession,
    MemorySessionStore,
    DefaultNativeSessionHandler,
    SimpleSession,
)


from yosai.core.serialize.serialize import (
    SerializationManager,
)

thread_local = threading.local()  # use only one global instance

from yosai.core.subject.subject import(
    Yosai,
    DefaultSubjectContext,
    DefaultSubjectStore,
    DelegatingSubject,
    SecurityManagerCreator,
    global_subject_context,
    global_yosai_context,
)

from yosai.core.authc.strategy import (
    DefaultAuthenticationAttempt,
    AllRealmsSuccessfulStrategy,
    AtLeastOneRealmSuccessfulStrategy,
    FirstRealmSuccessfulStrategy,
)

from yosai.core.authc.authc import (
    DefaultAuthenticator,
    TOTPToken,
    UsernamePasswordToken,
    token_info,
)

from yosai.core.authc.credential import (
    PasslibVerifier,
)

from yosai.core.authz.authz import (
    AllPermission,
    DefaultPermission,
    ModularRealmAuthorizer,
    IndexedAuthorizationInfo,
    IndexedPermissionVerifier,
    SimpleRoleVerifier,
    WildcardPermission,
)


from yosai.core.realm.realm import (
    AccountStoreRealm,
)


from yosai.core.mgt.mgt import (
    AbstractRememberMeManager,
    NativeSecurityManager,
)
