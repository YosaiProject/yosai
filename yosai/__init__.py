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

__author__ = "Darin Gordon"
__copyright__ = "Copyright 2015, The Yosai Project"
__credits__ = ["Apache Shiro Project Contributors"]
__license__ = "Apache"
__version__ = "0.0.1"
__maintainer__ = "Darin Gordon"
__email__ = "dkcdkg@gmail.com"
__status__ = "Development"

from .exceptions import (
    AbstractMethodException,
    AccountException,
    AccountCacheHandlerException,
    AccountStoreRealmAuthenticationException,
    AuthenticationConfigException,
    AuthenticationSettingsContextException,
    AuthenticationException,
    AuthenticationStrategyMissingRealmException,
    AuthorizationException,
    CacheException,
    CacheAccountException,
    CacheKeyRemovalException,
    ClearCacheAccountException,
    ConcurrentAccessException,
    CredentialsException,
    CryptContextException,
    DeleteSubjectException,
    DisabledAccountException,
    DisabledSessionException,
    EventBusMessageDataException,
    EventBusSubscriptionException,
    EventBusTopicException,
    ExecutionException,
    ExcessiveAttemptsException,
    ExpiredCredentialsException,
    ExpiredSessionException,
    FileNotFoundException,
    GenericException,
    GetCachedAccountException,
    HostUnauthorizedException,
    IllegalArgumentException,
    IllegalStateException,
    IncorrectCredentialsException,
    IncorrectAttributeException,
    InvalidArgumentException,
    InvalidAuthcAttemptRealmsArgumentException,
    InvalidSessionException,
    InvalidAuthenticationTokenException,
    InvalidSerializationFormatException,
    InvalidTokenPasswordException,
    LockedAccountException,
    MisconfiguredException,
    MissingCredentialsException,
    MissingHashAlgorithmException,
    MissingMethodException,
    MissingPrivateSaltException,
    MultiRealmAuthenticationException,
    NullPointerException,
    PasswordMatchException,
    PasswordMatcherInvalidTokenException,
    PasswordMatcherInvalidAccountException,
    PepperPasswordException,
    PrimaryIdentifierIntegrityException,
    RealmAttributesException,
    RealmMisconfiguredException,
    SaveSubjectException,
    SecurityManagerException,
    SerializationException,
    SessionDeleteException,
    SessionException,
    SessionEventException,
    StoppedSessionException,
    UnauthenticatedException,
    UnauthorizedException,
    UnavailableSecurityManagerException,
    UncacheSessionException,
    UnknownAccountException,
    UnknownSessionException,
    UnrecognizedAttributeException,
    UnrecognizedIdentifierException,
    UnsupportedOperationException,
    UnsupportedTokenException,
    YosaiException,
)

from yosai.security_utils import (
    SecurityUtils,    
)

from yosai.serialize import abcs as serialize_abcs
from yosai.concurrency import abcs as concurrency_abcs
from yosai.event import abcs as event_abcs
from yosai.account import abcs as account_abcs
from yosai.authc import abcs as authc_abcs
from yosai.realm import abcs as realm_abcs
from yosai.authz import abcs as authz_abcs
from yosai.session import abcs as session_abcs
from yosai.subject import abcs as subject_abcs
from yosai.mgt import abcs as mgt_abcs
from yosai.cache import abcs as cache_abcs


from yosai.conf.yosaisettings import (
    settings,
    LazySettings,
    Settings,
)

from yosai.concurrency.concurrency import (
    StoppableScheduledExecutor,
)


from yosai.logging.s_logging import (
    LogManager,
)

from yosai.utils.utils import (
    OrderedSet,
    unix_epoch_time,
)

from yosai.serialize.serialize import (
    SerializationManager,
)

from yosai.event.event import (
    Event,
    DefaultEventBus,
)

from yosai.authc.authc_account import (
    DefaultCompositeAccountId,
    DefaultCompositeAccount,
)

from yosai.authc.strategy import (
    DefaultAuthenticationAttempt,
    AllRealmsSuccessfulStrategy,
    AtLeastOneRealmSuccessfulStrategy,
    FirstRealmSuccessfulStrategy,
)

from yosai.authc.context import (
    AuthenticationSettings,
    CryptContextFactory,
    authc_settings,
)

from yosai.authc.authc import (
    AbstractAuthcService,
    DefaultAuthenticator,
    DefaultHashService,
    DefaultPasswordService,
    UsernamePasswordToken,
)

from yosai.authc.credential import (
    PasswordMatcher,
    SimpleCredentialsMatcher,
    AllowAllCredentialsMatcher,
)


from yosai.realm.realm import (
    AccountStoreRealm,
    DefaultAccountCacheHandler,
)


from yosai.authz.authz import (
    AllPermission,
    DomainPermission,
    ModularRealmAuthorizer,
    SimpleAuthorizationInfo,
    SimpleRole,
    WildcardPermission,
    WildcardPermissionResolver,
)

from yosai.cache.cache import (
    DisabledCache,
    DisabledCacheManager,
#    MapCache,
#    MemoryConstrainedCacheManager,
)

from yosai.context.context import (
    MapContext,
)

from yosai.session.session_settings import (
    DefaultSessionSettings,
    session_settings,
)

from yosai.session.session_gen import(
    RandomSessionIDGenerator,
    UUIDSessionIDGenerator,
)

from yosai.session.session import (
    AbstractSessionStore,
    AbstractNativeSessionManager,
    AbstractValidatingSessionManager,
    CachingSessionStore,
    DefaultSessionContext,  
    DefaultSessionKey,
    DefaultSessionManager,
    DelegatingSession,
    DefaultSessionStorageEvaluator,
    ExecutorServiceSessionValidationScheduler,
    # EnterpriseCacheSessionStore,
    MemorySessionStore,
    ImmutableProxiedSession,
    ProxiedSession,
    # SessionTokenGenerator,
    SimpleSession,
    SimpleSessionFactory,
)

from yosai.subject.subject import(
    DefaultSubjectContext,
    DefaultSubjectStore,
    DefaultSubjectFactory,
    # DelegatingSubject,
    # StoppingAwareProxiedSession,
)

from yosai.subject.identifier import (
    SimpleIdentifierCollection,
)

from yosai.mgt.mgt import (
    DefaultSecurityManager,
)

