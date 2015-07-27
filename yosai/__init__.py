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
    PrimaryPrincipalIntegrityException,
    RealmAttributesException,
    RealmMisconfiguredException,
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
    UnrecognizedPrincipalException,
    UnsupportedOperationException,
    UnsupportedTokenException,
    YosaiException,
)

from .conf import (
    settings,
    LazySettings,
    Settings,
)

from .concurrency import (
    StoppableScheduledExecutor,
)


from .logging import (
    LogManager,
)

from .utils import (
    OrderedSet,
    unix_epoch_time,
)

from .event import (
    Event,
    EventBus,
)

from .authc import (
    DefaultAuthenticator,
    DefaultCompositeAccount,
    DefaultCompositeAccountId,
    PasswordMatcher,
    UsernamePasswordToken,
)

from .realm import (
    AccountStoreRealm,
    DefaultAccountCacheHandler,
)


from .authz import (
    AllPermission,
    DomainPermission,
    ModularRealmAuthorizer,
    SimpleAuthorizationInfo,
    SimpleRole,
    WildcardPermission,
    WildcardPermissionResolver,
)

"""
from .cache import (
#    MapCache,
#    MemoryConstrainedCacheManager,
)
"""

from .context import (
    MapContext,
)

"""
from .security import (
    # ApplicationSecurityManager,
    # DefaultSecurityManager,
    # SecurityUtils,
)
"""

from .serialize import (
    SerializationManager,
)

from .session import (
    AbstractSessionDAO,
    AbstractNativeSessionManager,
    AbstractValidatingSessionManager,
    CachingSessionDAO,
    DefaultSessionContext,  
    DefaultSessionKey,
    # DefaultSessionManager,
    DelegatingSession,
    # DefaultSessionStorageEvaluator,
    DefaultSessionSettings,
    ExecutorServiceSessionValidationScheduler,
    # EnterpriseCacheSessionDAO,
    MemorySessionDAO,
    ImmutableProxiedSession,
    ProxiedSession,
    RandomSessionIDGenerator,
    # Session,
    # SessionManager,
    # SessionTokenGenerator,
    SimpleSession,
    SimpleSessionFactory,
    UUIDSessionIDGenerator,
)

"""
from .subject import(
    # DefaultSubjectContext,
    # DefaultSubjectDAO,
    # DefaultSubjectFactory,
    # DelegatingSubject,
    # StoppingAwareProxiedSession,
)
"""

