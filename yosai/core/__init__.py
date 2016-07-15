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
    AbstractMethodException,
    AccountException,
    AccountStoreRealmAuthenticationException,
    AuthenticationConfigException,
    AuthenticationSettingsContextException,
    AuthenticationException,
    AuthenticationEventException,
    AuthenticationStrategyMissingRealmException,
    AuthorizationException,
    AuthorizationEventException,
    AuthzInfoNotFoundException,
    CacheException,
    ConcurrentAccessException,
    CredentialsNotFoundException,
    CredentialsException,
    CryptContextException,
    DeleteSubjectException,
    DeserializationException,
    DisabledAccountException,
    DisabledSessionException,
    EventBusMessageDataException,
    EventBusSubscriptionException,
    EventBusTopicException,
    EventException,
    EventRegistrationException,
    ExecutionException,
    ExcessiveAttemptsException,
    ExpiredCredentialsException,
    ExpiredSessionException,
    FileNotFoundException,
    GenericException,
    HostUnauthorizedException,
    IdentifierMismatchException,
    IdentifiersNotSetException,
    InvalidArgumentException,
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
    LogoutEventException,
    LoggingException,
    LoggingSetupException,
    MisconfiguredException,
    MissingCredentialsException,
    MissingHashAlgorithmException,
    MissingMethodException,
    MissingPrivateSaltException,
    MultiRealmAuthenticationException,
    PasswordMatchException,
    PasswordVerifierInvalidTokenException,
    PasswordVerifierInvalidAccountException,
    PreparePasswordException,
    PermissionIndexingException,
    RealmAttributesException,
    SaveSubjectException,
    SecurityManagerException,
    SecurityManagerNotSetException,
    SerializationException,
    SessionCacheException,
    SessionCreationException,
    SessionDeleteException,
    SessionException,
    SessionEventException,
    StoppedSessionException,
    SubjectContextException,
    SubjectException,
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
    YosaiContextException,
    YosaiException,
)

from yosai.core.serialize import abcs as serialize_abcs
from yosai.core.concurrency import abcs as concurrency_abcs
from yosai.core.event import abcs as event_abcs
from yosai.core.account import abcs as account_abcs
from yosai.core.authc import abcs as authc_abcs
from yosai.core.realm import abcs as realm_abcs
from yosai.core.authz import abcs as authz_abcs
from yosai.core.session import abcs as session_abcs
from yosai.core.subject import abcs as subject_abcs
from yosai.core.mgt import abcs as mgt_abcs
from yosai.core.cache import abcs as cache_abcs


from yosai.core.conf.yosaisettings import (
    settings,
    LazySettings,
    Settings,
)

from yosai.core.logging.slogging import (
    load_logconfig,
)


from yosai.core.serialize.serialize import (
    CollectionDict,
    JSONSerializer,
    MSGPackSerializer,
    SerializationManager,
)

from yosai.core.account.account import (
    Account,
)


from yosai.core.event.event import (
    DefaultEventBus,
    event_bus,
)


from yosai.core.concurrency.concurrency import (
    StoppableScheduledExecutor,
)


from yosai.core.utils.utils import (
    OrderedSet,
    ThreadStateManager,
    memoized_property,
    unix_epoch_time,
)


from yosai.core.session.session_settings import (
    DefaultSessionSettings,
    session_settings,
)


from yosai.core.session.session_gen import(
    RandomSessionIDGenerator,
    UUIDSessionIDGenerator,
)


from yosai.core.context.context import (
    MapContext,
)


from yosai.core.subject.identifier import (
    SimpleIdentifierCollection,
)


from yosai.core.session.session import (
    AbstractSessionStore,
    SessionEventHandler,
    CachingSessionStore,
    DefaultSessionContext,
    DefaultSessionKey,
    DefaultNativeSessionManager,
    DelegatingSession,
    DefaultSessionStorageEvaluator,
    # ExecutorServiceSessionValidationScheduler,
    MemorySessionStore,
    ProxiedSession,
    # SessionTokenGenerator,
    # ScheduledSessionValidator,
    DefaultNativeSessionHandler,
    SimpleSession,
    SimpleSessionFactory,
)


thread_local = threading.local()  # use only one global instance

from yosai.core.subject.subject import(
    Yosai,
    DefaultSubjectContext,
    DefaultSubjectStore,
    DefaultSubjectFactory,
    DelegatingSubject,
    SubjectBuilder,
    global_subject_context,
)


from yosai.core.authc.authc_account import (
    DefaultCompositeAccountId,
    DefaultCompositeAccount,
)

from yosai.core.authc.strategy import (
    DefaultAuthenticationAttempt,
    AllRealmsSuccessfulStrategy,
    AtLeastOneRealmSuccessfulStrategy,
    FirstRealmSuccessfulStrategy,
)

from yosai.core.authc.context import (
    AuthenticationSettings,
    CryptContextFactory,
    authc_settings,
)

from yosai.core.authc.authc import (
    Credential,
    CredentialResolver,
    DefaultAuthenticator,
    UsernamePasswordToken,
)

from yosai.core.authc.credential import (
    DefaultPasswordService,
    PasswordVerifier,
    SimpleCredentialsVerifier,
    AllowAllCredentialsVerifier,
)

from yosai.core.authz.authz import (
    AllPermission,
    AuthzInfoResolver,
    DefaultPermission,
    PermissionResolver,
    ModularRealmAuthorizer,
    IndexedAuthorizationInfo,
    IndexedPermissionVerifier,
    RoleResolver,
    SimpleRole,
    SimpleRoleVerifier,
    WildcardPermission,
)


from yosai.core.realm.realm import (
    AccountStoreRealm,
)


from yosai.core.mgt.mgt_settings import(
    DefaultMGTSettings,
    mgt_settings,
)


from yosai.core.mgt.mgt import (
    AbstractRememberMeManager,
    NativeSecurityManager,
)


from yosai.core.authc.decorators import (
    requires_authentication,
    requires_guest,
    requires_user,
)


from yosai.core.authz.decorators import (
    requires_dynamic_permission,
    requires_permission,
    requires_role,
)
